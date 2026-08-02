#!/usr/bin/env bun
// post-hook.ts — Claude Code hook → dashi-channel webhook proxy.
//
// Reads a Claude hook JSON envelope from stdin and POSTs it (with the chat
// id and bearer token from env) to the plugin's `/hooks/agent` endpoint.
//
// Hard invariants:
//   * Exit code 0 in ALL paths. Claude blocks the model if a hook exits non-
//     zero; visibility is best-effort, must never gate the agent.
//   * Stdout stays empty. Hooks that emit stdout get treated as additional
//     model context, so a `UserPromptSubmit` hook printing anything would
//     leak it back into the conversation.
//   * Stderr lines are redacted: never the bearer token, never the prompt
//     body, never the full tool input. One short message on failure paths
//     is the maximum.
//
// The helper does not write or read any files; configuration lives in env:
//   TELEGRAM_WEBHOOK_URL     e.g. http://127.0.0.1:8089/hooks/agent
//   TELEGRAM_WEBHOOK_TOKEN   bearer token configured on the plugin
//   TELEGRAM_HOOK_CHAT_ID    target Telegram chat id (string or numeric)
//   TELEGRAM_HOOK_AGENT_ID   optional agent id (defaults to no agentId)

export interface HookRequest {
  readonly url: string
  readonly headers: Readonly<Record<string, string>>
  readonly body: string
}

export interface BuildHookRequestInput {
  readonly env: Readonly<Record<string, string | undefined>>
  readonly hook: Record<string, unknown>
}

export interface BuildHookRequestError {
  readonly kind: 'error'
  readonly reason: string
}

export type BuildHookRequestResult = HookRequest | BuildHookRequestError

/**
 * Pure builder so unit tests can verify the wire shape without a network.
 * Returns either a request blueprint or a structured `error` shape — never
 * throws. Callers are expected to log the redacted `reason` and exit 0.
 */
export function buildHookRequest(input: BuildHookRequestInput): BuildHookRequestResult {
  const url = input.env.TELEGRAM_WEBHOOK_URL
  const token = input.env.TELEGRAM_WEBHOOK_TOKEN
  const chatId = input.env.TELEGRAM_HOOK_CHAT_ID
  const agentId = input.env.TELEGRAM_HOOK_AGENT_ID

  if (!url) return { kind: 'error', reason: 'missing TELEGRAM_WEBHOOK_URL' }
  if (!token) return { kind: 'error', reason: 'missing TELEGRAM_WEBHOOK_TOKEN' }
  if (!chatId) return { kind: 'error', reason: 'missing TELEGRAM_HOOK_CHAT_ID' }

  // Validate the hook payload looks like a Claude hook envelope by checking
  // for at least `hook_event_name` and `session_id`. We don't re-validate
  // the full schema here — the server is the boundary.
  if (typeof input.hook.hook_event_name !== 'string') {
    return { kind: 'error', reason: 'hook payload missing hook_event_name' }
  }

  const merged: Record<string, unknown> = {
    chatId,
    ...(agentId ? { agentId } : {}),
    ...input.hook,
  }

  return {
    url,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(merged),
  }
}

// ─────────────────────────────────────────────────────────────────────
// Delivery with a SessionStart-only retry (2026-08-03).
//
// The tmux session starts BEFORE the plugin's webhook listener accepts
// connections — observed as `webhook fetch failed: Unable to connect` at
// 22:38:01 against a listener that came up at 22:38:03. SessionStart is the
// hook that carries the chat→session binding the pinned context card renders
// from, and it fires exactly once per session, so losing that one POST leaves
// the card blank for the whole session.
//
// Scope of the retry is deliberately narrow:
//   * ONLY SessionStart. Claude WAITS for a hook to finish, so a retry budget
//     on UserPromptSubmit / Stop / PostToolUse would be latency on every turn.
//     Those events recur — a lost one self-heals on the next turn.
//   * ONLY on a fetch rejection, i.e. no HTTP response at all. A status code
//     proves the request reached the plugin; re-sending it would duplicate
//     session-lifecycle side effects. Dedup belongs on the server side.
// ─────────────────────────────────────────────────────────────────────

// How long SessionStart keeps trying. A DEADLINE rather than a fixed list of
// delays, because the length of the race is not ours to predict: the plugin
// runs `await bot.init()` — a live round-trip to api.telegram.org — BEFORE
// `startWebhookServer` (src/server.ts). On a cold start or a slow network that
// is seconds, so a budget calibrated on one observed 2 s gap would silently be
// too short exactly when it mattered. Paid only when nothing is listening.
export const SESSION_START_RETRY_DEADLINE_MS = 10_000

/** Capped exponential backoff between SessionStart attempts. */
const RETRY_BACKOFF_INITIAL_MS = 250
const RETRY_BACKOFF_MAX_MS = 2_000

// Per-attempt cap while we are still probing. NOT applied to the final attempt:
// `/hooks/agent` answers only after the memory writer, the status manager and
// the task mirror have run (src/webhook/server.ts), some of which call the
// Telegram API — so a slow-but-alive plugin must still get one untimed shot.
// Without this cap a host that black-holes packets would burn the OS connect
// timeout (~75 s on darwin) per attempt and blow Claude's own hook timeout.
const RETRY_PROBE_TIMEOUT_MS = 3_000

/** Hook events whose loss is terminal, so they may pay for a retry. */
const RETRYABLE_HOOK_EVENTS: ReadonlySet<string> = new Set(['SessionStart'])

const HTTP_OK_MIN = 200
const HTTP_OK_MAX = 299

/** Minimal `fetch` shape used here — keeps the seam free of DOM typings. */
export type HookFetch = (url: string, init: RequestInit) => Promise<Response>

export interface DeliverHookDeps {
  /** Test seam; defaults to the global `fetch`. */
  readonly fetchFn?: HookFetch
  /** Test seam; defaults to a real `setTimeout` sleep. */
  readonly sleep?: (ms: number) => Promise<void>
  /** Test seam; defaults to `Date.now`. */
  readonly now?: () => number
  /** Test seam; defaults to the redacted stderr `warn` above. */
  readonly warn?: (reason: string) => void
}

export interface DeliverHookResult {
  /** True only for a 2xx response. */
  readonly delivered: boolean
  /** Attempts actually made, including the first. */
  readonly attempts: number
  /** Present when the last attempt produced an HTTP response. */
  readonly status?: number
}

const realSleep = (ms: number): Promise<void> =>
  ms <= 0 ? Promise.resolve() : new Promise((resolve) => setTimeout(resolve, ms))

/** Redact anything token-shaped before a reason string can reach stderr. */
function redactReason(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err)
  return `webhook fetch failed: ${msg.replace(/Bearer\s+\S+/gi, 'Bearer ***')}`
}

/**
 * Read the Claude hook event name out of a parsed stdin envelope.
 *
 * Exported for tests: this one line decides whether the retry runs at all, and
 * a mutant that hard-codes the wrong name here left the whole suite green.
 *
 * @param payload Parsed hook envelope.
 * @returns The event name, or an empty string when it is not a string.
 */
export function resolveHookEventName(payload: Record<string, unknown>): string {
  const name = payload.hook_event_name
  return typeof name === 'string' ? name : ''
}

/**
 * POST a built hook request, retrying only the events (and only the failure
 * mode) where a retry is both safe and worth the latency. Never throws and
 * never writes to stdout; failures produce at most one redacted stderr line.
 *
 * @param request Blueprint from {@link buildHookRequest}.
 * @param hookEventName Claude's `hook_event_name` — decides the retry budget.
 * @param deps Optional test seams for fetch, sleep, clock and warn.
 * @returns Outcome of the last attempt plus the attempt count.
 */
export async function deliverHookRequest(
  request: HookRequest,
  hookEventName: string,
  deps: DeliverHookDeps = {},
): Promise<DeliverHookResult> {
  const doFetch = deps.fetchFn ?? ((url, init) => fetch(url, init))
  const sleep = deps.sleep ?? realSleep
  const now = deps.now ?? Date.now
  const emit = deps.warn ?? warn

  const retryable = RETRYABLE_HOOK_EVENTS.has(hookEventName)
  const startedAt = now()

  let attempts = 0
  let backoff = RETRY_BACKOFF_INITIAL_MS
  let failure: string | undefined
  let httpStatus: number | undefined

  for (;;) {
    // The attempt is "final" when no retry may follow it — that one runs
    // untimed, every earlier probe carries RETRY_PROBE_TIMEOUT_MS.
    const elapsed = now() - startedAt
    const isFinal = !retryable || elapsed >= SESSION_START_RETRY_DEADLINE_MS
    attempts++

    let outcome: Response | undefined
    try {
      const init: RequestInit = {
        method: 'POST',
        headers: { ...request.headers },
        body: request.body,
      }
      if (!isFinal) init.signal = AbortSignal.timeout(RETRY_PROBE_TIMEOUT_MS)
      outcome = await doFetch(request.url, init)
    } catch (err) {
      failure = redactReason(err)
      if (isFinal) break
      const remaining = SESSION_START_RETRY_DEADLINE_MS - (now() - startedAt)
      if (remaining <= 0) continue // deadline passed mid-attempt → final shot
      await sleep(Math.min(backoff, remaining))
      backoff = Math.min(backoff * 2, RETRY_BACKOFF_MAX_MS)
      continue
    }

    if (outcome.status >= HTTP_OK_MIN && outcome.status <= HTTP_OK_MAX) {
      return { delivered: true, attempts, status: outcome.status }
    }
    // An HTTP status means the plugin received it — don't re-send, or the
    // session-lifecycle side effects run twice. Don't log the response body
    // either: it can quote payload fields back.
    httpStatus = outcome.status
    failure = `webhook responded ${outcome.status}`
    break
  }

  // Emitted OUTSIDE the try: a throwing `warn` must not be mistaken for a
  // failed fetch and trigger a second POST.
  emit(failure ?? 'webhook delivery failed')
  return httpStatus === undefined
    ? { delivered: false, attempts }
    : { delivered: false, attempts, status: httpStatus }
}

// ─────────────────────────────────────────────────────────────────────
// Stdin reader. Bun supports `Bun.stdin.text()`, but we also accept the
// no-content case (some Claude hooks fire without stdin in dev).
// ─────────────────────────────────────────────────────────────────────

interface BunGlobal {
  readonly stdin?: { readonly text?: () => Promise<string> }
}

async function readStdin(): Promise<string> {
  try {
    // Bun exposes `Bun.stdin.text()`; the global type is opaque under Node
    // so we narrow through a local interface instead of an `unknown` cast
    // chain (review L1).
    const bun = (globalThis as { Bun?: BunGlobal }).Bun
    const fn = bun?.stdin?.text
    if (typeof fn === 'function') return await fn.call(bun?.stdin)
  } catch {
    /* fall through to Node-style fallback */
  }
  // Fallback for non-Bun runtimes (used in tests).
  return await new Promise<string>((resolve) => {
    const chunks: Buffer[] = []
    process.stdin.on('data', (chunk: Buffer) => chunks.push(chunk))
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    process.stdin.on('error', () => resolve(''))
  })
}

// Short, secret-free warning line. Anything we emit MUST be redacted —
// never include bearer tokens, prompt body, tool_input keys, etc.
function warn(reason: string): void {
  // 80 char cap so a verbose error string can't tail-leak through a long
  // line. Stderr only — stdout is intentionally untouched.
  const safe = reason.length > 80 ? `${reason.slice(0, 77)}...` : reason
  process.stderr.write(`telegram-hook: ${safe}\n`)
}

async function main(): Promise<void> {
  let raw = ''
  try {
    raw = await readStdin()
  } catch {
    warn('stdin read failed')
    return
  }
  if (raw.trim().length === 0) {
    // No payload — nothing to forward, exit cleanly.
    return
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    warn('stdin not valid JSON')
    return
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    warn('stdin payload not an object')
    return
  }

  const req = buildHookRequest({
    env: process.env,
    hook: parsed as Record<string, unknown>,
  })
  if ('kind' in req && req.kind === 'error') {
    warn(req.reason)
    return
  }

  // Narrow to HookRequest after the discriminator check.
  const request = req as HookRequest
  await deliverHookRequest(request, resolveHookEventName(parsed as Record<string, unknown>))
}

// Bun executes top-level await; we wrap so the script can also be imported
// by tests without running main(). Only run when executed directly.
const isMainModule = (() => {
  try {
    // Bun + Node both expose `import.meta.url` and (in CJS-compat layer)
    // `require.main === module`. We use a robust check: argv[1] basename
    // matches this file.
    const arg = process.argv[1] ?? ''
    return arg.endsWith('post-hook.ts') || arg.endsWith('post-hook.js')
  } catch {
    return false
  }
})()

if (isMainModule) {
  // Top-level await is supported in Bun; we explicitly catch so any unawaited
  // rejection still exits 0.
  await main().catch((err) => {
    warn(err instanceof Error ? err.message : 'unknown error')
  })
}
