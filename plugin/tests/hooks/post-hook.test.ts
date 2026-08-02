// Phase 7 / T5 — unit tests around the post-hook request builder.
// No real network: we exercise `buildHookRequest` directly.
//
// 2026-08-03: plus `deliverHookRequest`, which owns the SessionStart retry.

import { describe, expect, test } from 'bun:test'
import { spawnSync } from 'child_process'
import { join } from 'path'

import {
  buildHookRequest,
  deliverHookRequest,
  resolveHookEventName,
  retryDeadlineMs,
  SESSION_START_RETRY_DEADLINE_MS,
  type HookRequest,
} from '../../scripts/post-hook.js'

const TOKEN = 'unit-test-token'

function baseHook(): Record<string, unknown> {
  return {
    hook_event_name: 'Stop',
    session_id: 's1',
    transcript_path: '/tmp/t.jsonl',
    cwd: '/tmp',
  }
}

describe('buildHookRequest', () => {
  test('builds POST with bearer + JSON body containing chatId', () => {
    const result = buildHookRequest({
      env: {
        TELEGRAM_HOOK_CHAT_ID: '164795011',
        TELEGRAM_WEBHOOK_URL: 'http://127.0.0.1:8089/hooks/agent',
        TELEGRAM_WEBHOOK_TOKEN: TOKEN,
      },
      hook: baseHook(),
    })
    expect('kind' in result).toBe(false)
    if ('kind' in result) throw new Error('unreachable')
    expect(result.url).toBe('http://127.0.0.1:8089/hooks/agent')
    expect(result.headers.Authorization).toBe(`Bearer ${TOKEN}`)
    expect(result.headers['Content-Type']).toBe('application/json')
    expect(result.body).toContain('"chatId":"164795011"')
    expect(result.body).toContain('"hook_event_name":"Stop"')
  })

  test('attaches optional agentId when provided', () => {
    const result = buildHookRequest({
      env: {
        TELEGRAM_HOOK_CHAT_ID: '1',
        TELEGRAM_HOOK_AGENT_ID: 'dashi-channel',
        TELEGRAM_WEBHOOK_URL: 'http://x',
        TELEGRAM_WEBHOOK_TOKEN: TOKEN,
      },
      hook: baseHook(),
    })
    if ('kind' in result) throw new Error('unreachable')
    expect(result.body).toContain('"agentId":"dashi-channel"')
  })

  test('omits agentId when env unset', () => {
    const result = buildHookRequest({
      env: {
        TELEGRAM_HOOK_CHAT_ID: '1',
        TELEGRAM_WEBHOOK_URL: 'http://x',
        TELEGRAM_WEBHOOK_TOKEN: TOKEN,
      },
      hook: baseHook(),
    })
    if ('kind' in result) throw new Error('unreachable')
    expect(result.body).not.toContain('"agentId"')
  })

  test('missing TELEGRAM_WEBHOOK_URL → structured error', () => {
    const result = buildHookRequest({
      env: { TELEGRAM_HOOK_CHAT_ID: '1', TELEGRAM_WEBHOOK_TOKEN: TOKEN },
      hook: baseHook(),
    })
    expect('kind' in result).toBe(true)
    if (!('kind' in result)) throw new Error('unreachable')
    expect(result.reason).toContain('TELEGRAM_WEBHOOK_URL')
  })

  test('missing TELEGRAM_WEBHOOK_TOKEN → structured error', () => {
    const result = buildHookRequest({
      env: { TELEGRAM_HOOK_CHAT_ID: '1', TELEGRAM_WEBHOOK_URL: 'http://x' },
      hook: baseHook(),
    })
    if (!('kind' in result)) throw new Error('unreachable')
    expect(result.reason).toContain('TELEGRAM_WEBHOOK_TOKEN')
  })

  test('missing TELEGRAM_HOOK_CHAT_ID → structured error', () => {
    const result = buildHookRequest({
      env: { TELEGRAM_WEBHOOK_URL: 'http://x', TELEGRAM_WEBHOOK_TOKEN: TOKEN },
      hook: baseHook(),
    })
    if (!('kind' in result)) throw new Error('unreachable')
    expect(result.reason).toContain('TELEGRAM_HOOK_CHAT_ID')
  })

  test('hook payload without hook_event_name → error, never reaches network', () => {
    const result = buildHookRequest({
      env: {
        TELEGRAM_HOOK_CHAT_ID: '1',
        TELEGRAM_WEBHOOK_URL: 'http://x',
        TELEGRAM_WEBHOOK_TOKEN: TOKEN,
      },
      hook: { foo: 'bar' },
    })
    if (!('kind' in result)) throw new Error('unreachable')
    expect(result.reason).toContain('hook_event_name')
  })

  test('PreToolUse with prompt-shaped fields keeps tool_input intact', () => {
    const result = buildHookRequest({
      env: {
        TELEGRAM_HOOK_CHAT_ID: '1',
        TELEGRAM_WEBHOOK_URL: 'http://x',
        TELEGRAM_WEBHOOK_TOKEN: TOKEN,
      },
      hook: {
        hook_event_name: 'PreToolUse',
        session_id: 's1',
        transcript_path: '/tmp/t.jsonl',
        cwd: '/tmp',
        tool_name: 'Bash',
        tool_use_id: 'u1',
        tool_input: { command: 'bun test' },
      },
    })
    if ('kind' in result) throw new Error('unreachable')
    // tool_input is forwarded verbatim — the server is the masking boundary,
    // not the helper. Keeps the helper trivial enough to audit by eye.
    expect(result.body).toContain('"command":"bun test"')
  })

  test('bearer token not echoed into body', () => {
    const result = buildHookRequest({
      env: {
        TELEGRAM_HOOK_CHAT_ID: '1',
        TELEGRAM_WEBHOOK_URL: 'http://x',
        TELEGRAM_WEBHOOK_TOKEN: 'super-secret-token',
      },
      hook: baseHook(),
    })
    if ('kind' in result) throw new Error('unreachable')
    expect(result.body).not.toContain('super-secret-token')
    // …and lives only inside the header.
    expect(result.headers.Authorization).toBe('Bearer super-secret-token')
  })
})


// ─────────────────────────────────────────────────────────────────────
// deliverHookRequest — the SessionStart startup race (2026-08-03).
//
// The tmux session starts BEFORE the plugin's webhook listener accepts
// connections (observed: hook at 22:38:01, listener up at 22:38:03). The
// SessionStart hook carries the transcript path the pinned context card is
// rendered from, and it fires exactly once — so losing that one POST leaves
// the card showing a dash for the whole session.
//
// The tests below drive a FAKE CLOCK: `sleep` advances it, so a listener that
// comes up N ms late is expressed directly and the retry budget is checked by
// behaviour instead of by comparing the constant against itself.
// ─────────────────────────────────────────────────────────────────────

const REQUEST: HookRequest = {
  url: 'http://127.0.0.1:8089/hooks/agent',
  headers: { 'Content-Type': 'application/json', Authorization: 'Bearer t' },
  body: '{"hook_event_name":"SessionStart"}',
}

/** Connection-refused shape Bun/undici raise when nothing is listening yet. */
function connRefused(): Error {
  return new Error('Unable to connect. Is the computer able to access the url?')
}

interface Attempt {
  /** Fake-clock reading when the attempt was made. */
  readonly at: number
  /** Whether the attempt carried an abort signal (probe) or not (final). */
  readonly aborted: boolean
}

interface Harness {
  readonly fetchFn: (url: string, init: RequestInit) => Promise<Response>
  readonly sleep: (ms: number) => Promise<void>
  readonly now: () => number
  readonly warn: (reason: string) => void
  readonly attempts: Attempt[]
  readonly slept: number[]
  readonly warnings: string[]
  readonly elapsed: () => number
}

/**
 * Fake network + fake clock. `respond` decides the outcome of an attempt from
 * the current fake time: an `Error` is a rejected fetch, a number is a status.
 */
function harness(respond: (elapsedMs: number) => Error | number): Harness {
  const attempts: Attempt[] = []
  const slept: number[] = []
  const warnings: string[] = []
  let clock = 0
  return {
    attempts,
    slept,
    warnings,
    elapsed: (): number => clock,
    now: (): number => clock,
    fetchFn: (_url: string, init: RequestInit): Promise<Response> => {
      attempts.push({ at: clock, aborted: init.signal !== undefined })
      const outcome = respond(clock)
      if (outcome instanceof Error) return Promise.reject(outcome)
      return Promise.resolve(new Response('', { status: outcome }))
    },
    sleep: (ms: number): Promise<void> => {
      slept.push(ms)
      clock += ms
      return Promise.resolve()
    },
    warn: (reason: string): void => {
      warnings.push(reason)
    },
  }
}

/** Refuses every connection until `upAtMs`, then answers 200. */
const listenerUpAt =
  (upAtMs: number) =>
  (elapsed: number): Error | number =>
    elapsed < upAtMs ? connRefused() : 200

describe('deliverHookRequest', () => {
  test('SessionStart retries a refused connection and then succeeds', async () => {
    const h = harness(listenerUpAt(600))
    const result = await deliverHookRequest(REQUEST, 'SessionStart', h)
    expect(result.delivered).toBe(true)
    expect(result.status).toBe(200)
    expect(h.attempts.length).toBeGreaterThan(1)
    // A recovered delivery is not a failure — nothing is warned about.
    expect(h.warnings).toEqual([])
  })

  // The listener cannot come up before the plugin's `await bot.init()` round
  // trip to api.telegram.org finishes, so the budget has to survive a listener
  // that is SECONDS late — not just the 2 s once observed in the transcript.
  for (const upAt of [1_000, 2_500, 5_000, 9_000]) {
    test(`SessionStart still lands when the listener is ${upAt} ms late`, async () => {
      const h = harness(listenerUpAt(upAt))
      const result = await deliverHookRequest(REQUEST, 'SessionStart', h)
      expect(result.delivered).toBe(true)
      expect(h.warnings).toEqual([])
    })
  }

  test('SessionStart gives up after the deadline, without throwing', async () => {
    const h = harness(() => connRefused())
    const result = await deliverHookRequest(REQUEST, 'SessionStart', h)
    expect(result.delivered).toBe(false)
    expect(h.elapsed()).toBeGreaterThanOrEqual(SESSION_START_RETRY_DEADLINE_MS)
    // Bounded: the loop stops at the deadline instead of spinning.
    expect(h.elapsed()).toBeLessThan(SESSION_START_RETRY_DEADLINE_MS * 2)
    expect(h.warnings.length).toBe(1)
  })

  // Both reviews, 2026-08-03: an abort is indistinguishable from «never
  // arrived», so a per-attempt timeout would re-POST a SessionStart the plugin
  // had already accepted but was still handling (it answers only after the
  // memory writer / status manager / task mirror have run).
  test('no attempt is ever aborted — an abort would look like a lost request', async () => {
    const h = harness(() => connRefused())
    await deliverHookRequest(REQUEST, 'SessionStart', h)
    expect(h.attempts.length).toBeGreaterThan(1)
    expect(h.attempts.some((a) => a.aborted)).toBe(false)
  })

  test('backoff grows and stays capped', async () => {
    const h = harness(() => connRefused())
    await deliverHookRequest(REQUEST, 'SessionStart', h)
    expect(h.slept.length).toBeGreaterThan(2)
    // Grows: the widest wait is strictly longer than the first. (The LAST wait
    // is clamped to whatever is left of the deadline, so it proves nothing.)
    expect(Math.max(...h.slept)).toBeGreaterThan(h.slept[0] as number)
    // No single sleep may swallow the whole budget.
    for (const ms of h.slept) expect(ms).toBeLessThanOrEqual(SESSION_START_RETRY_DEADLINE_MS / 2)
  })

  for (const event of ['UserPromptSubmit', 'Stop', 'SessionEnd', 'PostToolUse']) {
    test(`${event} does not retry — it is per-turn latency, and it recurs`, async () => {
      const h = harness(() => connRefused())
      const result = await deliverHookRequest(REQUEST, event, h)
      expect(result.delivered).toBe(false)
      expect(h.attempts.length).toBe(1)
      expect(h.attempts[0]?.aborted).toBe(false)
      expect(h.slept).toEqual([])
    })
  }

  test('SessionStart does not retry an HTTP status — the plugin got the request', async () => {
    const h = harness(() => 500)
    const result = await deliverHookRequest(REQUEST, 'SessionStart', h)
    expect(h.attempts.length).toBe(1)
    expect(result.delivered).toBe(false)
    expect(result.status).toBe(500)
    expect(h.slept).toEqual([])
    expect(h.warnings.length).toBe(1)
  })

  // The 404 that actually kept the card blank: install-hooks.sh had written
  // TELEGRAM_HOOK_AGENT_ID='kuznets', and /hooks/agent answers 404 to any
  // agentId it does not own. A retry must NOT paper over that.
  test('a 404 is reported, not retried', async () => {
    const h = harness(() => 404)
    const result = await deliverHookRequest(REQUEST, 'SessionStart', h)
    expect(h.attempts.length).toBe(1)
    expect(result.status).toBe(404)
    expect(h.warnings[0]).toContain('404')
  })

  test('a 2xx status counts as delivered', async () => {
    for (const status of [200, 204]) {
      const h = harness(() => status)
      const result = await deliverHookRequest(REQUEST, 'SessionStart', h)
      expect(result.delivered).toBe(true)
      expect(h.attempts.length).toBe(1)
      expect(h.warnings).toEqual([])
    }
  })

  test('the warning never carries the bearer token', async () => {
    const h = harness(() => new Error('connect failed with Bearer super-secret-token'))
    await deliverHookRequest(REQUEST, 'Stop', h)
    expect(h.warnings.length).toBe(1)
    expect(h.warnings[0]).not.toContain('super-secret-token')
  })
})

// The one line that decides whether the retry runs at all. Without a test here
// a mutant that hard-codes the wrong event name leaves the whole suite green.
describe('resolveHookEventName', () => {
  test('reads the event name out of a hook envelope', () => {
    expect(resolveHookEventName({ hook_event_name: 'SessionStart' })).toBe('SessionStart')
    expect(resolveHookEventName({ hook_event_name: 'Stop' })).toBe('Stop')
  })

  test('a missing or non-string name degrades to the no-retry path', () => {
    expect(resolveHookEventName({})).toBe('')
    expect(resolveHookEventName({ hook_event_name: 42 })).toBe('')
    expect(resolveHookEventName({ hook_event_name: null })).toBe('')
  })

  test('the name it returns is the one that unlocks the retry', async () => {
    const parsed: Record<string, unknown> = { hook_event_name: 'SessionStart' }
    const h = harness(listenerUpAt(600))
    const result = await deliverHookRequest(REQUEST, resolveHookEventName(parsed), h)
    expect(result.delivered).toBe(true)
    expect(h.attempts.length).toBeGreaterThan(1)
  })
})

describe('retryDeadlineMs', () => {
  test('defaults when unset, honours a valid override', () => {
    expect(retryDeadlineMs({})).toBe(SESSION_START_RETRY_DEADLINE_MS)
    expect(retryDeadlineMs({ TELEGRAM_HOOK_RETRY_DEADLINE_MS: '400' })).toBe(400)
    expect(retryDeadlineMs({ TELEGRAM_HOOK_RETRY_DEADLINE_MS: '0' })).toBe(0)
  })

  // codex review round 2: a prefix-parse fails in the dangerous direction —
  // `1e9` reads as 1 ms, `0x10` as 0, so a value that looks generous would
  // quietly switch the retry off.
  test('a partially-numeric value is refused, not half-read', () => {
    for (const raw of ['1e9', '0x10', '600ms', ' 12 34', '1.5']) {
      expect(retryDeadlineMs({ TELEGRAM_HOOK_RETRY_DEADLINE_MS: raw })).toBe(
        SESSION_START_RETRY_DEADLINE_MS,
      )
    }
  })

  test('garbage and negatives fall back to the default, huge values are capped', () => {
    for (const raw of ['', 'soon', '-1']) {
      expect(retryDeadlineMs({ TELEGRAM_HOOK_RETRY_DEADLINE_MS: raw })).toBe(
        SESSION_START_RETRY_DEADLINE_MS,
      )
    }
    expect(retryDeadlineMs({ TELEGRAM_HOOK_RETRY_DEADLINE_MS: '999999999' })).toBeLessThanOrEqual(
      60_000,
    )
  })
})

// ─────────────────────────────────────────────────────────────────────
// End-to-end through the script's PUBLIC entry (stdin + env + exit code).
//
// codex review 2026-08-03: every test above drives the exported helper, so
// `main()` could be rewired to a plain one-shot fetch and the suite would stay
// green. These run the real file against a dead port.
// ─────────────────────────────────────────────────────────────────────

/** A port nothing listens on — a connect there is refused immediately. */
const DEAD_PORT = 8099
const E2E_DEADLINE_MS = 600

interface ScriptRun {
  readonly code: number
  readonly stdout: string
  readonly stderr: string
  readonly ms: number
}

function runScript(hookEventName: string): ScriptRun {
  const script = join(import.meta.dir, '..', '..', 'scripts', 'post-hook.ts')
  const payload = JSON.stringify({
    hook_event_name: hookEventName,
    session_id: 's-e2e',
    transcript_path: '/tmp/t.jsonl',
    cwd: '/tmp',
  })
  const startedAt = Date.now()
  const r = spawnSync(process.execPath, [script], {
    input: payload,
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH ?? '/usr/bin:/bin',
      HOME: process.env.HOME ?? '/tmp',
      TELEGRAM_HOOK_CHAT_ID: '1',
      TELEGRAM_WEBHOOK_URL: `http://127.0.0.1:${DEAD_PORT}/hooks/agent`,
      TELEGRAM_WEBHOOK_TOKEN: 'e2e-secret-token',
      TELEGRAM_HOOK_RETRY_DEADLINE_MS: String(E2E_DEADLINE_MS),
    },
  })
  return {
    code: r.status ?? -1,
    stdout: r.stdout ?? '',
    stderr: r.stderr ?? '',
    ms: Date.now() - startedAt,
  }
}

describe('post-hook.ts — public entry', () => {
  test('SessionStart against a dead port retries, still exits 0 with empty stdout', () => {
    const r = runScript('SessionStart')
    expect(r.code).toBe(0)
    expect(r.stdout).toBe('')
    // It kept trying for the whole (shortened) budget instead of giving up on
    // the first refusal — the behaviour the fix exists for.
    expect(r.ms).toBeGreaterThanOrEqual(E2E_DEADLINE_MS)
    expect(r.stderr).not.toContain('e2e-secret-token')
  })

  test('Stop against the same dead port gives up at once', () => {
    const r = runScript('Stop')
    expect(r.code).toBe(0)
    expect(r.stdout).toBe('')
    expect(r.ms).toBeLessThan(E2E_DEADLINE_MS)
    expect(r.stderr).not.toContain('e2e-secret-token')
  })
})
