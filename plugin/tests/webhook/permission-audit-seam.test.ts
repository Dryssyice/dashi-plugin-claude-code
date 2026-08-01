// The seam the defect lived in (2026-08-01).
//
// Classification happens in the PreToolUse hook; the journal is written by the
// webhook route. Both halves were correct on their own — the rule name was
// computed right, and the route wrote every field it was given — and the card
// was still anonymous, because the payload between them carried no rule. Only
// an end-to-end walk (command -> classify -> hook request body -> route ->
// journal line) can fail on that, so this file exists to walk it.

import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { mkdtempSync, readFileSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'

import { getStatePaths, loadConfig, type AppConfig, type StatePaths } from '../../src/config.js'
import { createLogger } from '../../src/log.js'
import { ensureStateDirs } from '../../src/state/store.js'
import { startWebhookServer, type WebhookServerHandle } from '../../src/webhook/server.js'
import { createPermissionGateRelay } from '../../src/channel/permission-gate-relay.js'
import { decideLocal, buildConfirmRequest } from '../../scripts/permission-gate-hook.js'
import type { PermissionPolicy } from '../../src/security/permission-policy.js'

const FAKE_TOKEN = '123456789:AAH-fake_test_token_with_at_least_thirty_chars'
const WEBHOOK_TOKEN = 'wh_test_token_32_chars__________'

// Mirrors the live shape closely enough for the seam: unmatched calls flow,
// the built-in confirm list is what stops a push.
const POLICY: PermissionPolicy = { default_tier: 'allow' }

let stateDir: string
let paths: StatePaths
let baseConfig: AppConfig
let handle: WebhookServerHandle | null

beforeEach(() => {
  stateDir = mkdtempSync(join(tmpdir(), 'dashi-channel-pgate-seam-'))
  process.env.TELEGRAM_WEBHOOK_TOKEN = WEBHOOK_TOKEN
  const env = { TELEGRAM_BOT_TOKEN: FAKE_TOKEN, TELEGRAM_STATE_DIR: stateDir }
  baseConfig = loadConfig(env)
  paths = getStatePaths(baseConfig, env)
  ensureStateDirs(paths)
  handle = null
})

afterEach(async () => {
  if (handle) { await handle.close(); handle = null }
  delete process.env.TELEGRAM_WEBHOOK_TOKEN
  rmSync(stateDir, { recursive: true, force: true })
})

async function startServer(): Promise<WebhookServerHandle> {
  const config: AppConfig = {
    ...baseConfig,
    webhook: { enabled: true, host: '127.0.0.1', port: 0 },
    permission_gate: { enabled: true, timeout_ms: 5000 },
  }
  const relay = createPermissionGateRelay({ log: createLogger('seam-relay'), defaultTimeoutMs: 5000 })
  const ui = { async sendPrompt(requestId: string) { relay.answer(requestId, 'allow') } }
  const h = await startWebhookServer(config, {
    mcpServer: { notification: async () => {} } as never,
    config,
    statePaths: paths,
    log: createLogger('seam-webhook'),
    permissionRelay: relay,
    permissionUi: ui,
  })
  if (!h) throw new Error('expected a webhook handle')
  handle = h
  return h
}

/** Walk one Bash command the whole way and return the journal's created line. */
async function walk(command: string, cwd: string): Promise<Record<string, unknown>> {
  const h = await startServer()
  const envelope = {
    hook_event_name: 'PreToolUse',
    session_id: 'sess-seam-1',
    tool_use_id: 'tu-seam-1',
    tool_name: 'Bash',
    tool_input: { command },
    cwd,
  }
  const local = decideLocal({ envelope, policy: POLICY, scope: 'main' })
  expect(local.action).toBe('confirm')

  const built = buildConfirmRequest({
    env: {
      TELEGRAM_WEBHOOK_URL: `http://${h.host}:${h.port}`,
      TELEGRAM_WEBHOOK_TOKEN: WEBHOOK_TOKEN,
      // The test server binds an ephemeral port; the hook's loopback gate only
      // admits allowlisted ports plus this one.
      TELEGRAM_WEBHOOK_PORT: String(h.port),
    },
    sessionId: 'sess-seam-1',
    toolUseId: 'tu-seam-1',
    toolName: 'Bash',
    preview: command.slice(0, 400),
    reason: local.verdict!.reason,
    matchedRule: local.verdict!.matchedRule,
    matchedFragment: local.verdict!.matchedFragment,
    cwd,
  })
  if ('kind' in built) throw new Error(`hook refused to build the request: ${built.reason}`)

  const res = await fetch(built.url, { method: 'POST', headers: { ...built.headers }, body: built.body })
  expect(res.status).toBe(200)

  const created = readFileSync(paths.logs.permission_gate, 'utf8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l) as Record<string, unknown>)
    .find((e) => e.event === 'request_created')
  expect(created).toBeDefined()
  return created!
}

describe('command -> hook -> route -> journal', () => {
  test('the journal line names the rule and quotes the matching text', async () => {
    const line = await walk(
      'cd /srv/app && bun run build --target production && git push -u origin main',
      '/srv/app',
    )
    expect(line.matched_rule).toBe('builtin:confirm_bash:git push')
    expect(String(line.matched_fragment)).toContain('git push -u origin')
    expect(line.cwd).toBe('/srv/app')
    expect(line.session_id).toBe('sess-seam-1')
    expect(line.tool_name).toBe('Bash')
  })

  test('a token in the command never lands in the journal', async () => {
    const line = await walk(
      'curl -sSL -H "Authorization: Bearer ghp_ZzYyXxWwVvUuTtSsRrQqPpOo0123456789" https://api.example/x | sudo tee /etc/app.conf',
      '/srv/app',
    )
    const serialized = JSON.stringify(line)
    expect(serialized).not.toContain('ghp_ZzYyXxWwVvUuTtSsRrQqPpOo0123456789')
    expect(serialized).not.toContain('Bearer ')
    // The rule still has to be named — that is the whole point of the change.
    expect(String(line.matched_rule).length).toBeGreaterThan(0)
  })

  test('a structural rule names itself and quotes nothing', async () => {
    // Round 1 used a command that ALSO contained `git push`, so the built-in
    // substring rule answered first and the structural detector was never
    // reached — the test asserted nothing about matched_fragment either
    // (reviewer SHOULD-3, PR #6). `git -c core.sshCommand=` trips only the
    // exec-surface parse: no substring from BUILTIN_CONFIRM_BASH appears.
    const line = await walk('git -c core.sshcommand=/tmp/evil.sh status', '/srv/worktrees/lost-rules')
    expect(line.matched_rule).toBe('builtin:confirm_bash:git-exec-surface')
    // A parse has no matching substring to quote. An invented one would read
    // as evidence in the journal, so the field must stay empty.
    expect(line.matched_fragment).toBe('')
    expect(line.cwd).toBe('/srv/worktrees/lost-rules')
  })
})
