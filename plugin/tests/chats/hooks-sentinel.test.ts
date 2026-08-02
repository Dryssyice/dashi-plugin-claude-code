// Phase 5 / FIX-H — sentinel tests for the multichat hooks.
//
// The hooks (pre-tool-use.sh, session-start.sh) live in
// `plugin/src/chats/hooks/` and are wired into per-chat Claude Code
// sessions by the tmux session pool. They MUST be no-ops when the
// surrounding process is not a per-chat session — otherwise an
// operator who accidentally registers them into the MASTER Thrall
// workspace would lock the master session out of every Bash / Edit /
// Read call (pre-tool-use returns exit 2 = block when CHAT_ID is
// unset).
//
// The sentinel: if `MULTICHAT_STATE_DIR` is unset, the hook is not
// running inside a per-chat session — exit 0 (allow / no-op).
//
// These tests drive the real shell scripts via spawnSync so the
// fail-closed branch we intentionally KEEP (MULTICHAT_STATE_DIR set
// but CHAT_ID unset) is also exercised end-to-end.

import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { spawnSync } from 'child_process'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'

const HOOKS_DIR = join(import.meta.dir, '..', '..', 'src', 'chats', 'hooks')
const PRE_HOOK = join(HOOKS_DIR, 'pre-tool-use.sh')
const SESSION_HOOK = join(HOOKS_DIR, 'session-start.sh')

interface RunResult {
  code: number
  stdout: string
  stderr: string
}

// Spawn a hook script with a clean env (we strip the parent env to make
// the sentinel check meaningful — `bun test` itself might inherit a
// stray MULTICHAT_STATE_DIR).
function run(
  script: string,
  env: Record<string, string>,
  stdin: string = '',
): RunResult {
  const r = spawnSync('bash', [script], {
    input: stdin,
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH ?? '/usr/bin:/bin',
      HOME: process.env.HOME ?? '/tmp',
      ...env,
    },
  })
  return {
    code: r.status ?? -1,
    stdout: r.stdout ?? '',
    stderr: r.stderr ?? '',
  }
}

let workspace: string
let policyPath: string

beforeEach(() => {
  workspace = mkdtempSync(join(tmpdir(), 'multichat-hooks-'))
  const chatsDir = join(workspace, 'chats')
  mkdirSync(chatsDir, { recursive: true })
  policyPath = join(chatsDir, 'policy.yaml')
  // Minimal policy: chat "164795011" with one Bash deny pattern and
  // no path/MCP denies. Lets us assert allow vs deny on Bash calls.
  writeFileSync(
    policyPath,
    [
      'version: 1',
      'chats:',
      '  "164795011":',
      '    deny:',
      '      bash_patterns:',
      '        - "rm -rf /"',
      '      mcp_tools: []',
      '      read_paths: []',
      '',
    ].join('\n'),
    'utf8',
  )
})

afterEach(() => {
  rmSync(workspace, { recursive: true, force: true })
})

describe('pre-tool-use.sh — sentinel pass-through', () => {
  test('MULTICHAT_STATE_DIR unset + arbitrary tool input -> exit 0, empty stdout', () => {
    // Note: we explicitly do NOT set MULTICHAT_STATE_DIR, but we also
    // pass an obviously dangerous Bash payload to prove the hook is a
    // total no-op — not just a lenient allow.
    const tool = JSON.stringify({
      tool_name: 'Bash',
      tool_input: { command: 'rm -rf /' },
    })
    const r = run(
      PRE_HOOK,
      { CLAUDE_WORKSPACE_DIR: workspace },
      tool,
    )
    expect(r.code).toBe(0)
    expect(r.stdout).toBe('')
  })
})

describe('pre-tool-use.sh — multichat context fail-closed without CHAT_ID', () => {
  test('MULTICHAT_STATE_DIR set + CHAT_ID unset -> deny (exit 2)', () => {
    const tool = JSON.stringify({
      tool_name: 'Bash',
      tool_input: { command: 'ls' },
    })
    const r = run(
      PRE_HOOK,
      {
        MULTICHAT_STATE_DIR: workspace,
        CLAUDE_WORKSPACE_DIR: workspace,
      },
      tool,
    )
    expect(r.code).toBe(2)
    // python json.dumps defaults to compact-ish formatting with spaces
    // after the separator. Match either `"decision": "block"` or
    // `"decision":"block"` defensively.
    expect(r.stdout).toMatch(/"decision":\s*"block"/)
    expect(r.stdout).toContain('CHAT_ID env var missing')
  })
})

describe('pre-tool-use.sh — multichat context with CHAT_ID', () => {
  test('allowed Bash command -> exit 0', () => {
    const tool = JSON.stringify({
      tool_name: 'Bash',
      tool_input: { command: 'ls -la' },
    })
    const r = run(
      PRE_HOOK,
      {
        MULTICHAT_STATE_DIR: workspace,
        CLAUDE_WORKSPACE_DIR: workspace,
        CHAT_ID: '164795011',
      },
      tool,
    )
    expect(r.code).toBe(0)
    expect(r.stdout).toBe('')
  })

  test('denied Bash command (matches policy bash_patterns) -> exit 2', () => {
    const tool = JSON.stringify({
      tool_name: 'Bash',
      tool_input: { command: 'sudo rm -rf / --no-preserve-root' },
    })
    const r = run(
      PRE_HOOK,
      {
        MULTICHAT_STATE_DIR: workspace,
        CLAUDE_WORKSPACE_DIR: workspace,
        CHAT_ID: '164795011',
      },
      tool,
    )
    expect(r.code).toBe(2)
    // python json.dumps defaults to compact-ish formatting with spaces
    // after the separator. Match either `"decision": "block"` or
    // `"decision":"block"` defensively.
    expect(r.stdout).toMatch(/"decision":\s*"block"/)
    expect(r.stdout).toContain('bash_patterns deny')
  })
})

describe('pre-tool-use.sh — the interpreter is chosen by checking, not by PATH', () => {
  // The hook used to run `python3` from PATH on the assumption that the one
  // PATH resolves has PyYAML. On this machine it did not, so the policy could
  // not be parsed and the fail-safe denied EVERY Bash / Edit / Read call in
  // every multichat session. The direction of the failure was right; the
  // effect was an agent that looks broken rather than a missing package.
  //
  // These tests put a yaml-less python3 first on PATH on purpose. Installing
  // PyYAML here would make them pass while fixing nothing — the next host
  // resolves a third interpreter.

  // A python3 that (a) reports no PyYAML and (b) makes it loud if the hook
  // runs the policy through it anyway: exit 99 with a marker no policy path
  // can produce.
  const SHIM = [
    '#!/usr/bin/env bash',
    'if [ "$1" = "-c" ]; then',
    '  case "$2" in *yaml*) exit 1;; esac',
    'fi',
    'printf \'%s\\n\' \'{"decision":"block","denied_by":"WRONG-INTERPRETER","reason":"the yaml-less shim ran the policy"}\'',
    'exit 99',
    '',
  ].join('\n')

  // Which interpreter the hook is SUPPOSED to fall back to is a property of the
  // host, not of the test. Masking PATH without naming a known-good fallback
  // would make these tests pass or fail depending on whether this machine keeps
  // its PyYAML in /usr/bin or in a venv — and a host-dependent test proves
  // nothing about the fix. So: probe once, pin it explicitly.
  function findYamlPython(): string | null {
    const probes = [
      '/usr/bin/python3',
      '/opt/homebrew/bin/python3',
      '/usr/local/bin/python3',
      spawnSync('bash', ['-c', 'command -v python3'], { encoding: 'utf8' })
        .stdout?.trim() ?? '',
    ]
    for (const p of probes) {
      if (!p) continue
      const r = spawnSync(p, ['-c', 'import yaml'], { encoding: 'utf8' })
      if (r.status === 0) return p
    }
    return null
  }

  const YAML_PYTHON = findYamlPython()
  // No PyYAML anywhere on this host: the «policy is still evaluated» cases have
  // nothing to evaluate it with. Skipped loudly rather than passed quietly.
  const withYaml = YAML_PYTHON ? test : test.skip

  let shimDir: string

  beforeEach(() => {
    shimDir = mkdtempSync(join(tmpdir(), 'yamlless-python-'))
    const shim = join(shimDir, 'python3')
    writeFileSync(shim, SHIM, { encoding: 'utf8', mode: 0o755 })
  })

  afterEach(() => {
    rmSync(shimDir, { recursive: true, force: true })
  })

  function runWithShimFirst(
    env: Record<string, string>,
    stdin: string,
  ): RunResult {
    return run(PRE_HOOK, {
      PATH: `${shimDir}:${process.env.PATH ?? '/usr/bin:/bin'}`,
      CHATS_HOOK_PYTHON_FALLBACKS: YAML_PYTHON ?? '',
      ...env,
    }, stdin)
  }

  withYaml('PATH python3 without PyYAML -> policy is still evaluated (deny survives)', () => {
    const r = runWithShimFirst(
      {
        MULTICHAT_STATE_DIR: workspace,
        CLAUDE_WORKSPACE_DIR: workspace,
        CHAT_ID: '164795011',
      },
      JSON.stringify({
        tool_name: 'Bash',
        tool_input: { command: 'sudo rm -rf / --no-preserve-root' },
      }),
    )
    expect(r.code).toBe(2)
    expect(r.stdout).toContain('bash_patterns deny')
    expect(r.stdout).not.toContain('WRONG-INTERPRETER')
  })

  withYaml('PATH python3 without PyYAML -> an allowed call is still allowed', () => {
    // The half that actually broke in production: not a deny that leaked, but
    // every ordinary call denied because the policy could not be read.
    const r = runWithShimFirst(
      {
        MULTICHAT_STATE_DIR: workspace,
        CLAUDE_WORKSPACE_DIR: workspace,
        CHAT_ID: '164795011',
      },
      JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls -la' } }),
    )
    expect(r.code).toBe(0)
    expect(r.stdout).toBe('')
  })

  withYaml('$CHATS_HOOK_PYTHON pointing at a yaml-less interpreter is skipped, not obeyed', () => {
    // The pin is a preference, not an override of the one requirement.
    const r = runWithShimFirst(
      {
        CHATS_HOOK_PYTHON: join(shimDir, 'python3'),
        MULTICHAT_STATE_DIR: workspace,
        CLAUDE_WORKSPACE_DIR: workspace,
        CHAT_ID: '164795011',
      },
      JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls -la' } }),
    )
    expect(r.code).toBe(0)
  })

  test('no interpreter with PyYAML anywhere -> deny, tagged hook-failure not policy', () => {
    // Emptying the fallback list is the only way to reach this branch on a
    // machine that has a working python somewhere. It must still deny — an
    // unreadable policy is not an open door — but the caller has to be able to
    // tell «the policy forbids this» from «I could not read the policy».
    const r = runWithShimFirst(
      {
        CHATS_HOOK_PYTHON_FALLBACKS: '',
        MULTICHAT_STATE_DIR: workspace,
        CLAUDE_WORKSPACE_DIR: workspace,
        CHAT_ID: '164795011',
      },
      JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls -la' } }),
    )
    expect(r.code).toBe(2)
    expect(r.stdout).toMatch(/"decision":\s*"block"/)
    expect(r.stdout).toContain('hook-failure')
    expect(r.stdout).toContain('no python3 with PyYAML found')
  })
})

describe('pre-tool-use.sh — a block says which kind of block it is', () => {
  test('a policy deny is tagged policy', () => {
    const r = run(
      PRE_HOOK,
      {
        MULTICHAT_STATE_DIR: workspace,
        CLAUDE_WORKSPACE_DIR: workspace,
        CHAT_ID: '164795011',
      },
      JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'rm -rf /' } }),
    )
    expect(r.code).toBe(2)
    expect(JSON.parse(r.stdout).denied_by).toBe('policy')
  })

  test('a missing policy file is tagged hook-failure', () => {
    rmSync(policyPath, { force: true })
    const r = run(
      PRE_HOOK,
      {
        MULTICHAT_STATE_DIR: workspace,
        CLAUDE_WORKSPACE_DIR: workspace,
        CHAT_ID: '164795011',
      },
      JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls' } }),
    )
    expect(r.code).toBe(2)
    expect(JSON.parse(r.stdout).denied_by).toBe('hook-failure')
  })

  test('an unparseable policy is tagged hook-failure, not a policy verdict', () => {
    writeFileSync(policyPath, 'chats: [unclosed\n', 'utf8')
    const r = run(
      PRE_HOOK,
      {
        MULTICHAT_STATE_DIR: workspace,
        CLAUDE_WORKSPACE_DIR: workspace,
        CHAT_ID: '164795011',
      },
      JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls' } }),
    )
    expect(r.code).toBe(2)
    const payload = JSON.parse(r.stdout)
    expect(payload.denied_by).toBe('hook-failure')
    expect(payload.reason).toContain('did not parse')
  })

  // codex review 2026-08-03, MUST. A policy can be perfectly valid YAML and
  // still be the wrong SHAPE. Those shapes used to reach `.get()` on a non-dict,
  // raise AttributeError and exit 1 — and Claude blocks on exit 2 and ONLY on
  // exit 2, so the fail-safe hook was failing OPEN in the corner it exists for.
  // The old suite could not see it: it tested torn YAML, never wrong-shaped YAML.
  const MISSHAPEN: ReadonlyArray<readonly [string, string]> = [
    ['a top-level list', '- one\n- two\n'],
    ['a top-level scalar', 'just a string\n'],
    ['chats as a list', 'version: 1\nchats:\n  - "164795011"\n'],
    ['the chat entry as a list', 'version: 1\nchats:\n  "164795011":\n    - deny\n'],
    [
      'the deny block as a list',
      'version: 1\nchats:\n  "164795011":\n    deny:\n      - rm -rf /\n',
    ],
    [
      'a deny list given as a bare string',
      'version: 1\nchats:\n  "164795011":\n    deny:\n      bash_patterns: "ls"\n',
    ],
  ]

  for (const [label, yaml] of MISSHAPEN) {
    test(`valid YAML with ${label} denies, and says the hook failed`, () => {
      writeFileSync(policyPath, yaml, 'utf8')
      const r = run(
        PRE_HOOK,
        {
          MULTICHAT_STATE_DIR: workspace,
          CLAUDE_WORKSPACE_DIR: workspace,
          CHAT_ID: '164795011',
        },
        JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls' } }),
      )
      // Exit 2 is the only code Claude reads as «blocked».
      expect(r.code).toBe(2)
      const payload = JSON.parse(r.stdout)
      expect(payload.decision).toBe('block')
      expect(payload.denied_by).toBe('hook-failure')
    })
  }

  // Same class as the plugin's `matched_fragment` leak: a refusal must not hand
  // back a piece of the policy. The rule is named by kind and position instead.
  test('a policy deny names the rule, never the rule text', () => {
    writeFileSync(
      policyPath,
      [
        'version: 1',
        'chats:',
        '  "164795011":',
        '    deny:',
        '      bash_patterns:',
        '        - "sekrit-path-fragment"',
        '',
      ].join('\n'),
      'utf8',
    )
    const r = run(
      PRE_HOOK,
      {
        MULTICHAT_STATE_DIR: workspace,
        CLAUDE_WORKSPACE_DIR: workspace,
        CHAT_ID: '164795011',
      },
      JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'echo sekrit-path-fragment' } }),
    )
    expect(r.code).toBe(2)
    expect(r.stdout).not.toContain('sekrit-path-fragment')
    expect(r.stdout).toContain('bash_patterns deny')
    expect(JSON.parse(r.stdout).denied_by).toBe('policy')
  })
})

describe('session-start.sh — sentinel pass-through', () => {
  test('MULTICHAT_STATE_DIR unset -> exit 0, no additionalContext emitted', () => {
    // Even if persona/policy exist, an unset MULTICHAT_STATE_DIR must
    // produce a clean exit with no JSON payload.
    mkdirSync(join(workspace, 'chats', '164795011'), { recursive: true })
    writeFileSync(
      join(workspace, 'chats', '164795011', 'persona.md'),
      'PERSONA SHOULD NOT LEAK',
      'utf8',
    )
    const r = run(SESSION_HOOK, {
      CLAUDE_WORKSPACE_DIR: workspace,
      CHAT_ID: '164795011',
    })
    expect(r.code).toBe(0)
    expect(r.stdout).toBe('')
  })
})

describe('session-start.sh — degraded-mode warning (Opus #16)', () => {
  // session-start was previously fail-open and silent when persona.md
  // was missing while pre-tool-use was fail-closed for the same state.
  // Result: Thrall would boot up cleanly and then every tool call would
  // be denied with no startup signal that the gate was broken. The fix
  // makes the inconsistency observable via additionalContext so the
  // session can route around the degradation on its first turn.

  test('MULTICHAT_STATE_DIR + CHAT_ID set + persona missing -> exit 0 + degraded-mode additionalContext', () => {
    // No persona.md, no chat dir. Policy.yaml is present (created by
    // beforeEach) but unused on this path.
    const r = run(SESSION_HOOK, {
      MULTICHAT_STATE_DIR: workspace,
      CLAUDE_WORKSPACE_DIR: workspace,
      CHAT_ID: '164795011',
    })
    expect(r.code).toBe(0)
    expect(r.stdout).not.toBe('')

    const payload = JSON.parse(r.stdout)
    expect(payload.hookSpecificOutput?.hookEventName).toBe('SessionStart')
    const ctx = payload.hookSpecificOutput?.additionalContext ?? ''
    expect(ctx).toContain('Persona file missing')
    expect(ctx).toContain('164795011')
    expect(ctx).toContain(
      join(workspace, 'chats', '164795011', 'persona.md'),
    )
    expect(ctx).toContain('degraded mode')
    // Mirror to stderr for the operator tailing logs.
    expect(r.stderr).toContain('persona file not found')
  })

  test('MULTICHAT_STATE_DIR + CHAT_ID set + persona present -> normal injection, no degraded warning', () => {
    mkdirSync(join(workspace, 'chats', '164795011'), { recursive: true })
    writeFileSync(
      join(workspace, 'chats', '164795011', 'persona.md'),
      'Ты Тралл, архитектор Оргриммара.',
      'utf8',
    )
    const r = run(SESSION_HOOK, {
      MULTICHAT_STATE_DIR: workspace,
      CLAUDE_WORKSPACE_DIR: workspace,
      CHAT_ID: '164795011',
    })
    expect(r.code).toBe(0)
    expect(r.stdout).not.toBe('')

    const payload = JSON.parse(r.stdout)
    const ctx = payload.hookSpecificOutput?.additionalContext ?? ''
    // Persona is loaded as-is; degraded marker must not appear.
    expect(ctx).toContain('Тралл')
    expect(ctx).not.toContain('degraded mode')
    expect(ctx).not.toContain('Persona file missing')
  })
})
