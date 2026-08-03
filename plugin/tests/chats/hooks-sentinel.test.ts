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

  // Opus review 2026-08-03, S4: the `import yaml` probe runs BEFORE stdin is
  // captured, so it inherits the tool-call pipe. `python3 -c` does not read
  // stdin, but a wrapper shim (pyenv, conda and asdf are shell scripts) can —
  // and a drained pipe leaves the hook with an empty tool call, so every single
  // call denies with hook-failure. Fail-closed, but it is the same «the agent
  // looks broken» failure this hook was written to end.
  withYaml('an interpreter probe that consumes stdin does not eat the tool call', () => {
    const greedy = join(shimDir, 'greedy-python3')
    writeFileSync(
      greedy,
      [
        '#!/usr/bin/env bash',
        '# Drains whatever stdin it is given, then behaves like a real python.',
        'if [ "$1" = "-c" ]; then',
        '  cat >/dev/null 2>&1',
        'fi',
        `exec ${YAML_PYTHON} "$@"`,
        '',
      ].join('\n'),
      { encoding: 'utf8', mode: 0o755 },
    )
    const r = run(
      PRE_HOOK,
      {
        CHATS_HOOK_PYTHON: greedy,
        CHATS_HOOK_PYTHON_FALLBACKS: YAML_PYTHON ?? '',
        MULTICHAT_STATE_DIR: workspace,
        CLAUDE_WORKSPACE_DIR: workspace,
        CHAT_ID: '164795011',
      },
      JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls -la' } }),
    )
    // The call is allowed by the policy, so it must be allowed here too. If the
    // probe swallowed the pipe this comes back as a hook-failure deny.
    expect(`${r.code} ${r.stdout}`).toBe('0 ')
  })

  // Opus review 2026-08-03, S5: the header promises the pin is tried FIRST, and
  // nothing held that promise — swapping the two candidate lines left the suite
  // fully green. Whenever PATH's python happens to have PyYAML, an ignored pin
  // still looks like a working pin.
  withYaml('$CHATS_HOOK_PYTHON wins over a PATH python that also has PyYAML', () => {
    // A pin that HAS yaml (it delegates the probe) but is unmistakable when it
    // is the one that actually runs the policy.
    const pin = join(shimDir, 'pinned-python3')
    writeFileSync(
      pin,
      [
        '#!/usr/bin/env bash',
        'if [ "$1" = "-c" ]; then',
        `  exec ${YAML_PYTHON} "$@"`,
        'fi',
        'printf \'%s\\n\' \'{"decision":"block","denied_by":"PINNED","reason":"the pinned interpreter ran"}\'',
        'exit 2',
        '',
      ].join('\n'),
      { encoding: 'utf8', mode: 0o755 },
    )
    const r = run(
      PRE_HOOK,
      {
        // PATH's python3 is the host's yaml-capable one, so the pin can only
        // win on ORDER, never because it is the sole candidate.
        PATH: `${join(YAML_PYTHON as string, '..')}:/bin:/usr/bin`,
        CHATS_HOOK_PYTHON: pin,
        CHATS_HOOK_PYTHON_FALLBACKS: YAML_PYTHON ?? '',
        MULTICHAT_STATE_DIR: workspace,
        CLAUDE_WORKSPACE_DIR: workspace,
        CHAT_ID: '164795011',
      },
      JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls -la' } }),
    )
    expect(r.code).toBe(2)
    expect(JSON.parse(r.stdout).denied_by).toBe('PINNED')
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

  // Opus review 2026-08-03, S2: `denied_by` was set on every deny path in the
  // source, and the suite held only four of them. Two mutants survived a full
  // green run — including one that relabelled a hook failure as a policy
  // verdict, which is precisely the confusion this field exists to remove.
  test('every deny path carries denied_by, including the earliest ones', () => {
    const cases: ReadonlyArray<readonly [string, Record<string, string>, string]> = [
      [
        'CHAT_ID missing',
        { MULTICHAT_STATE_DIR: '@ws', CLAUDE_WORKSPACE_DIR: '@ws' },
        'hook-failure',
      ],
      [
        'no interpreter with PyYAML',
        {
          MULTICHAT_STATE_DIR: '@ws',
          CLAUDE_WORKSPACE_DIR: '@ws',
          CHAT_ID: '164795011',
          CHATS_HOOK_PYTHON: '/nonexistent/python3',
          CHATS_HOOK_PYTHON_FALLBACKS: '',
          // /bin has bash (so the script runs) and no python3 (so the search
          // finds nothing) — the branch is otherwise unreachable.
          PATH: '/bin',
        },
        'hook-failure',
      ],
    ]
    for (const [label, rawEnv, expected] of cases) {
      const env: Record<string, string> = {}
      for (const [k, v] of Object.entries(rawEnv)) env[k] = v === '@ws' ? workspace : v
      const r = run(
        PRE_HOOK,
        env,
        JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls' } }),
      )
      expect(`${label}: ${r.code}`).toBe(`${label}: 2`)
      expect(`${label}: ${JSON.parse(r.stdout).denied_by}`).toBe(`${label}: ${expected}`)
    }
  })

  // Opus review 2026-08-03, S3. Under the exit-2 contract Claude surfaces
  // STDERR to the model; the JSON on stdout is the exit-0 form. The hook exited
  // 2 and printed only stdout, so every block reached the model with no reason
  // attached — the field this commit is about was invisible to its reader.
  test('the refusal reaches stderr too, or the model is blocked without a reason', () => {
    const denials: ReadonlyArray<readonly [string, Record<string, string>]> = [
      ['policy deny', { MULTICHAT_STATE_DIR: '@ws', CLAUDE_WORKSPACE_DIR: '@ws', CHAT_ID: '164795011' }],
      ['CHAT_ID missing', { MULTICHAT_STATE_DIR: '@ws', CLAUDE_WORKSPACE_DIR: '@ws' }],
    ]
    for (const [label, rawEnv] of denials) {
      const env: Record<string, string> = {}
      for (const [k, v] of Object.entries(rawEnv)) env[k] = v === '@ws' ? workspace : v
      const r = run(
        PRE_HOOK,
        env,
        JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'rm -rf /' } }),
      )
      expect(`${label}: ${r.code}`).toBe(`${label}: 2`)
      expect(`${label}: ${r.stderr.includes('BLOCKED')}`).toBe(`${label}: true`)
      // …and it says WHICH kind of block, in the stream the model reads.
      expect(r.stderr).toMatch(/BLOCKED \((policy|hook-failure)\)/)
    }
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

  // codex review round 3, MUST — and the same defect one layer in. Round 2 made
  // a wrong-shaped deny list refuse; it refused only when the tool that arrived
  // was the tool that list is about. `read_paths: "secret"` was checked inside
  // `if tool_name in PATH_TOOLS`, so a Bash call sailed past a policy the hook
  // had already failed to understand.
  //
  // That is fail-open wearing the fail-safe's clothes, and it is invisible from
  // the inside: the broken list belongs to a tool nobody is calling, so nothing
  // ever complains. The shape of the whole deny block is now settled before the
  // hook looks at which tool is calling.
  const CROSS_TOOL: ReadonlyArray<readonly [string, string, unknown]> = [
    [
      'read_paths broken, a Bash call arrives',
      'version: 1\nchats:\n  "164795011":\n    deny:\n      read_paths: "secret"\n',
      { tool_name: 'Bash', tool_input: { command: 'ls' } },
    ],
    [
      'bash_patterns broken, a Read call arrives',
      'version: 1\nchats:\n  "164795011":\n    deny:\n      bash_patterns: "rm"\n',
      { tool_name: 'Read', tool_input: { file_path: '/tmp/harmless.txt' } },
    ],
    [
      'read_paths broken, a Read call arrives with no path at all',
      'version: 1\nchats:\n  "164795011":\n    deny:\n      read_paths: "secret"\n',
      { tool_name: 'Read', tool_input: {} },
    ],
    [
      'mcp_tools broken, a Bash call arrives',
      'version: 1\nchats:\n  "164795011":\n    deny:\n      mcp_tools: "mcp__*"\n',
      { tool_name: 'Bash', tool_input: { command: 'ls' } },
    ],
  ]

  for (const [label, yaml, call] of CROSS_TOOL) {
    test(`a broken policy denies whoever calls: ${label}`, () => {
      writeFileSync(policyPath, yaml, 'utf8')
      const r = run(
        PRE_HOOK,
        {
          MULTICHAT_STATE_DIR: workspace,
          CLAUDE_WORKSPACE_DIR: workspace,
          CHAT_ID: '164795011',
        },
        JSON.stringify(call),
      )
      expect(`${label}: ${r.code}`).toBe(`${label}: 2`)
      const payload = JSON.parse(r.stdout)
      expect(`${label}: ${payload.denied_by}`).toBe(`${label}: hook-failure`)
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

  // Opus review, round 3. Only `bash_patterns` had a test that proves it ever
  // MATCHES anything. Turning off the `read_paths` and `mcp_tools` comparisons
  // outright left the suite green — two deny lists the tests had never seen
  // work. A rule nothing exercises is a rule nobody will notice losing.
  const POLICY_WITH_RULES = [
    'version: 1',
    'chats:',
    '  "164795011":',
    '    deny:',
    '      mcp_tools:',
    '        - "mcp__forbidden*"',
    '      read_paths:',
    '        - "/protected/*"',
    '',
  ].join('\n')

  const POSITIVE_DENIES: ReadonlyArray<readonly [string, unknown, string]> = [
    [
      'an mcp tool matching the glob',
      { tool_name: 'mcp__forbidden__do_it', tool_input: {} },
      'mcp_tools deny',
    ],
    [
      'Read of a protected path',
      { tool_name: 'Read', tool_input: { file_path: '/protected/x' } },
      'read_paths deny',
    ],
    // The two the allowlist of tool names was short by. Both take a path like
    // everyone else, and the multichat session runs with bypassPermissions
    // naming this hook as its only gate — so on a perfectly correct policy the
    // protected path was readable through one and writable through the other.
    [
      'NotebookRead of a protected path',
      { tool_name: 'NotebookRead', tool_input: { notebook_path: '/protected/x.ipynb' } },
      'read_paths deny',
    ],
    [
      'MultiEdit of a protected path',
      { tool_name: 'MultiEdit', tool_input: { file_path: '/protected/x' } },
      'read_paths deny',
    ],
    // Grep and Glob point at a directory in `path`, and a directory of
    // protected files is read by searching it.
    [
      'Grep rooted at a protected path',
      { tool_name: 'Grep', tool_input: { pattern: 'x', path: '/protected/dir' } },
      'read_paths deny',
    ],
  ]

  for (const [label, call, expected] of POSITIVE_DENIES) {
    test(`the policy actually denies: ${label}`, () => {
      writeFileSync(policyPath, POLICY_WITH_RULES, 'utf8')
      const r = run(
        PRE_HOOK,
        {
          MULTICHAT_STATE_DIR: workspace,
          CLAUDE_WORKSPACE_DIR: workspace,
          CHAT_ID: '164795011',
        },
        JSON.stringify(call),
      )
      expect(`${label}: ${r.code}`).toBe(`${label}: 2`)
      const payload = JSON.parse(r.stdout)
      expect(`${label}: ${payload.denied_by}`).toBe(`${label}: policy`)
      expect(`${label}: ${payload.reason.startsWith(expected)}`).toBe(`${label}: true`)
    })
  }

  // …and a call that matches nothing still runs. Both halves, always: a gate
  // that denies everything is not a gate, it is an outage.
  test('a call matching no rule is allowed', () => {
    writeFileSync(policyPath, POLICY_WITH_RULES, 'utf8')
    const r = run(
      PRE_HOOK,
      {
        MULTICHAT_STATE_DIR: workspace,
        CLAUDE_WORKSPACE_DIR: workspace,
        CHAT_ID: '164795011',
      },
      JSON.stringify({ tool_name: 'Read', tool_input: { file_path: '/ordinary/x' } }),
    )
    expect(r.code).toBe(0)
  })

  // Opus review, round 3: four more ways the gate goes quiet without saying so.
  // Each one is authored by hand in a YAML file, each reads as correct, and
  // each turns some or all of the deny block into nothing.
  // The quietest of the four, and the only one that is fixed by APPLYING the
  // policy rather than by refusing it: an unquoted chat id is an int key in
  // YAML, so the string lookup missed and the chat silently got no rules at
  // all — while the server's own loader accepted the same file (js-yaml gives
  // it a string key) and brought the session up. Keys are compared as text now.
  test('an unquoted chat id still gets its rules', () => {
    writeFileSync(
      policyPath,
      'version: 1\nchats:\n  164795011:\n    deny:\n      bash_patterns:\n        - "sudo"\n',
      'utf8',
    )
    const r = run(
      PRE_HOOK,
      {
        MULTICHAT_STATE_DIR: workspace,
        CLAUDE_WORKSPACE_DIR: workspace,
        CHAT_ID: '164795011',
      },
      JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'sudo id' } }),
    )
    expect(r.code).toBe(2)
    expect(JSON.parse(r.stdout).denied_by).toBe('policy')
  })

  const QUIET: ReadonlyArray<readonly [string, string]> = [
    [
      'a typo in a deny key — reads like a rule, is not one',
      'version: 1\nchats:\n  "164795011":\n    deny:\n      bash_patern:\n        - "rm"\n',
    ],
    [
      'non-string rules inside a valid list — [on, 007] is [True, 7] after YAML',
      'version: 1\nchats:\n  "164795011":\n    deny:\n      bash_patterns:\n        - on\n        - 007\n',
    ],
    [
      'a version this hook does not know',
      'version: 2\nchats:\n  "164795011":\n    deny:\n      bash_patterns:\n        - "rm"\n',
    ],
  ]

  for (const [label, yaml] of QUIET) {
    test(`a policy that would silently stop denying is refused: ${label}`, () => {
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
      expect(`${label}: ${r.code}`).toBe(`${label}: 2`)
      expect(`${label}: ${JSON.parse(r.stdout).denied_by}`).toBe(`${label}: hook-failure`)
    })
  }

  // Every complaint at once. Naming only the first costs the operator one
  // round of editing per mistake, in a file where every mistake locks the chat.
  test('a policy with several mistakes names all of them', () => {
    writeFileSync(
      policyPath,
      'version: 1\nchats:\n  "164795011":\n    deny:\n      read_paths: "x"\n      bash_patterns: "y"\n      typo_key: []\n',
      'utf8',
    )
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
    const reason = JSON.parse(r.stdout).reason
    expect(reason).toContain('read_paths is not a list')
    expect(reason).toContain('bash_patterns is not a list')
    expect(reason).toContain('typo_key')
  })

  // The shape complaint must not quote the policy either. `matched_fragment`
  // cost four rounds by leaking on the match path; this is the same leak one
  // branch over, and until now nothing tested it.
  test('a shape refusal names the key, never the offending value', () => {
    writeFileSync(
      policyPath,
      'version: 1\nchats:\n  "164795011":\n    deny:\n      read_paths: "sekrit-path-fragment"\n',
      'utf8',
    )
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
    expect(r.stdout).not.toContain('sekrit-path-fragment')
    expect(r.stderr).not.toContain('sekrit-path-fragment')
    expect(JSON.parse(r.stdout).reason).toContain('read_paths is not a list')
  })

  // The tool call is the half an injected prompt actually controls. Unreadable
  // JSON already denied; readable JSON of the wrong shape fell through to
  // defaults and was allowed — the same asymmetry, on the more exposed side.
  const MALFORMED_CALLS: ReadonlyArray<readonly [string, string]> = [
    ['the call is a list', '[]'],
    ['the call is a string', '"Bash"'],
    ['tool_name is not a string', '{"tool_name": 42, "tool_input": {}}'],
    ['tool_input is a string', '{"tool_name": "Bash", "tool_input": "ls"}'],
    ['tool_input is a list', '{"tool_name": "Bash", "tool_input": []}'],
  ]

  for (const [label, body] of MALFORMED_CALLS) {
    test(`a tool call of the wrong shape denies: ${label}`, () => {
      writeFileSync(policyPath, POLICY_WITH_RULES, 'utf8')
      const r = run(
        PRE_HOOK,
        {
          MULTICHAT_STATE_DIR: workspace,
          CLAUDE_WORKSPACE_DIR: workspace,
          CHAT_ID: '164795011',
        },
        body,
      )
      expect(`${label}: ${r.code}`).toBe(`${label}: 2`)
      expect(`${label}: ${JSON.parse(r.stdout).denied_by}`).toBe(`${label}: hook-failure`)
    })
  }
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
