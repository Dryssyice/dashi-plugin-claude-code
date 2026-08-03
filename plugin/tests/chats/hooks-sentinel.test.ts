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
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'fs'
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

// The fields `ChatPolicySchema` requires, as the YAML lines that sit under a
// chat id. Every fixture that is meant to be a LEGITIMATE entry is built from
// this rather than hand-written.
//
// codex found the reason twice: the suite used to drive the hook with miniature
// policies the real loader would have thrown on, so it could prove neither
// direction — that a legal live file is accepted, nor that an illegal one is
// refused. Values are deliberately spelled the way the README spells them,
// including the YAML 1.1 traps (`off`, `no`, `yes`), because that is what is on
// disk on the operator's machine.
const REQUIRED_FIELDS = [
  '    mode: private',
  '    streaming: progress',
  '    tmux_mirror: false',
  '    edit_message_progress: false',
  '    delivery: final_only',
  '    persona_file: persona.md',
  '    handoff_file: handoff.md',
  '    system_reminder: ""',
].join('\n')

/** One complete chat entry: the required fields plus whatever the test adds. */
function entry(id: string, extra = ''): string {
  const tail = extra ? `${extra.replace(/\n+$/, '')}\n` : ''
  return `  "${id}":\n${REQUIRED_FIELDS}\n${tail}`
}

// The top level `MultichatPolicySchema` requires. Left out of the first version
// of this helper, which meant «legitimate» fixtures were still files the loader
// rejects — the same substitution one level up from the one it was written to
// remove.
const TOP_FIELDS = [
  'version: 1',
  'allowlist:',
  '  chats: ["164795011"]',
  '  users: ["abramov_aicreator"]',
  'mention_allowlist: ["abramov_aicreator"]',
].join('\n')

/** A whole policy.yaml around one or more entries. */
function policyOf(...entries: string[]): string {
  return `${TOP_FIELDS}\nchats:\n${entries.join('')}`
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
    policyOf(
      entry(
        '164795011',
        [
          '    deny:',
          '      bash_patterns:',
          '        - "rm -rf /"',
          '      mcp_tools: []',
          '      read_paths: []',
        ].join('\n'),
      ),
    ),
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
      policyOf(
        entry(
          '164795011',
          ['    deny:', '      bash_patterns:', '        - "sekrit-path-fragment"'].join('\n'),
        ),
      ),
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
  const POLICY_WITH_RULES = policyOf(
    entry(
      '164795011',
      [
        '    deny:',
        '      mcp_tools:',
        '        - "mcp__forbidden*"',
        '      read_paths:',
        '        - "/protected/*"',
      ].join('\n'),
    ),
  )

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
      // The id is UNQUOTED on purpose — that is the whole test.
      policyOf(
        entry('164795011', ['    deny:', '      bash_patterns:', '        - "sudo"'].join('\n')),
      ).replace('"164795011":', '164795011:'),
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

  // Each case names the phrase the refusal must carry. That third column is not
  // decoration: exit code plus `denied_by` are identical for EVERY deny in this
  // file, including the one the crash trap produces, so a suite that checks only
  // those two cannot tell a check that fired from a check that was deleted. Five
  // mutants proved it — remove the explicit guard and the AttributeError one
  // line later delivers the same 2 and the same `hook-failure`. The reason is
  // the only observable that differs, and it is also the only thing the operator
  // gets to navigate by.
  const QUIET: ReadonlyArray<readonly [string, string, string]> = [
    [
      'a typo in a deny key — reads like a rule, is not one',
      'version: 1\nchats:\n  "164795011":\n    deny:\n      bash_patern:\n        - "rm"\n',
      'unknown deny keys',
    ],
    [
      'non-string rules inside a valid list — [on, 007] is [True, 7] after YAML',
      'version: 1\nchats:\n  "164795011":\n    deny:\n      bash_patterns:\n        - on\n        - 007\n',
      'has non-string rules at #1, #2',
    ],
    [
      'a version this hook does not know',
      'version: 2\nchats:\n  "164795011":\n    deny:\n      bash_patterns:\n        - "rm"\n',
      'version is not 1',
    ],
  ]

  for (const [label, yaml, phrase] of QUIET) {
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
      const payload = JSON.parse(r.stdout)
      expect(`${label}: ${payload.denied_by}`).toBe(`${label}: hook-failure`)
      expect(`${label}: ${payload.reason.includes(phrase)}`).toBe(`${label}: true`)
    })
  }

  // codex round 5: an invalid file was applied as an EMPTY policy whenever the
  // calling chat had no entry of its own — the complaint was collected and the
  // function returned before reporting it. Fail-open reintroduced by the order
  // of two statements, in the function written to remove fail-open.
  test('an invalid file denies even when this chat has no entry at all', () => {
    writeFileSync(
      policyPath,
      'version: 2\nchats:\n  "999":\n    deny:\n      bash_patterns:\n        - "rm"\n',
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
    expect(JSON.parse(r.stdout).denied_by).toBe('hook-failure')
  })

  // …and the whole file is validated, not only the calling chat's corner of it.
  // The TypeScript loader is strict over every chat, so a file it would reject
  // must not be a file this hook accepts — otherwise the session comes up under
  // a policy the gate reads differently from the server that loaded it. The
  // cost is stated rather than hidden: one malformed entry anywhere locks every
  // chat until the file is fixed.
  const OTHER_CHAT_BROKEN: ReadonlyArray<readonly [string, string]> = [
    ['a deny list of the wrong type', '    deny:\n      read_paths: "not-a-list"\n'],
    ['an entry with no value at all', ''],
    ['a deny block with no value', '    deny:\n'],
    ['an entry that is a list', '    - deny\n'],
  ]

  for (const [label, tail] of OTHER_CHAT_BROKEN) {
    test(`another chat's broken entry denies this chat too: ${label}`, () => {
      writeFileSync(
        policyPath,
        'version: 1\nchats:\n  "164795011":\n    deny:\n      bash_patterns:\n        - "rm"\n  "999":\n' +
          tail,
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
      expect(`${label}: ${r.code}`).toBe(`${label}: 2`)
      const payload = JSON.parse(r.stdout)
      expect(`${label}: ${payload.denied_by}`).toBe(`${label}: hook-failure`)
      // The operator still gets a place to look — the 1-based position of the
      // entry, second in this file — but the other chat's id stays out of a
      // session that may be sitting in a public group and may repeat its
      // refusal there.
      expect(`${label}: ${payload.reason.includes('chat entry #2')}`).toBe(`${label}: true`)
      expect(`${label}: ${payload.reason.includes('999')}`).toBe(`${label}: false`)
    })
  }

  // Opus review, final round. The three shapes in which the STRICT pass
  // allowed everything — the largest fail-open left in the file, and it hid
  // behind looking like tidiness. The loader answers the same question the
  // opposite way (a null policy is to be treated as DENY, in as many words),
  // and the server reads the file once at startup while this hook re-reads it
  // per call: overwriting policy.yaml a single time silently removed every deny
  // rule from every live session, logged nowhere.
  const SILENTLY_EMPTY: ReadonlyArray<readonly [string, string, string]> = [
    ['an empty file', '{}\n', 'version is missing'],
    ['a version with no chats block', 'version: 1\n', 'the chats block is missing'],
    [
      'a chats block with no chats in it',
      'version: 1\nchats: {}\n',
      'this chat has no entry in policy.yaml',
    ],
    [
      'a file that does not mention this chat',
      'version: 1\nchats:\n  "999":\n    deny:\n      bash_patterns:\n        - "rm"\n',
      'this chat has no entry in policy.yaml',
    ],
    [
      'no version at all',
      'chats:\n  "164795011":\n    deny:\n      bash_patterns:\n        - "rm"\n',
      'version is missing',
    ],
  ]

  for (const [label, yaml, phrase] of SILENTLY_EMPTY) {
    test(`a policy that would allow everything is refused: ${label}`, () => {
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
      const payload = JSON.parse(r.stdout)
      expect(`${label}: ${payload.denied_by}`).toBe(`${label}: hook-failure`)
      // Without this line, deleting the `version`/`chats` presence checks leaves
      // the suite green: the NEXT check denies the same file for a different
      // reason, and the operator is sent to the wrong line.
      expect(`${label}: ${payload.reason.includes(phrase)}`).toBe(`${label}: true`)
    })
  }

  // A chat gets ITS OWN rules and not the neighbour's. Nothing tested this:
  // deleting the `if mine:` that scopes the assignment left the whole suite
  // green, and under that mutation one chat executes another chat's deny list —
  // extra refusals, plus another chat's configuration leaking into behaviour.
  // Every two-chat fixture until now had the second chat either broken (so the
  // refusal came first) or without a deny block at all.
  test("a chat executes its own deny list, not the neighbour's", () => {
    writeFileSync(
      policyPath,
      policyOf(
        entry(
          '164795011',
          ['    deny:', '      bash_patterns:', '        - "mine-only"'].join('\n'),
        ),
        entry('999', ['    deny:', '      bash_patterns:', '        - "theirs-only"'].join('\n')),
      ),
      'utf8',
    )
    const env = {
      MULTICHAT_STATE_DIR: workspace,
      CLAUDE_WORKSPACE_DIR: workspace,
      CHAT_ID: '164795011',
    }
    const theirs = run(
      PRE_HOOK,
      env,
      JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'theirs-only now' } }),
    )
    expect(`neighbour's rule: ${theirs.code}`).toBe(`neighbour's rule: 0`)

    const ours = run(
      PRE_HOOK,
      env,
      JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'mine-only now' } }),
    )
    expect(`own rule: ${ours.code}`).toBe(`own rule: 2`)
  })

  // Another chat's id must not travel into this session's refusal: a session in
  // a public group can repeat the reason it was blocked with into that group.
  test("a refusal about another chat names a position, not that chat's id", () => {
    writeFileSync(
      policyPath,
      'version: 1\nchats:\n  "164795011":\n    deny: {}\n  "-1003784643974":\n    deny:\n      read_paths: "not-a-list"\n',
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
    expect(r.stdout).not.toContain('1003784643974')
    expect(r.stderr).not.toContain('1003784643974')
    expect(JSON.parse(r.stdout).reason).toContain('chat entry #2')
  })

  // The one field an injected prompt actually writes, in the two shapes this
  // hook got wrong in opposite directions.
  //
  // A non-string `command` was skipped in silence. A MISSING or empty one was
  // turned into `''`, which matches no pattern and reaches «Default allow» —
  // codex found the second on the round that fixed the first, and it is the
  // same defect `extractCommand` in permission-policy.ts already carries a
  // comment about: «the old code returned '' here and an empty command
  // auto-allowed». Two implementations of one gate, and the shell copy was a
  // round behind the TypeScript one.
  const MALFORMED_COMMANDS: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ['a list', { command: ['rm', '-rf', '/tmp/x'] }],
    ['a number', { command: 42 }],
    ['an object', { command: { cmd: 'ls' } }],
    ['missing entirely', {}],
    ['an empty string', { command: '' }],
    ['nothing but whitespace', { command: '   \t\n' }],
    ['null', { command: null }],
  ]

  for (const [label, toolInput] of MALFORMED_COMMANDS) {
    test(`a Bash call whose command is ${label} denies`, () => {
      writeFileSync(policyPath, POLICY_WITH_RULES, 'utf8')
      const r = run(
        PRE_HOOK,
        {
          MULTICHAT_STATE_DIR: workspace,
          CLAUDE_WORKSPACE_DIR: workspace,
          CHAT_ID: '164795011',
        },
        JSON.stringify({ tool_name: 'Bash', tool_input: toolInput }),
      )
      expect(`${label}: ${r.code}`).toBe(`${label}: 2`)
      const payload = JSON.parse(r.stdout)
      expect(`${label}: ${payload.denied_by}`).toBe(`${label}: hook-failure`)
      // Deleting the type half of the check does NOT open the gate —
      // `command.strip()` raises one line later and the crash trap denies. It
      // does make the refusal say «AttributeError» instead of naming the field,
      // and it makes the guard depend on an accident of the next statement.
      // Deleting the empty half opens it outright, and silently.
      expect(`${label}: ${payload.reason.includes('command is missing, empty')}`).toBe(
        `${label}: true`,
      )
    })
  }

  // codex round 8, MUST. `deney:` is `bash_patern:` one level up, and it is
  // worse: a misspelt deny KEY leaves the chat with no rules at all rather than
  // one rule short. The loader's `.strict()` throws on the same file, so before
  // this check the gate applied a policy the server would have refused to load.
  const STRAY_ENTRY_KEYS: ReadonlyArray<readonly [string, string]> = [
    ['the deny block itself misspelt', '    deney:\n      bash_patterns:\n        - "rm"\n'],
    ['a field the schema has never had', '    allow_everything: true\n'],
    ['a plural that reads right', '    denies:\n      bash_patterns:\n        - "rm"\n'],
  ]

  for (const [label, tail] of STRAY_ENTRY_KEYS) {
    test(`an unknown key in a chat entry is refused: ${label}`, () => {
      writeFileSync(policyPath, `version: 1\nchats:\n  "164795011":\n${tail}`, 'utf8')
      const r = run(
        PRE_HOOK,
        {
          MULTICHAT_STATE_DIR: workspace,
          CLAUDE_WORKSPACE_DIR: workspace,
          CHAT_ID: '164795011',
        },
        JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'rm -rf /' } }),
      )
      expect(`${label}: ${r.code}`).toBe(`${label}: 2`)
      const payload = JSON.parse(r.stdout)
      expect(`${label}: ${payload.denied_by}`).toBe(`${label}: hook-failure`)
      expect(`${label}: ${payload.reason.includes('unknown keys')}`).toBe(`${label}: true`)
    })
  }

  // codex round 9. The first version of the key check took only the unknown
  // half, arguing that the hook never READS `persona_file` so it should not
  // refuse over it. That argument does not follow from the coercion problem —
  // a name is present or it is not, nothing coerces — and it left the gate
  // applying files the loader would have rejected, against the invariant this
  // very loop is built on.
  test('a chat entry missing schema-required keys is refused', () => {
    writeFileSync(
      policyPath,
      // Everything the schema wants except `persona_file` and `system_reminder`.
      policyOf(
        entry('164795011', ['    deny:', '      bash_patterns:', '        - "rm"'].join('\n'))
          .replace('    persona_file: persona.md\n', '')
          .replace('    system_reminder: ""\n', ''),
      ),
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
    const payload = JSON.parse(r.stdout)
    expect(payload.denied_by).toBe('hook-failure')
    expect(payload.reason).toContain('missing keys: persona_file, system_reminder')
  })

  // …and the other direction, which is the whole reason the check is on NAMES
  // and not on values: every field the schema does allow must pass. PyYAML
  // reads YAML 1.1, so `streaming: off` arrives here as the boolean False while
  // the loader (js-yaml, JSON_SCHEMA) sees the string "off". A hook that
  // validated that value against the enum would deny every tool call in every
  // chat over a legal, documented file.
  test('a chat entry with the full documented shape is accepted, values and all', () => {
    writeFileSync(
      policyPath,
      [
        'version: 1',
        'allowlist:',
        '  chats: ["164795011"]',
        '  users: ["abramov_aicreator"]',
        'mention_allowlist: ["abramov_aicreator"]',
        'chats:',
        '  "164795011":',
        '    mode: private',
        '    streaming: off',
        '    tmux_mirror: no',
        '    edit_message_progress: yes',
        '    delivery: final_only',
        '    persona_file: persona.md',
        '    handoff_file: handoff.md',
        '    system_reminder: ""',
        '    idle_ttl_ms: 1800000',
        '    max_queue_depth: 1',
        '    deny:',
        '      bash_patterns:',
        '        - "rm -rf /"',
        '',
      ].join('\n'),
      'utf8',
    )
    const env = {
      MULTICHAT_STATE_DIR: workspace,
      CLAUDE_WORKSPACE_DIR: workspace,
      CHAT_ID: '164795011',
    }
    const allowed = run(
      PRE_HOOK,
      env,
      JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls -la' } }),
    )
    expect(`allowed: ${allowed.code}`).toBe('allowed: 0')

    // …and the rules in that same file still bite.
    const denied = run(
      PRE_HOOK,
      env,
      JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'sudo rm -rf / now' } }),
    )
    expect(`denied: ${denied.code}`).toBe('denied: 2')
    expect(JSON.parse(denied.stdout).denied_by).toBe('policy')
  })

  // The pin that makes the check above safe to keep. The hook's CHAT_KEYS is a
  // hand-copy of ChatPolicySchema; a field added to the schema and not to the
  // hook would make the hook refuse every call in every chat, live, with a
  // correct file on disk. That failure belongs in CI, not in the operator's
  // evening — so the two lists are compared directly, in the same repo.
  // The check that ends the whole class of finding, rather than one more
  // instance of it. Twice now a reviewer has pointed out that the fixtures the
  // suite calls «legitimate» are files the real loader would throw on — first at
  // the chat entry, then at the top level. So the builder's own output is fed to
  // the real schema here: if it drifts again, this test says so, and no future
  // round has to notice by eye.
  test('the fixture builder produces a policy the real loader accepts', async () => {
    const { MultichatPolicySchema } = await import('../../src/chats/policy-loader')
    const { JSON_SCHEMA, load } = await import('js-yaml')
    const parsed = load(
      policyOf(
        entry('164795011', ['    deny:', '      bash_patterns:', '        - "rm"'].join('\n')),
        entry('999'),
      ),
      { schema: JSON_SCHEMA },
    )
    const result = MultichatPolicySchema.safeParse(parsed)
    expect(result.success ? 'accepted' : JSON.stringify(result.error.issues)).toBe('accepted')
  })

  test('the hook’s chat-entry key lists match ChatPolicySchema exactly', async () => {
    const { ChatPolicySchema } = await import('../../src/chats/policy-loader')
    const hookSource = readFileSync(PRE_HOOK, 'utf8')

    function namesIn(constant: string): string[] {
      const block = hookSource.match(new RegExp(`${constant} = \\(([\\s\\S]*?)\\)`))
      expect(`${constant} found: ${block !== null}`).toBe(`${constant} found: true`)
      return [...(block?.[1] ?? '').matchAll(/'([a-z_]+)'/g)].map((m) => m[1] ?? '').sort()
    }

    // Both halves, because they carry different weight. A name missing from
    // CHAT_KEYS makes the hook refuse a legal file; a name wrongly in
    // CHAT_REQUIRED does the same for a file that omits an optional field. The
    // schema decides which is which: `.isOptional()` covers both `.optional()`
    // and `.default()`, which is exactly the split the hook needs.
    const shape = ChatPolicySchema.shape as Record<string, { isOptional(): boolean }>
    const required = namesIn('CHAT_REQUIRED')
    const optional = namesIn('CHAT_OPTIONAL')

    expect(required).toEqual(
      Object.entries(shape)
        .filter(([, field]) => !field.isOptional())
        .map(([name]) => name)
        .sort(),
    )
    expect([...required, ...optional].sort()).toEqual(Object.keys(shape).sort())
    // …and the hook must actually build its accepted set from both, or the two
    // lists above could be perfect while the check used only one of them.
    expect(hookSource).toContain('CHAT_KEYS = CHAT_REQUIRED + CHAT_OPTIONAL')

    // The top level, pinned the same way. It has no optional fields, so one
    // list is both «required» and «all allowed» — and if the schema ever grows
    // an optional one, this equality is what notices.
    const { MultichatPolicySchema } = await import('../../src/chats/policy-loader')
    expect(namesIn('TOP_REQUIRED')).toEqual(Object.keys(MultichatPolicySchema.shape).sort())
  })

  // The top-level half of the invariant, missing until codex asked for it a
  // second time: a policy without `allowlist` / `mention_allowlist` is one the
  // server would refuse to load, and the gate was applying it.
  const TOP_LEVEL_BROKEN: ReadonlyArray<readonly [string, string, string]> = [
    [
      'no allowlist at all',
      'version: 1\nmention_allowlist: []\nchats:\n  "164795011": {}\n',
      'missing top-level keys: allowlist',
    ],
    [
      'neither allowlist nor mention_allowlist',
      'version: 1\nchats:\n  "164795011": {}\n',
      'missing top-level keys: allowlist, mention_allowlist',
    ],
    [
      'a top-level key the schema has never had',
      'version: 1\nallowlist:\n  chats: []\n  users: []\nmention_allowlist: []\n' +
        'chats:\n  "164795011": {}\nbypass: true\n',
      'unknown top-level keys: bypass',
    ],
  ]

  for (const [label, yaml, phrase] of TOP_LEVEL_BROKEN) {
    test(`a policy the loader would reject at the top level is refused: ${label}`, () => {
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
      const payload = JSON.parse(r.stdout)
      expect(`${label}: ${payload.denied_by}`).toBe(`${label}: hook-failure`)
      expect(`${label}: ${payload.reason.includes(phrase)}`).toBe(`${label}: true`)
    })
  }

  // The 1-based position is the ONLY navigation the operator gets, because the
  // rule text is deliberately never printed. An off-by-one sends them to edit
  // the wrong line, and until now no assertion looked at the number.
  test('the rule position points at the rule that fired', () => {
    writeFileSync(
      policyPath,
      policyOf(
        entry(
          '164795011',
          [
            '    deny:',
            '      bash_patterns:',
            '        - "first-rule"',
            '        - "second-rule"',
            '        - "third-rule"',
          ].join('\n'),
        ),
      ),
      'utf8',
    )
    const r = run(
      PRE_HOOK,
      {
        MULTICHAT_STATE_DIR: workspace,
        CLAUDE_WORKSPACE_DIR: workspace,
        CHAT_ID: '164795011',
      },
      JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'run second-rule now' } }),
    )
    expect(r.code).toBe(2)
    expect(JSON.parse(r.stdout).reason).toBe('bash_patterns deny: rule #2 in policy.yaml')
  })

  // …and an entry that simply has no deny block is NOT a mistake. No rules for
  // a chat has always meant no denials, and a guard that cannot tell «absent»
  // from «half-typed» would lock every chat with a persona and no rules.
  test('another chat with no deny block at all is fine', () => {
    writeFileSync(
      policyPath,
      policyOf(
        entry('164795011', ['    deny:', '      bash_patterns:', '        - "rm"'].join('\n')),
        entry('999'),
      ),
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
    expect(r.code).toBe(0)
  })

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
  // Third column again: which part of the call the refusal names. Substituting
  // `tool_call = {}` for the refusal keeps the verdict — the missing tool_name
  // is caught one line down — so only the text tells the two apart.
  const MALFORMED_CALLS: ReadonlyArray<readonly [string, string, string]> = [
    ['the call is a list', '[]', 'the tool call is not an object'],
    ['the call is a string', '"Bash"', 'the tool call is not an object'],
    ['tool_name is not a string', '{"tool_name": 42, "tool_input": {}}', 'no usable tool_name'],
    // The shape that says least about itself was the one that got through:
    // `.get(…, '')` turned a missing name into a usable one, and a call with no
    // name matches no rule.
    ['tool_name is missing', '{"tool_input": {}}', 'no usable tool_name'],
    ['tool_name is empty', '{"tool_name": "", "tool_input": {}}', 'no usable tool_name'],
    [
      'tool_input is a string',
      '{"tool_name": "Bash", "tool_input": "ls"}',
      'tool_input is not an object',
    ],
    [
      'tool_input is a list',
      '{"tool_name": "Bash", "tool_input": []}',
      'tool_input is not an object',
    ],
  ]

  for (const [label, body, phrase] of MALFORMED_CALLS) {
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
      const payload = JSON.parse(r.stdout)
      expect(`${label}: ${payload.denied_by}`).toBe(`${label}: hook-failure`)
      expect(`${label}: ${payload.reason.includes(phrase)}`).toBe(`${label}: true`)
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
