#!/usr/bin/env bash
# Claude Code PreToolUse hook for multichat-thrall.
#
# Reads the tool-call JSON from stdin, loads the chat's deny rules from
# {WORKSPACE}/chats/policy.yaml (keyed by $CHAT_ID), and emits a
# {"decision":"block","reason":"..."} JSON + exit 2 if the call should
# be denied. Exit 0 = allow.
#
# Matching semantics (PLAN.md section 7 / Open Q 2):
#   * mcp_tools     — fnmatch glob against tool name (e.g.
#                     "mcp__dashi-gbrain-memory*").
#   * read_paths    — fnmatch glob against file_path / notebook_path
#                     for Read/Edit/Write/NotebookEdit. ** treated as *
#                     in fnmatch — sufficient for absolute paths in
#                     allow/deny lists.
#   * bash_patterns — substring match (case-insensitive) when the
#                     pattern contains no glob meta; fnmatch glob when
#                     it does. Substring is the right default here
#                     because policy.yaml lists short tokens like "env"
#                     that we want to reject anywhere in the command.
#
# Fail-safe: if $CHAT_ID is missing OR policy fails to load,
# unconditionally deny (exit 2) — better to lose a legitimate tool call
# than silently allow one through a misconfigured hook.
#
# Injection-safety: tool-call JSON is piped through stdin to a temp
# file; the temp path is passed via env to python. No content from the
# tool call is interpolated into shell.

set -euo pipefail

# Refuse, on BOTH streams. Under the exit-2 contract Claude surfaces STDERR to
# the model as the reason; the JSON on stdout is the machine-readable form an
# exit-0 hook would use. Printing only stdout, as this hook did, meant the model
# was blocked with no reason attached.
deny() {  # deny <denied_by> <reason>
  printf '{"decision":"block","denied_by":"%s","reason":"%s"}\n' "$1" "$2"
  printf 'BLOCKED (%s): %s\n' "$1" "$2" >&2
  exit 2
}

# Sentinel: this hook is multichat-specific. If MULTICHAT_STATE_DIR is unset
# the hook is running outside a per-chat tmux session (e.g. accidentally
# registered into the master Thrall workspace via a stray settings.json) and
# applying the strict gate would lock the master session out of every Bash /
# Edit / Read call. Pass-through silently.
if [[ -z "${MULTICHAT_STATE_DIR:-}" ]]; then
  exit 0
fi

# Fail-safe: CHAT_ID missing -> full deny.
if [[ -z "${CHAT_ID:-}" ]]; then
  deny hook-failure 'CHAT_ID env var missing (fail-safe deny)'
fi

WORKSPACE="${CLAUDE_WORKSPACE_DIR:-${HOME}/.claude-lab/thrall/.claude}"
POLICY_PATH="${WORKSPACE}/chats/policy.yaml"

if [[ ! -f "$POLICY_PATH" ]]; then
  deny hook-failure 'policy.yaml not found (fail-safe deny)'
fi

# Pick an interpreter that can actually read the policy.
#
# This used to be `python3` from PATH, on the assumption that the one PATH
# resolves has PyYAML. That assumption is not the hook's to make: Claude Code
# invokes it from an environment the hook neither controls nor inspects. On this
# machine PATH resolved to a Homebrew python WITHOUT PyYAML while /usr/bin had
# it, so the policy could not be parsed at all and the fail-safe denied every
# Bash, Edit and Read call in every multichat session. The direction of the
# failure was right; the effect was an agent that looks broken rather than a
# missing package.
#
# Installing PyYAML would fix this machine, not the defect -- the next host
# resolves a third python. So: try candidates and keep the first whose `import
# yaml` succeeds. Checking beats believing, and the check is the cheapest
# possible form of the thing the hook is about to do anyway.
#
# $CHATS_HOOK_PYTHON first, so an operator can pin an interpreter without
# editing this file. $CHATS_HOOK_PYTHON_FALLBACKS exists so the tests can empty
# the well-known-paths list and reach the «found nothing» branch: a deny path
# that cannot be provoked is a deny path nobody has ever seen run.
CHATS_HOOK_PYTHON_FALLBACKS="${CHATS_HOOK_PYTHON_FALLBACKS-/usr/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3}"

POLICY_PYTHON=""
# `set -f` for the loop only: the fallback list is unquoted ON PURPOSE, because
# it must word-split into candidates -- but unquoted also means pathname
# expansion, so a list containing `*` or `?` would be globbed against the
# current directory. Word splitting is wanted, globbing is not.
set -f
for candidate in \
  "${CHATS_HOOK_PYTHON:-}" \
  "$(command -v python3 2>/dev/null || true)" \
  ${CHATS_HOOK_PYTHON_FALLBACKS}
do
  [[ -n "$candidate" ]] || continue
  [[ -x "$candidate" ]] || continue
  # `</dev/null` matters: this probe runs BEFORE stdin is captured below, so it
  # inherits the tool-call pipe. `python3 -c` does not read stdin, but a wrapper
  # shim (pyenv, conda, asdf are shell scripts) can, and a drained pipe would
  # leave `cat > "$TMP_INPUT"` with an empty file -- turning every tool call
  # into a hook-failure deny. Fail-closed, but it is the same failure this hook
  # was written to end, re-entered through another door.
  if "$candidate" -c 'import yaml' >/dev/null 2>&1 </dev/null; then
    POLICY_PYTHON="$candidate"
    break
  fi
done
set +f

if [[ -z "$POLICY_PYTHON" ]]; then
  # Still a deny -- an unreadable policy must not become an open door. But the
  # reason now says which of the two things happened. «The policy forbids this»
  # and «I could not read the policy» are different events with different fixes,
  # and until now both arrived as an opaque block.
  deny hook-failure 'no python3 with PyYAML found (tried $CHATS_HOOK_PYTHON, PATH, then $CHATS_HOOK_PYTHON_FALLBACKS) — the chat policy could not be read, so nothing was evaluated'
fi

# Capture stdin into a temp file. Pass the path via env so python reads
# it without ever exposing the content to the shell.
TMP_INPUT="$(mktemp)"
trap 'rm -f "$TMP_INPUT"' EXIT
cat > "$TMP_INPUT"

CHAT_ID="$CHAT_ID" \
POLICY_PATH="$POLICY_PATH" \
TMP_INPUT_PATH="$TMP_INPUT" \
"$POLICY_PYTHON" - <<'PYEOF'
import fnmatch
import json
import os
import sys


def emit(denied_by: str, reason: str) -> None:
    """Write the refusal to BOTH streams, because they reach different readers.

    Under the exit-2 contract Claude surfaces STDERR to the model as the reason
    the call was blocked; the JSON-on-stdout form is what an exit-0 hook uses.
    This hook exits 2 and printed only stdout, so the model saw a block with no
    reason at all -- the whole point of `denied_by` reached a human reading raw
    hook output and nobody else. Stdout keeps the machine-readable shape, stderr
    carries the same two facts in words.
    """
    sys.stdout.write(
        json.dumps({'decision': 'block', 'denied_by': denied_by, 'reason': reason}) + '\n'
    )
    sys.stdout.flush()
    sys.stderr.write(f'BLOCKED ({denied_by}): {reason}\n')
    sys.stderr.flush()


def emit_block(reason: str, denied_by: str = 'policy') -> None:
    """Refuse the call, saying WHICH kind of refusal this is.

    `denied_by` separates «the policy forbids this» from «the hook could not
    evaluate the policy». Both must deny -- an unreadable policy is not an open
    door -- but they are different events with different fixes, and until now
    the caller saw one opaque block for both. A reader who cannot tell them
    apart eventually treats every block as a policy decision and stops looking
    for the broken install underneath.
    """
    emit(denied_by, reason)
    sys.exit(2)


def deny_on_crash(exc_type, exc, tb) -> None:  # noqa: ANN001 — sys.excepthook shape
    """Any unhandled exception becomes a BLOCK, not a pass.

    Claude treats exit 2 as «blocked» and every other code as «allowed», so an
    interpreter that dies on an unexpected input exits 1 and the call goes
    through -- a fail-safe hook failing open. Named guards below close the
    shapes we know about; this closes the ones we do not. `os._exit` because
    `sys.exit` inside an excepthook is swallowed and the process would still
    leave with 1. The exception itself is NOT printed: it can quote the policy
    or the tool call back at the caller.
    """
    emit('hook-failure', f'hook crashed ({exc_type.__name__}) — nothing was evaluated')
    os._exit(2)


sys.excepthook = deny_on_crash

chat_id = os.environ.get('CHAT_ID', '')
policy_path = os.environ.get('POLICY_PATH', '')
tmp_input_path = os.environ.get('TMP_INPUT_PATH', '')

try:
    with open(tmp_input_path, 'r', encoding='utf-8') as f:
        tool_call = json.load(f)
except Exception:  # noqa: BLE001
    # Type only: a decoder message can quote the offending text back, and the
    # offending text here is the tool call.
    emit_block('tool-call json unreadable (fail-safe deny)', 'hook-failure')

try:
    import yaml  # type: ignore
except ImportError:
    # The shell picked this interpreter BECAUSE `import yaml` worked in it, so
    # reaching here means the environment changed between the check and the run.
    # Kept as a guard rather than removed: the previous version of this hook
    # died here on every call, and a guard that has fired once is worth keeping.
    emit_block('PyYAML missing in the chosen interpreter (fail-safe deny)', 'hook-failure')

try:
    with open(policy_path, 'r', encoding='utf-8') as f:
        policy = yaml.safe_load(f)
except Exception:  # noqa: BLE001
    # The parser's message quotes the offending LINE of policy.yaml. That line
    # is policy content and has no business in the caller's transcript, so the
    # exception is named by type only.
    emit_block('policy.yaml did not parse (fail-safe deny)', 'hook-failure')


def as_mapping(value: object, what: str) -> dict:
    """Return ``value`` as a dict, denying if it is anything else.

    A policy can be perfectly valid YAML and still be the wrong SHAPE -- a top
    level list, `chats: []`, `deny: []`. Before this guard those shapes reached
    `.get()` on a non-dict, raised AttributeError and killed the interpreter
    with exit code 1. Claude blocks on exit 2 and ONLY on exit 2, so the
    fail-safe hook was failing OPEN in exactly the corner it exists for. An
    absent key is different and stays allowed: no rules for this chat has
    always meant no denials.
    """
    if value is None:
        return {}
    if not isinstance(value, dict):
        emit_block(f'{what} is not a mapping (fail-safe deny)', 'hook-failure')
    return value


def as_sequence(value: object, what: str) -> list:
    """Return ``value`` as a list, denying if it is anything else.

    A bare string here would iterate CHARACTER by character and quietly match
    almost nothing -- a deny list that silently stops denying.
    """
    if value is None:
        return []
    if not isinstance(value, list):
        emit_block(f'{what} is not a list (fail-safe deny)', 'hook-failure')
    return value


policy = as_mapping(policy, 'policy.yaml root')
chats = as_mapping(policy.get('chats'), 'policy.yaml chats')
chat_cfg = as_mapping(chats.get(chat_id), 'the chat entry')
deny = as_mapping(chat_cfg.get('deny'), 'the deny block')

# The SHAPE of the whole deny block is settled HERE, before anything looks at
# which tool is calling.
#
# Validating each list inside the branch that consumes it made the refusal
# depend on the caller: `read_paths: "secret"` is the same broken policy whether
# a Read or a Bash arrives, but only the Read would have been refused. The Bash
# ran, under a policy the hook had already failed to understand -- fail-open
# wearing the fail-safe's clothes, and invisible because the tool that triggers
# it is not the tool the broken list is about.
#
# A policy that does not parse is not a policy. It cannot be enforced for some
# callers and waived for the rest.
mcp_tools = as_sequence(deny.get('mcp_tools'), 'mcp_tools')
read_paths = as_sequence(deny.get('read_paths'), 'read_paths')
bash_patterns = as_sequence(deny.get('bash_patterns'), 'bash_patterns')

# Defensive: tool_call may be malformed under prompt injection.
tool_name = ''
tool_input = {}
if isinstance(tool_call, dict):
    raw_tool = tool_call.get('tool_name', '')
    if isinstance(raw_tool, str):
        tool_name = raw_tool
    raw_input = tool_call.get('tool_input', {})
    if isinstance(raw_input, dict):
        tool_input = raw_input

# A refusal names the RULE, never the rule's text. The pattern comes out of
# policy.yaml and can carry a path or a token fragment; printing it hands the
# caller a piece of the policy on every block. The rule kind plus its 1-based
# position is enough to find the line in policy.yaml, and carries nothing.
def rule_ref(section: str, index: int) -> str:
    return f'{section} deny: rule #{index + 1} in policy.yaml'


# 1) mcp_tools / tool-name deny — fnmatch globs.
for i, pattern in enumerate(mcp_tools):
    if isinstance(pattern, str) and fnmatch.fnmatch(tool_name, pattern):
        emit_block(rule_ref('mcp_tools', i))

# 2) read_paths — only for tools that take a file path.
PATH_TOOLS = {'Read', 'Edit', 'Write', 'NotebookEdit'}
if tool_name in PATH_TOOLS:
    candidate = tool_input.get('file_path') or tool_input.get('notebook_path') or ''
    if isinstance(candidate, str) and candidate:
        for i, pattern in enumerate(read_paths):
            if not isinstance(pattern, str):
                continue
            if fnmatch.fnmatch(candidate, pattern):
                emit_block(rule_ref('read_paths', i))

# 3) bash_patterns — substring by default, fnmatch when meta present.
if tool_name == 'Bash':
    command = tool_input.get('command') or ''
    if isinstance(command, str):
        cmd_lower = command.lower()
        for i, pattern in enumerate(bash_patterns):
            if not isinstance(pattern, str):
                continue
            pat_lower = pattern.lower()
            has_meta = any(ch in pat_lower for ch in '*?[')
            if has_meta:
                if fnmatch.fnmatch(cmd_lower, pat_lower):
                    emit_block(rule_ref('bash_patterns', i))
            else:
                if pat_lower in cmd_lower:
                    emit_block(rule_ref('bash_patterns', i))

# Default allow.
sys.exit(0)
PYEOF
