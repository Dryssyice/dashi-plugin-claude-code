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
  printf '%s\n' '{"decision":"block","denied_by":"hook-failure","reason":"CHAT_ID env var missing (fail-safe deny)"}'
  exit 2
fi

WORKSPACE="${CLAUDE_WORKSPACE_DIR:-${HOME}/.claude-lab/thrall/.claude}"
POLICY_PATH="${WORKSPACE}/chats/policy.yaml"

if [[ ! -f "$POLICY_PATH" ]]; then
  printf '%s\n' '{"decision":"block","denied_by":"hook-failure","reason":"policy.yaml not found (fail-safe deny)"}'
  exit 2
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
for candidate in \
  "${CHATS_HOOK_PYTHON:-}" \
  "$(command -v python3 2>/dev/null || true)" \
  ${CHATS_HOOK_PYTHON_FALLBACKS}
do
  [[ -n "$candidate" ]] || continue
  [[ -x "$candidate" ]] || continue
  if "$candidate" -c 'import yaml' >/dev/null 2>&1; then
    POLICY_PYTHON="$candidate"
    break
  fi
done

if [[ -z "$POLICY_PYTHON" ]]; then
  # Still a deny -- an unreadable policy must not become an open door. But the
  # reason now says which of the two things happened. «The policy forbids this»
  # and «I could not read the policy» are different events with different fixes,
  # and until now both arrived as an opaque block.
  printf '%s\n' '{"decision":"block","denied_by":"hook-failure","reason":"no python3 with PyYAML found (tried $CHATS_HOOK_PYTHON, PATH, then $CHATS_HOOK_PYTHON_FALLBACKS) — the chat policy could not be read, so nothing was evaluated"}'
  exit 2
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


def emit_block(reason: str, denied_by: str = 'policy') -> None:
    """Refuse the call, saying WHICH kind of refusal this is.

    `denied_by` separates «the policy forbids this» from «the hook could not
    evaluate the policy». Both must deny -- an unreadable policy is not an open
    door -- but they are different events with different fixes, and until now
    the caller saw one opaque block for both. A reader who cannot tell them
    apart eventually treats every block as a policy decision and stops looking
    for the broken install underneath.
    """
    print(json.dumps({'decision': 'block', 'denied_by': denied_by, 'reason': reason}))
    sys.exit(2)


chat_id = os.environ.get('CHAT_ID', '')
policy_path = os.environ.get('POLICY_PATH', '')
tmp_input_path = os.environ.get('TMP_INPUT_PATH', '')

try:
    with open(tmp_input_path, 'r', encoding='utf-8') as f:
        tool_call = json.load(f)
except Exception as e:  # noqa: BLE001
    emit_block(f'tool-call json unreadable: {e}', 'hook-failure')

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
        policy = yaml.safe_load(f) or {}
except Exception as e:  # noqa: BLE001
    emit_block(f'policy load failed: {e}', 'hook-failure')

chat_cfg = (policy.get('chats') or {}).get(chat_id) or {}
deny = chat_cfg.get('deny') or {}

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

# 1) mcp_tools / tool-name deny — fnmatch globs.
for pattern in (deny.get('mcp_tools') or []):
    if isinstance(pattern, str) and fnmatch.fnmatch(tool_name, pattern):
        emit_block(f'mcp_tools deny: {pattern}')

# 2) read_paths — only for tools that take a file path.
PATH_TOOLS = {'Read', 'Edit', 'Write', 'NotebookEdit'}
if tool_name in PATH_TOOLS:
    candidate = tool_input.get('file_path') or tool_input.get('notebook_path') or ''
    if isinstance(candidate, str) and candidate:
        for pattern in (deny.get('read_paths') or []):
            if not isinstance(pattern, str):
                continue
            if fnmatch.fnmatch(candidate, pattern):
                emit_block(f'read_paths deny: {pattern}')

# 3) bash_patterns — substring by default, fnmatch when meta present.
if tool_name == 'Bash':
    command = tool_input.get('command') or ''
    if isinstance(command, str):
        cmd_lower = command.lower()
        for pattern in (deny.get('bash_patterns') or []):
            if not isinstance(pattern, str):
                continue
            pat_lower = pattern.lower()
            has_meta = any(ch in pat_lower for ch in '*?[')
            if has_meta:
                if fnmatch.fnmatch(cmd_lower, pat_lower):
                    emit_block(f'bash_patterns deny: {pattern}')
            else:
                if pat_lower in cmd_lower:
                    emit_block(f'bash_patterns deny: {pattern}')

# Default allow.
sys.exit(0)
PYEOF
