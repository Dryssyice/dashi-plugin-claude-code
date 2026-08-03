#!/usr/bin/env bash
# Claude Code SessionStart hook for multichat-thrall.
#
# Reads $CHAT_ID (set by tmux-session-pool when spawning the session),
# loads {WORKSPACE}/chats/{CHAT_ID}/persona.md and the chat's
# system_reminder from {WORKSPACE}/chats/policy.yaml, and emits the
# Claude Code SessionStart hook JSON:
#   {"hookSpecificOutput":{"hookEventName":"SessionStart",
#                          "additionalContext":"<persona>\n\n---\n\n<reminder>"}}
#
# Failure modes (graceful degradation — do not block the session):
#   * CHAT_ID empty / unset      -> log to stderr, exit 0 (no injection).
#   * persona.md missing         -> log to stderr, emit degraded-mode
#                                   additionalContext warning so the
#                                   session sees that pre-tool-use will
#                                   deny every tool call until persona
#                                   is provisioned. Exit 0.
#   * policy.yaml unreadable     -> log to stderr, exit 0.
#   * python3 unavailable        -> log to stderr, exit 0.
#
# Injection-safety: persona content and policy reminder are read into
# files and loaded by python3 via env-passed paths. Nothing from those
# files is interpolated into shell. The JSON is built by json.dumps.

set -euo pipefail

# Sentinel: this hook is multichat-specific. If MULTICHAT_STATE_DIR is unset
# the hook is running outside a per-chat tmux session (e.g. accidentally
# registered into the master Thrall workspace). Exit cleanly without emitting
# any additionalContext so the master session is not polluted with a chat
# persona it never asked for.
if [[ -z "${MULTICHAT_STATE_DIR:-}" ]]; then
  exit 0
fi

if [[ -z "${CHAT_ID:-}" ]]; then
  echo "session-start: CHAT_ID not set, skipping persona injection" >&2
  exit 0
fi

WORKSPACE="${CLAUDE_WORKSPACE_DIR:-${HOME}/.claude-lab/thrall/.claude}"
# The second consumer of policy.yaml in this session, and it had the same
# hard-coded default as the gate: with a configured `policy_path` the reminder
# and persona context came from a file the server never loaded.
POLICY_PATH="${TELEGRAM_MULTICHAT_POLICY_PATH:-${WORKSPACE}/chats/policy.yaml}"
PERSONA_PATH="${WORKSPACE}/chats/${CHAT_ID}/persona.md"

# The gate learned to pick its interpreter by TESTING the import rather than
# trusting PATH; this hook did not, and it is the second reader of the same
# policy.yaml. `command -v python3` is happy with any python3 — including a
# homebrew one with no PyYAML, which is what PATH resolves to on this machine.
# The consequence was silent: `import yaml` failed inside the heredoc, the
# except branch set `yaml = None`, and the session booted with the persona but
# WITHOUT its per-chat system_reminder. Exit 0, stderr nobody reads, and the
# operator's per-chat instructions simply never arrived.
#
# Same candidate order and the same `</dev/null` reasoning as pre-tool-use.sh;
# see the long comment there. The two hooks must agree on which interpreter
# reads the policy, or they disagree about what the policy SAYS.
CHATS_HOOK_PYTHON_FALLBACKS="${CHATS_HOOK_PYTHON_FALLBACKS-/usr/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3}"

POLICY_PYTHON=""
set -f
for candidate in \
  "${CHATS_HOOK_PYTHON:-}" \
  "$(command -v python3 2>/dev/null || true)" \
  ${CHATS_HOOK_PYTHON_FALLBACKS}
do
  [[ -n "$candidate" ]] || continue
  [[ -x "$candidate" ]] || continue
  if "$candidate" -c 'import yaml' >/dev/null 2>&1 </dev/null; then
    POLICY_PYTHON="$candidate"
    break
  fi
done
set +f

# Unlike the gate, this hook must NOT deny — SessionStart degrades by design.
# But a python3 with no PyYAML is still usable for the persona and for building
# the JSON, so fall back to it rather than emitting nothing: losing the persona
# too would turn a missing reminder into a missing identity.
PERSONA_PYTHON="$POLICY_PYTHON"
if [[ -z "$PERSONA_PYTHON" ]]; then
  PERSONA_PYTHON="$(command -v python3 2>/dev/null || true)"
fi
if [[ -z "$PERSONA_PYTHON" ]]; then
  echo "session-start: no usable python3 found, skipping injection" >&2
  exit 0
fi

# Persona missing while running inside a multichat session is an
# operationally degraded state — the session will boot but every
# subsequent tool call will be denied by pre-tool-use.sh (fail-closed
# branch when policy lookup fails or persona context is absent). Emit
# an explicit additionalContext warning so the Claude session sees the
# degradation on startup and can route the next action (escalate to
# operator, refuse work, etc.) instead of plowing into a wall of denies.
if [[ ! -f "$PERSONA_PATH" ]]; then
  echo "session-start: persona file not found at ${PERSONA_PATH} — emitting degraded-mode warning" >&2
  CHAT_ID="$CHAT_ID" \
  PERSONA_PATH="$PERSONA_PATH" \
  "$PERSONA_PYTHON" - <<'PYEOF'
import json
import os

chat_id = os.environ.get('CHAT_ID', '')
persona_path = os.environ.get('PERSONA_PATH', '')

warning = (
    f"⚠ Persona file missing for chat {chat_id}: {persona_path}. "
    "Multichat session running in degraded mode — tool calls will be "
    "denied by pre-tool-use until persona is provisioned."
)

payload = {
    'hookSpecificOutput': {
        'hookEventName': 'SessionStart',
        'additionalContext': warning,
    }
}
print(json.dumps(payload, ensure_ascii=False))
PYEOF
  exit 0
fi

if [[ ! -f "$POLICY_PATH" ]]; then
  echo "session-start: policy file not found at ${POLICY_PATH}" >&2
  exit 0
fi

# Python loads persona + policy, emits SessionStart JSON. All paths
# arrive via env vars — no shell interpolation into the payload.
CHAT_ID="$CHAT_ID" \
POLICY_PATH="$POLICY_PATH" \
PERSONA_PATH="$PERSONA_PATH" \
POLICY_PYTHON_FOUND="$([[ -n "$POLICY_PYTHON" ]] && echo 1 || echo 0)" \
"$PERSONA_PYTHON" - <<'PYEOF'
import json
import os
import sys

chat_id = os.environ.get('CHAT_ID', '')
policy_path = os.environ.get('POLICY_PATH', '')
persona_path = os.environ.get('PERSONA_PATH', '')

try:
    import yaml  # type: ignore
except ImportError:
    print('session-start: PyYAML not available, skipping reminder', file=sys.stderr)
    yaml = None

persona = ''
try:
    with open(persona_path, 'r', encoding='utf-8') as f:
        persona = f.read()
except OSError as e:
    print(f'session-start: persona read failed: {e}', file=sys.stderr)
    sys.exit(0)

reminder = ''
if yaml is not None:
    try:
        with open(policy_path, 'r', encoding='utf-8') as f:
            policy = yaml.safe_load(f) or {}
        chat_cfg = (policy.get('chats') or {}).get(chat_id) or {}
        reminder = chat_cfg.get('system_reminder') or ''
    except Exception as e:  # noqa: BLE001 — best-effort
        print(f'session-start: policy parse failed: {e}', file=sys.stderr)

parts = [persona.rstrip()]
# A reminder that cannot be read must SAY so in the context the session sees.
# Before this, a missing PyYAML dropped the per-chat instructions and reported
# it only on stderr: the session looked normal and simply behaved as if the
# operator had written nothing for this chat.
if os.environ.get('POLICY_PYTHON_FOUND') != '1':
    parts.append('---')
    parts.append(
        '⚠ Per-chat system_reminder НЕ ПРОЧИТАН: не нашёлся python3 с PyYAML. '
        'Указания оператора для этого чата в контекст не попали — считай, что '
        'ты их не видел, и скажи об этом, прежде чем действовать по умолчанию.'
    )
if reminder:
    parts.append('---')
    parts.append(reminder.strip())
# Capability note (all chats): how to attach a file from a multichat session,
# which has no reply tool. The Stop hook turns the marker into an outbox
# attachment and the router sends it AFTER the text. Secrets are refused.
parts.append('---')
parts.append(
    'Отправка файла в чат: в этой сессии нет reply-инструмента, поэтому чтобы '
    'прикрепить файл, добавь в текст ответа маркер [[file: /абсолютный/путь]] '
    '(можно несколько). Файл уйдёт после текста. НЕ читай токен и не дёргай '
    'Telegram API напрямую. Секреты (.env, ключи, *.pem/*.key, secrets/) '
    'отправлять нельзя — они будут отклонены.'
)
additional_context = '\n\n'.join(parts)

payload = {
    'hookSpecificOutput': {
        'hookEventName': 'SessionStart',
        'additionalContext': additional_context,
    }
}
print(json.dumps(payload, ensure_ascii=False))
PYEOF
