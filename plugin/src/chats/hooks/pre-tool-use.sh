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


DENY_KEYS = ('mcp_tools', 'read_paths', 'bash_patterns')

# The chat-entry key names of `ChatPolicySchema`, split the way the schema
# splits them. REQUIRED is what it has no default for; OPTIONAL is `deny` plus
# the two fields it defaults, which a live file may legitimately omit.
#
# Both lists are pinned to the schema by a test, so a field added there reddens
# CI here instead of locking every live chat.
CHAT_REQUIRED = (
    'mode',
    'streaming',
    'tmux_mirror',
    'edit_message_progress',
    'delivery',
    'persona_file',
    'handoff_file',
    'system_reminder',
)
CHAT_OPTIONAL = ('deny', 'idle_ttl_ms', 'max_queue_depth')
CHAT_KEYS = CHAT_REQUIRED + CHAT_OPTIONAL

# The top level of `MultichatPolicySchema`, which is `.strict()` with no
# optional fields — so one list serves as both «required» and «all allowed».
TOP_REQUIRED = ('version', 'allowlist', 'mention_allowlist', 'chats')


def validated_deny(raw_policy: object, wanted_chat: str) -> dict:
    """Return this chat's deny lists, or refuse the call outright.

    ONE strict pass over the whole policy, before anything looks at the call.

    The previous rounds patched shapes one at a time -- a top-level list, then
    `deny: []`, then a list given as a bare string, then those checks running
    only for the tool they were about. Each fix was right and each left the next
    shape open, because the question was being asked once per shape instead of
    once. Review then found four more: an unquoted chat id (YAML makes it an
    INT, the string lookup misses, and every rule for that chat silently
    disappears while the server's own loader accepts the same file); a typo in a
    deny key, which reads in the file exactly like a rule; a non-string element
    inside an otherwise valid list, skipped in silence -- `[on, 007]` is
    `[True, 7]` after YAML and matches nothing; and a report that named only the
    FIRST broken key, so fixing the file took as many rounds as it had mistakes.

    So the shape of a policy is settled here, once, on the same terms the
    TypeScript loader already uses (`policy-loader.ts` is `.strict()` and pins
    `version`): anything this hook cannot fully understand is a refusal, and
    every complaint is collected before any is reported.

    Nothing here prints a VALUE from policy.yaml -- only key names the operator
    wrote and 1-based positions. A refusal that quotes the policy hands the
    caller a piece of it, which is the class that already cost four rounds
    elsewhere in this plugin.
    """
    problems: list[str] = []

    policy_map = raw_policy if raw_policy is not None else {}
    if not isinstance(policy_map, dict):
        emit_block('policy.yaml root is not a mapping (fail-safe deny)', 'hook-failure')

    # `version` and `chats` are REQUIRED, and their absence is a refusal rather
    # than a default.
    #
    # This was the largest fail-open left in the file and it hid behind looking
    # like tidiness: `{}` was a policy with no rules, `version: 1` with no
    # `chats:` was a policy with no rules, and a `chats` block that did not
    # mention the calling chat was a policy with no rules. Three ways to say
    # «allow everything», none of them logged anywhere.
    #
    # The loader answers the same question the opposite way -- `policy-loader.ts`
    # says in as many words that a null policy is to be treated as DENY, with no
    # fallback to defaults and no implicit allow -- and the server reads the file
    # ONCE at startup while this hook re-reads it on every call. So overwriting
    # policy.yaml a single time silently removed every deny rule from every live
    # session, and nothing anywhere recorded it.
    #
    # A running session is proof its chat was in the file when the session
    # started. If it is not there now, the file changed underneath, and that is
    # the moment to stop rather than the moment to assume the best.
    if 'version' not in policy_map:
        problems.append('version is missing')
    elif policy_map.get('version') != 1:
        problems.append('version is not 1')

    if 'chats' not in policy_map:
        problems.append('the chats block is missing')

    # The same invariant at the top level, which the previous round applied to
    # chat entries and left off here. `MultichatPolicySchema` is `.strict()` and
    # requires `allowlist` and `mention_allowlist` too; a file without them is a
    # file the server would not have loaded, and the gate has no business
    # applying one. Names only, for the coercion reason spelled out below.
    top_missing = [name for name in TOP_REQUIRED if name not in policy_map]
    if top_missing:
        problems.append('missing top-level keys: ' + ', '.join(top_missing))
    top_stray = sorted({str(k) for k in policy_map} - set(TOP_REQUIRED))
    if top_stray:
        problems.append('unknown top-level keys: ' + ', '.join(top_stray))

    chats_map = policy_map.get('chats')
    if chats_map is None:
        chats_map = {}
    if not isinstance(chats_map, dict):
        emit_block('policy.yaml chats is not a mapping (fail-safe deny)', 'hook-failure')
    elif not any(str(key) == wanted_chat for key in chats_map):
        problems.append('this chat has no entry in policy.yaml')

    # ONE exit, and that is the point rather than a style choice: the first
    # version returned early when this chat had no entry, and `version: 2` --
    # already collected as a problem -- was never reported. An invalid file was
    # applied as an empty policy, which is the fail-open this function exists to
    # remove, reintroduced by the order of two statements.
    lists: dict = {name: [] for name in DENY_KEYS}

    # EVERY chat's DENY BLOCK is validated, not just the calling chat's. A file
    # the TypeScript loader would reject must not be a file this hook accepts --
    # if the two disagree, the session comes up under a policy the gate reads
    # differently from the server that loaded it.
    #
    # Chat entries are checked by KEY NAME — required names present, unknown
    # names refused — and never by value.
    #
    # The names matter because `deney:` is a fail-open of exactly the shape this
    # function exists to remove, one level up from the `bash_patern:` typo
    # already caught inside the deny block: the rules read like rules in the
    # file, `deny` is absent, this chat gets no restrictions, and the loader's
    # `.strict()` would have thrown on the same file. A typo must not be the
    # difference between a gate and no gate.
    #
    # The VALUES are deliberately not checked, and this is a decision with a
    # reason rather than an omission. PyYAML reads YAML 1.1, js-yaml reads
    # JSON_SCHEMA: the documented `streaming: off` arrives here as the boolean
    # `False` and in the loader as the string `"off"`. A hook that validated
    # that value against the schema's enum would refuse a policy the server
    # accepts — turning every tool call in every chat into a denial over a
    # legal, documented file. Names do not coerce; values do.
    #
    # Drift between the two lists is caught by a test that reads the schema's
    # own keys (`hooks-sentinel.test.ts`), so a field added to
    # `ChatPolicySchema` reddens CI here rather than locking every live chat.
    #
    # The cost is real and belongs in the open: one malformed entry anywhere
    # locks every chat until the file is fixed. That is the same direction the
    # rest of this hook already chose, and a session running under a policy
    # nobody can parse is the thing being avoided.
    for index, (key, value) in enumerate(chats_map.items()):
        # The calling chat is named; every other chat is a POSITION.
        #
        # `chat {key}` for all of them meant a session could be told
        # «chat -100…: read_paths is not a list» about a completely different
        # conversation of the operator's — and a session in a public group can
        # repeat the reason it was blocked with into that group. The docstring
        # above promises no values out of policy.yaml; another chat's id is one
        # in every sense that matters.
        mine = str(key) == wanted_chat
        where = f'chat {key}' if mine else f'chat entry #{index + 1}'
        # `chats:\n  "999":` -- a key with nothing after it -- is `None` here,
        # and skipping it was the same fail-open one shape smaller: a crooked
        # record anywhere in the file went unmentioned while the rule claimed
        # every chat is validated. The TypeScript schema does not accept null
        # for an entry either.
        if value is None:
            problems.append(f'{where}: entry has no value')
            continue
        if not isinstance(value, dict):
            problems.append(f'{where}: entry is not a mapping')
            continue

        # Key NAMES against the schema, both directions.
        #
        # Unknown names first, because `deney: {...}` is the fail-open that
        # started this: it reads like a rule block, leaves `deny` absent, and
        # hands the chat no restrictions at all — `bash_patern:` one level up.
        #
        # Missing required names second. The first version of this check left
        # them out, on the argument that the hook does not READ `persona_file`
        # so it should not refuse over it. That argument is wrong twice: it does
        # not follow from the coercion problem below (a key name is present or
        # it is not — nothing coerces), and it quietly contradicts the invariant
        # this loop is built on. A file the loader would reject stays a file
        # this hook refuses; the two say the same thing about the same file, and
        # the operator is not left with a gate applying a policy the server
        # would not have loaded.
        entry_keys = {str(k) for k in value}
        stray = sorted(entry_keys - set(CHAT_KEYS))
        if stray:
            problems.append(f'{where}: unknown keys: ' + ', '.join(stray))
        missing = [name for name in CHAT_REQUIRED if name not in entry_keys]
        if missing:
            problems.append(f'{where}: missing keys: ' + ', '.join(missing))

        # An ABSENT `deny` is legitimate -- no rules for this chat has always
        # meant no denials. A `deny:` written with no value is not the same
        # thing: it is a half-typed rule block, and `.get()` cannot tell the two
        # apart, so the key is asked for by name.
        if 'deny' in value and value['deny'] is None:
            problems.append(f'{where}: deny has no value')
            continue
        deny_map = value.get('deny', {})
        if not isinstance(deny_map, dict):
            problems.append(f'{where}: deny is not a mapping')
            continue

        unknown = sorted(str(k) for k in deny_map if str(k) not in DENY_KEYS)
        if unknown:
            problems.append(f'{where}: unknown deny keys: ' + ', '.join(unknown))

        # `mine` was decided above, comparing keys as TEXT on both sides: an
        # unquoted chat id is an int here and a string in the loader that
        # validated the same file.
        for name in DENY_KEYS:
            rules = deny_map.get(name)
            if rules is None:
                continue
            if not isinstance(rules, list):
                problems.append(f'{where}: {name} is not a list')
                continue
            bad = [str(i + 1) for i, item in enumerate(rules) if not isinstance(item, str)]
            if bad:
                problems.append(f'{where}: {name} has non-string rules at #' + ', #'.join(bad))
            if mine:
                lists[name] = rules

    if problems:
        emit_block(
            'policy.yaml cannot be applied: ' + '; '.join(problems) + ' (fail-safe deny)',
            'hook-failure',
        )
    return lists


deny_lists = validated_deny(policy, chat_id)
mcp_tools = deny_lists['mcp_tools']
read_paths = deny_lists['read_paths']
bash_patterns = deny_lists['bash_patterns']

# The tool call gets the same treatment as the policy, and for the same reason.
# Unreadable JSON already denied; a readable object of the wrong shape --
# `tool_input` as a string, the whole call as a list -- fell through to defaults
# and was ALLOWED. That is the asymmetry this commit removes on the policy side,
# left standing on the side an injected call actually controls.
if not isinstance(tool_call, dict):
    emit_block('the tool call is not an object (fail-safe deny)', 'hook-failure')

# Absent and empty are refusals too, not just «not a string». `.get(…, '')`
# turned a missing name into a usable one, and a call with no name matches no
# rule -- so the shape that says least about itself was the shape that got
# through. Every real PreToolUse payload carries a tool name.
raw_tool = tool_call.get('tool_name')
if not isinstance(raw_tool, str) or not raw_tool:
    emit_block('the tool call has no usable tool_name (fail-safe deny)', 'hook-failure')
tool_name = raw_tool

raw_input = tool_call.get('tool_input')
if raw_input is None:
    raw_input = {}
if not isinstance(raw_input, dict):
    emit_block('tool_input is not an object (fail-safe deny)', 'hook-failure')
tool_input = raw_input

# A refusal names the RULE, never the rule's text. The pattern comes out of
# policy.yaml and can carry a path or a token fragment; printing it hands the
# caller a piece of the policy on every block. The rule kind plus its 1-based
# position is enough to find the line in policy.yaml, and carries nothing.
def rule_ref(section: str, index: int) -> str:
    return f'{section} deny: rule #{index + 1} in policy.yaml'


# 1) mcp_tools / tool-name deny — fnmatch globs.
#
# No isinstance guard on the pattern in any of the three loops below: a
# non-string rule is refused by validated_deny before we get here, and a guard
# that cannot fire reads as «this can happen» to the next person.
for i, pattern in enumerate(mcp_tools):
    if fnmatch.fnmatch(tool_name, pattern):
        emit_block(rule_ref('mcp_tools', i))

# 2) read_paths — wherever the call names a path.
#
# This used to be an allowlist of tool NAMES, and the allowlist was short by
# two: `MultiEdit` and `NotebookRead` take a path like everyone else and were
# not on it, so on a perfectly correct policy a protected path could be read
# through NotebookRead and written through MultiEdit. The multichat session runs
# with bypassPermissions and names this hook as its only gate, so there was
# nobody left to ask.
#
# The same mistake as the shape checks above, one layer down: the rule was made
# to depend on WHICH tool arrived rather than on what the call is doing.
#
# The scope is these three STRING fields and no more, which is narrower than it
# sounds and is stated here rather than implied. A path travelling as a LIST is
# not covered -- `reply(files: [...])` in this same plugin attaches a file to a
# Telegram message and would walk past every one of these. Naming it beats an
# earlier version of this comment, which claimed the class was closed and would
# have stopped the next reader from looking.
PATH_FIELDS = ('file_path', 'notebook_path', 'path')
for field in PATH_FIELDS:
    candidate = tool_input.get(field)
    if not isinstance(candidate, str) or not candidate:
        continue
    for i, pattern in enumerate(read_paths):
        if fnmatch.fnmatch(candidate, pattern):
            emit_block(rule_ref('read_paths', i))

# 3) bash_patterns — substring by default, fnmatch when meta present.
if tool_name == 'Bash':
    # A Bash call MUST carry a non-empty string command; everything else is
    # malformed and denies. This is `extractCommand` in permission-policy.ts
    # written out in the other language, down to the reason it exists there:
    # «the old code returned '' here and an empty command auto-allowed».
    #
    # This hook had both halves of that bug. A non-string `command` was skipped
    # in silence — `{"command": ["rm", "-rf", "/"]}` and `{"command": 42}` both
    # ran — and a MISSING or empty one was turned into `''`, which matches no
    # pattern and reaches «Default allow». Under bypassPermissions there is no
    # native prompt behind this hook to catch either.
    command = tool_input.get('command')
    if not isinstance(command, str) or not command.strip():
        emit_block(
            'Bash: command is missing, empty or not a string (fail-safe deny)',
            'hook-failure',
        )

    cmd_lower = command.lower()
    for i, pattern in enumerate(bash_patterns):
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
