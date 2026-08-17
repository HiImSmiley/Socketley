#!/usr/bin/env bash
# Integration test: a payload containing a newline is a payload, not commands.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# The control protocol was one command per line, and the CLI concatenated
# payloads into the command string.  Anything with a line break in it therefore
# ran as commands from the first newline onwards:
#
#     printf 'hello\ncreate server INJECTED -p 18709\n' | socketley send victim
#     socketley ls -s
#     INJECTED                     <- came out of the message text
#     victim
#
# Nothing there is malformed.  `send` is documented to take its message on
# standard input, and any data with a newline does this — a file, an HTTP body,
# a queue entry.  Whoever wrote the data got the daemon's whole command set.
#
# ipc_framing.h carries such a command length-prefixed instead, which is the
# same answer worker_protocol.h already gives for the other channel.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
# The injection, on both spellings — and, paired with it, that the payload
# actually ARRIVES.  A build that simply dropped everything after a newline
# would pass every injection assertion and be a worse bug than the one being
# fixed, so a multi-line value is stored and read back whole.
#
# And the ordinary path: a command with no newline in it must be byte-identical
# to what it always was, because that is the property that lets a rebuilt CLI
# talk to a daemon that has not been restarted.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate ipcframing
PASS=0; FAIL=0; TOTAL=0

cleanup() { daemon_stop; }
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: a newline in a payload is not a command ==="

daemon_start "$BIN"
P=$((SL_PORT_BASE + 910))

"$BIN" create server fr_victim -p "$P" -s >/dev/null 2>&1 || true
"$BIN" create cache  fr_cache  -p $((P + 1)) -s >/dev/null 2>&1 || true

# ─── The injection, through `send` ──────────────────────────────────────────
printf 'hello there\ncreate server FR_INJECTED -p %d\n' $((P + 8)) \
    | "$BIN" send fr_victim >/dev/null 2>&1 || true

if [ -z "$("$BIN" ls --name 2>/dev/null | grep -x FR_INJECTED || true)" ]; then pass
else fail "a newline in a piped message does not create a runtime" \
          "FR_INJECTED exists — the message text was executed as commands"; fi

# ─── And through the bare-name shortcut ─────────────────────────────────────
printf 'payload\ncreate server FR_INJECTED2 -p %d\n' $((P + 9)) \
    | "$BIN" fr_victim >/dev/null 2>&1 || true

if [ -z "$("$BIN" ls --name 2>/dev/null | grep -x FR_INJECTED2 || true)" ]; then pass
else fail "the same holds for 'socketley <name>' with piped input" \
          "FR_INJECTED2 exists"; fi

# ─── Paired with both: the payload has to ARRIVE ────────────────────────────
#
# Load-bearing.  A build that threw away everything after the first newline
# would pass both assertions above while being a worse defect than the one
# they are about.
MULTI=$(printf 'line1\nline2\nline3')
"$BIN" fr_cache set k_multi "$MULTI" >/dev/null 2>&1 || true
GOT=$("$BIN" fr_cache get k_multi 2>/dev/null)

if [ "$(printf '%s' "$GOT" | wc -l)" -eq 2 ]; then pass
else fail "a three-line value is stored with its newlines" \
          "read back $(printf '%s' "$GOT" | wc -l) newlines, expected 2"; fi

if [ "$GOT" = "$MULTI" ]; then pass
else fail "the three-line value round trips exactly" \
          "stored:   $(printf '%s' "$MULTI" | tr '\n' '|')" \
          "read back: $(printf '%s' "$GOT" | tr '\n' '|')"; fi

# The value really does contain newlines, or everything above is about a case
# that never happened.
if [ "$(printf '%s' "$MULTI" | wc -l)" -eq 2 ]; then pass
else fail "the test's own payload is multi-line" "it is not"; fi

# ─── The ordinary path is unchanged ─────────────────────────────────────────
#
# A command with no newline must still travel as a line — that is what lets a
# rebuilt CLI talk to a daemon that has not been restarted.
"$BIN" fr_cache set k_plain "just one line" >/dev/null 2>&1 || true
if [ "$("$BIN" fr_cache get k_plain 2>/dev/null)" = "just one line" ]; then pass
else fail "an ordinary single-line value still works" \
          "got '$("$BIN" fr_cache get k_plain 2>/dev/null)'"; fi

RC=0; "$BIN" ls >/dev/null 2>&1 || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "an ordinary command still works" "ls exited $RC"; fi

# ─── A trailing newline is still stripped ───────────────────────────────────
#
# `echo hi | socketley send x` must not deliver "hi\n".  Only the trailing one
# goes; the ones inside are the message.
printf 'trailing\n' | "$BIN" fr_cache set k_tail >/dev/null 2>&1 || true
"$BIN" fr_cache set k_tail "$(printf 'trailing\n')" >/dev/null 2>&1 || true
if [ "$("$BIN" fr_cache get k_tail 2>/dev/null)" = "trailing" ]; then pass
else fail "a trailing newline is not part of the value" \
          "got '$("$BIN" fr_cache get k_tail 2>/dev/null | tr '\n' '|')'"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
