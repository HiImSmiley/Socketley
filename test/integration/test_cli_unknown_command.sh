#!/bin/bash
# A word the CLI does not know, typed where there is no terminal
#
# `socketley <word>` has three readings, and which one it gets depends on
# something the caller never typed:
#
#   argc >= 3            socketley <name> <action> [args]
#   stdin not a terminal socketley <name>, with the message piped in
#   otherwise            unknown command
#
# The middle one swallows every typo made in a script, a pipeline or a CI step,
# because there stdin is never a terminal.  It used to answer "empty message" —
# naming neither the word it did not understand nor the reading it had picked —
# so a misspelled command in a script reported a problem with its input.
#
# The two cases are genuinely indistinguishable from inside the process: a
# misspelled command and a real runtime piped nothing are both one word with no
# data behind it.  So the requirement asserted here is that the message names
# both, and leads with the typo.
#
# No ports.  A daemon is started because every command that is not --help or
# version starts one; it is isolated so it is not somebody else's.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate cliunknown

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: an unknown command where there is no terminal ==="

daemon_start "$BIN"

# ─── The typo, with stdin closed — the script and CI case ───────────────────
#
# `|| RC=$?` and not `; RC=$?`: under set -e a failing command substitution
# ends the script on the assignment, before $? can be read, and this file would
# die of the very exit code it is here to check.
RC=0
OUT=$("$BIN" gibtsnicht </dev/null 2>&1) || RC=$?

if [ "$RC" -eq 1 ]; then
    pass
else
    fail "an unknown command exits 1" "got exit $RC"
fi

if printf '%s' "$OUT" | grep -qF "unknown command: gibtsnicht"; then
    pass
else
    fail "the message names the word it did not understand" \
         "got: $(printf '%s' "$OUT" | head -1)"
fi

# The other reading has to be named too, or the message is merely a different
# guess rather than an honest one.
if printf '%s' "$OUT" | grep -qF "echo 'data' | socketley gibtsnicht"; then
    pass
else
    fail "the message names the piped-send reading as well" \
         "the caller is told it is a typo with no way to learn otherwise"
fi

# ─── The control: the piped-send shortcut still works ───────────────────────
#
# Without this, a build that simply deleted cli_stdin_send would pass every
# assertion above.  The daemon must be the one answering, which it can only do
# if the message actually reached it.
RC2=0
OUT2=$(echo "hallo" | "$BIN" nichtvorhanden 2>&1) || RC2=$?
if printf '%s' "$OUT2" | grep -qF "runtime not found: nichtvorhanden"; then
    pass
else
    fail "a piped message still reaches the daemon" \
         "expected the daemon's \"runtime not found\", got: $(printf '%s' "$OUT2" | head -1)" \
         "exit was $RC2"
fi

# ─── And the real thing still sends ─────────────────────────────────────────
"$BIN" create server cliunk_srv -p "$((SL_PORT_BASE + 1160))" >/dev/null 2>&1 || true
"$BIN" start cliunk_srv >/dev/null 2>&1 || true
RC3=0
OUT3=$(echo "ping" | "$BIN" cliunk_srv 2>&1) || RC3=$?
if [ "$RC3" -eq 0 ] && ! printf '%s' "$OUT3" | grep -qiE "unknown command|runtime not found"; then
    pass
else
    fail "a piped message to a live runtime is sent" \
         "exit $RC3: $(printf '%s' "$OUT3" | head -1)"
fi
"$BIN" stop   cliunk_srv >/dev/null 2>&1 || true
"$BIN" remove cliunk_srv >/dev/null 2>&1 || true

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK"
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
