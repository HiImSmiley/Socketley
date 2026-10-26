#!/usr/bin/env bash
# Integration test: three CLI answers that broke the project's own contract.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# "success is silent; errors to stdout", and "exit 0 ok, 1 bad input, 2 fatal".
#
#   restart   relayed the daemon's refusal on stderr while its own start half,
#             four lines below, relayed the same class of refusal on stdout --
#             and cli_forward, which every other verb uses, sends it to stdout.
#             `stop nosuch` named the runtime; `restart nosuch` said nothing.
#
#   help      returned the child's raw status, so with no bash on PATH the
#             _exit(127) reached the shell as 127, in silence -- and a missing
#             help script exited 1, which says the operator's input was wrong
#             for a command that takes no input.
#
#   --backend stored an empty component as a backend, where --upstream's own
#             splitting loop in the same file skips one.  A doubled comma made
#             a backend that can never connect and that nothing named.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# Each row has a control beside it that passes on both trees: the same refusal
# from `stop`, an ordinary `help`, and a proxy with two real backends.  Without
# them a build that refused everything, or printed nothing anywhere, would read
# as a pass.  Exit codes are compared numerically -- `-ne 0` is satisfied by
# the 127 and the 1 this file exists to change.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate clicontract

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
         local l; for l in "${@:3}"; do echo "        $l"; done; }
cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: the CLI's own output and exit-code contract ==="
daemon_start "$BIN"
P=$((SL_PORT_BASE + 1600))

# ─── 1. a relayed refusal goes to stdout ────────────────────────────────────
RC=0; OUT=$("$BIN" restart cc_nosuch 2>/dev/null) || RC=$?
case "$RC:$OUT" in
    1:*cc_nosuch*) pass ;;
    *) fail "restart names a missing runtime on stdout" \
            "exit $RC, stdout: ${OUT:-<nothing>}" \
            "stderr had it; every other verb puts it on stdout" ;;
esac

# Control: the same refusal from `stop` is already on stdout, so the row above
# is about the stream and not about the message existing at all.
RC=0; OUT=$("$BIN" stop cc_nosuch 2>/dev/null) || RC=$?
case "$RC:$OUT" in
    1:*cc_nosuch*) pass ;;
    *) fail "the control: stop already answers on stdout" \
            "exit $RC, stdout: ${OUT:-<nothing>}" ;;
esac

# Control: an ordinary restart still works, so a build that refused every
# restart would not pass the row above.
"$BIN" create server cc_live -p "$P" -s >/dev/null 2>&1 || true
sleep 0.8
RC=0; "$BIN" restart cc_live >/dev/null 2>&1 || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "an ordinary restart still works" "exit $RC"; fi

# ─── 2. help exits 0, 1 or 2 ────────────────────────────────────────────────
# The help script is found through /proc/self/exe, not through PATH, so an
# empty PATH leaves the script reachable and takes away the bash that runs it.
RC=0; OUT=$(env PATH=/nonexistent "$BIN" help 2>&1) || RC=$?
if [ "$RC" -eq 2 ] && [ -n "$OUT" ]; then pass
else fail "help that cannot be run exits 2 and says so" \
          "exit $RC, said: ${OUT:-<nothing>}" \
          "127 is the child's own status passed straight through"; fi

# Control: with a bash on PATH it is exit 0 and prints something.
RC=0; OUT=$("$BIN" help 2>&1) || RC=$?
if [ "$RC" -eq 0 ] && [ -n "$OUT" ]; then pass
else fail "help still prints help" "exit $RC, ${#OUT} bytes"; fi

# ─── 3. a doubled comma is not a backend ────────────────────────────────────
"$BIN" create proxy cc_comma -p $((P + 10)) \
       --backend ",127.0.0.1:$((P + 20))" --protocol http >/dev/null 2>&1 || true
SHOW=$("$BIN" show cc_comma 2>/dev/null | tr -d '\n')
case "$SHOW" in
    *'"backends"'*) pass ;;
    *) fail "the runtime with a leading comma shows a backends list" "show said: ${SHOW:-<nothing>}" ;;
esac
case "$SHOW" in
    *'"backends": ['*'""'*) fail "a leading comma is not a backend" \
                                 "show carries an empty one: $(echo "$SHOW" | grep -o '"backends":[^]]*.')" ;;
    *) pass ;;
esac

# Control: two real backends are still two, so a build that dropped every
# backend would not pass the row above.
"$BIN" create proxy cc_two -p $((P + 11)) \
       --backend "127.0.0.1:$((P + 21)),127.0.0.1:$((P + 22))" \
       --protocol http >/dev/null 2>&1 || true
N=$("$BIN" show cc_two 2>/dev/null | grep -o '127\.0\.0\.1' | wc -l)
if [ "$N" -eq 2 ]; then pass
else fail "two backends are still two" "show names $N of them"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
