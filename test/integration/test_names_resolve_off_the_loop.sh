#!/usr/bin/env bash
# Integration test: a name that is looked up off the loop still gets dialled
#
# A server's upstream and a client's reconnect resolve their target's name on
# a thread of their own and take the answer up on a later turn, so the first
# attempt finds the answer still out.  What this file checks is that such an
# attempt is asked again shortly instead of being dropped or counted against
# the backoff: a server whose `-u localhost:P` dials, and a client whose
# `-t localhost:P` comes back after its target does.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate names_offloop
TGT=$((SL_PORT_BASE+210)); SVR=$((SL_PORT_BASE+211))
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    for n in nl_up nl_tgt nl_cli; do
        "$BIN" stop "$n" 2>/dev/null || true; "$BIN" remove "$n" 2>/dev/null || true
    done
    daemon_stop
}
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

conns() {  # how many connections a runtime reports, 0 when it says nothing
    "$BIN" stats "$1" 2>/dev/null | grep -m1 '^connections:' | cut -d: -f2 | tr -d ' ' || true
}
upstreams() {  # how many upstreams a server reports as connected
    "$BIN" stats "$1" 2>/dev/null | sed -n 's|^upstreams:\([0-9]*\)/.*|\1|p' | head -1
}
wait_for() {   # command, wanted output, tenths of a second
    for _ in $(seq 1 "$3"); do
        [ "$($1)" = "$2" ] && return 0
        sleep 0.1
    done
    return 1
}

echo "=== Integration: names are resolved off the loop and still dialled ==="

"$BIN" create server nl_tgt -p "$TGT" -s >/dev/null

# Under a second: the first dial finds the lookup out, and the next is a tenth
# of a second later rather than the one-second backoff of a refused dial.
"$BIN" create server nl_up -p "$SVR" -u "localhost:$TGT" -s >/dev/null
if wait_for "upstreams nl_up" 1 9; then pass "a server's upstream named by host dials within a second"
else fail "a server's upstream named by host dials within a second" \
          "upstreams: '$(upstreams nl_up)', target connections: '$(conns nl_tgt)'"; fi

"$BIN" create client nl_cli -t "localhost:$TGT" --reconnect 10 -s >/dev/null
sleep 0.4
BEFORE=$(conns nl_tgt)

# The client reconnects through its resolver once the target is back; the
# server's own upstream reconnects as well, so the target counts both.
"$BIN" stop nl_tgt >/dev/null
sleep 0.5
"$BIN" start nl_tgt >/dev/null
if wait_for "conns nl_tgt" "$BEFORE" 80; then pass "a client named by host reconnects after its target returns"
else fail "a client named by host reconnects after its target returns" \
          "the target had $BEFORE connections before and $(conns nl_tgt) after"; fi

RC=0
timeout 10 "$BIN" send nl_cli "hello" >/dev/null 2>&1 || RC=$?
if [ "$RC" -eq 0 ]; then pass "the reconnected client can send"
else fail "the reconnected client can send" "send exited $RC"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
