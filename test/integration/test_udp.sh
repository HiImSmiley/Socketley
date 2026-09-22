#!/usr/bin/env bash
# Integration test: UDP server and client
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate udp
PORT=$((SL_PORT_BASE+220))
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop udp_client 2>/dev/null || true
    "$BIN" stop udp_test 2>/dev/null || true
    sleep 0.5
    "$BIN" remove udp_client 2>/dev/null || true
    "$BIN" remove udp_test 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

assert_contains() {
    TOTAL=$((TOTAL+1))
    if grep -q "$2" <<<"$1"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$2]: not found in output"
    fi
}

echo "=== Integration: UDP ==="

# Ensure daemon is running
daemon_start "$BIN"

# Test: Create UDP server
create_ok "UDP server created" "$BIN" create server udp_test -p "$PORT" --udp -s
sleep 0.3

# Test: Create UDP client
create_ok "UDP client created" "$BIN" create client udp_client --udp -t 127.0.0.1:"$PORT" -s
sleep 0.3

# Test: Both show in ps as running
#
# A lone `OUT=$(cmd)` takes its exit status from the substitution, so a failing
# CLI command used to end this file at the assignment with no `Results` line.
# daemon_required carries on when the daemon is still serving — the assertion
# below is what reports a command that failed on its own merits — and stops,
# with counts, when it is not.  See lib_daemon.sh.
OUT=$("$BIN" ps 2>&1) || daemon_required "ps"
assert_contains "$OUT" "udp_test" "UDP server in ps"
assert_contains "$OUT" "udp_client" "UDP client in ps"

# Test: ls shows both
OUT=$("$BIN" ls 2>&1) || daemon_required "ls"
assert_contains "$OUT" "udp_test" "UDP server in ls"
assert_contains "$OUT" "udp_client" "UDP client in ls"

# ─── THE DATAGRAM, ASKED OF THE SERVER AND NOT OF nc ────────────────────────
# This used to be `echo ... | nc -u ... || true` followed by an unconditional
# PASS, under the comment "If we get here without error, the send succeeded".
# A local UDP send does not fail -- the kernel takes the datagram whether
# anything is listening or not -- and the `|| true` swallowed it if it did.  So
# the assertion could not fail, which AGENTS.md names as not being coverage:
# every one of the six UDP defects found in this tree could have shipped past
# it.  What the server counted is the thing only the server can answer.
stat_of() { "$BIN" stats "$1" 2>/dev/null | awk -F: -v k="$2" '$1 == k { print $2; exit }'; }

MSG_BEFORE=$(stat_of udp_test total_messages); MSG_BEFORE=${MSG_BEFORE:-0}
IN_BEFORE=$(stat_of udp_test bytes_in);        IN_BEFORE=${IN_BEFORE:-0}

# Three, so a server that answered one by accident still has to have counted.
for _ in 1 2 3; do
    echo "hello-udp" | nc -u -q 1 127.0.0.1 "$PORT" 2>/dev/null || true
done
sleep 1

MSG_AFTER=$(stat_of udp_test total_messages); MSG_AFTER=${MSG_AFTER:-0}
IN_AFTER=$(stat_of udp_test bytes_in);        IN_AFTER=${IN_AFTER:-0}

TOTAL=$((TOTAL+1))
if [ "$((MSG_AFTER - MSG_BEFORE))" -eq 3 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [three datagrams are three messages]: total_messages went" \
         "$MSG_BEFORE -> $MSG_AFTER; the datagrams left this box, so what is" \
         "missing is the server having read them"
fi

# bytes_in beside it, because a count that moves while the bytes do not is a
# server delivering empty reads -- and bytes_in read 0 for the life of every
# UDP server until it was fixed, with total_messages climbing beside it.
TOTAL=$((TOTAL+1))
if [ "$((IN_AFTER - IN_BEFORE))" -ge 30 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [the bytes are counted too]: bytes_in went $IN_BEFORE -> $IN_AFTER," \
         "and three ten-byte datagrams are thirty"
fi

# Test: Server still running after receiving datagram
OUT=$("$BIN" ps 2>&1) || daemon_required "ps"
assert_contains "$OUT" "udp_test" "UDP server still running"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
