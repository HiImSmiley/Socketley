#!/usr/bin/env bash
# Integration test: UDP server and client
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
daemon_isolate udp
PORT=19220
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

# Test: Send a UDP datagram to the server
TOTAL=$((TOTAL+1))
echo "hello-udp" | nc -u -q 1 127.0.0.1 "$PORT" 2>/dev/null || true
# If we get here without error, the send succeeded
PASS=$((PASS+1))

# Test: Server still running after receiving datagram
OUT=$("$BIN" ps 2>&1) || daemon_required "ps"
assert_contains "$OUT" "udp_test" "UDP server still running"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
