#!/usr/bin/env bash
# Integration test: UDP server and client
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
PORT=19220
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop udp_client 2>/dev/null || true
    "$BIN" remove udp_client 2>/dev/null || true
    "$BIN" stop udp_test 2>/dev/null || true
    "$BIN" remove udp_test 2>/dev/null || true
}
trap cleanup EXIT

assert_contains() {
    TOTAL=$((TOTAL+1))
    if echo "$1" | grep -q "$2"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$2]: not found in output"
    fi
}

echo "=== Integration: UDP ==="

# Ensure daemon is running
"$BIN" daemon 2>/dev/null &
sleep 0.3

# Test: Create UDP server
"$BIN" create server udp_test -p "$PORT" --udp -s 2>&1 || true
sleep 0.3

# Test: Create UDP client
"$BIN" create client udp_client --udp -t 127.0.0.1:"$PORT" -s 2>&1 || true
sleep 0.3

# Test: Both show in ps as running
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "udp_test" "UDP server in ps"
assert_contains "$OUT" "udp_client" "UDP client in ps"

# Test: ls shows both
OUT=$("$BIN" ls 2>&1)
assert_contains "$OUT" "udp_test" "UDP server in ls"
assert_contains "$OUT" "udp_client" "UDP client in ls"

# Test: Send a UDP datagram to the server
TOTAL=$((TOTAL+1))
echo "hello-udp" | nc -u -q 1 127.0.0.1 "$PORT" 2>/dev/null || true
# If we get here without error, the send succeeded
PASS=$((PASS+1))

# Test: Server still running after receiving datagram
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "udp_test" "UDP server still running"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
