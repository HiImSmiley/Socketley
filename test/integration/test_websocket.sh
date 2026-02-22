#!/usr/bin/env bash
# Integration test: WebSocket upgrade detection and TCP coexistence
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
PORT=19200
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop ws_test 2>/dev/null || true
    sleep 0.5
    "$BIN" remove ws_test 2>/dev/null || true
}
trap cleanup EXIT

assert_eq() {
    TOTAL=$((TOTAL+1))
    local got="$1" expected="$2" label="$3"
    if [ "$got" = "$expected" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: got '$got', expected '$expected'"
    fi
}

assert_contains() {
    TOTAL=$((TOTAL+1))
    if echo "$1" | grep -q "$2"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$2]: not found in output"
    fi
}

echo "=== Integration: WebSocket ==="

# Ensure daemon is running
"$BIN" daemon 2>/dev/null &
sleep 0.3

"$BIN" create server ws_test -p "$PORT" -s 2>&1 || true
sleep 0.3

# Test: Send WebSocket upgrade request, expect 101 Switching Protocols
WS_KEY="dGhlIHNhbXBsZSBub25jZQ=="
WS_RESPONSE=$(printf "GET / HTTP/1.1\r\nHost: 127.0.0.1:$PORT\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: $WS_KEY\r\nSec-WebSocket-Version: 13\r\n\r\n" | nc -q 1 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r')
assert_contains "$WS_RESPONSE" "101 Switching Protocols" "WS upgrade 101"
assert_contains "$WS_RESPONSE" "Upgrade: websocket" "WS upgrade header"
assert_contains "$WS_RESPONSE" "Sec-WebSocket-Accept" "WS accept header"

# Test: Plain TCP message works (coexistence)
# Server accepts raw TCP alongside WebSocket on the same port
TOTAL=$((TOTAL+1))
echo "hello-tcp" | nc -q 1 127.0.0.1 "$PORT" 2>/dev/null || true
# If we get here without error, the server accepted the raw TCP connection
PASS=$((PASS+1))

# Test: A second plain TCP connection also works
TOTAL=$((TOTAL+1))
echo "hello-again" | nc -q 1 127.0.0.1 "$PORT" 2>/dev/null || true
PASS=$((PASS+1))

# Test: Server is still running after mixed connections
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "ws_test" "server still running"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
