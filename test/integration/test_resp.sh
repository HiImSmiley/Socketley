#!/usr/bin/env bash
# Integration test: RESP2 protocol (Redis wire protocol) on cache
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
PORT=19250
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop resp_test 2>/dev/null || true
    "$BIN" remove resp_test 2>/dev/null || true
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
        echo "  FAIL: expected '$2' in output"
    fi
}

send_resp() {
    printf '%s' "$1" | nc -q 1 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r'
}

echo "=== Integration: RESP2 protocol ==="

# Ensure daemon is running
"$BIN" daemon 2>/dev/null &
sleep 0.3

"$BIN" create cache resp_test -p "$PORT" --resp -s 2>&1 || true
sleep 0.3

# Test: SET via RESP2
RESULT=$(send_resp '*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$5\r\nmyval\r\n')
assert_contains "$RESULT" "+OK" "RESP SET"

# Test: GET via RESP2
RESULT=$(send_resp '*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n')
assert_contains "$RESULT" "myval" "RESP GET"

# Test: DEL via RESP2
RESULT=$(send_resp '*2\r\n$3\r\nDEL\r\n$5\r\nmykey\r\n')
assert_contains "$RESULT" ":1" "RESP DEL"

# Test: GET after DEL returns nil
RESULT=$(send_resp '*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n')
assert_contains "$RESULT" "nil" "RESP GET after DEL"

# Test: PING
RESULT=$(send_resp '*1\r\n$4\r\nPING\r\n')
assert_contains "$RESULT" "+PONG" "RESP PING"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
