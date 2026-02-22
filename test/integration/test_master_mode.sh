#!/usr/bin/env bash
# Integration test: server master mode authentication
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
PORT=19210
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop master_test 2>/dev/null || true
    sleep 0.5
    "$BIN" remove master_test 2>/dev/null || true
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

send_cmd() {
    echo "$1" | nc -q 1 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r'
}

echo "=== Integration: master mode ==="

# Ensure daemon is running
"$BIN" daemon 2>/dev/null &
sleep 0.3

"$BIN" create server master_test -p "$PORT" --mode master --master-pw secret123 -s 2>&1 || true
sleep 0.3

# Test: Correct password grants master
RESULT=$(send_cmd 'master secret123')
assert_eq "$RESULT" "master: ok" "correct password"

# Test: Wrong password is denied
RESULT=$(send_cmd 'master wrongpw')
assert_eq "$RESULT" "master: denied" "wrong password"

# Test: Server is still running after auth attempts
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "master_test" "server still running"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
