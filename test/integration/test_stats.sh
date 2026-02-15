#!/usr/bin/env bash
# Integration test: stats command
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
PORT=19200
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop statsvr 2>/dev/null || true
    "$BIN" remove statsvr 2>/dev/null || true
}
trap cleanup EXIT

assert_contains() {
    TOTAL=$((TOTAL+1))
    if echo "$1" | grep -q "$2"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: expected '$2' in output"
    fi
}

echo "=== Integration: stats command ==="

# Ensure daemon is running
"$BIN" daemon 2>/dev/null &
sleep 0.3

"$BIN" create server statsvr -p "$PORT" -s 2>&1 || true
sleep 0.3

# Generate some connections
echo "hello" | nc -q 1 127.0.0.1 "$PORT" 2>/dev/null || true
sleep 0.2

OUT=$("$BIN" stats statsvr 2>&1)
assert_contains "$OUT" "total_connections"
assert_contains "$OUT" "total_messages"
assert_contains "$OUT" "bytes_in"
assert_contains "$OUT" "bytes_out"
assert_contains "$OUT" "type:server"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
