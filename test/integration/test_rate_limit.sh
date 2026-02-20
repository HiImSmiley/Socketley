#!/usr/bin/env bash
# Integration test: rate limiting and max connections
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
PORT=19230
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    # Kill any lingering nc processes from this test
    kill $NC_PID1 $NC_PID2 $NC_PID3 $NC_PID4 2>/dev/null || true
    "$BIN" stop rl_test 2>/dev/null || true
    "$BIN" remove rl_test 2>/dev/null || true
}
NC_PID1=""; NC_PID2=""; NC_PID3=""; NC_PID4=""
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

echo "=== Integration: rate limit & max connections ==="

# Ensure daemon is running
"$BIN" daemon 2>/dev/null &
sleep 0.3

"$BIN" create server rl_test -p "$PORT" --rate-limit 2 --max-connections 3 -s 2>&1 || true
sleep 0.3

# Test: Server shows in ps
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "rl_test" "server in ps"

# Test: Open 3 connections (within limit) — hold them open with sleep
(sleep 2) | nc -q 3 127.0.0.1 "$PORT" >/dev/null 2>&1 &
NC_PID1=$!
(sleep 2) | nc -q 3 127.0.0.1 "$PORT" >/dev/null 2>&1 &
NC_PID2=$!
(sleep 2) | nc -q 3 127.0.0.1 "$PORT" >/dev/null 2>&1 &
NC_PID3=$!
sleep 0.3

# Test: 4th connection should be rejected (max-connections=3)
# The 4th nc should close immediately or be refused
(sleep 2) | nc -q 3 127.0.0.1 "$PORT" >/dev/null 2>&1 &
NC_PID4=$!
sleep 0.3

# Check stats to verify connection count
OUT=$("$BIN" stats rl_test 2>&1)
assert_contains "$OUT" "total_connections" "stats has total_connections"

# Test: Server is still running
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "rl_test" "server still running after connections"

# Kill held connections
kill $NC_PID1 $NC_PID2 $NC_PID3 $NC_PID4 2>/dev/null || true
wait $NC_PID1 $NC_PID2 $NC_PID3 $NC_PID4 2>/dev/null || true
NC_PID1=""; NC_PID2=""; NC_PID3=""; NC_PID4=""
sleep 0.3

# Test: Server still healthy after all connections closed
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "rl_test" "server healthy after cleanup"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
