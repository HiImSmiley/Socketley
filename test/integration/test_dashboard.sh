#!/usr/bin/env bash
# Integration test: dashboard command and metrics API
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop dash_svr 2>/dev/null || true
    sleep 0.5
    "$BIN" remove dash_svr 2>/dev/null || true
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

assert_not_empty() {
    TOTAL=$((TOTAL+1))
    if [ -n "$1" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: $2 was empty"
    fi
}

echo "=== Integration: dashboard ==="

# Ensure daemon is running
"$BIN" daemon 2>/dev/null &
sleep 0.3

# Test: dashboard command without metrics (should give info message)
OUT=$("$BIN" dashboard 2>&1) || true
TOTAL=$((TOTAL+1))
# Either shows a URL or says not configured — both are valid
if echo "$OUT" | grep -qE "Dashboard:|not configured|not enabled|metrics"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: unexpected dashboard output: $OUT"
fi

# Create a runtime to test stats endpoints later
"$BIN" create server dash_svr -p 19390 -s 2>&1 || true
sleep 0.3

# Test: runtime is visible
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "dash_svr"

# Test: stats command works
OUT=$("$BIN" stats dash_svr 2>&1)
assert_contains "$OUT" "connections:"
assert_contains "$OUT" "total_connections:"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
