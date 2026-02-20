#!/usr/bin/env bash
# Integration test: error handling (invalid inputs, duplicates, conflicts)
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
PORT=19290
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop err_svr1 2>/dev/null || true
    "$BIN" remove err_svr1 2>/dev/null || true
    "$BIN" stop err_svr2 2>/dev/null || true
    "$BIN" remove err_svr2 2>/dev/null || true
    "$BIN" stop err_svr3 2>/dev/null || true
    "$BIN" remove err_svr3 2>/dev/null || true
}
trap cleanup EXIT

assert_fail() {
    TOTAL=$((TOTAL+1))
    if [ "$1" -ne 0 ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$2]: expected non-zero exit, got 0"
    fi
}

assert_error_output() {
    TOTAL=$((TOTAL+1))
    if [ -n "$1" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$2]: expected error output, got empty"
    fi
}

echo "=== Integration: error cases ==="

# Ensure daemon is running
"$BIN" daemon 2>/dev/null &
sleep 0.3

# Test: Create server with invalid port (99999)
OUT=$("$BIN" create server err_badport -p 99999 2>&1 || true)
RC=$?
# Either non-zero exit or error in output
TOTAL=$((TOTAL+1))
if [ "$RC" -ne 0 ] || echo "$OUT" | grep -qi "error\|invalid\|fail"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [invalid port]: expected error, got rc=$RC output='$OUT'"
fi
"$BIN" remove err_badport 2>/dev/null || true

# Test: Duplicate name
"$BIN" create server err_svr1 -p "$PORT" 2>&1 || true
sleep 0.3
OUT=$("$BIN" create server err_svr1 -p $((PORT+1)) 2>&1 || true)
RC=$?
TOTAL=$((TOTAL+1))
if [ "$RC" -ne 0 ] || echo "$OUT" | grep -qi "error\|exists\|already\|duplicate"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [duplicate name]: expected error, got rc=$RC output='$OUT'"
fi

# Test: Stop non-existent runtime
OUT=$("$BIN" stop nonexistent_runtime_xyz 2>&1 || true)
RC=$?
TOTAL=$((TOTAL+1))
if [ "$RC" -ne 0 ] || echo "$OUT" | grep -qi "error\|not found\|unknown"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [stop nonexistent]: expected error, got rc=$RC output='$OUT'"
fi

# Test: Remove non-existent runtime
OUT=$("$BIN" remove nonexistent_runtime_xyz 2>&1 || true)
RC=$?
TOTAL=$((TOTAL+1))
if [ "$RC" -ne 0 ] || echo "$OUT" | grep -qi "error\|not found\|unknown"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [remove nonexistent]: expected error, got rc=$RC output='$OUT'"
fi

# Test: Port conflict (create+start two servers on same port)
"$BIN" start err_svr1 2>&1 || true
sleep 0.3
"$BIN" create server err_svr2 -p "$PORT" 2>&1 || true
OUT=$("$BIN" start err_svr2 2>&1 || true)
RC=$?
TOTAL=$((TOTAL+1))
if [ "$RC" -ne 0 ] || echo "$OUT" | grep -qi "error\|fail\|in use\|bind"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [port conflict]: expected error, got rc=$RC output='$OUT'"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
