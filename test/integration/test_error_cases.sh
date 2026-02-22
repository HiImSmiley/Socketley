#!/usr/bin/env bash
# Integration test: error handling (invalid inputs, duplicates, conflicts)
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
PORT=19290
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop err_svr1 2>/dev/null || true
    "$BIN" stop err_svr2 2>/dev/null || true
    "$BIN" stop err_svr3 2>/dev/null || true
    sleep 0.5
    "$BIN" remove err_svr1 2>/dev/null || true
    "$BIN" remove err_svr2 2>/dev/null || true
    "$BIN" remove err_svr3 2>/dev/null || true
    "$BIN" remove err_badport 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Integration: error cases ==="

# Ensure daemon is running
"$BIN" daemon 2>/dev/null &
sleep 0.3

# Test: Create server with invalid port (99999)
RC=0
OUT=$("$BIN" create server err_badport -p 99999 2>&1) || RC=$?
TOTAL=$((TOTAL+1))
if [ "$RC" -ne 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [invalid port]: expected non-zero exit, got rc=$RC"
fi

# Test: Duplicate name
"$BIN" create server err_svr1 -p "$PORT" 2>&1 || true
sleep 0.3
RC=0
OUT=$("$BIN" create server err_svr1 -p $((PORT+1)) 2>&1) || RC=$?
TOTAL=$((TOTAL+1))
if [ "$RC" -ne 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [duplicate name]: expected non-zero exit, got rc=$RC"
fi

# Test: Stop non-existent runtime
RC=0
OUT=$("$BIN" stop nonexistent_runtime_xyz 2>&1) || RC=$?
TOTAL=$((TOTAL+1))
if [ "$RC" -ne 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [stop nonexistent]: expected non-zero exit, got rc=$RC"
fi

# Test: Remove non-existent runtime
RC=0
OUT=$("$BIN" remove nonexistent_runtime_xyz 2>&1) || RC=$?
TOTAL=$((TOTAL+1))
if [ "$RC" -ne 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [remove nonexistent]: expected non-zero exit, got rc=$RC"
fi

# Test: Create with unknown runtime type
RC=0
OUT=$("$BIN" create foobartype err_svr3 -p $((PORT+2)) 2>&1) || RC=$?
TOTAL=$((TOTAL+1))
if [ "$RC" -ne 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [unknown type]: expected non-zero exit, got rc=$RC"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
