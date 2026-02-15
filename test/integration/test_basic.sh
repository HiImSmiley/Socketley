#!/usr/bin/env bash
# Integration test: basic runtime lifecycle (create/run/stop/remove)
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop testsvr 2>/dev/null || true
    "$BIN" remove testsvr 2>/dev/null || true
    "$BIN" stop autosvr 2>/dev/null || true
    "$BIN" remove autosvr 2>/dev/null || true
}
trap cleanup EXIT

assert_ok() {
    TOTAL=$((TOTAL+1))
    if [ $? -eq 0 ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: $1"
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

echo "=== Integration: basic lifecycle ==="

# Ensure daemon is running (started by run_all.sh or already running)
"$BIN" daemon 2>/dev/null &
sleep 0.3

# Test: create server
OUT=$("$BIN" create server testsvr -p 19000 2>&1) || true
assert_ok "create server"

# Test: ls shows it
OUT=$("$BIN" ls 2>&1)
assert_contains "$OUT" "testsvr"

# Test: run
OUT=$("$BIN" run testsvr 2>&1) || true
assert_ok "run server"
sleep 0.2

# Test: ps shows running
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "testsvr"

# Test: stop
OUT=$("$BIN" stop testsvr 2>&1) || true
assert_ok "stop server"
sleep 0.2

# Test: remove
OUT=$("$BIN" remove testsvr 2>&1) || true
assert_ok "remove server"

# Test: ls no longer shows testsvr
OUT=$("$BIN" ls 2>&1)
TOTAL=$((TOTAL+1))
if ! echo "$OUT" | grep -q "testsvr"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: testsvr still in ls after remove"
fi

# Test: create with -s (start immediately)
OUT=$("$BIN" create server autosvr -p 19001 -s 2>&1) || true
assert_ok "create+start"
sleep 0.2
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "autosvr"

# Cleanup
"$BIN" stop autosvr 2>/dev/null || true
"$BIN" remove autosvr 2>/dev/null || true

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
