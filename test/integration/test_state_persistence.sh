#!/usr/bin/env bash
# Integration test: state persistence (create, show, remove lifecycle)
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
daemon_isolate persist
PORT=19270
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop persist_test 2>/dev/null || true
    sleep 0.5
    "$BIN" remove persist_test 2>/dev/null || true
    daemon_stop
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

assert_not_contains() {
    TOTAL=$((TOTAL+1))
    if ! echo "$1" | grep -q "$2"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: did not expect '$2' in output"
    fi
}

echo "=== Integration: state persistence ==="

# Ensure daemon is running
daemon_start "$BIN"

# Test: Create server (don't start)
create_ok "server created" "$BIN" create server persist_test -p "$PORT"
sleep 0.3

# Test: ls shows the runtime
OUT=$("$BIN" ls 2>&1)
assert_contains "$OUT" "persist_test" "runtime in ls"

# Test: show returns config with name and port
OUT=$("$BIN" show persist_test 2>&1)
assert_contains "$OUT" "persist_test" "show contains name"
assert_contains "$OUT" "$PORT" "show contains port"

# Test: Remove it
"$BIN" remove persist_test 2>&1 || true
sleep 0.3

# Test: ls no longer shows it
OUT=$("$BIN" ls 2>&1)
assert_not_contains "$OUT" "persist_test" "runtime removed from ls"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
