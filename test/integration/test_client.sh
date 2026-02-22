#!/usr/bin/env bash
# Integration test: client-server communication
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
SVR_PORT=19280
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop cli_client 2>/dev/null || true
    "$BIN" stop cli_svr 2>/dev/null || true
    sleep 0.5
    "$BIN" remove cli_client 2>/dev/null || true
    "$BIN" remove cli_svr 2>/dev/null || true
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

assert_ok() {
    TOTAL=$((TOTAL+1))
    if [ "$1" -eq 0 ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$2]: exit code $1, expected 0"
    fi
}

echo "=== Integration: client-server ==="

# Ensure daemon is running
"$BIN" daemon 2>/dev/null &
sleep 0.3

# Create and start server
"$BIN" create server cli_svr -p "$SVR_PORT" -s 2>&1 || true
sleep 0.3

# Create and start client connecting to server
"$BIN" create client cli_client -t "127.0.0.1:$SVR_PORT" -s 2>&1 || true
sleep 0.3

# Test: Both show in ps
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "cli_svr" "server in ps"
assert_contains "$OUT" "cli_client" "client in ps"

# Test: Send message from client
"$BIN" send cli_client "hello from client" 2>&1 || true
RC=$?
assert_ok "$RC" "send from client"

# Test: Send message from server (broadcast)
"$BIN" send cli_svr "hello from server" 2>&1 || true
RC=$?
assert_ok "$RC" "send from server"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
