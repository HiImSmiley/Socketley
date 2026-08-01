#!/usr/bin/env bash
# Integration test: client-server communication
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
daemon_isolate client
SVR_PORT=19280
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop cli_client 2>/dev/null || true
    "$BIN" stop cli_svr 2>/dev/null || true
    sleep 0.5
    "$BIN" remove cli_client 2>/dev/null || true
    "$BIN" remove cli_svr 2>/dev/null || true
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
daemon_start "$BIN"

# Create and start server
create_ok "server created" "$BIN" create server cli_svr -p "$SVR_PORT" -s
sleep 0.3

# Create and start client connecting to server
create_ok "client created" "$BIN" create client cli_client -t "127.0.0.1:$SVR_PORT" -s
sleep 0.3

# Test: Both show in ps
#
# A lone `OUT=$(cmd)` takes its exit status from the substitution, so a failing
# CLI command used to end this file at the assignment with no `Results` line.
# daemon_required carries on when the daemon is still serving — the assertion
# below is what reports it — and stops, with counts, when it is not.
OUT=$("$BIN" ps 2>&1) || daemon_required "ps"
assert_contains "$OUT" "cli_svr" "server in ps"
assert_contains "$OUT" "cli_client" "client in ps"

# Test: Send message from client
#
# `cmd || true; RC=$?` reads the status of `true`, so RC was 0 whatever `send`
# did and both assertions below passed unconditionally.  The status has to be
# captured by the thing that tolerates the failure, not after it.
RC=0
"$BIN" send cli_client "hello from client" >/dev/null 2>&1 || RC=$?
assert_ok "$RC" "send from client"

# Test: Send message from server (broadcast)
RC=0
"$BIN" send cli_svr "hello from server" >/dev/null 2>&1 || RC=$?
assert_ok "$RC" "send from server"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
