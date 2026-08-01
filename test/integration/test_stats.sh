#!/usr/bin/env bash
# Integration test: stats command
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
daemon_isolate stats
PORT=19200
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop statsvr 2>/dev/null || true
    "$BIN" remove statsvr 2>/dev/null || true
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

echo "=== Integration: stats command ==="

# Ensure daemon is running
daemon_start "$BIN"

create_ok "server created" "$BIN" create server statsvr -p "$PORT" -s
sleep 0.3

# Generate some connections
echo "hello" | nc -q 1 127.0.0.1 "$PORT" 2>/dev/null || true
sleep 0.2

# `stats` on a runtime a refused create never built exits non-zero, and a lone
# `OUT=$(cmd)` takes its status from the substitution — so this one line was the
# whole file's ending, with none of the four assertions below and no `Results`.
# daemon_required carries on while the daemon is serving, because the assertions
# below are what report a missing runtime, and stops with counts when it is not.
OUT=$("$BIN" stats statsvr 2>&1) || daemon_required "stats statsvr"
assert_contains "$OUT" "total_connections"
assert_contains "$OUT" "total_messages"
assert_contains "$OUT" "bytes_in"
assert_contains "$OUT" "bytes_out"
assert_contains "$OUT" "type:server"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
