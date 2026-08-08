#!/usr/bin/env bash
# Integration test: rate limiting and max connections
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate ratelimit
PORT=$((SL_PORT_BASE+230))
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    # Kill any lingering nc processes from this test
    kill $NC_PID1 $NC_PID2 $NC_PID3 $NC_PID4 2>/dev/null || true
    "$BIN" stop rl_test 2>/dev/null || true
    sleep 0.5
    "$BIN" remove rl_test 2>/dev/null || true
    daemon_stop
}
NC_PID1=""; NC_PID2=""; NC_PID3=""; NC_PID4=""
trap cleanup EXIT

assert_contains() {
    TOTAL=$((TOTAL+1))
    if grep -q "$2" <<<"$1"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$2]: not found in output"
    fi
}

echo "=== Integration: rate limit & max connections ==="

# Ensure daemon is running
daemon_start "$BIN"

create_ok "server created" "$BIN" create server rl_test -p "$PORT" \
    --rate-limit 2 --max-connections 3 -s
sleep 0.3

# Test: Server shows in ps
#
# A lone `OUT=$(cmd)` takes its exit status from the substitution, so a failing
# CLI command used to end this file at the assignment with no `Results` line.
# daemon_required carries on when the daemon is still serving — the assertion
# below is what reports a command that failed on its own merits — and stops,
# with counts, when it is not.  See lib_daemon.sh.
OUT=$("$BIN" ps 2>&1) || daemon_required "ps"
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
OUT=$("$BIN" stats rl_test 2>&1) || daemon_required "stats rl_test"
assert_contains "$OUT" "total_connections" "stats has total_connections"

# Test: Server is still running
OUT=$("$BIN" ps 2>&1) || daemon_required "ps"
assert_contains "$OUT" "rl_test" "server still running after connections"

# Kill held connections
kill $NC_PID1 $NC_PID2 $NC_PID3 $NC_PID4 2>/dev/null || true
wait $NC_PID1 $NC_PID2 $NC_PID3 $NC_PID4 2>/dev/null || true
NC_PID1=""; NC_PID2=""; NC_PID3=""; NC_PID4=""
sleep 0.3

# Test: Server still healthy after all connections closed
OUT=$("$BIN" ps 2>&1) || daemon_required "ps"
assert_contains "$OUT" "rl_test" "server healthy after cleanup"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
