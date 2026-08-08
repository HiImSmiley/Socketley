#!/usr/bin/env bash
# Integration test: dashboard command and metrics API
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate dashboard
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop dash_svr 2>/dev/null || true
    sleep 0.5
    "$BIN" remove dash_svr 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

assert_contains() {
    TOTAL=$((TOTAL+1))
    if grep -q "$2" <<<"$1"; then
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
daemon_start "$BIN"

# Test: dashboard command without metrics (should give info message)
OUT=$("$BIN" dashboard 2>&1) || true
TOTAL=$((TOTAL+1))
# Either shows a URL or says not configured — both are valid
if grep -qE "Dashboard:|not configured|not enabled|metrics" <<<"$OUT"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: unexpected dashboard output: $OUT"
fi

# Create a runtime to test stats endpoints later
create_ok "server created" "$BIN" create server dash_svr -p $((SL_PORT_BASE+390)) -s
sleep 0.3

# Test: runtime is visible
#
# The `|| true` three tests up is right for that one — a dashboard that is not
# configured legitimately exits non-zero and the assertion accepts both answers.
# These two are different: they must not end the file either, but a failure here
# is not expected, so it goes to daemon_required, which carries on when the
# daemon is still serving and stops with counts when it is not.
OUT=$("$BIN" ps 2>&1) || daemon_required "ps"
assert_contains "$OUT" "dash_svr"

# Test: stats command works
OUT=$("$BIN" stats dash_svr 2>&1) || daemon_required "stats dash_svr"
assert_contains "$OUT" "connections:"
assert_contains "$OUT" "total_connections:"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
