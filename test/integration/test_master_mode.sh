#!/usr/bin/env bash
# Integration test: server master mode authentication
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate mastermode
PORT=$((SL_PORT_BASE+210))
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop master_test 2>/dev/null || true
    sleep 0.5
    "$BIN" remove master_test 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

assert_eq() {
    TOTAL=$((TOTAL+1))
    local got="$1" expected="$2" label="$3"
    if [ "$got" = "$expected" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: got '$got', expected '$expected'"
    fi
}

assert_contains() {
    TOTAL=$((TOTAL+1))
    if grep -q "$2" <<<"$1"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$2]: not found in output"
    fi
}

# `|| true` on the pipeline: a refused create leaves nothing on $PORT, nc exits
# non-zero, `pipefail` promotes it, and both `RESULT=$(send_cmd …)` below are
# simple commands whose status is exactly that — so the file ended at the first
# password check and never reported either of them.  An empty answer is not
# "master: ok", and assert_eq is what says so.
send_cmd() {
    echo "$1" | nc -q 1 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r' || true
}

echo "=== Integration: master mode ==="

# Ensure daemon is running
daemon_start "$BIN"

create_ok "master-mode server created" "$BIN" create server master_test -p "$PORT" \
    --mode master --master-pw secret123 -s
sleep 0.3

# Test: Correct password grants master
RESULT=$(send_cmd 'master secret123')
assert_eq "$RESULT" "master: ok" "correct password"

# Test: Wrong password is denied
RESULT=$(send_cmd 'master wrongpw')
assert_eq "$RESULT" "master: denied" "wrong password"

# Test: Server is still running after auth attempts
#
# A lone `OUT=$(cmd)` takes its exit status from the substitution; the guard is
# what keeps a failing `ps` from ending the file before its `Results` line.
OUT=$("$BIN" ps 2>&1) || daemon_required "ps"
assert_contains "$OUT" "master_test" "server still running"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
