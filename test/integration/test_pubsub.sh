#!/usr/bin/env bash
# Integration test: cache pub/sub
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate pubsub
PORT=$((SL_PORT_BASE+300))
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    kill "$SUB_PID" 2>/dev/null || true
    "$BIN" stop pubcache 2>/dev/null || true
    "$BIN" remove pubcache 2>/dev/null || true
    rm -f /tmp/sub-output-$$.txt
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

# `|| true` on the pipeline: a refused create leaves nothing on $PORT, nc exits
# non-zero, `pipefail` promotes it, and `RESULT=$(send_cmd …)` below is a simple
# command whose status is exactly that — so the file used to end at the publish
# with no `Results` line and the subscriber check never ran at all.  The empty
# answer is the finding; assert_eq is what reports it.
send_cmd() {
    echo "$1" | nc -q 1 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r' || true
}

echo "=== Integration: pub/sub ==="

# Ensure daemon is running
daemon_start "$BIN"

create_ok "cache created" "$BIN" create cache pubcache -p "$PORT" -s
sleep 0.3

# Subscribe in background (keep connection open)
(echo "subscribe news"; sleep 3) | nc -q 4 127.0.0.1 "$PORT" > /tmp/sub-output-$$.txt 2>/dev/null &
SUB_PID=$!
sleep 0.3

# Publish
RESULT=$(send_cmd 'publish news hello-world')
assert_eq "$RESULT" "1" "publish returns subscriber count"

sleep 0.5

# Check subscriber received
TOTAL=$((TOTAL+1))
if grep -q "hello-world" /tmp/sub-output-$$.txt 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: subscriber did not receive message"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
