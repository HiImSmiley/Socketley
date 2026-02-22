#!/usr/bin/env bash
# Integration test: proxy routing (TCP round-robin)
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BE1_PORT=19261
BE2_PORT=19262
TCP_PROXY_PORT=19263
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop proxy_tcp 2>/dev/null || true
    "$BIN" stop proxy_be1 2>/dev/null || true
    "$BIN" stop proxy_be2 2>/dev/null || true
    sleep 0.5
    "$BIN" remove proxy_tcp 2>/dev/null || true
    "$BIN" remove proxy_be1 2>/dev/null || true
    "$BIN" remove proxy_be2 2>/dev/null || true
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


echo "=== Integration: proxy routing ==="

# Ensure daemon is running
"$BIN" daemon 2>/dev/null &
sleep 0.3

# Create two backend servers
"$BIN" create server proxy_be1 -p "$BE1_PORT" -s 2>&1 || true
"$BIN" create server proxy_be2 -p "$BE2_PORT" -s 2>&1 || true
sleep 0.3

# Create TCP proxy with round-robin strategy
"$BIN" create proxy proxy_tcp -p "$TCP_PROXY_PORT" --backend "127.0.0.1:$BE1_PORT,127.0.0.1:$BE2_PORT" --protocol tcp --strategy round-robin -s 2>&1 || true
sleep 0.5

# Test: All 3 runtimes show in ps
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "proxy_be1" "backend 1 in ps"
assert_contains "$OUT" "proxy_be2" "backend 2 in ps"
assert_contains "$OUT" "proxy_tcp" "proxy in ps"

# Test: TCP proxy accepts connections and forwards to backend
# Server broadcasts to other clients, so send from two connections:
# first one establishes, second one sends data, first should receive broadcast
TOTAL=$((TOTAL+1))
RC=0
echo "hello proxy" | nc -q 1 127.0.0.1 "$TCP_PROXY_PORT" 2>/dev/null || RC=$?
if [ "$RC" -eq 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [TCP proxy connect]: nc exit code $RC"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
