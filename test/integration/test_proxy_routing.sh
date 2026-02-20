#!/usr/bin/env bash
# Integration test: proxy routing (HTTP + TCP, round-robin)
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
PROXY_PORT=19260
BE1_PORT=19261
BE2_PORT=19262
TCP_PROXY_PORT=19263
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop proxy_test 2>/dev/null || true
    "$BIN" remove proxy_test 2>/dev/null || true
    "$BIN" stop proxy_tcp 2>/dev/null || true
    "$BIN" remove proxy_tcp 2>/dev/null || true
    "$BIN" stop proxy_be1 2>/dev/null || true
    "$BIN" remove proxy_be1 2>/dev/null || true
    "$BIN" stop proxy_be2 2>/dev/null || true
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

assert_not_empty() {
    TOTAL=$((TOTAL+1))
    if [ -n "$1" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$2]: output was empty"
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

# Create HTTP proxy with round-robin strategy
"$BIN" create proxy proxy_test -p "$PROXY_PORT" --backend "127.0.0.1:$BE1_PORT,127.0.0.1:$BE2_PORT" --strategy round-robin -s 2>&1 || true
sleep 0.3

# Test: All 3 runtimes show in ps
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "proxy_be1" "backend 1 in ps"
assert_contains "$OUT" "proxy_be2" "backend 2 in ps"
assert_contains "$OUT" "proxy_test" "proxy in ps"

# Test: Send HTTP request through proxy, expect some response (not empty)
RESULT=$(printf 'GET /proxy_test/test HTTP/1.1\r\nHost: localhost\r\n\r\n' | nc -q 1 127.0.0.1 "$PROXY_PORT" 2>/dev/null || true)
assert_not_empty "$RESULT" "HTTP proxy response"

# Create TCP proxy
"$BIN" create proxy proxy_tcp -p "$TCP_PROXY_PORT" --backend "127.0.0.1:$BE1_PORT" --protocol tcp -s 2>&1 || true
sleep 0.3

# Test: TCP proxy shows in ps
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "proxy_tcp" "TCP proxy in ps"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
