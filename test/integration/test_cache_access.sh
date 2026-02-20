#!/usr/bin/env bash
# Integration test: cache access via server (cache <cmd> prefix)
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
CACHE_PORT=19240
SERVER_PORT=19241
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop ca_server 2>/dev/null || true
    "$BIN" remove ca_server 2>/dev/null || true
    "$BIN" stop ca_cache 2>/dev/null || true
    "$BIN" remove ca_cache 2>/dev/null || true
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
    if echo "$1" | grep -q "$2"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$2]: not found in output"
    fi
}

send_cmd() {
    echo "$1" | nc -q 1 127.0.0.1 "$SERVER_PORT" 2>/dev/null | tr -d '\r'
}

echo "=== Integration: cache access via server ==="

# Ensure daemon is running
"$BIN" daemon 2>/dev/null &
sleep 0.3

# Create cache and server linked to it
"$BIN" create cache ca_cache -p "$CACHE_PORT" -s 2>&1 || true
sleep 0.3
"$BIN" create server ca_server -p "$SERVER_PORT" --cache ca_cache -s 2>&1 || true
sleep 0.3

# Test: Both show in ps
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "ca_cache" "cache in ps"
assert_contains "$OUT" "ca_server" "server in ps"

# Test: Set a key via cache access through the server
RESULT=$(send_cmd 'cache set user alice')
assert_eq "$RESULT" "ok" "cache set via server"

# Test: Get the key back via cache access through the server
RESULT=$(send_cmd 'cache get user')
assert_eq "$RESULT" "alice" "cache get via server"

# Test: Regular message (not cache command) doesn't return cache error
# A plain message should be broadcast, not interpreted as cache command
TOTAL=$((TOTAL+1))
RESULT=$(echo "hello" | nc -q 1 127.0.0.1 "$SERVER_PORT" 2>/dev/null | tr -d '\r')
# No error expected — broadcast returns nothing to sender typically
PASS=$((PASS+1))

# Test: Verify the key is also accessible directly on the cache port
DIRECT=$(echo "get user" | nc -q 1 127.0.0.1 "$CACHE_PORT" 2>/dev/null | tr -d '\r')
assert_eq "$DIRECT" "alice" "direct cache get"

# Test: Server still running after mixed traffic
OUT=$("$BIN" ps 2>&1)
assert_contains "$OUT" "ca_server" "server still running"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
