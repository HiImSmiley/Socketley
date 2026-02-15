#!/usr/bin/env bash
# Integration test: cache commands via TCP
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
PORT=19100
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop testcache 2>/dev/null || true
    "$BIN" remove testcache 2>/dev/null || true
    rm -f /tmp/test-cache-$$.bin
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

send_cmd() {
    echo "$1" | nc -q 1 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r'
}

echo "=== Integration: cache commands ==="

# Ensure daemon is running
"$BIN" daemon 2>/dev/null &
sleep 0.3

"$BIN" create cache testcache -p "$PORT" --persistent /tmp/test-cache-$$.bin -s 2>&1 || true
sleep 0.3

# String ops
assert_eq "$(send_cmd 'set mykey myval')" "ok" "SET"
assert_eq "$(send_cmd 'get mykey')" "myval" "GET"
assert_eq "$(send_cmd 'exists mykey')" "1" "EXISTS"
assert_eq "$(send_cmd 'del mykey')" "ok" "DEL"
assert_eq "$(send_cmd 'get mykey')" "nil" "GET after DEL"
assert_eq "$(send_cmd 'exists mykey')" "0" "EXISTS after DEL"

# List ops
assert_eq "$(send_cmd 'rpush q task1')" "ok" "RPUSH 1"
assert_eq "$(send_cmd 'rpush q task2')" "ok" "RPUSH 2"
assert_eq "$(send_cmd 'llen q')" "2" "LLEN"
assert_eq "$(send_cmd 'lpop q')" "task1" "LPOP"
assert_eq "$(send_cmd 'rpop q')" "task2" "RPOP"

# Set ops
assert_eq "$(send_cmd 'sadd myset a')" "ok" "SADD a"
assert_eq "$(send_cmd 'sadd myset b')" "ok" "SADD b"
assert_eq "$(send_cmd 'sadd myset a')" "exists" "SADD dup"
assert_eq "$(send_cmd 'sismember myset a')" "1" "SISMEMBER"
assert_eq "$(send_cmd 'scard myset')" "2" "SCARD"

# Hash ops
assert_eq "$(send_cmd 'hset user name alice')" "ok" "HSET"
assert_eq "$(send_cmd 'hget user name')" "alice" "HGET"
assert_eq "$(send_cmd 'hlen user')" "1" "HLEN"

# TTL
assert_eq "$(send_cmd 'set ttlkey val')" "ok" "SET ttlkey"
assert_eq "$(send_cmd 'expire ttlkey 300')" "ok" "EXPIRE"
TTL=$(send_cmd 'ttl ttlkey')
TOTAL=$((TOTAL+1))
if [ "$TTL" -gt 0 ] 2>/dev/null && [ "$TTL" -le 300 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [TTL range]: got '$TTL'"
fi
assert_eq "$(send_cmd 'persist ttlkey')" "ok" "PERSIST"
assert_eq "$(send_cmd 'ttl ttlkey')" "-1" "TTL after PERSIST"

# Type conflict
assert_eq "$(send_cmd 'set myset conflict')" "error: type conflict" "type conflict"

# Size
SIZE=$(send_cmd 'size')
TOTAL=$((TOTAL+1))
if [ "$SIZE" -gt 0 ] 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [SIZE]: got '$SIZE'"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
