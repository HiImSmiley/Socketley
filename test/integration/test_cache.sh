#!/usr/bin/env bash
# Integration test: cache commands via TCP
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
daemon_isolate cache
PORT=19150
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop testcache 2>/dev/null || true
    sleep 0.5
    "$BIN" remove testcache 2>/dev/null || true
    rm -f /tmp/test-cache-$$.bin
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

# The `|| true` belongs to this pipeline, not to any caller's assignment.
#
# When the create was refused nothing is listening on $PORT, nc exits non-zero,
# and `pipefail` makes that the pipeline's status.  Callers that write
# `assert_eq "$(send_cmd …)" …` are unaffected — a command substitution in an
# argument does not decide the command's status — but the two that write
# `TTL=$(send_cmd …)` are a simple command whose status *is* this one, and under
# `set -e` the file ended there: no TTL assertions, no SIZE assertion, no
# `Results` line, and an exit status of 1 that came from nc rather than from the
# failure count.  An empty answer is the right result to hand back; the assert
# below is what reports it, and it needs the file to still be running.
send_cmd() {
    echo "$1" | nc -q 1 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r' || true
}

echo "=== Integration: cache commands ==="

# Ensure daemon is running
daemon_start "$BIN"

create_ok "cache created" "$BIN" create cache testcache -p "$PORT" \
    --persistent /tmp/test-cache-$$.bin -s
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
