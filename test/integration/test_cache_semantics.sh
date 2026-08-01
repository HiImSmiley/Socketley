#!/usr/bin/env bash
# Integration test: cache behaviour against the Redis contract.
#
# These are semantics a client written against Redis will assume, checked over
# RESP so the comparison is like for like. Each case names the Redis rule it
# encodes, because "differs from Redis" is only a defect where Redis's behaviour
# is the documented one clients rely on.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_daemon.sh"
daemon_isolate cachesem
PORT=19703
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop semcache 2>/dev/null || true
    sleep 0.3
    "$BIN" remove semcache 2>/dev/null || true
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

echo "=== Integration: cache semantics vs the Redis contract ==="

if ! command -v redis-cli >/dev/null 2>&1; then
    echo "  SKIP: redis-cli not available"
    exit 0
fi

daemon_start "$BIN"
"$BIN" create cache semcache -p "$PORT" --resp -s 2>&1 || true
# PING/+PONG, not an accepted connection: a cache accepts before it has
# finished loading and can answer.
ready_resp 127.0.0.1 "$PORT" 20 || true

r() { redis-cli -p "$PORT" "$@" 2>/dev/null; }

# SET discards any existing TTL unless KEEPTTL is given (Redis SET docs).
# Without this, a value written by a later SET inherits the previous deadline
# and is deleted at a time the writer has no reason to expect.
r SET ttlkey v1 >/dev/null
r EXPIRE ttlkey 100 >/dev/null
r SET ttlkey v2 >/dev/null
assert_eq "$(r TTL ttlkey)" "-1" "SET clears an existing TTL"

r SET vanish v1 >/dev/null
r EXPIRE vanish 2 >/dev/null
r SET vanish v2 >/dev/null
sleep 3
assert_eq "$(r GET vanish)" "v2" "value written after EXPIRE survives the old deadline"

# TTL returns -1 when the key exists without an expiry, -2 when it does not
# exist. No other negative value is part of the contract.
r SET plain v >/dev/null
assert_eq "$(r TTL plain)"   "-1" "TTL of a key without expiry is -1"
assert_eq "$(r TTL nosuch)"  "-2" "TTL of a missing key is -2"

# An expired key must be indistinguishable from an absent one.
r SET gone v >/dev/null
r PEXPIRE gone 50 >/dev/null
sleep 1
assert_eq "$(r EXISTS gone)" "0"  "expired key reports EXISTS 0"
assert_eq "$(r TTL gone)"    "-2" "expired key reports TTL -2"
assert_eq "$(r GET gone)"    ""   "expired key reports GET nil"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
