#!/usr/bin/env bash
# Integration test: cache replication.
#
# The initial full sync writes the leader's whole dataset to the follower in one
# go.  Anything larger than the socket send buffer therefore cannot be handed to
# a single non-blocking send, and a sender that gives up on the first short write
# leaves the follower holding a truncated dataset while both sides believe they
# are in sync — the failure is invisible from either end.
#
# The dataset below is deliberately sized past a default send buffer (roughly
# 200 KB on Linux) so a truncating implementation cannot pass by accident.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
LEADER_PORT=19290
FOLLOWER_PORT=19291
KEYS=${KEYS:-20000}
PASS=0; FAIL=0; TOTAL=0
DAEMON_PID=""

cleanup() {
    "$BIN" stop replfollower 2>/dev/null || true
    "$BIN" stop replleader   2>/dev/null || true
    sleep 0.5
    "$BIN" remove replfollower 2>/dev/null || true
    "$BIN" remove replleader   2>/dev/null || true
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
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

send_to() {  # port, command
    echo "$2" | nc -q 1 127.0.0.1 "$1" 2>/dev/null | tr -d '\r'
}

key_count() {  # port -> number of keys, via the runtime's own stats
    "$BIN" stats "$1" 2>/dev/null | grep -oP '^keys:\K[0-9]+' | head -1
}

echo "=== Integration: cache replication ==="

"$BIN" daemon >/dev/null 2>&1 &
DAEMON_PID=$!
sleep 0.5

"$BIN" create cache replleader -p "$LEADER_PORT" -s 2>&1 || true
sleep 0.5

# Populate the leader before any follower exists, so this data can only reach
# the follower through the initial full sync rather than through live streaming.
{
    for i in $(seq 1 "$KEYS"); do
        printf 'set replkey%d valuevaluevalue%d\n' "$i" "$i"
    done
} | nc -q 2 127.0.0.1 "$LEADER_PORT" >/dev/null 2>&1

assert_eq "$(key_count replleader)" "$KEYS" "leader holds all keys"

# Attach the follower. Its setup() connects and sends "replicate", which makes
# the leader dump everything it has.
"$BIN" create cache replfollower -p "$FOLLOWER_PORT" --replicate "127.0.0.1:$LEADER_PORT" -s 2>&1 || true
sleep 3

assert_eq "$(key_count replfollower)" "$KEYS" "follower received the full dump"

# Spot-check the ends of the dataset: a truncated transfer keeps the early keys
# and loses the late ones, so both ends have to be verified.
assert_eq "$(send_to "$FOLLOWER_PORT" 'get replkey1')"        "valuevaluevalue1"       "first key replicated"
assert_eq "$(send_to "$FOLLOWER_PORT" "get replkey$KEYS")"    "valuevaluevalue$KEYS"   "last key replicated"

# Live streaming after the initial sync.
send_to "$LEADER_PORT" 'set livekey livevalue' >/dev/null
sleep 1
assert_eq "$(send_to "$FOLLOWER_PORT" 'get livekey')" "livevalue" "live write replicated"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
