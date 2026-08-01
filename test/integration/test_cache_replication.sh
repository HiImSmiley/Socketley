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
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
daemon_isolate cacherepl
LEADER_PORT=19290
FOLLOWER_PORT=19291
PLAIN_PORT=19292
KEYS=${KEYS:-20000}
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop replfollower 2>/dev/null || true
    "$BIN" stop replleader   2>/dev/null || true
    "$BIN" stop replplain    2>/dev/null || true
    sleep 0.5
    "$BIN" remove replfollower 2>/dev/null || true
    "$BIN" remove replleader   2>/dev/null || true
    "$BIN" remove replplain    2>/dev/null || true
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

send_to() {  # port, command
    echo "$2" | nc -q 1 127.0.0.1 "$1" 2>/dev/null | tr -d '\r'
}

key_count() {  # port -> number of keys, via the runtime's own stats
    "$BIN" stats "$1" 2>/dev/null | grep -oP '^keys:\K[0-9]+' | head -1
}

echo "=== Integration: cache replication ==="

daemon_start "$BIN"

create_ok "leader created" "$BIN" create cache replleader -p "$LEADER_PORT" -s
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
create_ok "follower created" "$BIN" create cache replfollower -p "$FOLLOWER_PORT" \
    --replicate "127.0.0.1:$LEADER_PORT" -s
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

# ─── A cache nobody asked to replicate is not a follower ─────────────────────
#
# Every `import` and every `edit` applies the whole document, and a cache that
# was never given --replicate has no replicate_target field in its document at
# all — so both hand the setter an empty string.  Reading that as "this cache
# follows somebody" turned an unrelated edit into a permanent demotion: the
# cache became a follower of nothing, and from then on it refused REPLICATE with
# "error: this node is a follower", because that check runs before any other.
#
# The edit below is the most innocuous one available.  It changes the eviction
# policy and says nothing whatsoever about replication, which is the point: the
# operator did not ask for a replication change and must not get one.
create_ok "plain cache created" "$BIN" create cache replplain -p "$PLAIN_PORT" -s
sleep 1

repl_role_of() {  # name -> 0 none, 1 leader, 2 follower
    "$BIN" stats "$1" 2>/dev/null | grep -oP '^repl_role:\K[0-9]+' | head -1
}

assert_eq "$(repl_role_of replplain)" "0" "plain cache starts with no replication role"

EDITOR_SCRIPT="$SOCKETLEY_TMPD/edit-eviction.sh"
cat > "$EDITOR_SCRIPT" <<'EDEOF'
#!/usr/bin/env bash
sed -i 's/"eviction": "noeviction"/"eviction": "lru"/' "$1"
EDEOF
chmod +x "$EDITOR_SCRIPT"
EDITOR="$EDITOR_SCRIPT" "$BIN" edit replplain >/dev/null 2>&1 || true
sleep 0.5

assert_eq "$(repl_role_of replplain)" "0" "an edit that says nothing about replication leaves the role alone"

# The oracle: ask it to serve a REPLICATE.  A cache that was quietly made a
# follower answers "error: this node is a follower" here, and can never be a
# leader again.
assert_eq "$(send_to "$PLAIN_PORT" 'replicate')" "ok" "an edited plain cache still accepts REPLICATE"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
