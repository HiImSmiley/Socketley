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
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate cacherepl
LEADER_PORT=$((SL_PORT_BASE+290))
FOLLOWER_PORT=$((SL_PORT_BASE+291))
PLAIN_PORT=$((SL_PORT_BASE+292))
KEYS=${KEYS:-20000}
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop replfollower2 2>/dev/null || true
    "$BIN" stop replfollower 2>/dev/null || true
    "$BIN" stop replleader   2>/dev/null || true
    "$BIN" stop replplain    2>/dev/null || true
    sleep 0.5
    "$BIN" remove replfollower2 2>/dev/null || true
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

# ─── EVERY MUTATING COMMAND, NOT SIX OF THEM ─────────────────────────────────
#
# The leader replicates every mutating command verbatim.  The follower applied
# six — set, del, lpush, rpush, sadd, hset — and let the rest fall into
# `default: break`.  So an INCR, an EXPIRE, an LPOP, an SREM or an HDEL on the
# leader never reached the follower at all: it kept the old value, both sides
# believed they were in sync, and nothing on either end could tell.
#
# `set` with options was worse than missing.  The leader replicates
# `SET key value EX 10` as the line `set key value ex 10`; the follower split it
# on the first space and stored the VALUE as "value ex 10".  Not a stale value —
# a different one, on a key the leader holds correctly.
#
# One assertion per command family, each one a command the six-case switch had
# no arm for.  The pattern is the same throughout: establish a value on both
# sides, mutate on the leader, read the follower.
seed_and_check() {   # label, seed-command, mutate-command, read-command, expected
    local label=$1 seed=$2 mutate=$3 read=$4 expected=$5
    [ -n "$seed" ] && { send_to "$LEADER_PORT" "$seed" >/dev/null; sleep 0.3; }
    send_to "$LEADER_PORT" "$mutate" >/dev/null
    sleep 0.6
    assert_eq "$(send_to "$FOLLOWER_PORT" "$read")" "$expected" "$label"
}

seed_and_check "incr replicates"        'set ctr 5'          'incr ctr'            'get ctr'        '6'
seed_and_check "decr replicates"        'set ctr2 5'         'decr ctr2'           'get ctr2'       '4'
seed_and_check "incrby replicates"      'set ctr3 5'         'incrby ctr3 10'      'get ctr3'       '15'
seed_and_check "append replicates"      'set app hello'      'append app world'    'get app'        'helloworld'
seed_and_check "getset replicates"      'set gs old'         'getset gs new'       'get gs'         'new'
seed_and_check "setnx replicates"       ''                   'setnx nx firstvalue' 'get nx'         'firstvalue'
seed_and_check "lpop replicates"        'rpush mylist a'     'lpop mylist'         'llen mylist'    '0'
seed_and_check "srem replicates"        'sadd myset m1'      'srem myset m1'       'scard myset'    '0'
seed_and_check "hdel replicates"        'hset myhash f v'    'hdel myhash f'       'hlen myhash'    '0'
seed_and_check "mset replicates"        ''                   'mset ma 1 mb 2'      'get mb'         '2'

# TTL commands: the follower has to learn that a key expires, not just what it
# holds.  A key the leader has expired but the follower has not is the same
# divergence one command later.
send_to "$LEADER_PORT" 'set ttlkey ttlvalue' >/dev/null; sleep 0.3
send_to "$LEADER_PORT" 'expire ttlkey 100'   >/dev/null; sleep 0.6
TTL_ON_FOLLOWER=$(send_to "$FOLLOWER_PORT" 'ttl ttlkey')
TOTAL=$((TOTAL+1))
if [ "$TTL_ON_FOLLOWER" -gt 0 ] 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [expire replicates]: follower reports ttl '$TTL_ON_FOLLOWER', expected a positive number"
fi

# persist is the other half — the follower must also learn that a TTL is gone.
send_to "$LEADER_PORT" 'persist ttlkey' >/dev/null; sleep 0.6
assert_eq "$(send_to "$FOLLOWER_PORT" 'ttl ttlkey')" "-1" "persist replicates"

# ─── SET WITH OPTIONS: the value itself was wrong ────────────────────────────
#
# Not a missing update — a different value on the same key.
#
# It has to be sent in RESP, and that is the whole point.  The TEXT protocol has
# no SET options at all: `set k v ex 100` stores the literal string "v ex 100"
# on the LEADER too, so a follower holding the same string is agreeing with it
# and there is nothing to find.  Written against the text protocol this
# assertion failed for a reason that had nothing to do with replication, which
# is how it was caught.
#
# In RESP the leader applies the options properly — value "rv", a TTL — and then
# replicates by joining the arguments with spaces into a text line.  The
# follower reads that line with the text interpreter, which has no options, and
# stores the option words as part of the value.
resp_set_ex() {   # port key value seconds
    printf '*5\r\n$3\r\nSET\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n$2\r\nEX\r\n$%d\r\n%s\r\n' \
        "${#2}" "$2" "${#3}" "$3" "${#4}" "$4" \
        | nc -q 1 127.0.0.1 "$1" >/dev/null 2>&1
}

resp_set_ex "$LEADER_PORT" optkey optvalue 100
sleep 0.8

# First that the leader did the right thing, or the comparison below is about
# nothing.
assert_eq "$(send_to "$LEADER_PORT" 'get optkey')" "optvalue" \
          "RESP SET with EX stores the bare value on the leader"
LEADER_TTL=$(send_to "$LEADER_PORT" 'ttl optkey')
TOTAL=$((TOTAL+1))
if [ "${LEADER_TTL:-0}" -gt 0 ] 2>/dev/null; then PASS=$((PASS+1))
else FAIL=$((FAIL+1)); echo "  FAIL [RESP SET with EX sets a TTL on the leader]: ttl '$LEADER_TTL'"; fi

# And now the follower, which used to answer 'optvalue EX 100'.
assert_eq "$(send_to "$FOLLOWER_PORT" 'get optkey')" "optvalue" \
          "the follower stores the value, not the option words"

FOLLOWER_TTL=$(send_to "$FOLLOWER_PORT" 'ttl optkey')
TOTAL=$((TOTAL+1))
if [ "${FOLLOWER_TTL:-0}" -gt 0 ] 2>/dev/null; then PASS=$((PASS+1))
else FAIL=$((FAIL+1)); echo "  FAIL [the TTL reaches the follower]: ttl '$FOLLOWER_TTL', expected a positive number"; fi

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

# ─── THE FULL SYNC CARRIES MILLISECONDS ──────────────────────────────────────
#
# dump_commands() emitted `expire key <seconds>`, cast from the remaining
# duration.  A key with 500 ms left became `expire key 0`, which the `> 0` test
# then dropped — so it came back from the dump with NO expiry and lived forever.
# Every key under a second was immortalised by being written down, and anything
# above one lost its fractional part.
#
# Asserted on the emitted text rather than on the follower's TTL, deliberately:
# a follower applies the dump a moment after it was built, so its remaining time
# is lower either way and a comparison cannot tell truncation from transmission
# delay.  The wire is where the answer is.
send_to "$LEADER_PORT" 'set dumpkey dumpvalue' >/dev/null
send_to "$LEADER_PORT" 'pexpire dumpkey 30500' >/dev/null
sleep 0.3
# `|| true` is load-bearing, not decoration.  timeout kills nc at 3 s because a
# replication link never closes, so the pipeline exits 124 — and under
# `set -euo pipefail` a lone VAR=$(...) takes the file's exit status from it.
# Without the guard this file ends here, silently: no assertions, no Results
# line, exit 0.  lib_daemon.sh has the long version of this note.
DUMP=$(printf 'replicate\n' | timeout 3 nc 127.0.0.1 "$LEADER_PORT" 2>/dev/null | tr -d '\r' || true)

TOTAL=$((TOTAL+1))
if grep -qE '^pexpire dumpkey [0-9]+$' <<<"$DUMP"; then PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [the full sync emits a millisecond TTL]"
    echo "        TTL lines in the dump: $(grep -E '^(p?expire) dumpkey' <<<"$DUMP" | tr '\n' ' ')"
fi

# And the seconds form is gone, or both could be present and the assertion above
# would pass on a dump that still truncates.
TOTAL=$((TOTAL+1))
if grep -qE '^expire dumpkey ' <<<"$DUMP"; then
    FAIL=$((FAIL+1))
    echo "  FAIL [the seconds form is no longer emitted]: $(grep -E '^expire dumpkey ' <<<"$DUMP")"
else PASS=$((PASS+1)); fi

# The remainder really survived: 30500 ms cannot be a whole number of seconds.
DUMP_MS=$(grep -oE '^pexpire dumpkey [0-9]+$' <<<"$DUMP" | awk '{print $3}' || true)
TOTAL=$((TOTAL+1))
if [ -n "$DUMP_MS" ] && [ $((DUMP_MS % 1000)) -ne 0 ]; then PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [the sub-second remainder survived]: got '${DUMP_MS:-<none>}' ms"
fi

# ─── RESP SET refuses an option it does not know ─────────────────────────────
#
# `SET k v FOO` matched no case, fell through `default: break` and reported
# success — so a mistyped option silently became a plain SET.  A caller that
# wrote EXX instead of EX got a key with no expiry and an "+OK".
RESP_ERR=$(printf '*4\r\n$3\r\nSET\r\n$6\r\noptbad\r\n$2\r\nvv\r\n$3\r\nFOO\r\n' \
    | timeout 3 nc -q 1 127.0.0.1 "$LEADER_PORT" 2>/dev/null | tr -d '\r' || true)
TOTAL=$((TOTAL+1))
if grep -qi "err" <<<"$RESP_ERR"; then PASS=$((PASS+1))
else FAIL=$((FAIL+1)); echo "  FAIL [an unknown SET option is refused]: got '$RESP_ERR'"; fi

assert_eq "$(send_to "$LEADER_PORT" 'get optbad')" "nil" \
          "the refused SET stored nothing"

# ─── A value containing a newline ────────────────────────────────────────────
#
# The replication link was one command per line and a cache value is arbitrary
# bytes, so a value with a line break ended at the break on the follower and the
# remainder was interpreted as a command.  Measured on the parent commit:
#
#     leader    get nk  ->  a<LF>b
#     follower  get nk  ->  a
#
# Written over RESP because the text protocol cannot express the value at all —
# a newline is its command separator too, so a text `set nk a<LF>b` is not a
# truncated write, it is two commands, and asserting on it would measure the
# wrong layer.
printf '*3\r\n$3\r\nSET\r\n$2\r\nnk\r\n$5\r\naa\nbb\r\n' \
    | timeout 3 nc -q 1 127.0.0.1 "$LEADER_PORT" >/dev/null 2>&1 || true
sleep 0.6

# Read both sides over RESP as well: `get` on the text protocol answers with a
# line, so it cannot show what came after the newline either.  This is the
# assertion the first version got wrong — it compared text-protocol reads and
# both sides said "aa", which looked like agreement and was two truncations.
L_RAW=$(printf '*2\r\n$3\r\nGET\r\n$2\r\nnk\r\n' \
    | timeout 3 nc -q 1 127.0.0.1 "$LEADER_PORT" 2>/dev/null | od -An -c | tr -s ' ' || true)
F_RAW=$(printf '*2\r\n$3\r\nGET\r\n$2\r\nnk\r\n' \
    | timeout 3 nc -q 1 127.0.0.1 "$FOLLOWER_PORT" 2>/dev/null | od -An -c | tr -s ' ' || true)

TOTAL=$((TOTAL+1))
if [ -n "$L_RAW" ] && [ "$L_RAW" = "$F_RAW" ]; then PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [a value containing a newline replicates whole]:"
    echo "        leader  : ${L_RAW:-<nothing>}"
    echo "        follower: ${F_RAW:-<nothing>}"
    echo "        the line-based link ended the value at its first newline and"
    echo "        ran the remainder as a command of its own."
fi

# And the halves are not merely equal — equality alone passes when BOTH sides
# lost the value, and a follower that stored nothing would satisfy it.  The
# leader has to be holding the whole five bytes.
TOTAL=$((TOTAL+1))
if grep -q 'a a \\n b b' <<<"$L_RAW"; then PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [the leader holds the whole value]: ${L_RAW:-<nothing>}"
    echo "        without this the comparison above passes on two empty answers."
fi

# ─── The same value through the INITIAL FULL SYNC ────────────────────────────
#
# The two halves of the link are separate code: live writes go through
# replicate_command, and a follower attaching gets dump_commands.  Fixing only
# the live half would leave every value ALREADY stored broken while every value
# written afterwards was fine — and the assertion above cannot tell, because its
# follower was attached before the value was written.
#
# So a second follower attaches now, with `nk` already in the dataset, and has
# to receive it through the dump.
SECOND_PORT=$((SL_PORT_BASE+293))
"$BIN" create cache replfollower2 -p "$SECOND_PORT" \
    --replicate "127.0.0.1:$LEADER_PORT" -s >/dev/null 2>&1 || true
sleep 3

F2_RAW=$(printf '*2\r\n$3\r\nGET\r\n$2\r\nnk\r\n' \
    | timeout 3 nc -q 1 127.0.0.1 "$SECOND_PORT" 2>/dev/null | od -An -c | tr -s ' ' || true)

TOTAL=$((TOTAL+1))
if [ -n "$L_RAW" ] && [ "$L_RAW" = "$F2_RAW" ]; then PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [the full sync carries a value containing a newline]:"
    echo "        leader   : ${L_RAW:-<nothing>}"
    echo "        follower2: ${F2_RAW:-<nothing>}"
    echo "        dump_commands writes one command per line, so a stored value"
    echo "        with a newline truncates for every follower that attaches."
fi

# The control: this follower really did sync, rather than being empty and
# matching an empty leader read by accident.
TOTAL=$((TOTAL+1))
F2_KEYS=$(key_count replfollower2)
if [ "${F2_KEYS:-0}" -ge "$KEYS" ]; then PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [the second follower completed its full sync]: holds ${F2_KEYS:-<none>} keys, expected at least $KEYS"
fi

# ─── A MULTI-KEY DELETE HAS TO REACH THE FOLLOWER ───────────────────────────
#
# repl() joins a RESP command's arguments with spaces and the follower reads the
# result with the TEXT interpreter — whose `del` takes the WHOLE remainder as one
# key.  So `DEL p1 p2` travelled as `del p1 p2`, the follower deleted a key
# literally named "p1 p2", and p1 and p2 stayed where they were.  Measured
# before the fix, on these two unsharded caches:
#
#     leader   after DEL p1 p2 -> nil nil
#     follower after DEL p1 p2 -> q1 q2
#
# The two diverge and nothing reports it — the follower is up, the link is
# healthy, and the data is simply different.  This is the same trap the note on
# repl_set_effect describes for SET's options, which was found there and missed
# here.
#
# The assertion is on the FOLLOWER's value, not on the leader's and not on a
# count: the leader was always right, and a key count cannot tell a delete that
# did not replicate from one that did — both leave the follower with a key more
# than it should have only if you know which key.
if command -v redis-cli >/dev/null 2>&1; then
    redis-cli -p "$LEADER_PORT" SET mkd1 mv1 >/dev/null 2>&1
    redis-cli -p "$LEADER_PORT" SET mkd2 mv2 >/dev/null 2>&1
    sleep 1.5
    assert_eq "$(send_to "$FOLLOWER_PORT" 'get mkd1')" "mv1" \
        "the follower has the key before the multi-key delete"

    redis-cli -p "$LEADER_PORT" DEL mkd1 mkd2 >/dev/null 2>&1
    sleep 1.5
    assert_eq "$(send_to "$LEADER_PORT"   'get mkd1')" "nil" \
        "a multi-key DEL removed the first key on the leader"
    assert_eq "$(send_to "$FOLLOWER_PORT" 'get mkd1')" "nil" \
        "a multi-key DEL reached the follower (first key)"
    assert_eq "$(send_to "$FOLLOWER_PORT" 'get mkd2')" "nil" \
        "a multi-key DEL reached the follower (second key)"

    # And the other multi-key write, which was correct already and must stay so:
    # a regression here would mean the per-pair replication dropped a pair.
    redis-cli -p "$LEADER_PORT" MSET mks1 sv1 mks2 sv2 >/dev/null 2>&1
    sleep 1.5
    assert_eq "$(send_to "$FOLLOWER_PORT" 'get mks1')" "sv1" \
        "a RESP MSET reached the follower (first pair)"
    assert_eq "$(send_to "$FOLLOWER_PORT" 'get mks2')" "sv2" \
        "a RESP MSET reached the follower (second pair)"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
