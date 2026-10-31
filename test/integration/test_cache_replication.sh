#!/usr/bin/env bash
# The initial full sync writes the leader's whole dataset in one go, so the
# dataset here is sized past a default send buffer and a sender that gives up
# on the first short write cannot pass by accident -- a truncation both sides
# read as being in sync.
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

# Attach the follower, whose setup sends "replicate" and makes the leader dump
# everything it has.
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

# One assertion per command family, each a command the follower's six-case
# switch had no arm for, because everything else fell into `default: break` and
# left both sides believing they were in sync.
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

# The follower has to learn that a key expires and not just what it holds,
# because a key the leader has expired and the follower has not is the same
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

# Sent in RESP because the text protocol has no SET options at all, so a text
# `set k v ex 100` stores the option words on the leader too and a follower
# agreeing with it has nothing to find.
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

# A cache never given --replicate hands the setter an empty string through
# every import and edit, and reading that as "this cache follows somebody" made
# an unrelated eviction-policy edit a permanent demotion.
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

# The oracle is asking it to serve a REPLICATE, which a cache quietly made a
# follower refuses and can never be a leader again.
assert_eq "$(send_to "$PLAIN_PORT" 'replicate')" "ok" "an edited plain cache still accepts REPLICATE"

# ─── THE FULL SYNC CARRIES MILLISECONDS ──────────────────────────────────────
# Asserted on the emitted text rather than on the follower's TTL, because a
# follower applies the dump a moment after it was built and a comparison cannot
# tell truncation from transmission delay.
send_to "$LEADER_PORT" 'set dumpkey dumpvalue' >/dev/null
send_to "$LEADER_PORT" 'pexpire dumpkey 30500' >/dev/null
sleep 0.3
# `|| true` is load-bearing: a replication link never closes so timeout exits
# 124, and under pipefail a lone VAR=$(...) would end this file here with no
# assertions and exit 0.
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

# An unknown option matched no case and fell through `default: break` reporting
# success, so a caller who wrote EXX instead of EX got a key with no expiry and
# an "+OK".
RESP_ERR=$(printf '*4\r\n$3\r\nSET\r\n$6\r\noptbad\r\n$2\r\nvv\r\n$3\r\nFOO\r\n' \
    | timeout 3 nc -q 1 127.0.0.1 "$LEADER_PORT" 2>/dev/null | tr -d '\r' || true)
TOTAL=$((TOTAL+1))
if grep -qi "err" <<<"$RESP_ERR"; then PASS=$((PASS+1))
else FAIL=$((FAIL+1)); echo "  FAIL [an unknown SET option is refused]: got '$RESP_ERR'"; fi

assert_eq "$(send_to "$LEADER_PORT" 'get optbad')" "nil" \
          "the refused SET stored nothing"

# ─── A value containing a newline ────────────────────────────────────────────
# Written over RESP because the text protocol cannot express a value with a
# line break at all -- there it is two commands rather than a truncated write,
# so asserting on it would measure the wrong layer.
printf '*3\r\n$3\r\nSET\r\n$2\r\nnk\r\n$5\r\naa\nbb\r\n' \
    | timeout 3 nc -q 1 127.0.0.1 "$LEADER_PORT" >/dev/null 2>&1 || true
sleep 0.6

# Both sides read over RESP as well, because a text `get` answers with a line
# and cannot show what came after the newline -- the first version compared
# text reads and read two truncations as agreement.
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

# Equality alone passes when both sides lost the value, so the leader has to be
# holding the whole five bytes.
TOTAL=$((TOTAL+1))
if grep -q 'a a \\n b b' <<<"$L_RAW"; then PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [the leader holds the whole value]: ${L_RAW:-<nothing>}"
    echo "        without this the comparison above passes on two empty answers."
fi

# A second follower attaches with the value already in the dataset, because
# live writes and the initial dump are separate code and the assertion above
# cannot see the dump half at all.
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

# The follower's text interpreter takes `del`'s whole remainder as one key, so
# a multi-key delete deleted a key literally named "p1 p2" -- asserted on the
# follower's value rather than on a count, because the leader was always right
# and a count cannot tell which key survived.
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

# ─── A leader that goes away and comes back ─────────────────────────────────
#
# connect_to_master() ran once, at start, and the comment at the drop site
# promised "a fresh one" that nothing ever asked for.  So a follower whose
# leader restarted sat there holding whatever it had at the moment the link
# broke -- not stale for a second, stale until somebody restarted the follower
# too -- and said nothing about it.
# The dump is a list of `set` and `rpush` commands with nothing in front of
# them, so a full sync into a follower that still holds data merges rather than
# replacing: a key the leader dropped while the link was down survives on the
# follower, and a list it already had is appended to a second time.  Seeded
# before the link breaks, because a follower holding data of its own when the
# dump arrives is the only shape that can tell the two apart.
send_to "$LEADER_PORT" 'set ghostkey shouldvanish' >/dev/null
send_to "$LEADER_PORT" 'rpush ghostlist a' >/dev/null
send_to "$LEADER_PORT" 'rpush ghostlist b' >/dev/null
SEEDED=""
for _ in $(seq 1 10); do
    [ "$(send_to "$FOLLOWER_PORT" 'get ghostkey')" = "shouldvanish" ] && { SEEDED=yes; break; }
    sleep 0.5
done
assert_eq "$SEEDED" "yes" "the follower holds data of its own before the link breaks"
assert_eq "$(send_to "$FOLLOWER_PORT" 'llen ghostlist')" "2" \
    "and holds the list at its leader's length"

"$BIN" stop replleader >/dev/null 2>&1 || true
sleep 1.2
"$BIN" start replleader >/dev/null 2>&1 || true

# The leader has to actually be back, or the poll below would be measuring a
# failed restart and reporting it as a failed reconnect.  Probed with the write
# it needs anyway, and not with `ping`: that is a RESP command and this is the
# line protocol, which answers "failed: unknown command" to it.
LEADER_BACK=""
for _ in $(seq 1 10); do
    send_to "$LEADER_PORT" 'set afterrestart backagain' >/dev/null 2>&1
    [ "$(send_to "$LEADER_PORT" 'get afterrestart')" = "backagain" ] && { LEADER_BACK=yes; break; }
    sleep 0.5
done
assert_eq "$LEADER_BACK" "yes" "the leader came back on its own port"

# The premise the two assertions at the end rest on, asserted rather than
# assumed: a leader that came back carrying its old dataset would make a merge
# and a replacement look identical.
assert_eq "$(send_to "$LEADER_PORT" 'exists ghostkey')" "0" \
    "the restarted leader does not carry the dataset it had before"
send_to "$LEADER_PORT" 'rpush ghostlist a' >/dev/null
send_to "$LEADER_PORT" 'rpush ghostlist b' >/dev/null

# The backoff is 1, 2, 4, 8, 16 seconds, so the reconnect lands on one of the
# early attempts.  Polled rather than slept through, because the slowest case
# is what the sleep would have to be and the usual case is the second attempt.
GOT=""
for _ in $(seq 1 15); do
    GOT=$(send_to "$FOLLOWER_PORT" 'get afterrestart')
    [ "$GOT" = "backagain" ] && break
    sleep 1
done
assert_eq "$GOT" "backagain" "the follower dialled its leader again after it came back"

# And it says so, which is the half that makes it diagnosable.
assert_eq "$(send_to "$FOLLOWER_PORT" 'info' | grep -c 'master_link_status:up')" "1" \
    "the recovered follower reports its link as standing"

# Whatever order the reconnect fell in -- dump then live pushes, or the pushes
# first -- both answers are the leader's, and both differ from the merge.
assert_eq "$(send_to "$FOLLOWER_PORT" 'exists ghostkey')" "0" \
    "a resync replaced the follower's dataset rather than merging into it"
assert_eq "$(send_to "$FOLLOWER_PORT" 'llen ghostlist')" "2" \
    "and a list the follower already had was not appended to twice"

# A leader that speaks only RESP (--resp) is followed too: the follower's request is a CRLF line its inline reader
# takes, and `replicate` is a command of its RESP dispatch.  Before, the request waited for a CR that never came.
RESP_LEADER=$((SL_PORT_BASE+294)); RESP_FOLLOWER=$((SL_PORT_BASE+295))
"$BIN" create cache replrespl -p "$RESP_LEADER" --resp -s >/dev/null 2>&1
sleep 0.5
printf '*3\r\n$3\r\nSET\r\n$5\r\nrkey1\r\n$2\r\nv1\r\n*3\r\n$3\r\nSET\r\n$5\r\nrkey2\r\n$2\r\nv2\r\n' |
    nc -q 1 127.0.0.1 "$RESP_LEADER" >/dev/null 2>&1
"$BIN" create cache replrespf -p "$RESP_FOLLOWER" --replicate "127.0.0.1:$RESP_LEADER" -s >/dev/null 2>&1
for _ in $(seq 1 50); do [ "$(key_count replrespf)" = 2 ] && break; sleep 0.1; done
assert_eq "$(key_count replrespf)" "2" "a follower of a --resp leader gets its dump"
assert_eq "$(send_to "$RESP_FOLLOWER" 'get rkey2')" "v2" "and the values in it"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
