#!/usr/bin/env bash
# An off-the-shelf cluster client routes for itself, and stops crossing.
#
# ─── WHAT THIS FILE IS ACTUALLY ASSERTING ───────────────────────────────────
#
# A sharded cache costs more CPU per request than the same work with no
# crossings.  Measured on this tree, 8 client processes x 50 connections, three
# interleaved passes per arm, medians, rps per server core: 63,849 on the shared
# port against 87,401 routed, and four independent single-shard caches at
# 87,663.  The crossing is not slow because of how it is implemented — it is on
# the ring, it makes zero blocking syscalls, the daemon relay is out of the
# path — it is slow because it EXISTS.  With N shards a random key is foreign (N-1)/N of the time, and until
# now the client could not choose its shard: every shard joins one port under
# SO_REUSEPORT and the kernel assigns by 4-tuple hash.
#
# So the fix is not a faster crossing, it is a client that never causes one, and
# the only clients worth having are the ones already written.  That is the whole
# reason the slot function is Redis's CRC16 and not ours.
#
# Which makes THROUGHPUT the wrong assertion here, and the count of crossings
# the right one.  A build where the client is not actually routing still answers
# every key correctly — over the mesh — and would pass any read-back test while
# measuring exactly what it measured before.  `mesh_direct` and `mesh_relayed`
# are per shard in `stats`, and for a cluster-aware client both must be about
# zero.  If they are not, the client is not routing and nothing else here means
# anything.
#
# ─── THE CONTROL THAT MAKES THAT NUMBER READABLE ────────────────────────────
#
# Zero crossings is also what a broken cache with no traffic reports.  So the
# same keys are driven through the SHARED port in a second arm, where the
# crossings MUST appear — that is the arm that says the counter works, the
# fallback still exists, and this test could have failed.
#
# ─── THE EXTERNAL ORACLE ────────────────────────────────────────────────────
#
# CLUSTER KEYSLOT is checked against numbers Redis itself publishes (foo=12182,
# bar=5061, hello=866, key1=9189), not against this build.  An agreement
# between our slot function and our own idea of it proves nothing: the entire
# value of the function is that a STRANGER computes the same answer.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate cacheclust

# ── Why these are twenty apart ──────────────────────────────────────────────
#
# A cache with --shards N binds N+1 ports: the shared one, and base+1+i per
# shard.  Adjacent bases collide, and the collision refuses the start.
P4=$((SL_PORT_BASE+1470))       # four shards  (+1471..1474)
P1=$((SL_PORT_BASE+1490))       # one shard, the unsharded control

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    for n in cl4 cl1; do "$BIN" stop "$n" >/dev/null 2>&1 || true; done
    sleep 0.4
    for n in cl4 cl1; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a cluster-aware client routes to the shard that owns the key ==="

if ! command -v redis-cli >/dev/null 2>&1; then
    echo "  SKIP: redis-cli is the off-the-shelf client this whole file is about"
    exit 0
fi

daemon_start "$BIN"

"$BIN" create cache cl4 -p "$P4" --shards 4 --resp -s >/dev/null 2>&1 \
    || { echo "  FATAL: a four-shard cache would not start"; exit 2; }
"$BIN" create cache cl1 -p "$P1" --resp -s >/dev/null 2>&1

ready_resp() {
    local port=$1 i
    for i in $(seq 1 80); do
        redis-cli -p "$port" PING 2>/dev/null | grep -q PONG && return 0
        sleep 0.25
    done
    return 1
}

ready_resp "$P4" || { echo "  FATAL: the four-shard cache never answered"; exit 2; }
ready_resp "$P1" || { echo "  FATAL: the one-shard cache never answered";  exit 2; }

# ── 1: every shard bound its own port ───────────────────────────────────────
#
# Not a formality: the map published below is a FORMULA, so a shard that failed
# to bind would be advertised anyway and every client would spend its retry
# budget on a connection refused.
BOUND=0
for i in 1 2 3 4; do
    ready_resp $((P4+i)) && BOUND=$((BOUND+1))
done
if [ "$BOUND" -eq 4 ]; then
    ok "each of the four shards answers on its own port (base+1..base+4)"
else
    bad "each of the four shards answers on its own port" \
        "$BOUND of 4 answered PING on base+1..base+4"
fi

# ── 2: the slot function is Redis's, checked against Redis's own numbers ────
SLOT_OK=0
for pair in "foo 12182" "bar 5061" "hello 866" "key1 9189"; do
    set -- $pair
    got=$(redis-cli -p "$P4" CLUSTER KEYSLOT "$1" 2>/dev/null)
    [ "$got" = "$2" ] && SLOT_OK=$((SLOT_OK+1)) \
        || echo "        CLUSTER KEYSLOT $1 -> '$got', Redis says $2"
done
[ "$SLOT_OK" -eq 4 ] && ok "CLUSTER KEYSLOT matches the slots Redis publishes (4/4)" \
    || bad "CLUSTER KEYSLOT matches the slots Redis publishes" \
           "$SLOT_OK of 4; a client computing its own slot would route every key wrong"

# The hash tag, which is how a client puts two keys on one shard on purpose.
T1=$(redis-cli -p "$P4" CLUSTER KEYSLOT "{user1000}.following" 2>/dev/null)
T2=$(redis-cli -p "$P4" CLUSTER KEYSLOT "{user1000}.followers" 2>/dev/null)
T3=$(redis-cli -p "$P4" CLUSTER KEYSLOT "user1000" 2>/dev/null)
if [ -n "$T1" ] && [ "$T1" = "$T2" ] && [ "$T1" = "$T3" ]; then
    ok "a {hash tag} puts both keys in the slot of the tag ($T1)"
else
    bad "a {hash tag} puts both keys in the slot of the tag" \
        "got '$T1' '$T2' '$T3'; a client that tagged keys would find them split"
fi

# ── 3: the map covers the keyspace exactly once ─────────────────────────────
#
# Parsed out of CLUSTER SLOTS the way a client reads it: start, end, host, port.
MAP=$(redis-cli -p "$P4" CLUSTER SLOTS 2>/dev/null)
# redis-cli writing to a pipe emits one bare token per line -- no "(integer)"
# markers, no indices -- so the reply reads as: start, end, host, port, id, for
# each range in turn.  Parsed as a token list rather than as redis-cli's
# interactive rendering, which is what the first version of this test got wrong.
TOKENS=$(printf '%s\n' "$MAP" | sed 's/^ *//; s/ *$//' | grep -v '^$')
PORTS_IN_MAP=0
for i in 1 2 3 4; do
    printf '%s\n' "$TOKENS" | grep -qx "$((P4+i))" && PORTS_IN_MAP=$((PORTS_IN_MAP+1))
done
HAS_ZERO=$(printf '%s\n' "$TOKENS" | grep -cx 0 || true)
HAS_LAST=$(printf '%s\n' "$TOKENS" | grep -cx 16383 || true)
if [ "$HAS_ZERO" -ge 1 ] && [ "$PORTS_IN_MAP" -eq 4 ]; then
    ok "CLUSTER SLOTS publishes a range from slot 0 and all four shard ports"
else
    bad "CLUSTER SLOTS publishes a range from slot 0 and all four shard ports" \
        "slot 0 present: $HAS_ZERO, ports present: $PORTS_IN_MAP of 4" \
        "$(printf '%s' "$TOKENS" | tr '\n' ' ' | head -c 220)"
fi
if [ "$HAS_LAST" -ge 1 ]; then
    ok "the last slot of the keyspace is claimed by somebody"
else
    bad "the last slot of the keyspace is claimed by somebody" \
        "16383 appears in no range; keys above the last boundary have no owner" \
        "$(printf '%s' "$TOKENS" | tr '\n' ' ' | head -c 220)"
fi

# ── 4: CLUSTER INFO tells a client whether to bother ────────────────────────
INFO4=$(redis-cli -p "$P4" CLUSTER INFO 2>/dev/null)
INFO1=$(redis-cli -p "$P1" CLUSTER INFO 2>/dev/null)
if printf '%s' "$INFO4" | grep -q 'cluster_enabled:1' \
   && printf '%s' "$INFO4" | grep -q 'cluster_state:ok'; then
    ok "a sharded cache reports cluster_enabled:1 and cluster_state:ok"
else
    bad "a sharded cache reports cluster_enabled:1" "$(printf '%s' "$INFO4" | tr '\n' '|' | head -c 200)"
fi
if printf '%s' "$INFO1" | grep -q 'cluster_enabled:0'; then
    ok "an unsharded cache reports cluster_enabled:0 rather than a map of one"
else
    bad "an unsharded cache reports cluster_enabled:0" \
        "it answers CLUSTER, which is right, but must not invite a client to shard"
fi

# ── 5: four distinct node ids, one 'myself' per node ────────────────────────
IDS=$(for i in 1 2 3 4; do redis-cli -p $((P4+i)) CLUSTER MYID 2>/dev/null; done)
UNIQ=$(printf '%s\n' "$IDS" | sort -u | grep -c . || true)
LEN=$(printf '%s\n' "$IDS" | head -1 | tr -d '\n' | wc -c)
if [ "$UNIQ" -eq 4 ] && [ "$LEN" -eq 40 ]; then
    ok "four shards publish four distinct 40-character node ids"
else
    bad "four shards publish four distinct 40-character node ids" \
        "$UNIQ distinct, first id $LEN characters" \
        "a repeated id makes a client believe two nodes are one"
fi
NODES=$(redis-cli -p $((P4+1)) CLUSTER NODES 2>/dev/null)
NLINES=$(printf '%s\n' "$NODES" | grep -c 'connected' || true)
NMY=$(printf '%s\n' "$NODES" | grep -c 'myself' || true)
if [ "$NLINES" -eq 4 ] && [ "$NMY" -eq 1 ]; then
    ok "CLUSTER NODES lists four nodes with exactly one marked myself"
else
    bad "CLUSTER NODES lists four nodes with exactly one marked myself" \
        "$NLINES lines, $NMY marked myself"
fi

# ── 6: the wrong shard says MOVED, and names the right port ─────────────────
#
# `foo` is slot 12182, which at four shards is 12182*4/16384 = shard 2, so its
# owner is base+3.  Asked of base+1 the answer must be a redirect and NOT the
# value: a crossing here would be correct and would defeat the entire change.
SLOT_FOO=12182
OWNER=$(( SLOT_FOO * 4 / 16384 ))
OWNER_PORT=$(( P4 + 1 + OWNER ))
WRONG_PORT=$(( P4 + 1 + ((OWNER + 1) % 4) ))
redis-cli -p "$OWNER_PORT" SET foo clusterval >/dev/null 2>&1
MOVED=$(redis-cli -p "$WRONG_PORT" GET foo 2>&1)
if printf '%s' "$MOVED" | grep -q "MOVED $SLOT_FOO" \
   && printf '%s' "$MOVED" | grep -q ":$OWNER_PORT"; then
    ok "the wrong shard answers MOVED $SLOT_FOO and names port $OWNER_PORT"
else
    bad "the wrong shard answers MOVED and names the owner's port" \
        "got '$MOVED' from port $WRONG_PORT; expected MOVED $SLOT_FOO ...:$OWNER_PORT"
fi

# And the owner answers it, which is what says the redirect pointed somewhere real.
VAL=$(redis-cli -p "$OWNER_PORT" GET foo 2>/dev/null)
[ "$VAL" = "clusterval" ] && ok "the shard the redirect names holds the key" \
    || bad "the shard the redirect names holds the key" "got '$VAL'"

# The shared port keeps working exactly as before: no redirect, the value.
VAL_SHARED=$(redis-cli -p "$P4" GET foo 2>&1)
if [ "$VAL_SHARED" = "clusterval" ]; then
    ok "the shared port still answers the value rather than a redirect"
else
    bad "the shared port still answers the value rather than a redirect" \
        "got '$VAL_SHARED' — a client that never opted in has been broken"
fi

# ── 7: THE ABORT CRITERION — a routing client causes no crossings ───────────
mesh_total() {
    local st; st=$("$BIN" stats cl4 2>&1 || true)
    printf '%s\n' "$st" | awk -F: '
        /^mesh_direct:/  {d+=$2}
        /^mesh_relayed:/ {r+=$2}
        END{print d+r+0}'
}

sleep 2
BEFORE=$(mesh_total)

# `redis-cli -c` is the client: it follows MOVED, reads the map, and thereafter
# sends each key to its owner.  200 keys is enough that all four shards are
# addressed and a client that ignored the map would cross about 150 times.
for i in $(seq 1 200); do
    redis-cli -c -p $((P4+1)) SET "ck$i" "cv$i" >/dev/null 2>&1
done
CMISS=0
for i in $(seq 1 200); do
    [ "$(redis-cli -c -p $((P4+1)) GET "ck$i" 2>/dev/null)" = "cv$i" ] || CMISS=$((CMISS+1))
done
sleep 2
AFTER_CLUSTER=$(mesh_total)
CROSS_CLUSTER=$((AFTER_CLUSTER - BEFORE))

[ "$CMISS" -eq 0 ] && ok "a cluster-aware client reaches every key (200/200)" \
    || bad "a cluster-aware client reaches every key" "$CMISS of 200 missing"

# Now the same keys through the SHARED port, where a crossing is the only way
# an answer can be produced.  This is the arm that says the counter works.
for i in $(seq 1 200); do
    redis-cli -p "$P4" GET "ck$i" >/dev/null 2>&1
done
sleep 2
AFTER_SHARED=$(mesh_total)
CROSS_SHARED=$((AFTER_SHARED - AFTER_CLUSTER))

echo "        crossings: cluster-routed arm $CROSS_CLUSTER, shared-port arm $CROSS_SHARED"

if [ "$CROSS_SHARED" -gt 50 ]; then
    ok "the shared port still crosses ($CROSS_SHARED for 200 reads) — the counter works"
else
    bad "the shared port still crosses" \
        "only $CROSS_SHARED crossings for 200 reads spread over four shards" \
        "with the counter reading near zero on both arms, arm 7 proves nothing"
fi

# The threshold, and why it is not zero: redis-cli -c learns the map from the
# first MOVED, so the handful of commands before each refresh are answered by
# whichever shard it was talking to.  Those are redirects, not crossings — but
# the CLUSTER SLOTS and PING it sends are answered locally too, so the honest
# claim is "an order of magnitude below the shared arm", not "exactly zero".
if [ "$CROSS_CLUSTER" -lt $((CROSS_SHARED / 4)) ]; then
    ok "the routed arm crossed $CROSS_CLUSTER times against $CROSS_SHARED on the shared port"
else
    bad "the routed arm crossed far less than the shared one" \
        "routed $CROSS_CLUSTER, shared $CROSS_SHARED" \
        "the client is not routing, and any throughput measured here is measuring" \
        "the mesh with extra steps"
fi

# ── 8: a plain client still reads what the cluster client wrote ─────────────
PMISS=0
for i in $(seq 1 50); do
    [ "$(redis-cli -p "$P4" GET "ck$i" 2>/dev/null)" = "cv$i" ] || PMISS=$((PMISS+1))
done
[ "$PMISS" -eq 0 ] && ok "a plain client on the shared port reads all of it back (50/50)" \
    || bad "a plain client on the shared port reads it back" "$PMISS of 50 missing"

# ── 9: a multi-key command that spans shards is refused, not bounced ────────
#
# -MOVED here would be a hang and not an error: the shard named would look at
# the same command, find keys that belong HERE, and redirect back.
MK=$(redis-cli -p $((P4+1)) MGET foo bar hello key1 2>&1)
if printf '%s' "$MK" | grep -qi 'CROSSSLOT'; then
    ok "a multi-key command spanning shards is refused with CROSSSLOT"
else
    bad "a multi-key command spanning shards is refused with CROSSSLOT" \
        "got '$(printf '%s' "$MK" | tr '\n' '|' | head -c 120)'"
fi
# And the same command on the shared port is still served across the mesh.
MK_SHARED=$(redis-cli -p "$P4" MGET foo ck1 ck2 2>&1)
if printf '%s' "$MK_SHARED" | grep -q 'clusterval'; then
    ok "the shared port still answers the same multi-key command over the mesh"
else
    bad "the shared port still answers the same multi-key command" \
        "got '$(printf '%s' "$MK_SHARED" | tr '\n' '|' | head -c 120)'"
fi

# ── 10: SCAN on a shard port ends ───────────────────────────────────────────
#
# The runtime-wide cursor walks shard 0, then shard 1, and so on.  Handed to a
# client talking to ONE node that cursor never terminates: the "on to the next
# shard" value is served here, from the start, forever.
SC_OUT=$(mktemp)
timeout 20 redis-cli -p $((P4+2)) --scan --pattern 'ck*' >"$SC_OUT" 2>/dev/null
SC_RC=$?
SC=$(grep -c . "$SC_OUT" || true)
rm -f "$SC_OUT"
if [ "$SC_RC" -eq 0 ] && [ "$SC" -gt 0 ]; then
    ok "SCAN on a shard port terminates and returns that shard's keys ($SC)"
else
    bad "SCAN on a shard port terminates" \
        "exit $SC_RC after $SC keys; a non-terminating cursor is a hung client"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
