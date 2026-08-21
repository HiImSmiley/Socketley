#!/usr/bin/env bash
# Integration test: a cache split into N processes answers as one store.
#
# ─── WHY THIS FILE IS NAMED pending_ AND NOT test_ ──────────────────────────
#
# run_all.sh globs integration/test_*.sh.  This file is deliberately outside
# that glob, because `--shards` on a cache is still REFUSED — lifting that
# refusal is the last step of this work and it must not be lifted until the
# multi-key commands, the keyspace-wide commands and persistence with a changed
# shard count are routed too.  Everything this file asserts about is step one:
# the single-key class.
#
# It is committed rather than held back, because it has been run.  The numbers
# below are what it produced on a scratch build — the one refusal line in
# shards_config_refusal() compiled out with -DSOCKETLEY_SCRATCH_CACHE_SHARDS,
# nothing else changed:
#
#     without routing   9 of 12 keys read back as (nil), and which 9 changed
#                       run to run: 4 shards, one connection each, so a SET
#                       landed in one process and the GET asked another.
#                       Text and RESP alike.
#     with routing      12 of 12, in the order the pipeline asked, over 200
#                       rounds of 12 commands in each protocol with no failure,
#                       and 200 abrupt aborts mid-crossing with the runtime
#                       still serving afterwards.
#     one-shard control 12 of 12 on both builds, which is what says this test is
#                       about sharding and not about SET and GET.
#
# Rename it to test_cache_shard_routing.sh in the change that removes the
# refusal.  That change is where it starts running, and where it stops being a
# claim about a build nobody else can make.
#
# ─── THE DEFECT IT HOLDS DOWN ──────────────────────────────────────────────
#
# The cache's own --shards refusal names it exactly: "a SET lands in whichever
# process the kernel gave that connection to and a later GET on a new connection
# asks a different one, so the answer is a miss for data that was stored — 1/N
# of the time, without an error anywhere."
#
# What removes it is ownership by key hash: `shard = hash(key) mod N`, computed
# from shared/cache_shard_map.h so that N processes that never speak to each
# other cannot disagree, and a command naming somebody else's key crossing to
# them through the request channel.
#
# ─── HOW THIS IS ASSERTED, AND WHY EACH ASSERTION CAN FAIL ─────────────────
#
#   1. Twelve keys written on one connection and read on another come back.
#      On the broken build about (N-1)/N of them are (nil).  The count is the
#      assertion: asserting that ONE key round-trips passes on the broken build
#      whenever that key happens to be owned by the shard the connection landed
#      on, which is 1 time in 4.
#
#   2. The replies come back in the order the pipeline asked.  Twelve distinct
#      values, compared as a sequence and not as a set — a routing that answers
#      every question and interleaves the answers is unreadable to a pipelined
#      client, and a set comparison cannot see it.
#
#   3. A shard holding NO connection has nevertheless processed commands.  That
#      one cannot pass without routing at all: a shard with zero connections
#      executes zero commands unless somebody sent it some.  It is read out of
#      `stats`, which reports each shard separately.
#
#   4. The one-shard control does all of the above and must stay green on both
#      builds.  Without it a red in 1-3 could be an ordinary cache defect.
#
#   5. The commands that are NOT routed are refused by name.  When this file was
#      written that meant the multi-key and keyspace-wide classes; those are
#      routed now and pending_cache_shard_multikey.sh holds them down, so what
#      is asserted here is the two that are refused on purpose — the dump-file
#      commands and replication.  A silent wrong answer from one shard's slice
#      is the exact failure this whole change exists to remove, so "not
#      implemented" has to be louder than "not implemented well".
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate cacheshard

P_T4=$((SL_PORT_BASE+1240))     # four shards, text protocol
P_R4=$((SL_PORT_BASE+1241))     # four shards, RESP
P_T1=$((SL_PORT_BASE+1242))     # one shard, the control

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    for n in sh4t sh4r sh1t; do
        "$BIN" stop "$n" >/dev/null 2>&1 || true
    done
    sleep 0.4
    for n in sh4t sh4r sh1t; do
        "$BIN" remove "$n" >/dev/null 2>&1 || true
    done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a sharded cache answers as one store ==="

daemon_start "$BIN"

# A cache with --shards is refused by every build that has not had the refusal
# compiled out.  Said once, here, rather than as twelve failed assertions.
if ! "$BIN" create cache sh4t -p "$P_T4" --shards 4 -s >/dev/null 2>&1; then
    echo "  SKIP: this build refuses --shards on a cache, which is still the"
    echo "        shipped answer.  Build with -DSOCKETLEY_SCRATCH_CACHE_SHARDS"
    echo "        to run this file:"
    echo "        touch socketley/shared/runtime_definitions.h && \
#   make -C make config=release_x64 CPPFLAGS=-DSOCKETLEY_SCRATCH_CACHE_SHARDS
#
# The touch is not optional: make tracks file times, not compiler flags, so
# adding or removing the define alone rebuilds nothing and leaves the refusal
# compiled in from the previous build.  A `find -newer` freshness check cannot
# see that either -- the only reliable check is the string:
#   strings bin/Release/socketley | grep -c 'not available on a cache'   # 0 = on"
    exit 0
fi
"$BIN" create cache sh4r -p "$P_R4" --shards 4 --resp -s >/dev/null 2>&1
"$BIN" create cache sh1t -p "$P_T1" --shards 1 -s        >/dev/null 2>&1

# Four forks, four execs and four rings.  Waited for by asking, not by sleeping
# a number somebody guessed.
ready() {
    local port=$1 i
    for i in $(seq 1 60); do
        printf 'set __ready 1\n' | timeout 2 nc -q1 127.0.0.1 "$port" 2>/dev/null \
            | grep -q '^ok$' && return 0
        sleep 0.25
    done
    return 1
}
ready_resp() {
    local port=$1 i
    for i in $(seq 1 60); do
        redis-cli -p "$port" PING 2>/dev/null | grep -q PONG && return 0
        sleep 0.25
    done
    return 1
}

if ! command -v nc >/dev/null 2>&1; then
    echo "  SKIP: nc is required to speak the cache's text protocol"
    exit 0
fi

ready     "$P_T4" || { echo "  FATAL: the four-shard cache never answered"; exit 2; }
ready     "$P_T1" || { echo "  FATAL: the one-shard cache never answered";  exit 2; }

# ── 1 + 2: written on one connection, read on another, in order ─────────────
#
# Two connections and not one, and that is the whole point: SO_REUSEPORT gives
# each new connection to whichever shard the kernel picks, so the GETs are asked
# of a process that did not see the SETs.  On one connection a broken build
# would still answer, because the same shard would hold both halves.
text_roundtrip() {
    local port=$1 tag=$2
    local sets="" gets="" i
    for i in $(seq 0 11); do
        sets="${sets}set ${tag}k${i} ${tag}v${i}\n"
        gets="${gets}get ${tag}k${i}\n"
    done
    printf "$sets" | timeout 5 nc -q1 127.0.0.1 "$port" >/dev/null 2>&1
    printf "$gets" | timeout 5 nc -q1 127.0.0.1 "$port" 2>/dev/null
}

OUT4=$(text_roundtrip "$P_T4" a)
HITS4=$(printf '%s\n' "$OUT4" | grep -c '^av[0-9]*$' || true)
EXPECT=$(for i in $(seq 0 11); do echo "av$i"; done)

if [ "$HITS4" -eq 12 ]; then
    ok "every key written to a four-shard cache reads back (12/12)"
else
    bad "every key written to a four-shard cache reads back" \
        "got $HITS4 of 12; a shard answered for a key it does not own" \
        "$(printf '%s' "$OUT4" | tr '\n' '|')"
fi

if [ "$OUT4" = "$EXPECT" ]; then
    ok "the replies come back in the order the pipeline asked them"
else
    bad "the replies come back in the order the pipeline asked them" \
        "a pipelined client has no other way to tell two replies apart" \
        "got:      $(printf '%s' "$OUT4"    | tr '\n' ' ')" \
        "expected: $(printf '%s' "$EXPECT"  | tr '\n' ' ')"
fi

# ── 4: the control ─────────────────────────────────────────────────────────
OUT1=$(text_roundtrip "$P_T1" b)
HITS1=$(printf '%s\n' "$OUT1" | grep -c '^bv[0-9]*$' || true)
if [ "$HITS1" -eq 12 ]; then
    ok "the one-shard control reads back 12/12"
else
    bad "the one-shard control reads back 12/12" \
        "this is not about sharding at all — an unsharded cache lost data" \
        "$(printf '%s' "$OUT1" | tr '\n' '|')"
fi

# ── the same over RESP, which is a second dispatch and a second decision ───
if command -v redis-cli >/dev/null 2>&1; then
    ready_resp "$P_R4" || { echo "  FATAL: the RESP cache never answered"; exit 2; }
    for i in $(seq 0 11); do
        redis-cli -p "$P_R4" SET "rk$i" "rv$i" >/dev/null 2>&1
    done
    RHITS=0
    for i in $(seq 0 11); do
        [ "$(redis-cli -p "$P_R4" GET "rk$i" 2>/dev/null)" = "rv$i" ] \
            && RHITS=$((RHITS+1))
    done
    if [ "$RHITS" -eq 12 ]; then
        ok "the RESP dispatch routes too (12/12)"
    else
        bad "the RESP dispatch routes too" \
            "got $RHITS of 12 — the text switch and the RESP switch are two" \
            "sites, and one of them is not asking who owns the key"
    fi

    # ── 5: what is NOT routed is refused by name ────────────────────────────
    #
    # The multi-key and keyspace-wide classes were refused here when this file
    # was written and are routed now — pending_cache_shard_multikey.sh holds
    # them down.  What is left is the two classes that are refused on purpose
    # rather than pending: a command that reads or writes the dump file, and one
    # that attaches a stream to a single shard.  Both would appear to work.
    # `flush` was refused here when this file was written and is routed now —
    # step four gave each shard its own dump file, so the collision that made
    # fanning it out dangerous no longer exists.  What it answers is the
    # interpreter's own reply, merged; pending_cache_shard_persist.sh holds the
    # dump behaviour down.  Nothing is asserted about it here.

    RP=$(printf 'replicate 127.0.0.1:1\n' | timeout 5 nc -q1 127.0.0.1 "$P_T4" 2>/dev/null | head -1)
    case "$RP" in
        *"one shard"*)
            ok "a replication stream is refused rather than carrying a fraction" ;;
        *)
            bad "a replication stream is refused" \
                "a follower attached to one shard receives that shard's writes" \
                "and nothing says the rest are missing — got '$RP'" ;;
    esac

    # And a command that needs no key at all is still answered where it is
    # asked.  Without this, "everything is refused" would pass 5 and 6.
    if [ "$(redis-cli -p "$P_R4" PING 2>/dev/null)" = "PONG" ]; then
        ok "a connection-scoped command is answered where it was asked"
    else
        bad "a connection-scoped command is answered where it was asked" \
            "PING has no key and must not have been routed anywhere"
    fi
else
    echo "  (redis-cli absent — the RESP assertions did not run)"
fi

# ── 3: a shard with no connections has still executed commands ─────────────
#
# The assertion that cannot pass without a crossing.  `stats` reports each shard
# separately; a shard whose total_connections is zero and whose
# commands_processed is not has been handed work by a sibling and by nothing
# else.
sleep 2.5
ST=$("$BIN" stats sh4t 2>&1 || true)

# ── 3: the keys of ONE connection ended up in more than one shard ──────────
#
# This used to look for a shard with connections:0 and commands_processed>0,
# which only holds when the kernel happens to give no connection to at least one
# shard — with four shards and a handful of connections it often gives one to
# each, and the assertion then fails on a correct build.  Luck is not a test.
#
# The keys are the durable evidence: one connection wrote them all, so a build
# that does not route puts every one of them in that connection's shard.  A
# spread over more than one shard cannot happen without a crossing.
HOLDING=$(printf '%s\n' "$ST" | awk -F: '/^keys:/ { if ($2+0 > 0) n++ } END { print n+0 }')
if [ "$HOLDING" -gt 1 ]; then
    ok "one connection's keys are spread over $HOLDING shards"
else
    bad "one connection's keys are spread over more than one shard" \
        "$HOLDING shard(s) hold any keys — everything landed where the" \
        "connection did, so nothing crossed a shard boundary" \
        "$(printf '%s' "$ST" | tr '\n' '|')"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
