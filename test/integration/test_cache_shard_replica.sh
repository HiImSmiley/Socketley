#!/usr/bin/env bash
# Integration test: replication and a sharded cache, in both directions.
#
# ─── THIS RAN AS pending_ WHILE THE REFUSAL STOOD ──────────────────────────
#
# `--shards` on a cache was refused while this was being built, so the file was
# outside run_all.sh's glob and run against a scratch build.  Both are gone.
#
# ─── THE TWO DIRECTIONS ARE NOT THE SAME QUESTION ──────────────────────────
#
# A SHARDED LEADER cannot have a follower.  A follower arrives as one TCP
# connection, SO_REUSEPORT hands it to one shard, and that shard is the only
# writer its socket may ever have — two writers on one socket cannot be ordered
# and the follower has no way to resync from a spliced command.  The other N-1
# shards have no socket to it at all.  Measured: `replicate` on a four-shard
# cache is refused by name, and a follower configured against it stays empty.
#
# A SHARDED FOLLOWER works, and for a reason worth asserting rather than
# assuming: `--replicate` is a property of the runtime, so all N shards dial the
# leader and all N are promoted — the leader reports `followers:4` — and each
# shard keeps the part of the stream its slice owns.
#
# ─── WHAT EACH ASSERTION CATCHES ───────────────────────────────────────────
#
#   leader refused        a build that lets a sharded leader promote a follower
#                         sends it one shard's writes and reports success.
#   follower converges    every key, read back individually.  A key COUNT
#                         cannot tell "all four shards kept everything" from
#                         "each kept its own quarter" — both give the right
#                         total only in the second case, and the first gives
#                         four times it.  So the total is asserted too.
#   no duplication        the summed size equals the leader's, not N times it.
#                         That is the assertion that fails if the ownership
#                         filter stops filtering.
#   multi-key writes      `mset` names keys in different slices, so as ONE
#                         command it belongs to no shard.  Before the emitters
#                         were made to replicate one key at a time, a sharded
#                         follower dropped every one of them while its size
#                         never moved.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate cacheshardrepl
L=$((SL_PORT_BASE+1290)); F1=$((SL_PORT_BASE+1291))
F4=$((SL_PORT_BASE+1292)); L4=$((SL_PORT_BASE+1293)); FX=$((SL_PORT_BASE+1294))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local l; for l in "${@:3}"; do echo "        $l"; done; }

cleanup() {
    for n in rl rf1 rf4 rl4 rfx; do "$BIN" stop "$n" >/dev/null 2>&1 || true; done
    sleep 0.4
    for n in rl rf1 rf4 rl4 rfx; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: replication and a sharded cache ==="
command -v nc >/dev/null 2>&1 || { echo "  SKIP: nc required"; exit 0; }
daemon_start "$BIN"

ready(){ local i; for i in $(seq 1 100); do
    printf 'set __r 1\n' | timeout 2 nc -q1 127.0.0.1 "$1" 2>/dev/null | grep -q '^ok$' && return 0
    sleep 0.25; done; return 1; }
g(){ printf "get $2\n" | timeout 2 nc -q1 127.0.0.1 "$1" 2>/dev/null | head -1; }
sz(){ printf 'size\n' | timeout 3 nc -q1 127.0.0.1 "$1" 2>/dev/null | head -1; }

if ! "$BIN" create cache rl4 -p "$L4" --shards 4 -s >/dev/null 2>&1; then
    echo "  FATAL: --shards on a cache was refused.  It is a supported"
    echo "         configuration now, so this is a defect and not a skip."
    exit 2
fi
ready "$L4" || { echo "  FATAL: the four-shard cache never answered"; exit 2; }

# ── a sharded leader refuses to become one ─────────────────────────────────
RP=$(printf 'replicate\n' | timeout 5 nc -q1 127.0.0.1 "$L4" 2>/dev/null | head -1)
case "$RP" in
    *"one shard"*)
        ok "a sharded cache refuses to be a replication leader, by name" ;;
    ok|*"ok"*)
        bad "a sharded cache refuses to be a replication leader" \
            "it accepted the promotion — that follower will receive one shard's" \
            "writes and nothing will report the other three" ;;
    *)  bad "a sharded cache refuses to be a replication leader" "got '$RP'" ;;
esac

# And a follower pointed at one really does stay empty.
"$BIN" create cache rfx -p "$FX" --replicate "127.0.0.1:$L4" -s >/dev/null 2>&1
for i in $(seq 1 40); do printf "set s$i sv$i\n" | timeout 2 nc -q1 127.0.0.1 "$L4" >/dev/null 2>&1; done
sleep 4
FXSZ=$(sz "$FX")
if [ "${FXSZ:-0}" -le 1 ]; then
    ok "a follower of a sharded leader receives nothing rather than a quarter"
else
    bad "a follower of a sharded leader receives nothing rather than a quarter" \
        "it holds $FXSZ keys — a fraction of the leader, which is the outcome" \
        "the refusal exists to prevent"
fi
"$BIN" stop rfx >/dev/null 2>&1; "$BIN" remove rfx >/dev/null 2>&1
"$BIN" stop rl4 >/dev/null 2>&1; "$BIN" remove rl4 >/dev/null 2>&1; sleep 0.5

# ── a sharded follower of an unsharded leader ──────────────────────────────
"$BIN" create cache rl  -p "$L"  -s >/dev/null 2>&1
ready "$L" || { echo "  FATAL: the leader never answered"; exit 2; }
"$BIN" create cache rf1 -p "$F1" --replicate "127.0.0.1:$L" -s >/dev/null 2>&1
"$BIN" create cache rf4 -p "$F4" --shards 4 --replicate "127.0.0.1:$L" -s >/dev/null 2>&1
sleep 4

for i in $(seq 1 30); do printf "set t$i tv$i\n" | timeout 2 nc -q1 127.0.0.1 "$L" >/dev/null 2>&1; done
printf 'mset u1 a1 u2 a2 u3 a3 u4 a4\n' | timeout 3 nc -q1 127.0.0.1 "$L" >/dev/null 2>&1
sleep 4

MISS=0
for i in $(seq 1 30); do [ "$(g "$F4" "t$i")" = "tv$i" ] || MISS=$((MISS+1)); done
if [ "$MISS" -eq 0 ]; then
    ok "a sharded follower has every replicated key (30/30)"
else
    bad "a sharded follower has every replicated key" "$MISS of 30 missing"
fi

UMISS=0
for i in 1 2 3 4; do [ "$(g "$F4" "u$i")" = "a$i" ] || UMISS=$((UMISS+1)); done
if [ "$UMISS" -eq 0 ]; then
    ok "a multi-key write reaches a sharded follower (4/4)"
else
    bad "a multi-key write reaches a sharded follower" \
        "$UMISS of 4 missing — an mset names keys in different slices, so as one" \
        "command it belongs to none of them and is dropped whole"
fi

LSZ=$(sz "$L"); F1SZ=$(sz "$F1"); F4SZ=$(sz "$F4")
if [ "$F4SZ" = "$LSZ" ] && [ "$F1SZ" = "$LSZ" ]; then
    ok "the sharded follower holds the leader's keys once, not N times (size $F4SZ)"
else
    bad "the sharded follower holds the leader's keys once, not N times" \
        "leader $LSZ, unsharded follower $F1SZ, sharded follower $F4SZ" \
        "a sharded follower that stops filtering keeps every key in every shard"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
