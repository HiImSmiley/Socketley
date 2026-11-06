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
#   one stream, not N     each follower shard names its slice and the leader
#                         sends it only that, so a four-shard follower costs
#                         the leader about what a one-shard follower does, in
#                         the dump and in the live stream, and the four shards
#                         together read the stream once.  Red when every shard
#                         reads the whole stream: about four times.
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
# A sharded cache also binds base+1..base+N, its cluster-mode shard ports, so bases sit ten apart.
L=$((SL_PORT_BASE+1290)); F1=$((SL_PORT_BASE+1291)); FX=$((SL_PORT_BASE+1292))
F4=$((SL_PORT_BASE+1300)); L4=$((SL_PORT_BASE+1310))
BL1=$((SL_PORT_BASE+1320)); BF1=$((SL_PORT_BASE+1321)); BL4=$((SL_PORT_BASE+1330)); BF4=$((SL_PORT_BASE+1340))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local l; for l in "${@:3}"; do echo "        $l"; done; }

cleanup() {
    for n in rl rf1 rf4 rl4 rfx bl1 bf1 bl4 bf4; do "$BIN" stop "$n" >/dev/null 2>&1 || true; done
    sleep 0.4
    for n in rl rf1 rf4 rl4 rfx bl1 bf1 bl4 bf4; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
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
"$BIN" create cache rfx -p "$FX" --replicate "127.0.0.1:$L4" -s >/dev/null 2>&1 \
    || bad "the follower of the sharded leader starts" "create rfx failed"
for i in $(seq 1 40); do printf "set s$i sv$i\n" | timeout 2 nc -q1 127.0.0.1 "$L4" >/dev/null 2>&1; done
sleep 4
FXSZ=$(sz "$FX")
if ! [[ "$FXSZ" =~ ^[0-9]+$ ]]; then
    bad "a follower of a sharded leader receives nothing rather than a quarter" \
        "it never answered size: got '$FXSZ'"
elif [ "$FXSZ" -le 1 ]; then
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
"$BIN" create cache rf1 -p "$F1" --replicate "127.0.0.1:$L" -s >/dev/null 2>&1 \
    || { echo "  FATAL: the unsharded follower was not created"; exit 2; }
"$BIN" create cache rf4 -p "$F4" --shards 4 --replicate "127.0.0.1:$L" -s >/dev/null 2>&1 \
    || { echo "  FATAL: the sharded follower was not created"; exit 2; }
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
if [[ "$LSZ" =~ ^[1-9][0-9]*$ ]] && [ "$F4SZ" = "$LSZ" ] && [ "$F1SZ" = "$LSZ" ]; then
    ok "the sharded follower holds the leader's keys once, not N times (size $F4SZ)"
else
    bad "the sharded follower holds the leader's keys once, not N times" \
        "leader $LSZ, unsharded follower $F1SZ, sharded follower $F4SZ" \
        "a sharded follower that stops filtering keeps every key in every shard"
fi

# ── what a sharded follower costs the leader ───────────────────────────────
# Two leaders given the same writes, one followed by a one-shard cache and one by a four-shard cache: 400 keys of 200
# bytes before the follower dials (the dump) and 400 after (the live stream).
fig(){ "$BIN" stats "$1" 2>/dev/null | awk -F: -v k="$2" '$1==k {s+=$2} END{print s+0}'; }
load(){ python3 - "$1" "$2" "$3" <<'PY'
import socket, sys
port, lo, hi = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
s = socket.create_connection(("127.0.0.1", port), timeout=10)
s.sendall(b"".join(b"set b:%d %s\n" % (i, b"v" * 200) for i in range(lo, hi)))
got = b""
while got.count(b"\n") < hi - lo:
    got += s.recv(1 << 16)
PY
}
"$BIN" create cache bl1 -p "$BL1" -s >/dev/null 2>&1; "$BIN" create cache bl4 -p "$BL4" -s >/dev/null 2>&1
ready "$BL1" && ready "$BL4" || bad "the two byte-counting leaders answer" "one never did"
load "$BL1" 0 400; load "$BL4" 0 400
"$BIN" create cache bf1 -p "$BF1" --replicate "127.0.0.1:$BL1" -s >/dev/null 2>&1
"$BIN" create cache bf4 -p "$BF4" --shards 4 --replicate "127.0.0.1:$BL4" -s >/dev/null 2>&1
for i in $(seq 1 40); do [ "$(fig bl4 followers)" = 4 ] && [ "$(fig bl1 followers)" = 1 ] && break; sleep 0.25; done
load "$BL1" 400 800; load "$BL4" 400 800
for i in $(seq 1 40); do [ "$(fig bf4 keys)" -ge 801 ] && [ "$(fig bf1 keys)" -ge 801 ] && break; sleep 0.25; done
sleep 1.5      # a worker publishes its figures on an interval
O1=$(fig bl1 bytes_out); O4=$(fig bl4 bytes_out); I1=$(fig bf1 bytes_in); I4=$(fig bf4 bytes_in)
K4=$(fig bf4 keys); K1=$(fig bf1 keys)
echo "    leader out: $O1 for one shard, $O4 for four; follower in: $I1 one shard, $I4 four shards; keys $K1 / $K4"
if [ "$K4" = "$K1" ] && [ "$K1" -ge 801 ]; then
    ok "the four-shard follower holds every key once ($K4)"
else
    bad "the four-shard follower holds every key once" "one shard $K1, four shards $K4"
fi
RO=$(awk -v a="$O4" -v b="$O1" 'BEGIN{ if (b > 0) printf "%.2f", a / b; else print "nan" }')
if awk -v r="$RO" 'BEGIN{ exit !(r > 0.8 && r < 1.5) }'; then
    ok "the leader sends a four-shard follower what it sends a one-shard one (${RO}x)"
else
    bad "the leader sends a four-shard follower what it sends a one-shard one" "${RO}x; every shard getting the whole stream is about 4x"
fi
RI=$(awk -v a="$I4" -v b="$I1" 'BEGIN{ if (b > 0) printf "%.2f", a / b; else print "nan" }')
if awk -v r="$RI" 'BEGIN{ exit !(r > 0.8 && r < 1.5) }'; then
    ok "the four follower shards together read the stream once (${RI}x)"
else
    bad "the four follower shards together read the stream once" "${RI}x of a one-shard follower"
fi
BMISS=0
for i in 0 1 2 3 397 398 399 400 401 402 797 798 799; do
    [ "$(g "$BF4" "b:$i" | wc -c)" -eq 201 ] || BMISS=$((BMISS+1))
done
[ "$BMISS" -eq 0 ] && ok "keys from the dump and the stream read back through the follower's shared port" \
    || bad "keys from the dump and the stream read back through the follower's shared port" "$BMISS of 13 missing"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
