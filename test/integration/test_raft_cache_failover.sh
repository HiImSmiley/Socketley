#!/usr/bin/env bash
# suite: isolated -- its own daemons, sockets, state directories and port window, so it runs beside the others
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
# test_raft_placement proves a cluster keeps a runtime running.  A cache is
# different: it holds data, so keeping it running is not enough, and losing the
# node that leads it must not lose the cache.  Three real daemons on one host, a
# cache of three replicas, a client writing continuously, and a real kill -9 of
# the node that holds the primary.
#
# ─── ONE HOST, ONE PORT ─────────────────────────────────────────────────────
# The followers of a cache dial the primary on its -p port, so a cluster cache
# needs a TCP port, and on one host each replica needs its own.  The nodes are
# named 1, 2 and 3 and the spec says -p 2080{node}, so replica n listens on
# 2080n; on real hosts every node binds the same port and needs no placeholder.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#  declare        a cache that is refused, one with no primary or with two, a
#                 follower that takes a write, a write that does not reach the
#                 followers, placement that does not name the primary
#  kill -9        no promotion within the bound; the promoted replica not the
#                 one that held most; an acknowledged write older than the
#                 asynchronous window missing after the promotion; the new primary
#                 refusing writes; the proxy that follows the primary staying
#                 on the dead one
#  return         the old primary that comes back serving as a second primary,
#                 keeping writes the cluster never had, or not following
#  fast restart   a primary that is restarted before it is declared down leading
#                 again with an empty dataset, and wiping the followers with it
#  hung daemon    a primary whose daemon is stopped (SIGSTOP) still taking
#                 writes after its lease, beside the primary that replaced it
#  no quorum      a primary that has lost its lease still taking writes, and
#                 one that loses its data for having been fenced
#
# Not covered here: network partitions (they need netns or iptables, which need
# root; test_cluster_brain runs them in a simulation of the real state machines).
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
. "$HERE/lib_raft.sh"

PASS=0; FAIL=0; TOTAL=0
T=$(mktemp -d /tmp/socketley-cachefo-XXXXXX)
daemon_watch "$T"   # its processes go with it if it is killed
PB=$((SL_PORT_BASE + 1900))
CB=$((SL_PORT_BASE + 1800))
NODES=()
RAFT_COMPACT_EVERY=8
WRITER_PID=""

echo "=== Integration: a cluster cache survives the loss of its primary's node ==="

ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad()  { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL: $*"; }
check() { if eval "$1"; then ok; else bad "$2"; fi; }

cleanup() {
    set +e
    local n
    [ -n "$WRITER_PID" ] && kill -9 "$WRITER_PID" 2>/dev/null
    for n in "${NODES[@]}"; do
        kill -CONT "$(cat "$T/$n.pid" 2>/dev/null)" 2>/dev/null
        kill -9 "$(cat "$T/$n.pid" 2>/dev/null)" 2>/dev/null
        daemon_sweep "$(sock "$n")"
    done
    if [ -n "${SOCKETLEY_KEEP_TMPD:-}" ]; then echo "  kept: $T" >&2; else rm -rf "$T"; fi
}
trap cleanup EXIT

. "$HERE/lib_raft_cache.sh"

# ─── three nodes form a cluster ─────────────────────────────────────────────
check 'form_cluster' "three daemons did not agree on three voters and one leader within 25 s"

# ─── refusals at the command ────────────────────────────────────────────────
refuse() {   # refuse <needle> <cluster args...>: exit 1, said on stdout
    local needle=$1; shift
    local out rc=0
    out=$(as 2 cluster "$@" 2>&1) || rc=$?
    check '[ "$rc" = 1 ] && grep -q -- "$needle" <<<"$out"' "cluster $*: exit $rc, said: $out"
}
refuse "needs -p"              create cache c --replicas 2
refuse "the cluster's to set"  create cache c -p "$(cport 1)" --replicate 127.0.0.1:1 --replicas 2
refuse "unix socket"           create cache c -p "$(cport 1)" --listen "unix:$T/x.sock" --replicas 2
refuse "sharded"               create cache c -p "$(cport 1)" --shards 2 --replicas 2

# ─── a cache of three replicas gets one primary, and the others copy it ─────
out=$(as 2 cluster create cache c -p "$((CB / 10)){node}" --replicas 3 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 0 ] && [ -z "$out" ]' "cluster create cache: exit $rc, output: $out (success is silent)"
one_primary() { local p; p=$(leading 1 2 3); [ -n "$p" ] && [ "$(count_of "$p")" = 1 ]; }
check 'wait_for 30 one_primary' "the cache does not have exactly one primary within 30 s: [$(leading 1 2 3)]"
P=$(leading 1 2 3)
check '[ -n "$P" ] && [ "$(count_of "$P")" = 1 ]' "the primaries are [$P]"
check 'wait_for 30 "settled_on $P 1 1 2 3"' "the followers did not settle on node $P in epoch 1 within 30 s"
check 'wait_for 10 "[ \"\$(placement_primary 1)\" = \"$P 1\" ] && [ \"\$(placement_primary 2)\" = \"$P 1\" ] && [ \"\$(placement_primary 3)\" = \"$P 1\" ]"' \
      "placement on every node does not name node $P as the primary of epoch 1: [$(placement_primary 1)] [$(placement_primary 2)] [$(placement_primary 3)]"
check 'saw "copy at epoch 1 offset" as 2 cluster placement' "placement does not show what each copy has reached"
check '[ "$(takers t0 1 2 3)" = "$P" ]' "the replicas that take a write are [$(takers t0a 1 2 3)], not the primary alone"
check '[ "$(cmd "$(target "$P")" "set greeting hello")" = ok ]' "the primary does not take a write"
followers=(); for n in 1 2 3; do [ "$n" != "$P" ] && followers+=("$n"); done
check 'wait_for 10 "[ \"\$(cmd \"\$(target ${followers[0]})\" \"get greeting\")\" = hello ] && [ \"\$(cmd \"\$(target ${followers[1]})\" \"get greeting\")\" = hello ]"' \
      "a write to the primary did not reach both followers"
check 'saw "^cluster_role:primary" as "$P" stats c && saw "^cluster_role:follower" as "${followers[0]}" stats c' "stats does not say which replica leads"

# A proxy that names the cache as its backend follows the primary, wherever it is.
out=$(as 3 cluster create proxy px --listen "unix:$T/px-{node}.sock" --backend @c --protocol tcp --replicas 3 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 0 ] && [ -z "$out" ]' "cluster create proxy: exit $rc, output: $out"
via_proxy() { [ "$(cmd "unix:$T/px-$1.sock" "set $2 via-proxy")" = ok ]; }
check 'wait_for 30 "via_proxy 2 p1"' "a write through the proxy on node 2 never reached the primary"
check '[ "$(cmd "$(target "$P")" "get p1")" = via-proxy ]' "the write through the proxy is not on the primary"

# ─── kill -9 the node that holds the primary, with a client writing ─────────
: >"$T/acked"
python3 "$CLIENT" writer "$T/acked" "$(target 1)" "$(target 2)" "$(target 3)" >/dev/null 2>&1 &
WRITER_PID=$!
sleep 3
acked_before=$(wc -l <"$T/acked")
check '[ "$acked_before" -gt 500 ]' "the writer got only $acked_before writes acknowledged in 3 s"

# The followers copy at whatever speed they can; the promotion must pick the one that holds more, so note what each holds now.
L=$(leader_of 1 2 3 || true)
old=$P
survivors=(); for n in 1 2 3; do [ "$n" != "$old" ] && survivors+=("$n"); done
t0=$(now_ns)
node_kill "$old"
# The first write any survivor accepts is the new primary taking over.
new=""
while :; do
    ms=$(ms_since "$t0")
    new=$(takers f1 "${survivors[@]}")
    [ -n "$new" ] && break
    [ "$ms" -gt 30000 ] && break
    sleep 0.05
done
failover_ms=$(ms_since "$t0")
FAILOVERS=("$failover_ms")
echo "  kill -9 of the primary's node $old ($([ "$old" = "$L" ] && echo the Raft leader || echo not the Raft leader)): a survivor took a write after ${failover_ms} ms"
# The proxy on a survivor was on the dead primary, and its group now names the new one.
via=${survivors[0]}
proxied=0
while [ "$(ms_since "$t0")" -lt 40000 ]; do
    via_proxy "$via" p2 && { proxied=1; break; }
    sleep 0.05
done
proxy_ms=$(ms_since "$t0")
PROXY_MS=("$proxy_ms")
echo "  the first write through the proxy on node $via succeeded ${proxy_ms} ms after the kill"
check '[ -n "$new" ] && [ "$(count_of "$new")" = 1 ]' "after the kill the replicas that take writes are [$new]"
check '[ "$failover_ms" -le 12000 ]' "the promotion took ${failover_ms} ms"
kill -9 "$WRITER_PID" 2>/dev/null || true
wait "$WRITER_PID" 2>/dev/null || true
WRITER_PID=""
check 'wait_for 15 "[ \"\$(placement_primary ${survivors[0]})\" = \"$new 2\" ] && [ \"\$(placement_primary ${survivors[1]})\" = \"$new 2\" ]"' \
      "placement on the survivors does not name node $new as the primary of epoch 2: [$(placement_primary "${survivors[0]}")] [$(placement_primary "${survivors[1]}")]"
check 'grep -q "cache c: .* leads epoch 2" "$T/${survivors[0]}.log"' "the promotion is not in the survivors' logs"

# What the old primary acknowledged and the survivors lack: only the asynchronous window, nothing older.
res=$(python3 "$CLIENT" check "$T/acked" "$(target "$new")" "$((t0 - 1000000000))" "$t0")
total=$(sed -n 's/^acked=\([0-9]*\) .*/\1/p' <<<"$res")
missing=$(sed -n 's/.* missing=\([0-9]*\) .*/\1/p' <<<"$res")
older=$(sed -n 's/.*missing_before_cutoff=\([0-9]*\) .*/\1/p' <<<"$res")
holes=$(sed -n 's/.* holes=\([0-9]*\)$/\1/p' <<<"$res")
echo "  the writer had $total writes acknowledged; $missing are missing from the new primary; $older of them were acknowledged more than a second before the kill"
check '[ "$older" = 0 ]' "$older writes acknowledged more than a second before the kill are missing after the promotion"
# Replication is ordered, so what survives is a prefix of what was acknowledged: no write is lost that a later one outlived.
check '[ "$holes" = 0 ]' "$holes writes survived that were acknowledged after a write that is missing"
LOST=("$missing")
check '[ "$(cmd "$(target "$new")" "set after-failover yes")" = ok ]' "the new primary does not take a write"
other=""; for n in "${survivors[@]}"; do [ "$n" != "$new" ] && other=$n; done
check 'wait_for 15 "[ \"\$(cmd \"\$(target $other)\" \"get after-failover\")\" = yes ]"' "the write to the new primary did not reach the other survivor"
check 'wait_for 30 "settled_on $new 2 ${survivors[*]}"' "the surviving follower did not settle on node $new in epoch 2"

# And what it wrote went to the new primary.
check '[ "$proxied" = 1 ]' "a write through the proxy on node $via still fails 40 s after the kill"
check '[ "$(cmd "$(target "$new")" "get p2")" = via-proxy ]' "the write through the proxy did not reach the new primary"

# ─── the old primary comes back: a follower of the new one, never a leader ──
start_member "$old"
w0=$(now_ns)
led_old=0; two=0; follows=0
for i in $(seq 1 200); do
    p=$(leading 1 2 3)
    [ "$(count_of "$p")" -gt 1 ] && two=1
    [ "$(crole "$old")" = primary ] && led_old=1
    if settled_on "$new" 2 1 2 3 && [ "$(crole "$old")" = follower ]; then follows=1; break; fi
    sleep 0.1
done
echo "  the old primary's node $old is a follower again after $(ms_since "$w0") ms"
check '[ "$led_old" = 0 ]' "the restarted node $old led its cache"
check '[ "$two" = 0 ]' "two replicas led the cache at one poll while node $old came back"
check '[ "$follows" = 1 ]' "the restarted node $old is not a follower of node $new in epoch 2 after 20 s: [$(crole "$old")]"
check '[ "$(cmd "$(target "$old")" "get after-failover")" = yes ]' "the restarted node does not hold what the new primary holds"
check '[ "$(cmd "$(target "$old")" "set nope 1")" != ok ]' "the restarted node takes a write as a follower"
check '[ "$(takers t1 1 2 3)" = "$new" ]' "the replicas that take a write are [$(takers t1a 1 2 3)] once node $old is back"
check '[ "$(cstat "$old" cluster_incarnation)" != "" ] && [ "$(cstat "$old" cluster_epoch)" = 2 ]' "the restarted replica does not hold epoch 2's copy"

# ─── a primary restarted before it is declared down comes back empty and does not lead ─────
L=$(leader_of 1 2 3 || true)
cur=$new
greeting_before=$(cmd "$(target "$cur")" "get greeting")
t1=$(now_ns)
node_kill "$cur"
sleep 0.5
start_member "$cur"
fast_led=0; two=0
for i in $(seq 1 300); do
    [ "$(crole "$cur")" = primary ] && fast_led=1
    p=$(leading 1 2 3)
    [ "$(count_of "$p")" -gt 1 ] && two=1
    if [ -n "$p" ] && [ "$p" != "$cur" ] && settled_on "$p" 3 1 2 3; then break; fi
    sleep 0.1
done
np=$(leading 1 2 3)
echo "  the primary's node $cur was killed and restarted within a second: node $np led after $(ms_since "$t1") ms"
check '[ "$fast_led" = 0 ]' "the restarted node $cur, holding nothing, led its cache before a replica that had the data"
check '[ "$two" = 0 ]' "two replicas led the cache at one poll around the restart"
check '[ -n "$np" ] && [ "$np" != "$cur" ] && [ "$(count_of "$np")" = 1 ]' "after the restart the primary is [$np]"
check '[ "$(cmd "$(target "$np")" "get greeting")" = "$greeting_before" ] && [ "$greeting_before" = hello ]' "the data written before the restart is gone from the new primary"
check 'wait_for 20 "settled_on $np 3 1 2 3"' "the replicas did not settle on node $np in epoch 3"
check '[ "$(cmd "$(target "$cur")" "get greeting")" = hello ]' "the restarted replica did not copy the primary's data"

# ─── a daemon that hangs cannot keep its primary serving past the lease ─────
P=$(leading 1 2 3)
hung=$P
rest=(); for n in 1 2 3; do [ "$n" != "$hung" ] && rest+=("$n"); done
epoch_before=$(cstat "$hung" cluster_epoch)
kill -STOP "$(cat "$T/$hung.pid")"
h0=$(now_ns)
still=1; two=0; took_over=""
while [ "$(ms_since "$h0")" -lt 14000 ]; do
    tk=$(takers h "$hung" "${rest[@]}")
    [ "$(count_of "$tk")" -gt 1 ] && two=1
    [[ " $tk " == *" $hung "* ]] || { [ "$still" = 1 ] && still=0 && fenced_ms=$(ms_since "$h0"); }
    if [ -n "$tk" ] && [[ " $tk " != *" $hung "* ]]; then took_over=$tk; took_ms=$(ms_since "$h0"); break; fi
    sleep 0.1
done
[ "$still" = 1 ] && fenced_ms=none
echo "  the primary's daemon on node $hung was stopped: its worker refused writes after ${fenced_ms:-?} ms, node ${took_over:-nobody} took over after ${took_ms:-?} ms"
check '[ "$two" = 0 ]' "two replicas took writes at one poll while the primary's daemon was stopped"
check '[ "$still" = 0 ] && [ "$fenced_ms" -le 4500 ]' "the primary whose daemon was stopped still took writes after ${fenced_ms} ms, past its lease"
check '[ -n "$took_over" ]' "no other replica took over within 14 s of the primary's daemon being stopped"
# The hung daemon is killed and started again, which is what an operator does with one; it is not resumed, because a
# SIGCONT ends a daemon today (io_uring_wait_cqe returns EINTR and the loop leaves), which is not what this file is about.
node_kill "$hung"
start_member "$hung"
check 'wait_for 60 "[ \"\$(count_of \"\$(leading 1 2 3)\")\" = 1 ] && [ \"\$(crole $hung)\" = follower ]"' "the restarted node $hung is not a follower after 60 s: [$(crole "$hung")] and the primaries are [$(leading 1 2 3)]"
check 'wait_for 30 "settled_on \$(leading 1 2 3) \$(cstat \$(leading 1 2 3) cluster_epoch) 1 2 3"' "the replicas did not settle after the hung node was restarted"
check '[ "$(cmd "$(target "$hung")" "get greeting")" = hello ]' "the restarted replica does not hold the data"

# ─── a primary that loses its quorum stops taking writes, and keeps its data ─
P=$(leading 1 2 3)
others=(); for n in 1 2 3; do [ "$n" != "$P" ] && others+=("$n"); done
check '[ "$(cmd "$(target "$P")" "set before-quorum-loss kept")" = ok ]' "the primary does not take a write before its quorum is lost"
q0=$(now_ns)
for n in "${others[@]}"; do node_kill "$n"; done
fenced=0
while [ "$(ms_since "$q0")" -lt 15000 ]; do
    [ "$(cmd "$(target "$P")" "set quorum-probe x")" != ok ] && { fenced=1; break; }
    sleep 0.1
done
qms=$(ms_since "$q0")
echo "  a primary without a quorum refused writes after ${qms} ms"
check '[ "$fenced" = 1 ]' "the primary still takes writes 15 s after it lost its quorum"
check '[ "$qms" -le 8000 ]' "the primary took ${qms} ms to stop taking writes without a quorum, past its lease"
check '[ "$(cmd "$(target "$P")" "get before-quorum-loss")" != kept ]' "a fenced primary answers a read"
check 'wait_for 5 "[ \"\$(crole $P)\" = fenced ]"' "the primary's stats do not say it is fenced: [$(crole "$P")]"
for n in "${others[@]}"; do start_member "$n"; done
check 'wait_for 40 formed' "the cluster did not form again after the quorum came back"
check 'wait_for 40 "[ \"\$(count_of \"\$(leading 1 2 3)\")\" = 1 ]"' "no single primary after the quorum came back: [$(leading 1 2 3)]"
check '[ "$(leading 1 2 3)" = "$P" ]' "the primary that was fenced for want of a quorum is not the primary again: [$(leading 1 2 3)]"
check '[ "$(cmd "$(target "$P")" "get before-quorum-loss")" = kept ]' "the fenced primary lost its data instead of keeping it fenced"
check 'wait_for 40 "settled_on $P \$(cstat $P cluster_epoch) 1 2 3"' "the restarted replicas did not sync from the primary that was fenced"
check '[ "$(cmd "$(target "${others[0]}")" "get before-quorum-loss")" = kept ]' "a follower does not hold what the fenced primary kept"

# ─── remove ─────────────────────────────────────────────────────────────────
out=$(as 1 cluster remove px 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 0 ] && [ -z "$out" ]' "cluster remove px: exit $rc, output: $out"
out=$(as 1 cluster remove c 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 0 ] && [ -z "$out" ]' "cluster remove c: exit $rc, output: $out"
check 'wait_for 20 "[ -z \"\$(leading 1 2 3)\" ] && ! saw \"\\[cluster\\]\" as 1 ls"' "a replica is still listed or leading after cluster remove"

echo "  promotion times (ms, kill -9 to a survivor taking a write): ${FAILOVERS[*]}; to a write through a proxy: ${PROXY_MS[*]}"
echo "  writes acknowledged and missing after the promotion: ${LOST[*]}"
echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
