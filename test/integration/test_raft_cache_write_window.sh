#!/usr/bin/env bash
# suite: isolated -- its own daemons, sockets, state directories and port window, so it runs beside the others
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
# A cluster cache replicates asynchronously: the primary acknowledges a write
# and streams it afterwards, so when its node dies the promoted follower may lack
# writes the client was told had succeeded.  The manual says how many, and this
# file is where the numbers come from: a client writes continuously, the node
# holding the primary is killed with kill -9, and every acknowledged write is
# read back from the new primary.
#
# Three conditions, several kills each:
#   steady    one connection, one write at a time, about a thousand a second
#   burst     one connection pipelining 200 writes at a time with no pause
#   stalled   the burst, with both followers' workers stopped (SIGSTOP) for four
#             seconds before the kill, so the primary has a backlog it has not
#             been able to hand to the kernel
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#  prefix         a write lost that a LATER write outlived: replication is
#                 ordered, so what survives must be a prefix of the history
#  steady, burst  a write acknowledged more than a quarter of a second before
#                 the kill missing after the promotion, which would be a
#                 replication that lags by more than the time a write takes
#                 to reach a follower
#  after          a cluster that does not settle and serve after each kill
#
# kill -9 is a process dying on a machine that stays up.  A follower that is
# keeping up has everything but the last instant, and one that is not reading
# has only what fit in its receive buffer, so the window is how far behind the
# best follower was.  A machine that loses power or is cut off needs netns or
# iptables (root) to try.  Each round writes its own keys (KEY_PREFIX), since the
# keys of the last round are still in the cache.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
. "$HERE/lib_raft.sh"

PASS=0; FAIL=0; TOTAL=0
T=$(mktemp -d /tmp/socketley-cachewin-XXXXXX)
daemon_watch "$T"   # its processes go with it if it is killed
PB=$((SL_PORT_BASE + 1900))
CB=$((SL_PORT_BASE + 1800))
NODES=()
RAFT_COMPACT_EVERY=50
WRITER_PID=""
STALLED=()
ROUNDS=${ROUNDS:-3}

echo "=== Integration: what an acknowledged write can lose when the primary's node is killed ==="

ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad()  { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL: $*"; }
check() { if eval "$1"; then ok; else bad "$2"; fi; }

cleanup() {
    set +e
    local n p
    [ -n "$WRITER_PID" ] && kill -9 "$WRITER_PID" 2>/dev/null
    for p in "${STALLED[@]}"; do kill -CONT "$p" 2>/dev/null; done
    for n in "${NODES[@]}"; do
        kill -9 "$(cat "$T/$n.pid" 2>/dev/null)" 2>/dev/null
        daemon_sweep "$(sock "$n")"
    done
    if [ -n "${SOCKETLEY_KEEP_TMPD:-}" ]; then echo "  kept: $T" >&2; else rm -rf "$T"; fi
}
trap cleanup EXIT

. "$HERE/lib_raft_cache.sh"

check 'form_cluster' "three daemons did not agree on three voters and one leader within 25 s"
out=$(as 2 cluster create cache c -p "$((CB / 10)){node}" --replicas 3 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 0 ] && [ -z "$out" ]' "cluster create cache: exit $rc, output: $out"
one_primary() { local p; p=$(leading 1 2 3); [ -n "$p" ] && [ "$(count_of "$p")" = 1 ]; }
check 'wait_for 30 one_primary' "the cache does not have exactly one primary within 30 s"

declare -A MISSING ACKED RECENT
round() {   # round <condition> <round number>
    local cond=$1 i=$2 P n
    P=$(leading 1 2 3)
    local followers=(); for n in 1 2 3; do [ "$n" != "$P" ] && followers+=("$n"); done
    local epoch; epoch=$(cstat "$P" cluster_epoch)
    check 'wait_for 60 "settled_on $P $epoch 1 2 3"' "$cond $i: the replicas did not settle on node $P before the round"
    : >"$T/acked"
    export KEY_PREFIX="$cond$i-"
    case $cond in
        steady) python3 "$CLIENT" writer "$T/acked" "$(target 1)" "$(target 2)" "$(target 3)" >/dev/null 2>&1 & ;;
        *)      python3 "$CLIENT" burst "$T/acked" 200 "$(target 1)" "$(target 2)" "$(target 3)" >/dev/null 2>&1 & ;;
    esac
    WRITER_PID=$!
    sleep 3
    STALLED=()
    if [ "$cond" = stalled ]; then
        local f pid
        for f in "${followers[@]}"; do
            pid=$(cstat "$f" pid)
            [ -n "$pid" ] && { kill -STOP "$pid"; STALLED+=("$pid"); }
        done
        sleep 4
    fi
    local t0; t0=$(now_ns)
    node_kill "$P"
    local p
    for p in "${STALLED[@]}"; do kill -CONT "$p" 2>/dev/null || true; done
    STALLED=()
    local survivors=("${followers[@]}") new=""
    while [ "$(ms_since "$t0")" -lt 30000 ]; do
        new=$(takers w "${survivors[@]}")
        [ -n "$new" ] && break
        sleep 0.05
    done
    kill -9 "$WRITER_PID" 2>/dev/null || true
    wait "$WRITER_PID" 2>/dev/null || true
    WRITER_PID=""
    check '[ -n "$new" ] && [ "$(count_of "$new")" = 1 ]' "$cond $i: after the kill the replicas that take writes are [$new]"
    [ -n "$new" ] || return 0
    local res total missing recent holes
    res=$(python3 "$CLIENT" check "$T/acked" "$(target "$new")" "$((t0 - 250000000))" "$t0")
    total=$(sed -n 's/^acked=\([0-9]*\) .*/\1/p' <<<"$res")
    missing=$(sed -n 's/.* missing=\([0-9]*\) .*/\1/p' <<<"$res")
    recent=$(sed -n 's/.*missing_before_cutoff=\([0-9]*\) .*/\1/p' <<<"$res")
    holes=$(sed -n 's/.* holes=\([0-9]*\)$/\1/p' <<<"$res")
    echo "  $cond $i: $total writes acknowledged, $missing missing from node $new ($recent of them acknowledged more than 250 ms before the kill), $holes survived a missing one"
    ACKED[$cond]="${ACKED[$cond]:-} $total"
    MISSING[$cond]="${MISSING[$cond]:-} $missing"
    RECENT[$cond]="${RECENT[$cond]:-} $recent"
    check '[ "$holes" = 0 ]' "$cond $i: $holes writes survived that were acknowledged after one that is missing"
    check '[ "$total" -gt 1000 ]' "$cond $i: only $total writes were acknowledged before the kill"
    if [ "$cond" != stalled ]; then
        check '[ "$recent" = 0 ]' "$cond $i: $recent writes acknowledged more than 250 ms before the kill are missing after the promotion"
    fi
    start_member "$P"
    check 'wait_for 60 "[ \"\$(count_of \"\$(leading 1 2 3)\")\" = 1 ] && settled_on \$(leading 1 2 3) \$(cstat \$(leading 1 2 3) cluster_epoch) 1 2 3"' \
          "$cond $i: the cluster did not settle after node $P was restarted"
}

for cond in steady burst stalled; do
    for i in $(seq 1 "$ROUNDS"); do round "$cond" "$i"; done
done

for cond in steady burst stalled; do
    echo "  $cond: acknowledged [${ACKED[$cond]# }], missing after the promotion [${MISSING[$cond]# }]"
done
echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
