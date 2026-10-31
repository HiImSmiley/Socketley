#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Three daemons on one host with separate sockets and a shared cluster
# directory, verifying discovery, group resolution and proxy @group routing --
# a simulation, because a real member has a namespace to itself and finds its
# peers through the directory and network addresses rather than socket paths,
# and everything here is per-run since the state directory is keyed to the
# socket whenever that is not the default.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
PASS=0; FAIL=0; TOTAL=0

TMPD=$(mktemp -d /tmp/socketley-cluster-XXXXXX)

daemon_watch "$TMPD"   # its processes go with it if it is killed
export HOME="$TMPD/home"
mkdir -p "$HOME"
CLUSTER_DIR="$TMPD/cluster"
mkdir -p "$CLUSTER_DIR"
SOCK_NODE1="$TMPD/node1.sock"
SOCK_NODE2="$TMPD/node2.sock"
SOCK_GW="$TMPD/gw.sock"
# Tests 7 and 8 run their own little cluster — see the header above them.
SOCK_WIT="$TMPD/witness.sock"
SOCK_RJ="$TMPD/rejoin.sock"
SOCK_IN="$TMPD/intruder.sock"
NODE1_PORT=$((SL_PORT_BASE+301))
NODE2_PORT=$((SL_PORT_BASE+302))
GW_PORT=$((SL_PORT_BASE+310))
DAEMON_PIDS=()

# Three roles, three names, because api1, api2 and a gateway are three
# different things.
RT_API1="clst_api1"
RT_API2="clst_api2"
RT_GW="clst_gw"

node1() { SOCKETLEY_SOCKET="$SOCK_NODE1" "$BIN" "$@"; }
node2() { SOCKETLEY_SOCKET="$SOCK_NODE2" "$BIN" "$@"; }
gw()    { SOCKETLEY_SOCKET="$SOCK_GW"    "$BIN" "$@"; }

cleanup() {
    set +e
    # ─── Why the stops are guarded ─────────────────────────────────────────────
    # Only talk to a daemon that is answering, and sweep by socket at the end
    # for anything raised anyway, because a CLI command against a dead socket
    # auto-starts a detached daemon that outlives the run on its ports.
    for sock_var in SOCK_NODE1 SOCK_NODE2 SOCK_GW; do
        eval "sock=\$$sock_var"
        daemon_alive "$sock" || continue
        for rt in "$RT_API1" "$RT_API2" "$RT_GW"; do
            SOCKETLEY_SOCKET="$sock" "$BIN" stop "$rt" &>/dev/null
        done
    done
    sleep 0.5
    for sock_var in SOCK_NODE1 SOCK_NODE2 SOCK_GW; do
        eval "sock=\$$sock_var"
        daemon_alive "$sock" || continue
        for rt in "$RT_API1" "$RT_API2" "$RT_GW"; do
            SOCKETLEY_SOCKET="$sock" "$BIN" remove "$rt" &>/dev/null
        done
    done

    # Kill daemons
    for pid in "${DAEMON_PIDS[@]}"; do
        [ "$pid" = "0" ] && continue
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    done
    daemon_sweep "$SOCK_NODE1"
    daemon_sweep "$SOCK_NODE2"
    daemon_sweep "$SOCK_GW"
    daemon_sweep "$SOCK_WIT"
    daemon_sweep "$SOCK_RJ"
    daemon_sweep "$SOCK_IN"
    rm -rf "$TMPD"
}
trap cleanup EXIT

assert_contains() {
    TOTAL=$((TOTAL+1))
    if grep -q "$2" <<<"$1"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: expected '$2' in output"
        echo "  GOT: $1"
    fi
}

assert_not_contains() {
    TOTAL=$((TOTAL+1))
    if ! grep -q "$2" <<<"$1"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: did not expect '$2' in output"
    fi
}

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

# One numeric field out of `stats` asked of the daemon on SOCKET, empty rather
# than 0 when it could not be read, because 0 is a legitimate reading of every
# counter below.
cluster_counter() {
    local v
    v=$(SOCKETLEY_SOCKET="$1" "$BIN" stats "$2" 2>/dev/null \
        | sed -n "s/^$3:\([0-9][0-9]*\)$/\1/p" | head -1) || v=""
    printf '%s' "$v"
}

# Combined bytes_in over the named runtimes, or empty if any one could not be
# read, because round-robin decides which member gets the connection and a
# partial sum is no measurement rather than a smaller number.
cluster_sum_bytes_in() {
    local total=0 spec sock rt v
    for spec in "$@"; do
        sock=${spec%%|*}; rt=${spec#*|}
        v=$(cluster_counter "$sock" "$rt" bytes_in)
        if [ -z "$v" ]; then printf ''; return 0; fi
        total=$((total + v))
    done
    printf '%s' "$total"
}

echo "=== Integration: cluster discovery ==="

# ─── Start 3 daemons ──────────────────────────────────────────────────────────
# Waiting for the daemon to say it is up rather than sleeping, because
# configuration mode auto-starts a detached daemon nobody has the pid of when
# the socket does not answer.
start_node() {   # start_node SOCKET NAME
    local sock=$1 name=$2 i
    SOCKETLEY_SOCKET="$sock" "$BIN" daemon >>"$TMPD/$name.log" 2>&1 &
    DAEMON_PIDS+=($!)
    for i in $(seq 1 100); do
        grep -q "daemon started" "$TMPD/$name.log" 2>/dev/null && break
        sleep 0.1
    done
    if [ ! -S "$sock" ]; then
        echo "ERROR: daemon socket $sock not created"
        tail -5 "$TMPD/$name.log" 2>/dev/null | sed 's/^/    /'
        exit 1
    fi
    SOCKETLEY_SOCKET="$sock" "$BIN" daemon --name "$name" --cluster "$CLUSTER_DIR"
}

start_node "$SOCK_NODE1" node1
start_node "$SOCK_NODE2" node2
start_node "$SOCK_GW"    gateway
sleep 0.5

# ─── Create runtimes ──────────────────────────────────────────────────────────

# create_ok takes the whole command because these go through the per-node
# wrappers, and a runtime that was never created is reported by every assertion
# in tests 1 to 5 as "discovery does not work".
create_ok "api runtime on node1 created" node1 create server "$RT_API1" -p "$NODE1_PORT" -g api -s
create_ok "api runtime on node2 created" node2 create server "$RT_API2" -p "$NODE2_PORT" -g api -s

# Wait for cluster heartbeat cycle (publish every 2s)
sleep 3

# ─── Test 1: Daemon discovery (cluster ls) ─────────────────────────────────────

echo "  Test 1: daemon discovery"
# ─── Why each capture names a socket ────────────────────────────────────────
# Guarded because a lone `OUT=$(cmd)` takes the file's exit status from the
# substitution, and daemon_required is given the socket explicitly since the
# wrappers set SOCKETLEY_SOCKET only for the duration of one command.
OUT=$(node1 cluster ls 2>&1)      || daemon_required "cluster ls" "$SOCK_NODE1"
assert_contains "$OUT" "node1"
assert_contains "$OUT" "node2"
assert_contains "$OUT" "gateway"

# ─── Test 2: Runtime visibility (cluster ps) ───────────────────────────────────

echo "  Test 2: runtime visibility"
OUT=$(node1 cluster ps 2>&1)      || daemon_required "cluster ps" "$SOCK_NODE1"
assert_contains "$OUT" "$RT_API1"
assert_contains "$OUT" "$RT_API2"

# ─── Test 3: Group resolution (cluster group api) ─────────────────────────────

echo "  Test 3: group resolution"
OUT=$(node1 cluster group api 2>&1) || daemon_required "cluster group api" "$SOCK_NODE1"
assert_contains "$OUT" "node1"
assert_contains "$OUT" "node2"
assert_contains "$OUT" "$NODE1_PORT"
assert_contains "$OUT" "$NODE2_PORT"

# A group name is the operator's text: a brace in one cut the published list short there, and a backslash came back
# doubled, so neither group, nor any runtime published after it, was seen from another daemon.
echo "  Test 3b: group names with JSON's own characters"
create_ok "a runtime in a group with a brace and a backslash created" node2 create server clst_odd -p "$((SL_PORT_BASE+304))" -g 'odd}x\y' -s
create_ok "and one after it" node2 create server clst_zz -p "$((SL_PORT_BASE+305))" -g after -s
OUT=""
for _ in $(seq 1 30); do
    OUT=$(node1 cluster group 'odd}x\y' 2>&1; node1 cluster group after 2>&1) || true
    printf '%s' "$OUT" | grep -q "$((SL_PORT_BASE+304))" && printf '%s' "$OUT" | grep -q "$((SL_PORT_BASE+305))" && break
    sleep 0.5
done
assert_contains "$OUT" "$((SL_PORT_BASE+304))"
assert_contains "$OUT" "$((SL_PORT_BASE+305))"
node2 remove clst_odd >/dev/null 2>&1; node2 remove clst_zz >/dev/null 2>&1
for _ in $(seq 1 30); do
    node1 cluster ps 2>/dev/null | grep -qE 'clst_odd|clst_zz' || break
    sleep 0.5
done

# ─── Test 4: Cluster stats ────────────────────────────────────────────────────

echo "  Test 4: cluster stats"
OUT=$(node1 cluster stats 2>&1)   || daemon_required "cluster stats" "$SOCK_NODE1"
assert_contains "$OUT" "3 healthy"
assert_contains "$OUT" "api"
assert_contains "$OUT" "2 members"

# ─── Test 5: Proxy @group routing ──────────────────────────────────────────────

echo "  Test 5: proxy @group routing"
create_ok "@group gateway created on the gateway node" \
    gw create proxy "$RT_GW" -p "$GW_PORT" \
    --backend @api --protocol tcp --strategy round-robin -s
sleep 1

# The oracle is the daemons' own counters rather than nc's exit status, which
# is 0 for anything that accepts on that port: the gateway's runtime counts the
# connection and the payload's bytes arrive at an @api member, summed over
# node1 and node2 because round-robin picks which one -- the half no
# port-holder and no empty group can fake.
CL_PAYLOAD="hello cluster"
CL_N=$(( ${#CL_PAYLOAD} + 1 ))       # printf adds the newline that is also sent
GC0=$(cluster_counter "$SOCK_GW" "$RT_GW" total_connections)
GB0=$(cluster_sum_bytes_in "$SOCK_NODE1|$RT_API1" "$SOCK_NODE2|$RT_API2")

# `timeout` around nc, because `-q 1` only bounds the wait after the peer has
# hung up and a stray port-holder that accepts and holds leaves nc blocked with
# two whole cluster scenarios unreported.
RC=0
printf '%s\n' "$CL_PAYLOAD" | timeout 10 nc -q 1 127.0.0.1 "$GW_PORT" >/dev/null 2>&1 || RC=$?

# Wait for the counters to settle rather than sleeping a guess at how long a
# cross-daemon forward takes; on success this returns as soon as both have moved.
GC1=$GC0; GB1=$GB0
for _ in $(seq 1 40); do
    GC1=$(cluster_counter "$SOCK_GW" "$RT_GW" total_connections)
    GB1=$(cluster_sum_bytes_in "$SOCK_NODE1|$RT_API1" "$SOCK_NODE2|$RT_API2")
    if [ -n "$GC0" ] && [ -n "$GC1" ] && [ -n "$GB0" ] && [ -n "$GB1" ] \
       && [ "$GC1" -gt "$GC0" ] && [ "$GB1" -ge "$((GB0 + CL_N))" ]; then
        break
    fi
    sleep 0.1
done

if [ -z "$GC0" ] || [ -z "$GC1" ]; then
    fail "proxy @group: the gateway accepted the connection" \
         "could not read $RT_GW's total_connections (before='$GC0' after='$GC1')" \
         "— the gateway daemon did not answer, so nothing was measured"
elif [ "$GC1" -eq "$((GC0 + 1))" ]; then
    pass
else
    fail "proxy @group: the gateway accepted the connection" \
         "$RT_GW's total_connections went $GC0 -> $GC1, wanted exactly one more (nc exited $RC)." \
         "Something may still answer port $GW_PORT — that is what the old nc-exit-code" \
         "check measured — but it is not this gateway."
fi

if [ -z "$GB0" ] || [ -z "$GB1" ]; then
    fail "proxy @group: the payload reached an @api member" \
         "could not read bytes_in for $RT_API1/$RT_API2 (before='$GB0' after='$GB1')"
elif [ "$GB1" -eq "$((GB0 + CL_N))" ]; then
    pass
else
    fail "proxy @group: the payload reached an @api member" \
         "bytes_in across $RT_API1+$RT_API2 went $GB0 -> $GB1, wanted exactly $CL_N more" \
         "($((GB1 - GB0)) arrived).  The gateway took the connection, but @api did not" \
         "resolve to a reachable member on another daemon."
fi

# ─── Test 6: Stale detection ──────────────────────────────────────────────────

echo "  Test 6: stale detection"
# Stop runtime on node2 first, then kill the daemon
node2 stop "$RT_API2" 2>/dev/null || true
sleep 0.5
node2 remove "$RT_API2" 2>/dev/null || true
N2_FILE="$CLUSTER_DIR/node2.json"
cp "$N2_FILE" "$TMPD/node2.json.last" 2>/dev/null || true
kill "${DAEMON_PIDS[1]}" 2>/dev/null || true
wait "${DAEMON_PIDS[1]}" 2>/dev/null || true
DAEMON_PIDS[1]=0

# Stale threshold is 10s; wait for it to expire
sleep 12

# A daemon that left on SIGTERM took its file along, so its last heartbeat is put back to be judged.
N2_PLANTED=0
if [ ! -f "$N2_FILE" ] && [ -s "$TMPD/node2.json.last" ]; then
    cp "$TMPD/node2.json.last" "$N2_FILE"; N2_PLANTED=1
fi

# node1's daemon, deliberately, not node2's: node2's was killed on purpose a few
# lines up, and this is the one that has to still be answering for the staleness
# question to mean anything.
OUT=$(node1 cluster ls 2>&1)      || daemon_required "cluster ls" "$SOCK_NODE1"
[ "$N2_PLANTED" = 1 ] && rm -f "$N2_FILE"
# A heartbeat 12 s old is past the 10 s threshold, so node2 has to be listed as stale.
TOTAL=$((TOTAL+1))
if grep -q "stale" < <(grep "node2" <<<"$OUT"); then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: node2 not listed as stale 12s after its last heartbeat"
    echo "        ($([ "$N2_PLANTED" = 1 ] && echo "its file was put back after it left" || echo "its file was still there"))"
    echo "  GOT: $OUT"
fi

# node1 should still be healthy
assert_contains "$OUT" "node1"
assert_not_contains "$(echo "$OUT" | grep node1)" "stale"

# The two directions of one rule -- a node reclaiming its own name inside the
# staleness window, and a different live daemon refused it -- on a cluster of
# their own, because a restart is when a daemon restores its state directory,
# and the rule that separates them is that a fresh file may be taken over only
# when its advertised host, control socket path and boot id are this daemon's
# own.

RJ_DIR="$TMPD/cluster2"; mkdir -p "$RJ_DIR"
RJ_PORT=$((SL_PORT_BASE+303))

wit() { SOCKETLEY_SOCKET="$SOCK_WIT" "$BIN" "$@"; }
rj()  { SOCKETLEY_SOCKET="$SOCK_RJ"  "$BIN" "$@"; }
intr(){ SOCKETLEY_SOCKET="$SOCK_IN"  "$BIN" "$@"; }

# By count of "daemon started" rather than presence, because the node in test 7
# boots twice into one log and a presence check returns before the socket is
# bound.
spawn_daemon() {
    local s=$1 l=$2 i n want
    n=$(grep -c "daemon started" "$l" 2>/dev/null || true)
    [ -n "$n" ] || n=0
    want=$((n + 1))

    SOCKETLEY_SOCKET="$s" "$BIN" daemon >>"$l" 2>&1 &
    SPAWNED_PID=$!
    for i in $(seq 1 100); do
        n=$(grep -c "daemon started" "$l" 2>/dev/null || true)
        [ -n "$n" ] || n=0
        [ "$n" -ge "$want" ] && break
        sleep 0.1
    done
    if [ ! -S "$s" ] || ! kill -0 "$SPAWNED_PID" 2>/dev/null; then
        echo "  FATAL: daemon never came up on $s"
        tail -5 "$l" 2>/dev/null | sed 's/^/         /'
        exit 2
    fi
}

echo "  Test 7: a node reclaiming its own name after a restart"

spawn_daemon "$SOCK_WIT" "$TMPD/witness.log"; DAEMON_PIDS+=($SPAWNED_PID)
wit daemon --name witness --cluster "$RJ_DIR"

spawn_daemon "$SOCK_RJ" "$TMPD/rejoin.log"; RJ_PID=$SPAWNED_PID
DAEMON_PIDS+=($RJ_PID)
rj daemon --name rejoin1 --cluster "$RJ_DIR"
create_ok "runtime on the rejoining node created" \
    rj create server clst_rj -p "$RJ_PORT" -g rejoingroup -s
sleep 3

TOTAL=$((TOTAL+1))
if [ -f "$RJ_DIR/rejoin1.json" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: rejoin1 never published before it was killed"
fi

# SIGKILL, so the file is left behind with a frozen heartbeat — the shape a
# crashed container, a `Restart=on-failure` and a `docker kill` all leave.
HB_BEFORE=$(grep -o '"heartbeat":[0-9]*' "$RJ_DIR/rejoin1.json" 2>/dev/null | cut -d: -f2 || true)
kill -9 "$RJ_PID" 2>/dev/null || true
wait "$RJ_PID" 2>/dev/null || true
rm -f "$SOCK_RJ"
spawn_daemon "$SOCK_RJ" "$TMPD/rejoin.log"; RJ_PID2=$SPAWNED_PID
DAEMON_PIDS+=($RJ_PID2)

# The only restart in this file is the only place the state directory's
# ownership can be observed, so it is asserted rather than arranged around --
# on one shared HOME this daemon restored the other two daemons' runtimes onto
# ports they were already serving and the file still reported 32/32.
# `ls`, not `ls -a`: -a is a ps flag and ls never had one, so this line used
# to be a full listing with an ignored argument.  Once unknown flags stopped
# being ignored it became "unknown flag: -a" -- and the three foreign checks
# below still passed on it, because an error message names no runtime either.
# That is what the fourth check is for.
RJ_INV=$(rj ls 2>&1 || true)
for foreign in "$RT_API1" "$RT_API2" "$RT_GW"; do
    TOTAL=$((TOTAL+1))
    if grep -q "$foreign" <<<"$RJ_INV"; then
        FAIL=$((FAIL+1))
        echo "  FAIL: the restarted node restored $foreign, which belongs to another"
        echo "        daemon in this file and is running on it now"
        echo "  GOT: $RJ_INV"
    else
        PASS=$((PASS+1))
    fi
done

# The other direction, so the three above cannot pass by the daemon restoring
# nothing at all: its own runtime did come back.
TOTAL=$((TOTAL+1))
if grep -q "clst_rj" <<<"$RJ_INV"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: the restarted node did not restore its own runtime either —"
    echo "        the three checks above are not evidence of isolation"
    echo "  GOT: $RJ_INV"
fi

# The test has to have reached the hole it aims at, because every build rejoins
# once the heartbeat is stale.
AGE=$(( $(date +%s) - ${HB_BEFORE:-0} ))
if [ "$AGE" -ge 10 ]; then
    echo "  FATAL: the staleness window closed (${AGE}s) before the restart got"
    echo "         there; this run would pass without testing anything."
    exit 2
fi

RC=0
RJOUT=$(rj daemon --name rejoin1 --cluster "$RJ_DIR" 2>&1) || RC=$?
TOTAL=$((TOTAL+1))
if [ "$RC" -eq 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: rejoin refused ${AGE}s into the 10s window (exit $RC)"
    echo "  GOT: $RJOUT"
fi

# Up and serving is not the same as in the cluster, and the gap between them is
# the whole defect: assert both, from the peer's side.
TOTAL=$((TOTAL+1))
if grep -q "clst_rj" < <(rj ls 2>/dev/null); then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: the restarted daemon is not even serving its runtime"
fi

sleep 4
OUT=$(wit cluster ls 2>&1 || true)
TOTAL=$((TOTAL+1))
if grep -qv "stale" < <(grep '^rejoin1' <<<"$OUT"); then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: the witness cannot see rejoin1 after its restart"
    echo "  GOT: $OUT"
fi

OUT=$(wit cluster group rejoingroup 2>&1 || true)
assert_contains "$OUT" "clst_rj"

echo "  Test 8: a different daemon may not take a live node's name"

# The target is the witness, whose daemon has been up throughout, so the holder
# is unambiguously a second live daemon told apart by its control socket rather
# than by its hostname.
spawn_daemon "$SOCK_IN" "$TMPD/intruder.log"; DAEMON_PIDS+=($SPAWNED_PID)

RC=0
intr daemon --name witness --cluster "$RJ_DIR" >/dev/null 2>&1 || RC=$?
TOTAL=$((TOTAL+1))
if [ "$RC" -ne 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: a second live daemon was allowed to claim the name witness"
fi

# Checked with no sleep in front of it, because the holder republishes on its
# own 2s timer and a refusal that deletes the entry looks like nothing at all
# one cycle later.
TOTAL=$((TOTAL+1))
if [ -f "$RJ_DIR/witness.json" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: the refused daemon deleted the live holder's cluster entry"
fi

RC=0
intr daemon --name witness --cluster "$RJ_DIR" >/dev/null 2>&1 || RC=$?
TOTAL=$((TOTAL+1))
if [ "$RC" -ne 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: the same claim was refused once and granted on the retry —"
    echo "        two live daemons now publish one name"
fi

# A daemon that could not join says so when asked, rather than reporting the
# same thing as a daemon that was never asked to.
OUT=$(intr cluster ls 2>&1 || true)
assert_contains "$OUT" "cluster mode is off"

# And both live holders are still holders, seen from the witness.
sleep 3
OUT=$(wit cluster ls 2>&1 || true)
for who in witness rejoin1; do
    TOTAL=$((TOTAL+1))
    if grep -qv "stale" < <(grep "^$who" <<<"$OUT"); then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: $who lost its membership to a daemon that was refused"
        echo "  GOT: $OUT"
    fi
done

# ─── Summary ──────────────────────────────────────────────────────────────────

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
