#!/usr/bin/env bash
# Integration test: multi-daemon cluster discovery
#
# Starts 3 daemons on localhost with separate sockets and a shared cluster
# directory, then verifies discovery, group resolution, and proxy @group routing.
#
# Three daemons in one filesystem namespace is what SOCKETLEY_SOCKET is for, and
# it is a simulation: a real cluster member is a container or a host, so it has a
# namespace to itself and runs on the default path.  Members find each other
# through the shared cluster directory and network addresses, never through
# socket paths.
#
# Everything below is per-run — sockets, state directory, cluster directory.  The
# socket paths used to be three fixed names in /tmp, which meant two runs of this
# file on one machine were the same three daemons, and the state directory was
# shared by all three nodes and by every other test on the box.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
PASS=0; FAIL=0; TOTAL=0

TMPD=$(mktemp -d /tmp/socketley-cluster-XXXXXX)
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
NODE1_PORT=19301
NODE2_PORT=19302
GW_PORT=19310
DAEMON_PIDS=()

# Use unique runtime names to avoid state-dir collisions between daemons
RT_API1="clst_api1"
RT_API2="clst_api2"
RT_GW="clst_gw"

node1() { SOCKETLEY_SOCKET="$SOCK_NODE1" "$BIN" "$@"; }
node2() { SOCKETLEY_SOCKET="$SOCK_NODE2" "$BIN" "$@"; }
gw()    { SOCKETLEY_SOCKET="$SOCK_GW"    "$BIN" "$@"; }

cleanup() {
    set +e
    # ─── Why the stops are guarded ─────────────────────────────────────────────
    #
    # This is where two daemons per suite run used to be born.  Test 6 kills
    # node2's daemon on purpose, and then this function ran `node2 stop` and
    # `node2 remove` regardless — CLI commands against a socket with nothing
    # behind it.  Every CLI command except `daemon`, `version` and `help`
    # auto-starts a daemon when the socket does not answer, forking and
    # setsid-ing one detached from this shell, so each of those calls raised a
    # brand new daemon on node2's socket.  The kill loop below skips it (its slot
    # is 0 by then and the pid would be wrong anyway), the `rm -f` unlinked the
    # socket so nothing could even see it afterwards, and the process stayed up
    # until someone went looking.  A full suite reliably left two behind, from
    # here and from test_cluster_lua.sh, and they then sat on the next run's
    # ports and heartbeated into whatever cluster directory came along.
    #
    # So: only talk to a daemon that is answering, and sweep by socket at the end
    # for anything that got raised anyway.
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
    if echo "$1" | grep -q "$2"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: expected '$2' in output"
        echo "  GOT: $1"
    fi
}

assert_not_contains() {
    TOTAL=$((TOTAL+1))
    if ! echo "$1" | grep -q "$2"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: did not expect '$2' in output"
    fi
}

echo "=== Integration: cluster discovery ==="

# ─── Start 3 daemons ──────────────────────────────────────────────────────────
#
# `daemon --name ... --cluster ...` is configuration mode: it talks to a daemon
# that is already up, and like every other CLI command it auto-starts a detached
# one when the socket does not answer.  The `sleep 0.3` this used to wait was a
# guess about how long binding takes, and losing that guess on a loaded machine
# did not fail — it started a second daemon nobody had the pid of.  Waiting for
# the daemon to say it is up removes the race rather than widening it.
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
# wrapper functions rather than through $BIN directly.  A refused create here is
# worth naming twice over: every assertion in tests 1 to 5 is about a runtime
# being discovered across daemons, and a runtime that was never created is
# reported by all of them as "discovery does not work".
create_ok "api runtime on node1 created" node1 create server "$RT_API1" -p "$NODE1_PORT" -g api -s
create_ok "api runtime on node2 created" node2 create server "$RT_API2" -p "$NODE2_PORT" -g api -s

# Wait for cluster heartbeat cycle (publish every 2s)
sleep 3

# ─── Test 1: Daemon discovery (cluster ls) ─────────────────────────────────────

echo "  Test 1: daemon discovery"
# ─── Why each capture names a socket ────────────────────────────────────────
#
# A lone `OUT=$(cmd)` is a simple command whose exit status is the
# substitution's, so under `set -euo pipefail` a failing `cluster` command ended
# this file at the assignment: no assertion, no `Results` line, and — since test
# 6 is the one that kills a daemon on purpose — no way to tell "discovery is
# broken" from "the file stopped before it looked".
#
# daemon_required is given the socket explicitly here.  This file runs three
# daemons on three sockets and the wrapper functions set SOCKETLEY_SOCKET for
# the duration of one command, so the ambient value the other tests rely on is
# not set: without the argument the liveness check would ask about the wrong
# daemon, and answering "gone" for a daemon that is fine would stop a run that
# should carry on.
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

# TCP connect through the proxy should succeed
TOTAL=$((TOTAL+1))
RC=0
echo "hello cluster" | nc -q 1 127.0.0.1 "$GW_PORT" 2>/dev/null || RC=$?
if [ "$RC" -eq 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [proxy @group connect]: nc exit code $RC"
fi

# ─── Test 6: Stale detection ──────────────────────────────────────────────────

echo "  Test 6: stale detection"
# Stop runtime on node2 first, then kill the daemon
node2 stop "$RT_API2" 2>/dev/null || true
sleep 0.5
node2 remove "$RT_API2" 2>/dev/null || true
kill "${DAEMON_PIDS[1]}" 2>/dev/null || true
wait "${DAEMON_PIDS[1]}" 2>/dev/null || true
DAEMON_PIDS[1]=0

# Stale threshold is 10s; wait for it to expire
sleep 12

# node1's daemon, deliberately, not node2's: node2's was killed on purpose a few
# lines up, and this is the one that has to still be answering for the staleness
# question to mean anything.
OUT=$(node1 cluster ls 2>&1)      || daemon_required "cluster ls" "$SOCK_NODE1"
# node2 should be stale or its heartbeat should be old
TOTAL=$((TOTAL+1))
if echo "$OUT" | grep "node2" | grep -q "stale"; then
    PASS=$((PASS+1))
else
    # If node2 unpublished on shutdown, it might be gone entirely
    if ! echo "$OUT" | grep -q "node2"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: node2 not stale/gone after 12s"
        echo "  GOT: $OUT"
    fi
fi

# node1 should still be healthy
assert_contains "$OUT" "node1"
assert_not_contains "$(echo "$OUT" | grep node1)" "stale"

# ─── Tests 7 and 8: reclaiming a name, and not being able to steal one ────────
#
# The two directions of one rule, and they need a cluster of their own: these
# tests kill and restart a daemon on purpose, and the daemons above share a
# state directory, so a restart up there would have one node restoring another
# node's runtimes onto ports that are already taken.  Three fresh daemons, three
# HOMEs, one fresh cluster directory, nothing borrowed.
#
#   witness   joins and stays.  It is the peer, and the point: a node that
#             cannot join is not merely unhappy, it is missing from everyone
#             else's view, and only another daemon can testify to that.
#   rejoin1   the node that gets killed and comes back inside the window.
#   intruder  a second, different, live daemon that wants the name rejoin1.
#
# What used to happen here, on the same machine, in the same second:
#
#   - rejoin1 restarted inside the 10s staleness window found its own file
#     still fresh and was refused with "name may already be in use".  Its
#     daemon then went on serving with cluster mode off — no group, no peer
#     could see it, and nothing but an exit code said so.
#   - intruder, a genuinely different daemon, was refused once and then let in
#     on the second attempt, because the refusal path deleted the file it had
#     just declined to overwrite.  Two live daemons then published one name.
#
# The rule that separates them: a fresh file may be taken over only when its
# claim — advertised host, control socket path, kernel boot id — is this
# daemon's own.  A unix socket path admits one process at a time, so a fresh
# file carrying our own triple was written by a process that is gone.

WIT_HOME="$TMPD/hwit"; RJ_HOME="$TMPD/hrj"; IN_HOME="$TMPD/hin"
mkdir -p "$WIT_HOME" "$RJ_HOME" "$IN_HOME"
RJ_DIR="$TMPD/cluster2"; mkdir -p "$RJ_DIR"
RJ_PORT=19303

wit() { HOME="$WIT_HOME" SOCKETLEY_SOCKET="$SOCK_WIT" "$BIN" "$@"; }
rj()  { HOME="$RJ_HOME"  SOCKETLEY_SOCKET="$SOCK_RJ"  "$BIN" "$@"; }
intr(){ HOME="$IN_HOME"  SOCKETLEY_SOCKET="$SOCK_IN"  "$BIN" "$@"; }

# spawn_daemon HOME SOCKET LOG -> sets SPAWNED_PID
#
# By count of "daemon started", not by presence: the node in test 7 boots twice
# into the same log, and "has the line appeared" is already true the second
# time.  That returns instantly, before the socket is bound, and the readiness
# wait becomes a race the test loses at its own startup.
spawn_daemon() {
    local h=$1 s=$2 l=$3 i n want
    n=$(grep -c "daemon started" "$l" 2>/dev/null || true)
    [ -n "$n" ] || n=0
    want=$((n + 1))

    HOME="$h" SOCKETLEY_SOCKET="$s" "$BIN" daemon >>"$l" 2>&1 &
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

spawn_daemon "$WIT_HOME" "$SOCK_WIT" "$TMPD/witness.log"; DAEMON_PIDS+=($SPAWNED_PID)
wit daemon --name witness --cluster "$RJ_DIR"

spawn_daemon "$RJ_HOME" "$SOCK_RJ" "$TMPD/rejoin.log"; RJ_PID=$SPAWNED_PID
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
spawn_daemon "$RJ_HOME" "$SOCK_RJ" "$TMPD/rejoin.log"; RJ_PID2=$SPAWNED_PID
DAEMON_PIDS+=($RJ_PID2)

# The test has to have reached the hole it is aiming at.  If the machine was
# slow enough that the entry aged out on its own, a rejoin proves nothing —
# every build rejoins once the heartbeat is stale.
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
if rj ls 2>/dev/null | grep -q "clst_rj"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: the restarted daemon is not even serving its runtime"
fi

sleep 4
OUT=$(wit cluster ls 2>&1 || true)
TOTAL=$((TOTAL+1))
if echo "$OUT" | grep '^rejoin1' | grep -qv "stale"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: the witness cannot see rejoin1 after its restart"
    echo "  GOT: $OUT"
fi

OUT=$(wit cluster group rejoingroup 2>&1 || true)
assert_contains "$OUT" "clst_rj"

echo "  Test 8: a different daemon may not take a live node's name"

# The target is `witness`, whose daemon has been up throughout and has never
# been killed — so nothing here depends on how test 7 went, and the holder is
# unambiguously a second, live, different daemon.  Same machine and same
# hostname as the intruder; what tells them apart is the control socket, and a
# unix socket path admits one process at a time.
spawn_daemon "$IN_HOME" "$SOCK_IN" "$TMPD/intruder.log"; DAEMON_PIDS+=($SPAWNED_PID)

RC=0
intr daemon --name witness --cluster "$RJ_DIR" >/dev/null 2>&1 || RC=$?
TOTAL=$((TOTAL+1))
if [ "$RC" -ne 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: a second live daemon was allowed to claim the name witness"
fi

# Checked with no sleep in front of it, and that is the point: the holder
# republishes on its own 2s timer, so a refusal that deletes the entry looks
# like nothing at all one cycle later.  The refusal used to reset the discovery
# object, whose destructor unlinked the very file the refusal had just declined
# to overwrite — which is what let the retry below in.
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
    if echo "$OUT" | grep "^$who" | grep -qv "stale"; then
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
