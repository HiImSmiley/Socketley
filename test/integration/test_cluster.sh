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
#
# ONE HOME IS NOW ENOUGH.  Six daemons run in this file and they share it.  The
# state directory is keyed to the socket path whenever that path is not the
# default one, so six sockets are six state directories, and no daemon here can
# see, restore or delete another's runtimes.  Tests 7 and 8 used to need three
# HOMEs of their own for exactly that reason — see the note above them.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
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
NODE1_PORT=$((SL_PORT_BASE+301))
NODE2_PORT=$((SL_PORT_BASE+302))
GW_PORT=$((SL_PORT_BASE+310))
DAEMON_PIDS=()

# Three roles, three names.  These used to be spelled distinctly because the
# three daemons shared one state directory and a repeated name would have been
# one runtime; that is no longer the reason, and they stay distinct because
# api1, api2 and a gateway are three different things.
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

# cluster_counter SOCKET RUNTIME FIELD
#
# One numeric field out of `stats`, asked of the daemon on SOCKET -- this file
# runs three of them and the runtime whose counter is wanted is not always on
# the same one.  The empty string when the runtime is not there or the daemon
# did not answer, deliberately not 0: 0 is a legitimate reading of every counter
# below, and "there was nothing to read" must not compare equal to it.
cluster_counter() {
    local v
    v=$(SOCKETLEY_SOCKET="$1" "$BIN" stats "$2" 2>/dev/null \
        | sed -n "s/^$3:\([0-9][0-9]*\)$/\1/p" | head -1) || v=""
    printf '%s' "$v"
}

# cluster_sum_bytes_in SOCKET|RUNTIME...
#
# Combined bytes_in over the named runtimes, each on its own daemon, or the
# empty string if any one of them could not be read.  Summed because
# round-robin over the @api group picks which member gets the connection and
# either choice is a pass; a partial sum is not a smaller number, it is no
# measurement, and it says so.
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

# TCP connect through the proxy should reach a member of the @api group
#
# ─── What the old check could not tell apart ────────────────────────────────
#
#     RC=0
#     echo "hello cluster" | nc -q 1 127.0.0.1 "$GW_PORT" 2>/dev/null || RC=$?
#     if [ "$RC" -eq 0 ]; then PASS=$((PASS+1)); ...
#
# The entire assertion was nc's exit status, which is 0 for anything at all that
# accepts a TCP connection on that port.  Staged: with a foreign process holding
# the gateway's port so `create proxy` was refused and clst_gw never existed,
# this file printed 30/31 and `proxy @group connect` was not the one failure.
# It passed against a stranger.
#
# Connecting is not the claim.  The claim is the one thing this whole file is
# about: that `--backend @api` resolved a *group name* into runtimes living on
# *other daemons*, and that traffic actually crossed.  So the oracle is the
# daemons' own counters, and the two halves are asked of two different daemons:
#
#   * the gateway's clst_gw counts the connection -- asked of the gw daemon.
#     A stranger on the port cannot produce that, because the connection never
#     reached us.
#   * the payload's bytes arrive at an @api member -- asked of node1 and node2,
#     summed, because round-robin picks which one and either is a pass.  This is
#     the half that no port-holder and no empty group can fake, and it is the
#     half that makes this a test of @group routing rather than of bind().
CL_PAYLOAD="hello cluster"
CL_N=$(( ${#CL_PAYLOAD} + 1 ))       # printf adds the newline that is also sent
GC0=$(cluster_counter "$SOCK_GW" "$RT_GW" total_connections)
GB0=$(cluster_sum_bytes_in "$SOCK_NODE1|$RT_API1" "$SOCK_NODE2|$RT_API2")

# `timeout` around nc, because `-q 1` only bounds the wait *after* the peer has
# hung up.  A peer that accepts and then holds the connection open forever -- a
# stray port-holder is exactly that -- leaves nc blocked with nothing to time it
# out, and this file never reaches its `Results` line.  It is a 6-minute file
# with two whole cluster scenarios after this point; wedging here costs all of
# them, and a run that never reports is worse than one that reports red.
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
if grep -q "stale" < <(grep "node2" <<<"$OUT"); then
    PASS=$((PASS+1))
else
    # If node2 unpublished on shutdown, it might be gone entirely
    if ! grep -q "node2" <<<"$OUT"; then
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
# tests kill and restart a daemon on purpose, and a restart is the moment a
# daemon restores whatever its state directory holds.  Three fresh daemons, one
# fresh cluster directory, nothing borrowed.
#
# They used to need three HOMEs as well, and that was a workaround rather than
# isolation.  Every daemon in this file was reading one state directory derived
# from HOME alone, so the restart below restored node1's, node2's and the
# gateway's runtimes too — onto ports those three daemons were already serving.
# Separate HOMEs hid it.  The state directory is now keyed to the socket path,
# these three daemons are on three sockets, and the restart brings back the one
# runtime that belongs to it.
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

RJ_DIR="$TMPD/cluster2"; mkdir -p "$RJ_DIR"
RJ_PORT=$((SL_PORT_BASE+303))

wit() { SOCKETLEY_SOCKET="$SOCK_WIT" "$BIN" "$@"; }
rj()  { SOCKETLEY_SOCKET="$SOCK_RJ"  "$BIN" "$@"; }
intr(){ SOCKETLEY_SOCKET="$SOCK_IN"  "$BIN" "$@"; }

# spawn_daemon SOCKET LOG -> sets SPAWNED_PID
#
# By count of "daemon started", not by presence: the node in test 7 boots twice
# into the same log, and "has the line appeared" is already true the second
# time.  That returns instantly, before the socket is bound, and the readiness
# wait becomes a race the test loses at its own startup.
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

# ─── A restart restores this node's runtimes and nobody else's ───────────────
#
# The restart above is the only one in this file, which makes it the only place
# the state directory's ownership can be observed at all: restoring is what a
# daemon does with whatever its state directory holds, and nothing else in this
# suite starts a daemon that has runtimes waiting for it.
#
# This is asserted rather than arranged around.  Tests 7 and 8 used to be given
# three HOMEs of their own so that the question could not come up, and with
# those removed the question comes up on every run — but it did not fail
# anything on its own, which is why it needed writing down.  Measured here on a
# binary from before the state directory was keyed to the socket, one HOME:
#
#     PROBE  clst_rj    server 19303  Up 0 seconds     <- its own
#     PROBE  clst_api1  server 19301  Up 0 seconds     <- node1's, and node1 is serving it
#     PROBE  clst_gw    proxy  19310  Up 0 seconds     <- the gateway's, likewise
#
# Three daemons claiming two ports, and the file still reported 32/32 because no
# assertion had ever been pointed at it.  A `remove` on any of them would have
# deleted a state file belonging to a daemon that was still running it.
RJ_INV=$(rj ls -a 2>&1 || true)
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

# The target is `witness`, whose daemon has been up throughout and has never
# been killed — so nothing here depends on how test 7 went, and the holder is
# unambiguously a second, live, different daemon.  Same machine and same
# hostname as the intruder; what tells them apart is the control socket, and a
# unix socket path admits one process at a time.
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
