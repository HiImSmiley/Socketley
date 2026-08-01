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

# ─── Summary ──────────────────────────────────────────────────────────────────

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
