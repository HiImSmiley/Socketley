#!/usr/bin/env bash
# Integration test: multi-daemon cluster discovery
#
# Starts 3 daemons on localhost with separate sockets and a shared cluster
# directory, then verifies discovery, group resolution, and proxy @group routing.
#
# NOTE: All daemons share the same state directory (/var/lib/socketley/runtimes),
# so runtime names must be globally unique and explicitly cleaned up.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
PASS=0; FAIL=0; TOTAL=0

CLUSTER_DIR=$(mktemp -d)
SOCK_NODE1="/tmp/socketley-cluster-node1.sock"
SOCK_NODE2="/tmp/socketley-cluster-node2.sock"
SOCK_GW="/tmp/socketley-cluster-gw.sock"
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
    # Stop and remove runtimes (via whichever daemon owns them)
    for cmd in node1 node2 gw; do
        for rt in "$RT_API1" "$RT_API2" "$RT_GW"; do
            $cmd stop "$rt" &>/dev/null
        done
    done
    sleep 0.5
    for cmd in node1 node2 gw; do
        for rt in "$RT_API1" "$RT_API2" "$RT_GW"; do
            $cmd remove "$rt" &>/dev/null
        done
    done

    # Kill daemons
    for pid in "${DAEMON_PIDS[@]}"; do
        [ "$pid" = "0" ] && continue
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    done
    rm -f "$SOCK_NODE1" "$SOCK_NODE2" "$SOCK_GW"
    rm -rf "$CLUSTER_DIR"
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

SOCKETLEY_SOCKET="$SOCK_NODE1" "$BIN" daemon \
    --name node1 --cluster "$CLUSTER_DIR" --cluster-addr 127.0.0.1 2>/dev/null &
DAEMON_PIDS+=($!)
sleep 0.3

SOCKETLEY_SOCKET="$SOCK_NODE2" "$BIN" daemon \
    --name node2 --cluster "$CLUSTER_DIR" --cluster-addr 127.0.0.1 2>/dev/null &
DAEMON_PIDS+=($!)
sleep 0.3

SOCKETLEY_SOCKET="$SOCK_GW" "$BIN" daemon \
    --name gateway --cluster "$CLUSTER_DIR" --cluster-addr 127.0.0.1 2>/dev/null &
DAEMON_PIDS+=($!)
sleep 0.5

# Verify all sockets exist
for sock in "$SOCK_NODE1" "$SOCK_NODE2" "$SOCK_GW"; do
    if [ ! -S "$sock" ]; then
        echo "ERROR: daemon socket $sock not created"
        exit 1
    fi
done

# ─── Create runtimes ──────────────────────────────────────────────────────────

node1 create server "$RT_API1" -p "$NODE1_PORT" -g api -s 2>&1 || true
node2 create server "$RT_API2" -p "$NODE2_PORT" -g api -s 2>&1 || true

# Wait for cluster heartbeat cycle (publish every 2s)
sleep 3

# ─── Test 1: Daemon discovery (cluster ls) ─────────────────────────────────────

echo "  Test 1: daemon discovery"
OUT=$("$BIN" cluster "$CLUSTER_DIR" ls 2>&1)
assert_contains "$OUT" "node1"
assert_contains "$OUT" "node2"
assert_contains "$OUT" "gateway"

# ─── Test 2: Runtime visibility (cluster ps) ───────────────────────────────────

echo "  Test 2: runtime visibility"
OUT=$("$BIN" cluster "$CLUSTER_DIR" ps 2>&1)
assert_contains "$OUT" "$RT_API1"
assert_contains "$OUT" "$RT_API2"

# ─── Test 3: Group resolution (cluster group api) ─────────────────────────────

echo "  Test 3: group resolution"
OUT=$("$BIN" cluster "$CLUSTER_DIR" group api 2>&1)
assert_contains "$OUT" "node1"
assert_contains "$OUT" "node2"
assert_contains "$OUT" "$NODE1_PORT"
assert_contains "$OUT" "$NODE2_PORT"

# ─── Test 4: Cluster stats ────────────────────────────────────────────────────

echo "  Test 4: cluster stats"
OUT=$("$BIN" cluster "$CLUSTER_DIR" stats 2>&1)
assert_contains "$OUT" "3 healthy"
assert_contains "$OUT" "api"
assert_contains "$OUT" "2 members"

# ─── Test 5: Proxy @group routing ──────────────────────────────────────────────

echo "  Test 5: proxy @group routing"
gw create proxy "$RT_GW" -p "$GW_PORT" \
    --backend @api --protocol tcp --strategy round-robin -s 2>&1 || true
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

OUT=$("$BIN" cluster "$CLUSTER_DIR" ls 2>&1)
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
