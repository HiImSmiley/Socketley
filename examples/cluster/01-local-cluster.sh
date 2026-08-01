#!/usr/bin/env bash
# =============================================================================
# Local Cluster Discovery Demo
# =============================================================================
#
# Three daemons on one machine, each with a server or proxy, discovering each
# other through a temporary directory used as the shared "volume".
#
# This is a SIMULATION of docker-compose.yml in this directory, not the same
# thing.  Three daemons in one filesystem namespace need three socket paths, so
# every command here carries SOCKETLEY_SOCKET; a real cluster member is a
# container or a host, has a namespace to itself, runs on the DEFAULT socket
# and finds its peers through the cluster directory and the network addresses
# advertised in it.  Anything that depends on the namespaces being separate is
# invisible here — which is why test/docker/test_cluster_docker.sh exists.
#
# Usage: bash examples/cluster/01-local-cluster.sh
set -euo pipefail

BIN="${BIN:-socketley}"
command -v "$BIN" >/dev/null 2>&1 || {
    echo "socketley not found — set BIN=/path/to/socketley" >&2
    exit 1
}

# Everything this demo touches is per-run, including HOME.  The state directory
# is derived from HOME, and three daemons sharing one state directory share
# runtime names, each other's leftovers and the was_running auto-restart —
# so the second run of this file would be driving the first run's state.
TMPD=$(mktemp -d /tmp/socketley-cluster-demo-XXXXXX)
export HOME="$TMPD/home"
mkdir -p "$HOME"
CLUSTER_DIR="$TMPD/cluster"
mkdir -p "$CLUSTER_DIR"

echo "Cluster directory: $CLUSTER_DIR"

PIDS=()
cleanup() {
    echo ""
    echo "Cleaning up..."
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && wait "$pid" 2>/dev/null || true
    done
    rm -rf "$TMPD"
}
trap cleanup EXIT

# ─── Starting a node ─────────────────────────────────────────────────────────
#
# `socketley daemon --name X --cluster D` is NOT a second daemon.  It is a
# configuration command against the daemon that is already running, and like
# every other socketley command it auto-starts a detached daemon of its own if
# the socket does not answer yet.  This file used to `sleep 0.3` between the
# two, which is a race: lose it and a second daemon is forked that nothing has
# the pid of, it outlives the demo, and it goes on heartbeating into whatever
# cluster directory it was given.
#
# So wait for the daemon's own "daemon started" line, which it prints once the
# IPC socket is bound and any persisted state is restored.
start_node() {   # start_node NAME
    # Separate statements, not one `local a=1 b=$a`: every word on a command
    # line is expanded before the builtin runs, so $name in a sibling
    # assignment is still unset and `set -u` kills the script there.
    local name=$1
    local sock="$TMPD/$name.sock"
    local log="$TMPD/$name.log"
    local i

    SOCKETLEY_SOCKET="$sock" "$BIN" daemon >"$log" 2>&1 &
    PIDS+=($!)

    for i in $(seq 1 100); do
        grep -q "daemon started" "$log" 2>/dev/null && break
        sleep 0.1
    done
    if [ ! -S "$sock" ]; then
        echo "ERROR: daemon $name never came up on $sock" >&2
        tail -5 "$log" 2>/dev/null | sed 's/^/    /' >&2
        exit 1
    fi

    SOCKETLEY_SOCKET="$sock" "$BIN" daemon --name "$name" --cluster "$CLUSTER_DIR"
}

node() {   # node NAME ARGS...
    local name=$1; shift
    SOCKETLEY_SOCKET="$TMPD/$name.sock" "$BIN" "$@"
}

echo "Starting daemon node1..."
start_node node1
echo "Starting daemon node2..."
start_node node2
echo "Starting daemon gateway..."
start_node gateway

echo ""
echo "Creating server api1 on node1 (port 9001, group: api)..."
node node1 create server api1 -p 9001 -g api -s

echo "Creating server api2 on node2 (port 9002, group: api)..."
node node2 create server api2 -p 9002 -g api -s

# One publish interval, so every node has written its file and read the others'.
sleep 3

echo "Creating proxy gw on gateway (port 8080, backend: @api)..."
node gateway create proxy gw -p 8080 --backend @api --protocol tcp -s

echo ""
echo "=== Cluster State ==="
node gateway cluster ps

echo ""
echo "=== Cluster Stats ==="
node gateway cluster stats

echo ""
echo "=== Group 'api' Members ==="
node gateway cluster group api

echo ""
echo "Proxy is running on port 8080, routing to api1:9001 and api2:9002."
echo "Send it something and watch the backends' counters move:"
echo ""
echo "    printf 'hello\\n' | nc 127.0.0.1 8080"
echo "    SOCKETLEY_SOCKET=$TMPD/node1.sock $BIN stats api1"
echo "    SOCKETLEY_SOCKET=$TMPD/node2.sock $BIN stats api2"
echo ""
echo "A server in the default inout mode relays a message to its OTHER clients"
echo "and answers the sender nothing, so the reply is empty by design; the"
echo "total_connections counters are what show where the request went."
echo ""
echo "Press Ctrl+C to stop"

wait
