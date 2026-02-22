#!/bin/bash
# =============================================================================
# Local Cluster Discovery Demo
# =============================================================================
#
# Demonstrates multi-daemon cluster discovery without Docker.
# Uses a temporary directory as the shared cluster volume.
#
# Two daemons each run a server in group "api".
# A third daemon runs a proxy with @api backend.
# The proxy discovers both servers via the shared directory.

set -e

CLUSTER_DIR=$(mktemp -d)
echo "Cluster directory: $CLUSTER_DIR"

cleanup() {
    echo "Cleaning up..."
    kill $DAEMON1_PID $DAEMON2_PID $DAEMON3_PID 2>/dev/null || true
    rm -rf "$CLUSTER_DIR"
}
trap cleanup EXIT

# Start three daemons (in real usage, these would be in separate containers)
# Note: Each daemon needs its own socket path, so we use different SOCKETLEY_HOME dirs

export SOCKETLEY_DEV=1

echo "Starting daemon node1..."
SOCKETLEY_SOCKET=/tmp/socketley-node1.sock \
socketley daemon --name node1 --cluster "$CLUSTER_DIR" &
DAEMON1_PID=$!
sleep 0.5

echo "Starting daemon node2..."
SOCKETLEY_SOCKET=/tmp/socketley-node2.sock \
socketley daemon --name node2 --cluster "$CLUSTER_DIR" &
DAEMON2_PID=$!
sleep 0.5

echo "Starting daemon gateway..."
SOCKETLEY_SOCKET=/tmp/socketley-gateway.sock \
socketley daemon --name gateway --cluster "$CLUSTER_DIR" &
DAEMON3_PID=$!
sleep 0.5

# Create runtimes on each daemon
echo ""
echo "Creating server api1 on node1 (port 9001, group: api)..."
SOCKETLEY_SOCKET=/tmp/socketley-node1.sock \
socketley create server api1 -p 9001 -g api -s

echo "Creating server api2 on node2 (port 9002, group: api)..."
SOCKETLEY_SOCKET=/tmp/socketley-node2.sock \
socketley create server api2 -p 9002 -g api -s

# Wait for cluster discovery to pick up remote runtimes
sleep 3

echo "Creating proxy gw on gateway (port 8080, backend: @api)..."
SOCKETLEY_SOCKET=/tmp/socketley-gateway.sock \
socketley create proxy gw -p 8080 --backend @api --protocol tcp -s

echo ""
echo "=== Cluster State ==="
socketley cluster "$CLUSTER_DIR" ps

echo ""
echo "=== Cluster Stats ==="
socketley cluster "$CLUSTER_DIR" stats

echo ""
echo "=== Group 'api' Members ==="
socketley cluster "$CLUSTER_DIR" group api

echo ""
echo "Proxy is running on port 8080, routing to api1:9001 and api2:9002"
echo "Press Ctrl+C to stop"

wait
