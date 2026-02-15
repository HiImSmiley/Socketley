#!/bin/bash
# =============================================================================
# 03-combined.sh - Server and Client Together
# =============================================================================
#
# This example creates both a server and client, demonstrating
# a complete communication setup.
#
# USAGE:
#   ./03-combined.sh
#
# FLAGS DEMONSTRATED:
#   -p <port>        Set port
#   -t <host:port>   Target server (client only)
#   -s               Start immediately
#   -w <file>        Write all messages to file
#
# =============================================================================

set -e

CLEANUP() {
    echo ""
    echo "=== Cleaning up ==="
    socketley stop demo-client 2>/dev/null || true
    socketley stop demo-server 2>/dev/null || true
    socketley remove demo-client 2>/dev/null || true
    socketley remove demo-server 2>/dev/null || true
    echo "Done!"
}

# Cleanup on script exit
trap CLEANUP EXIT

echo "=== Combined Server + Client Demo ==="
echo ""

# Step 1: Create server
echo "[1/4] Creating server on port 9000..."
socketley create server demo-server \
    -p 9000 \
    -w /tmp/demo-server-messages.txt \
    --log /tmp/demo-server.log

# Step 2: Start server
echo "[2/4] Starting server..."
socketley start demo-server

# Step 3: Create client
echo "[3/4] Creating client..."
socketley create client demo-client \
    -t 127.0.0.1:9000 \
    -w /tmp/demo-client-messages.txt \
    --log /tmp/demo-client.log

# Step 4: Start client
echo "[4/4] Starting client..."
socketley start demo-client

echo ""
echo "=== Setup Complete ==="
echo ""

# Show status
echo "Running runtimes:"
socketley ps

echo ""
echo "=== Files Created ==="
echo "Server log:      /tmp/demo-server.log"
echo "Server messages: /tmp/demo-server-messages.txt"
echo "Client log:      /tmp/demo-client.log"
echo "Client messages: /tmp/demo-client-messages.txt"
echo ""

echo "Press Enter to stop and cleanup..."
read -r
