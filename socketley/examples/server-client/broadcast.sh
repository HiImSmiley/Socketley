#!/bin/bash
# =============================================================================
# broadcast.sh - One-to-Many Broadcasting
# =============================================================================
#
# Creates a server with multiple clients. Messages sent to the server
# are broadcast to all connected clients.
#
# USAGE:
#   ./broadcast.sh
#
# =============================================================================

set -e

echo "=== Broadcast Example ==="
echo ""

# Create broadcast server
echo "[1/4] Creating broadcast server..."
socketley create server broadcast-hub \
    -p 9000 \
    --mode inout \
    -s

# Create multiple clients
echo "[2/4] Creating client 1..."
socketley create client client-1 \
    -t 127.0.0.1:9000 \
    -w /tmp/client-1-messages.txt \
    -s

echo "[3/4] Creating client 2..."
socketley create client client-2 \
    -t 127.0.0.1:9000 \
    -w /tmp/client-2-messages.txt \
    -s

echo "[4/4] Creating client 3..."
socketley create client client-3 \
    -t 127.0.0.1:9000 \
    -w /tmp/client-3-messages.txt \
    -s

echo ""
echo "=== Broadcast Setup Complete ==="
echo ""
socketley ps
echo ""

echo "Architecture:"
echo ""
echo "  [client-1] ─┐"
echo "              │"
echo "  [client-2] ─┼── [broadcast-hub:9000]"
echo "              │"
echo "  [client-3] ─┘"
echo ""
echo "Messages received by the server are broadcast to ALL clients."
echo ""
echo "Test: Connect with 'nc localhost 9000' and send a message."
echo "      Check /tmp/client-*-messages.txt to see broadcasts."
echo ""
echo "Cleanup:"
echo "  socketley stop client-1 client-2 client-3 broadcast-hub"
echo "  socketley remove client-1 client-2 client-3 broadcast-hub"
