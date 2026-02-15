#!/bin/bash
# =============================================================================
# 01-hello-server.sh - Your First Socketley Server
# =============================================================================
#
# This example creates a simple TCP server listening on port 9000.
#
# USAGE:
#   ./01-hello-server.sh
#
# FLAGS DEMONSTRATED:
#   -p <port>   Set the listening port
#   -s          Start immediately after creation
#   --log       Log state transitions to a file
#
# =============================================================================

set -e

echo "=== Creating Hello Server ==="
echo ""

# Create a server named "hello-server" on port 9000
# -p 9000  : Listen on port 9000
# -s       : Start immediately (don't need separate 'run' command)
# --log    : Log state changes to file

socketley create server hello-server \
    -p 9000 \
    -s \
    --log /tmp/hello-server.log

echo ""
echo "Server created and started!"
echo ""

# Check status
echo "=== Runtime Status ==="
socketley ls

echo ""
echo "=== Server is listening on port 9000 ==="
echo ""
echo "Test with: nc localhost 9000"
echo "Or connect a client from another terminal."
echo ""
echo "View logs: cat /tmp/hello-server.log"
echo ""
echo "Stop with: socketley stop hello-server"
echo "Remove with: socketley remove hello-server"
