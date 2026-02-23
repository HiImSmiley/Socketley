#!/bin/bash
# =============================================================================
# 02-hello-client.sh - Your First Socketley Client
# =============================================================================
#
# This example creates a client that connects to a server.
# Note: A server must be running first (see 01-hello-server.sh)
#
# USAGE:
#   ./02-hello-client.sh
#
# FLAGS DEMONSTRATED:
#   -t <host:port>   Target server to connect to
#   -s               Start immediately
#   --log            Log state transitions
#
# =============================================================================

set -e

echo "=== Creating Hello Client ==="
echo ""
echo "Note: Make sure hello-server is running on port 9000"
echo ""

# Create a client named "hello-client" connecting to localhost:9000
# -t 127.0.0.1:9000  : Connect to this server
# -s                 : Start immediately

socketley create client hello-client \
    -t 127.0.0.1:9000 \
    -s \
    --log /tmp/hello-client.log

echo ""
echo "Client created and connected!"
echo ""

# Check status
echo "=== Runtime Status ==="
socketley ps

echo ""
echo "=== Client connected to 127.0.0.1:9000 ==="
echo ""
echo "View logs: cat /tmp/hello-client.log"
echo ""
echo "Stop with: socketley stop hello-client"
echo "Remove with: socketley remove hello-client"
