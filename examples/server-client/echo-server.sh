#!/bin/bash
# =============================================================================
# echo-server.sh - Echo Server Pattern
# =============================================================================
#
# Creates a server that echoes messages back. This is implemented using
# Lua callbacks to intercept and respond to incoming messages.
#
# USAGE:
#   ./echo-server.sh
#
# =============================================================================

set -e

echo "=== Echo Server Example ==="
echo ""

# Create Lua config for echo behavior
cat > /tmp/echo-server.lua << 'EOF'
-- Echo Server Lua Configuration
-- Every received message is echoed back to all clients

function on_message(msg)
    socketley.log("Received: " .. msg)
    -- Echo back to all connected clients
    self.broadcast(msg)
end

function on_start()
    socketley.log("Echo server started on port " .. self.port)
end

function on_stop()
    socketley.log("Echo server stopped")
end
EOF

echo "Creating echo server with Lua callbacks..."

socketley create server echo-server \
    -p 9000 \
    --lua /tmp/echo-server.lua \
    -s

echo ""
echo "=== Echo Server Running ==="
echo ""
echo "Test with netcat:"
echo "  nc localhost 9000"
echo "  Type a message and press Enter - it will be echoed back!"
echo ""
echo "Stop: socketley stop echo-server"
echo "Remove: socketley remove echo-server"
