#!/bin/bash
# =============================================================================
# bidirectional.sh - Full Duplex Communication
# =============================================================================
#
# Creates a chat-like setup where server and clients can both
# send and receive messages freely.
#
# USAGE:
#   ./bidirectional.sh
#
# =============================================================================

set -e

echo "=== Bidirectional Communication Example ==="
echo ""

# Create Lua config for logging
cat > /tmp/chat-server.lua << 'EOF'
function on_message(msg)
    socketley.log("[MSG] " .. msg)
    -- Broadcast to all other clients
    self.broadcast("[" .. os.date("%H:%M:%S") .. "] " .. msg)
end

function on_start()
    socketley.log("Chat server started")
end
EOF

cat > /tmp/chat-client.lua << 'EOF'
function on_message(msg)
    socketley.log("Received: " .. msg)
end

function on_start()
    socketley.log("Connected to chat")
end
EOF

echo "Creating chat server..."
socketley create server chat-server \
    -p 9000 \
    --lua /tmp/chat-server.lua \
    -s

echo "Creating chat clients..."
socketley create client alice \
    -t 127.0.0.1:9000 \
    --lua /tmp/chat-client.lua \
    -w /tmp/alice-chat.txt \
    -s

socketley create client bob \
    -t 127.0.0.1:9000 \
    --lua /tmp/chat-client.lua \
    -w /tmp/bob-chat.txt \
    -s

echo ""
echo "=== Chat Setup Complete ==="
echo ""
socketley ps
echo ""

echo "Architecture:"
echo ""
echo "  [alice] ←──────→ [chat-server:9000] ←──────→ [bob]"
echo ""
echo "Messages flow both ways. Server broadcasts to all clients."
echo ""
echo "Watch the chat logs:"
echo "  tail -f /tmp/alice-chat.txt"
echo "  tail -f /tmp/bob-chat.txt"
echo ""
echo "Test: Connect as a third user with 'nc localhost 9000'"
echo ""
echo "Cleanup:"
echo "  socketley stop alice bob chat-server"
echo "  socketley remove alice bob chat-server"
