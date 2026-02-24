#!/bin/bash
# =============================================================================
# 04-managed-chat.sh - Managed Chat Server (Wrapper API)
# =============================================================================
#
# Demonstrates a managed external using the socketley::server wrapper.
# The wrapper handles io_uring, signal handling, and the event loop
# automatically — much simpler than raw POSIX sockets.
#
# USAGE:
#   ./04-managed-chat.sh
#
# WHAT IT SHOWS:
#   1. Build and register a wrapper-based binary
#   2. Send messages and see broadcast behavior
#   3. Kill the process — daemon auto-restarts it
#   4. Service is back up without manual intervention
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}/../.."

CLEANUP() {
    socketley stop chat 2>/dev/null || true
    socketley remove chat 2>/dev/null || true
    rm -f /tmp/chat-server
}

trap CLEANUP EXIT

echo "=== Managed Chat Server (Wrapper API) ==="
echo ""

# Build — requires libsocketley_sdk.a
echo "[1/6] Building chat-server..."
g++ -std=c++17 -O2 \
    -I"${ROOT_DIR}/include/linux" \
    "${SCRIPT_DIR}/chat-server.cpp" \
    -L"${ROOT_DIR}/bin/Release" -lsocketley_sdk -luring -lssl -lcrypto \
    -o /tmp/chat-server
echo "      Built /tmp/chat-server"

# Register and start
echo "[2/6] Adding managed runtime..."
socketley add /tmp/chat-server --name chat -s
sleep 0.5

echo ""
echo "=== Runtime Status ==="
socketley ls
echo ""

# Test: send two messages from different "clients"
echo "[3/6] Testing chat..."
REPLY1=$(echo "hello from Alice" | nc -w 1 localhost 7070)
REPLY2=$(echo "hello from Bob"   | nc -w 1 localhost 7070)
echo "      Reply 1: $REPLY1"
echo "      Reply 2: $REPLY2"
echo ""

# Kill and watch auto-restart
PID1=$(socketley ps 2>/dev/null | grep chat | awk '{print $NF}')
echo "[4/6] Killing process (PID $PID1)..."
kill -9 "$PID1" 2>/dev/null || true

echo "[5/6] Waiting for auto-restart (~3s)..."
sleep 3

PID2=$(socketley ps 2>/dev/null | grep chat | awk '{print $NF}')
echo ""
echo "=== After Auto-Restart ==="
socketley ps
echo ""

if [ "$PID1" != "$PID2" ] && [ -n "$PID2" ]; then
    echo "      Auto-restart OK! PID $PID1 -> $PID2"
else
    echo "      Warning: restart may not have completed yet"
fi

# Test again
echo ""
echo "[6/6] Testing restarted service..."
REPLY=$(echo "still chatting" | nc -w 1 localhost 7070)
echo "      Reply: $REPLY"

echo ""
echo "=== Done ==="
