#!/bin/bash
# =============================================================================
# 05-managed-counter.sh - Managed Counter Server (Wrapper API)
# =============================================================================
#
# Demonstrates a managed external using the socketley::server wrapper with
# per-connection metadata (set_data / get_data). Each message gets a
# per-connection sequence number in the reply.
#
# USAGE:
#   ./05-managed-counter.sh
#
# WHAT IT SHOWS:
#   1. Build and register a wrapper-based binary
#   2. Per-connection state via set_data/get_data
#   3. Full stop/start lifecycle — state resets on restart (in-memory)
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="${SCRIPT_DIR}/../.."

CLEANUP() {
    socketley stop counter 2>/dev/null || true
    socketley remove counter 2>/dev/null || true
    rm -f /tmp/counter-server
}

trap CLEANUP EXIT

echo "=== Managed Counter Server (Wrapper API) ==="
echo ""

# Build
echo "[1/5] Building counter-server..."
g++ -std=c++17 -O2 \
    -I"${ROOT_DIR}/include/linux" \
    "${SCRIPT_DIR}/counter-server.cpp" \
    -L"${ROOT_DIR}/bin/Release" -lsocketley_sdk -luring -lssl -lcrypto \
    -o /tmp/counter-server
echo "      Built /tmp/counter-server"

# Register and start
echo "[2/5] Adding managed runtime..."
socketley add /tmp/counter-server --name counter -s
sleep 0.5

echo ""
echo "=== Runtime Status ==="
socketley ls
echo ""

# Send multiple messages — each gets an incrementing counter
echo "[3/5] Testing counter..."
R1=$(echo "first"  | nc -w 1 localhost 7071)
R2=$(echo "second" | nc -w 1 localhost 7071)
R3=$(echo "third"  | nc -w 1 localhost 7071)
echo "      $R1"
echo "      $R2"
echo "      $R3"
echo ""

# Stop and restart — counter resets (in-memory state)
echo "[4/5] Stop/start cycle..."
socketley stop counter
sleep 0.3
echo "      Stopped."
socketley start counter
sleep 0.5
echo "      Restarted."
echo ""

# Counter should be back to #1 after restart
echo "[5/5] Testing after restart (counter should reset)..."
R1=$(echo "hello again" | nc -w 1 localhost 7071)
echo "      $R1"

echo ""
echo "=== Done ==="
