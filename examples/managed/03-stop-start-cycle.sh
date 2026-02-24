#!/bin/bash
# =============================================================================
# 03-stop-start-cycle.sh - Full Lifecycle: Add, Stop, Start, Remove
# =============================================================================
#
# Demonstrates the complete lifecycle of a managed external runtime.
# Unlike plain `attach` (where stop just forgets the process), managed
# runtimes can be stopped and restarted like native socketley runtimes.
#
# USAGE:
#   ./03-stop-start-cycle.sh
#
# LIFECYCLE:
#   add  → daemon knows about the binary (created state)
#   -s   → daemon fork+exec's it (running state)
#   stop → daemon sends SIGTERM (stopped state, binary exits)
#   start→ daemon fork+exec's again (running state, new PID)
#   remove → unregister completely
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

CLEANUP() {
    socketley stop lifecycle 2>/dev/null || true
    socketley remove lifecycle 2>/dev/null || true
    rm -f /tmp/echo-service
}

trap CLEANUP EXIT

echo "=== Lifecycle Demo ==="
echo ""

# Build
g++ -std=c++17 -O2 \
    -I"${SCRIPT_DIR}/../../include/linux" \
    "${SCRIPT_DIR}/echo-service.cpp" \
    -o /tmp/echo-service

# Add without starting (-s omitted)
echo "[1/6] socketley add /tmp/echo-service --name lifecycle"
socketley add /tmp/echo-service --name lifecycle
echo "      Status: created (not running yet)"
socketley ls
echo ""

# Start
echo "[2/6] socketley start lifecycle"
socketley start lifecycle
sleep 0.5
echo "      Status: running"
socketley ps
echo ""

# Test
echo "[3/6] Testing..."
REPLY=$(echo "hello" | nc -w 1 localhost 7070)
echo "      Echo reply: $REPLY"
echo ""

# Stop
echo "[4/6] socketley stop lifecycle"
socketley stop lifecycle
sleep 0.3
echo "      Status: stopped"
socketley ls
echo ""

# Start again
echo "[5/6] socketley start lifecycle"
socketley start lifecycle
sleep 0.5
echo "      Status: running again (new PID)"
socketley ps
echo ""

# Test again
REPLY=$(echo "hello again" | nc -w 1 localhost 7070)
echo "      Echo reply: $REPLY"
echo ""

# Remove
echo "[6/6] socketley remove lifecycle"
socketley stop lifecycle 2>/dev/null || true
sleep 0.3
socketley remove lifecycle
echo "      Removed."
socketley ls
echo ""

echo "=== Lifecycle complete ==="
