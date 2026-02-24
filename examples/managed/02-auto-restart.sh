#!/bin/bash
# =============================================================================
# 02-auto-restart.sh - Daemon Auto-Restarts Crashed Managed Binaries
# =============================================================================
#
# Demonstrates the key advantage of managed externals over plain `attach`:
# when the binary crashes or is killed, the daemon automatically restarts it
# within ~2 seconds via its health-check timer.
#
# USAGE:
#   ./02-auto-restart.sh
#
# WHAT IT SHOWS:
#   1. Register and start a managed binary
#   2. Kill the process (simulating a crash)
#   3. The daemon detects the dead process and fork+exec's a new one
#   4. The service is back up without manual intervention
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

CLEANUP() {
    echo ""
    echo "=== Cleaning up ==="
    socketley stop crash-test 2>/dev/null || true
    socketley remove crash-test 2>/dev/null || true
    rm -f /tmp/echo-service
    echo "Done!"
}

trap CLEANUP EXIT

echo "=== Auto-Restart Demo ==="
echo ""

# Build and register
echo "[1/5] Building echo-service..."
g++ -std=c++17 -O2 \
    -I"${SCRIPT_DIR}/../../include/linux" \
    "${SCRIPT_DIR}/echo-service.cpp" \
    -o /tmp/echo-service

echo "[2/5] Adding managed runtime..."
socketley add /tmp/echo-service --name crash-test -s
sleep 0.5

# Show PID
echo ""
echo "=== Before Kill ==="
socketley ps
PID1=$(socketley ps 2>/dev/null | grep crash-test | awk '{print $NF}')
echo ""
echo "Current PID: $PID1"

# Kill the process (simulating a crash)
echo ""
echo "[3/5] Killing the process (simulating crash)..."
kill -9 "$PID1" 2>/dev/null || true

# Wait for the health check to detect and restart (2s timer + startup time)
echo "[4/5] Waiting for daemon to detect and restart (~3s)..."
sleep 3

# Verify it's back up with a new PID
echo ""
echo "=== After Auto-Restart ==="
socketley ps
PID2=$(socketley ps 2>/dev/null | grep crash-test | awk '{print $NF}')
echo ""
echo "New PID: $PID2"

if [ "$PID1" != "$PID2" ] && [ -n "$PID2" ]; then
    echo "Auto-restart successful! PID changed from $PID1 to $PID2"
else
    echo "Warning: restart may not have completed yet"
fi

# Test that the new instance works
echo ""
echo "[5/5] Testing restarted service..."
REPLY=$(echo "still alive" | nc -w 1 localhost 7070)
echo "Sent:     still alive"
echo "Received: $REPLY"
echo ""

echo "Press Enter to cleanup..."
read -r
