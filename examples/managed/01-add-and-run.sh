#!/bin/bash
# =============================================================================
# 01-add-and-run.sh - Register and Start a Managed External Binary
# =============================================================================
#
# This example compiles a C++ echo service and registers it with the daemon
# using `socketley add`. The daemon fork+exec's the binary, manages its
# lifecycle, and auto-restarts it on crash.
#
# USAGE:
#   ./01-add-and-run.sh
#
# COMMANDS DEMONSTRATED:
#   socketley add <path> -s          Register + start immediately
#   socketley add <path> --name X    Register with a custom name
#   socketley ls                     Verify the runtime appears
#   socketley stop <name>            Daemon sends SIGTERM to binary
#   socketley start <name>           Daemon re-launches the binary
#   socketley remove <name>          Unregister completely
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

CLEANUP() {
    echo ""
    echo "=== Cleaning up ==="
    socketley stop echo-svc 2>/dev/null || true
    socketley remove echo-svc 2>/dev/null || true
    rm -f /tmp/echo-service
    echo "Done!"
}

trap CLEANUP EXIT

echo "=== Managed External Runtime Demo ==="
echo ""

# Step 1: Build the echo service
echo "[1/4] Building echo-service..."
g++ -std=c++17 -O2 \
    -I"${SCRIPT_DIR}/../../include/linux" \
    "${SCRIPT_DIR}/echo-service.cpp" \
    -o /tmp/echo-service
echo "      Built /tmp/echo-service"

# Step 2: Register with the daemon and start immediately
# --name gives it a friendly name (default would be "echo-service" from filename)
# -s starts it right away
echo "[2/4] Adding managed runtime..."
socketley add /tmp/echo-service --name echo-svc -s

echo "[3/4] Waiting for binary to start..."
sleep 0.5

# Step 3: Verify it's running
echo ""
echo "=== Runtime Status ==="
socketley ls
echo ""

# Step 4: Test the echo server
echo "=== Testing Echo ==="
REPLY=$(echo "hello managed world" | nc -w 1 localhost 7070)
echo "Sent:     hello managed world"
echo "Received: $REPLY"
echo ""

echo "=== Demo running ==="
echo "Try:  echo 'test' | nc -w 1 localhost 7070"
echo ""
echo "Press Enter to stop and cleanup..."
read -r
