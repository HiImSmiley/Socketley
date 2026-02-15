#!/bin/bash
# =============================================================================
# Cache Pub/Sub Example
# =============================================================================
# Demonstrates publish/subscribe messaging through the cache runtime.
#
# USAGE:
#   ./pubsub.sh
# =============================================================================

set -e

echo "=== Cache Pub/Sub Example ==="
echo ""

# Create cache
socketley create cache pubstore -p 9000 -s
sleep 0.3

echo "Cache created. Starting subscriber in background..."

# Subscribe in background
(echo "subscribe news"; sleep 10) | nc -q 11 localhost 9000 &
SUB_PID=$!
sleep 0.3

echo "Publishing messages..."

# Publish messages
echo "publish news first-message" | nc -q 1 localhost 9000
echo "publish news second-message" | nc -q 1 localhost 9000

sleep 1
kill $SUB_PID 2>/dev/null || true

echo ""
echo "Multiple channels:"
echo "  echo 'subscribe alerts' | nc localhost 9000"
echo "  echo 'publish alerts critical-error' | nc localhost 9000"
echo ""

# Cleanup
socketley stop pubstore
socketley remove pubstore
echo "Done."
