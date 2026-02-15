#!/bin/bash
# =============================================================================
# Stats & Monitoring Example
# =============================================================================
# Shows how to monitor runtime statistics and hot-reload Lua scripts.
#
# USAGE:
#   ./stats-monitoring.sh
# =============================================================================

set -e

echo "=== Stats & Monitoring Example ==="
echo ""

# Create server
socketley create server api -p 9000 -s
sleep 0.3

# Generate some traffic
for i in $(seq 1 5); do
    echo "msg $i" | nc -q 0 localhost 9000 2>/dev/null &
done
sleep 1

echo "Server stats:"
socketley stats api
echo ""

# Create cache with maxmemory
socketley create cache store -p 9001 --maxmemory 10M --eviction allkeys-lru -s
sleep 0.3

# Write some data
for i in $(seq 1 10); do
    echo "set key$i value$i" | nc -q 0 localhost 9001 2>/dev/null
done
sleep 0.3

echo "Cache stats:"
socketley stats store
echo ""

# Cleanup
socketley stop api store
socketley remove api store
echo "Done."
