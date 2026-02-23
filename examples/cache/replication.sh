#!/bin/bash
# =============================================================================
# Cache Replication Example
# =============================================================================
# Leader-follower replication: writes on leader are replicated to followers.
#
# USAGE:
#   ./replication.sh
# =============================================================================

set -e

echo "=== Cache Replication Example ==="
echo ""

# Create leader
socketley create cache leader -p 9000 -s
sleep 0.3

# Create follower
socketley create cache follower -p 9001 --replicate 127.0.0.1:9000 -s
sleep 0.5

echo "Leader on :9000, Follower on :9001"
echo ""

# Write to leader
echo "Writing to leader..."
echo "set user alice" | nc -q 1 localhost 9000
echo "set score 100" | nc -q 1 localhost 9000
echo "lpush queue task1" | nc -q 1 localhost 9000
echo "lpush queue task2" | nc -q 1 localhost 9000

sleep 0.5

# Read from follower
echo "Reading from follower..."
echo -n "  user = "; echo "get user" | nc -q 1 localhost 9001
echo -n "  score = "; echo "get score" | nc -q 1 localhost 9001
echo -n "  queue length = "; echo "llen queue" | nc -q 1 localhost 9001

echo ""
echo "Replication stats:"
socketley stats leader 2>/dev/null | grep repl || echo "  (check socketley stats leader)"
socketley stats follower 2>/dev/null | grep repl || echo "  (check socketley stats follower)"

echo ""

# Cleanup
socketley stop follower leader
socketley remove follower leader
echo "Done."
