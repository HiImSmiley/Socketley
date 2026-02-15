#!/bin/bash
# =============================================================================
# cache-datastructures.sh - Extended Data Structures Demo
# =============================================================================
#
# Demonstrates lists, sets, hashes, and TTL/expiry features.
#
# USAGE:
#   ./cache-datastructures.sh
#
# REQUIRES: socketley daemon running, netcat installed
#
# =============================================================================

set -e

PORT=9200
CACHE=ds-demo

echo "=== Cache Data Structures Demo ==="
echo ""

# Create cache with persistence
socketley create cache $CACHE -p $PORT --persistent /tmp/ds-demo.bin --mode admin -s
echo "Cache '$CACHE' created on port $PORT"
echo ""

# --- Strings ---
echo "--- Strings ---"
echo -e "set user:1 alice\nset user:2 bob\nget user:1\nget user:2" | nc -q1 localhost $PORT
echo ""

# --- Lists (task queue) ---
echo "--- Lists (Task Queue) ---"
echo -e "rpush tasks build\nrpush tasks test\nrpush tasks deploy\nllen tasks\nlrange tasks 0 -1" | nc -q1 localhost $PORT
echo ""
echo "Pop next task:"
echo "lpop tasks" | nc -q1 localhost $PORT
echo ""

# --- Sets (tags) ---
echo "--- Sets (Tags) ---"
echo -e "sadd tags:project linux\nsadd tags:project networking\nsadd tags:project io-uring\nsadd tags:project linux\nscard tags:project\nsmembers tags:project" | nc -q1 localhost $PORT
echo ""

# --- Hashes (user profile) ---
echo "--- Hashes (User Profile) ---"
echo -e "hset profile:alice name Alice\nhset profile:alice role admin\nhset profile:alice team infra\nhgetall profile:alice\nhlen profile:alice" | nc -q1 localhost $PORT
echo ""

# --- TTL ---
echo "--- TTL (Session Expiry) ---"
echo -e "set session:abc token123\nexpire session:abc 30\nttl session:abc" | nc -q1 localhost $PORT
echo ""

# --- Type enforcement ---
echo "--- Type Enforcement ---"
echo -e "set typetest hello\nlpush typetest world" | nc -q1 localhost $PORT
echo "(lpush on string key returns 'error: type conflict')"
echo ""

# --- Size (counts all types) ---
echo "--- Total Keys ---"
echo "size" | nc -q1 localhost $PORT
echo ""

# --- Persistence ---
echo "--- Persistence ---"
echo "flush" | nc -q1 localhost $PORT
echo "Saved to /tmp/ds-demo.bin"
echo ""

# --- CLI Actions ---
echo "--- CLI Actions ---"
socketley $CACHE hset profile:bob name Bob
socketley $CACHE hget profile:bob name
socketley $CACHE lpush tasks hotfix
socketley $CACHE llen tasks
echo ""

echo "=== Demo Complete ==="
echo ""
echo "Cleanup:"
echo "  socketley stop $CACHE"
echo "  socketley remove $CACHE"
echo "  rm -f /tmp/ds-demo.bin"
