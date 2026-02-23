#!/bin/bash
# =============================================================================
# RESP Mode (Redis-compatible) Example
# =============================================================================
# Shows how to use socketley cache with redis-cli and Redis client libraries.
#
# PREREQUISITES:
#   redis-cli (from redis-tools package)
#
# USAGE:
#   ./resp-mode.sh
# =============================================================================

set -e

echo "=== RESP Mode (Redis-compatible) Example ==="
echo ""

# Create RESP-mode cache on Redis default port
socketley create cache myredis -p 6379 --resp -s
sleep 0.3

echo "Cache created with RESP mode on port 6379."
echo ""

if command -v redis-cli &>/dev/null; then
    echo "Using redis-cli:"
    echo ""

    # String operations
    redis-cli -p 6379 SET greeting "Hello, World!"
    redis-cli -p 6379 GET greeting

    # List operations
    redis-cli -p 6379 RPUSH tasks "task1" "task2" "task3"
    redis-cli -p 6379 LRANGE tasks 0 -1

    # Hash operations
    redis-cli -p 6379 HSET user:1 name "Alice" age "30"
    redis-cli -p 6379 HGETALL user:1

    # Set operations
    redis-cli -p 6379 SADD tags "linux" "docker" "io_uring"
    redis-cli -p 6379 SMEMBERS tags

    # TTL
    redis-cli -p 6379 SET session abc123
    redis-cli -p 6379 EXPIRE session 300
    redis-cli -p 6379 TTL session

    # PING
    redis-cli -p 6379 PING
else
    echo "redis-cli not found. Install with: apt install redis-tools"
    echo ""
    echo "You can also use any Redis client library (Python redis, Node ioredis, etc.):"
    echo "  import redis"
    echo "  r = redis.Redis(port=6379)"
    echo "  r.set('key', 'value')"
    echo "  r.get('key')"
fi

echo ""

# Cleanup
socketley stop myredis
socketley remove myredis
echo "Done."
