#!/bin/bash
# =============================================================================
# basic-cache.sh - In-Memory Key-Value Cache
# =============================================================================
#
# Creates a basic in-memory cache server.
#
# USAGE:
#   ./basic-cache.sh
#
# =============================================================================

set -e

echo "=== Basic Cache Example ==="
echo ""

echo "Creating cache server..."
socketley create cache my-cache \
    -p 9000 \
    -s

echo ""
echo "=== Cache Running ==="
echo ""
socketley ps
echo ""

echo "Cache server listening on port 9000"
echo ""
echo "Features:"
echo "  - In-memory key-value storage"
echo "  - Thread-safe operations"
echo "  - High-performance lookups"
echo ""
echo "Note: Data is lost when cache stops (use --persistent for persistence)"
echo ""
echo "Cleanup:"
echo "  socketley stop my-cache"
echo "  socketley remove my-cache"
