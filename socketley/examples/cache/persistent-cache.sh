#!/bin/bash
# =============================================================================
# persistent-cache.sh - Cache with File Persistence
# =============================================================================
#
# Creates a cache that persists data to disk.
# Data survives restarts.
#
# USAGE:
#   ./persistent-cache.sh
#
# FLAGS DEMONSTRATED:
#   --persistent <file>   Persistence file path
#
# =============================================================================

set -e

CACHE_FILE="/tmp/socketley-cache.bin"

echo "=== Persistent Cache Example ==="
echo ""

echo "Creating persistent cache..."
socketley create cache persistent-store \
    -p 9000 \
    --persistent "$CACHE_FILE" \
    -s

echo ""
echo "=== Persistent Cache Running ==="
echo ""
socketley ps
echo ""

echo "Persistence file: $CACHE_FILE"
echo ""
echo "Behavior:"
echo "  1. On START: Loads existing data from file (if exists)"
echo "  2. During runtime: All operations in memory"
echo "  3. On STOP: Saves all data to file"
echo ""
echo "Test persistence:"
echo "  1. Connect and store data"
echo "  2. Stop cache:  socketley stop persistent-store"
echo "  3. Start again: socketley start persistent-store"
echo "  4. Data is restored!"
echo ""
echo "File format: Binary (key_len + key + val_len + value)"
echo ""
echo "Inspect file: hexdump -C $CACHE_FILE"
echo ""
echo "Cleanup:"
echo "  socketley stop persistent-store"
echo "  socketley remove persistent-store"
echo "  rm -f $CACHE_FILE"
