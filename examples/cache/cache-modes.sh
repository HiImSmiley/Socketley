#!/bin/bash
# =============================================================================
# cache-modes.sh - Cache Access Control Modes
# =============================================================================
#
# Demonstrates readonly, readwrite, and admin cache modes.
#
# USAGE:
#   ./cache-modes.sh
#
# =============================================================================

set -e

echo "=== Cache Modes Example ==="
echo ""

# Create caches with different modes
echo "Creating caches with different access modes..."
socketley create cache readonly-cache -p 19001 --mode readonly -s
socketley create cache readwrite-cache -p 19002 --mode readwrite -s
socketley create cache admin-cache -p 19003 --mode admin -s

echo ""
socketley ps
echo ""

# Test readonly cache
echo "=== Testing readonly cache ==="
echo "GET (allowed):"
socketley readonly-cache get testkey
echo "Exit code: $?"

echo ""
echo "SET (denied):"
socketley readonly-cache set testkey value || true
echo ""

# Test readwrite cache
echo "=== Testing readwrite cache ==="
echo "SET (allowed):"
socketley readwrite-cache set mykey myvalue
echo "Exit code: $?"

echo ""
echo "GET (allowed):"
socketley readwrite-cache get mykey
echo ""

echo "FLUSH (denied - needs admin):"
socketley readwrite-cache flush /tmp/test.bin || true
echo ""

# Test admin cache
echo "=== Testing admin cache ==="
echo "SET (allowed):"
socketley admin-cache set adminkey adminvalue
echo "Exit code: $?"

echo ""
echo "FLUSH (allowed):"
socketley admin-cache flush /tmp/admin-cache.bin
echo "Exit code: $?"
echo ""

# Cleanup
echo "=== Cleanup ==="
socketley stop readonly-cache readwrite-cache admin-cache
socketley remove readonly-cache readwrite-cache admin-cache
rm -f /tmp/admin-cache.bin
echo "Done!"
