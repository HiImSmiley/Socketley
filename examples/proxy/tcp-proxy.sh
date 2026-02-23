#!/bin/bash
# =============================================================================
# tcp-proxy.sh - Raw TCP Proxy
# =============================================================================
#
# Creates a TCP proxy that forwards raw bytes without HTTP parsing.
# Useful for non-HTTP protocols or when you need transparent forwarding.
#
# USAGE:
#   ./tcp-proxy.sh
#
# FLAGS DEMONSTRATED:
#   --protocol tcp   Enable raw TCP mode (no HTTP parsing)
#
# =============================================================================

set -e

echo "=== TCP Proxy Example ==="
echo ""

# Create backend server
echo "[1/2] Creating backend server..."
socketley create server tcp-backend \
    -p 9001 \
    -s

# Create TCP proxy
echo "[2/2] Creating TCP proxy..."
socketley create proxy tcp-gateway \
    -p 8080 \
    --backend 127.0.0.1:9001 \
    --protocol tcp \
    -s

echo ""
echo "=== TCP Proxy Running ==="
echo ""
socketley ps
echo ""

echo "Architecture:"
echo ""
echo "  [Client] ──raw bytes──→ [tcp-gateway:8080] ──raw bytes──→ [tcp-backend:9001]"
echo ""
echo "Behavior:"
echo "  - No HTTP parsing or path routing"
echo "  - Bidirectional byte forwarding"
echo "  - Protocol agnostic (works with any TCP protocol)"
echo ""
echo "Use cases:"
echo "  - Database proxying"
echo "  - Custom binary protocols"
echo "  - TLS passthrough"
echo "  - Any non-HTTP TCP service"
echo ""
echo "Test:"
echo "  nc localhost 8080"
echo "  (Type anything - raw bytes forwarded to backend)"
echo ""
echo "Cleanup:"
echo "  socketley stop tcp-gateway tcp-backend"
echo "  socketley remove tcp-gateway tcp-backend"
