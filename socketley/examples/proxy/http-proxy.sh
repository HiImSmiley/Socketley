#!/bin/bash
# =============================================================================
# http-proxy.sh - Basic HTTP Reverse Proxy
# =============================================================================
#
# Creates an HTTP proxy that forwards requests to a backend server.
# Demonstrates path-based routing.
#
# USAGE:
#   ./http-proxy.sh
#
# FLAGS DEMONSTRATED:
#   --backend      Backend server address
#   --protocol     http (default) or tcp
#   -p             Proxy listening port
#
# =============================================================================

set -e

echo "=== HTTP Proxy Example ==="
echo ""

# Create backend server
echo "[1/2] Creating backend API server..."
socketley create server backend-api \
    -p 9001 \
    -s

# Create HTTP proxy
echo "[2/2] Creating HTTP proxy..."
socketley create proxy gateway \
    -p 8080 \
    --backend 127.0.0.1:9001 \
    --protocol http \
    -s

echo ""
echo "=== HTTP Proxy Running ==="
echo ""
socketley ps
echo ""

echo "Architecture:"
echo ""
echo "  [Client] ──HTTP──→ [gateway:8080] ──HTTP──→ [backend-api:9001]"
echo ""
echo "Path-based routing:"
echo "  Request:  curl localhost:8080/gateway/api/data"
echo "  Forwards: GET /api/data to backend"
echo ""
echo "Test:"
echo "  curl -v localhost:8080/gateway/health"
echo "  curl -v localhost:8080/gateway/api/users"
echo ""
echo "Note: The '/gateway' prefix is stripped before forwarding."
echo ""
echo "Cleanup:"
echo "  socketley stop gateway backend-api"
echo "  socketley remove gateway backend-api"
