#!/bin/bash
# =============================================================================
# runtime-name-backend.sh - Using Runtime Names as Backends
# =============================================================================
#
# Demonstrates using runtime names instead of IP:port for backends.
# The proxy resolves runtime names via runtime_manager.
#
# USAGE:
#   ./runtime-name-backend.sh
#
# =============================================================================

set -e

echo "=== Runtime Name Backend Example ==="
echo ""

# Create backend servers with names
echo "[1/3] Creating backend 'api-service'..."
socketley create server api-service \
    -p 9001 \
    -s

echo "[2/3] Creating backend 'auth-service'..."
socketley create server auth-service \
    -p 9002 \
    -s

# Create proxy using runtime NAMES (not IP:port)
echo "[3/3] Creating proxy with runtime name backends..."
socketley create proxy gateway \
    -p 8080 \
    --backend api-service,auth-service \
    --strategy round-robin \
    --protocol http \
    -s

echo ""
echo "=== Proxy with Named Backends ==="
echo ""
socketley ps
echo ""

echo "Configuration:"
echo "  Backend 1: api-service (resolved to port 9001)"
echo "  Backend 2: auth-service (resolved to port 9002)"
echo ""
echo "Benefits of runtime names:"
echo "  - No hardcoded ports"
echo "  - Automatic resolution via runtime_manager"
echo "  - Easy service discovery"
echo ""
echo "Test:"
echo "  curl localhost:8080/gateway/test"
echo ""
echo "Cleanup:"
echo "  socketley stop gateway api-service auth-service"
echo "  socketley remove gateway api-service auth-service"
