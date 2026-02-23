#!/bin/bash
# =============================================================================
# load-balancer.sh - Load Balancing Example
# =============================================================================
#
# Creates multiple backend servers and a proxy that load-balances
# requests across them.
#
# USAGE:
#   ./load-balancer.sh
#
# FLAGS DEMONSTRATED:
#   --backend     Multiple backends (comma-separated or repeated)
#   --strategy    round-robin, random, or lua
#
# =============================================================================

set -e

echo "=== Load Balancer Example ==="
echo ""

# Create backend servers
echo "[1/4] Creating backend server 1..."
socketley create server api-1 -p 9001 -s

echo "[2/4] Creating backend server 2..."
socketley create server api-2 -p 9002 -s

echo "[3/4] Creating backend server 3..."
socketley create server api-3 -p 9003 -s

# Create load balancer with round-robin strategy
echo "[4/4] Creating load balancer..."
socketley create proxy lb \
    -p 8080 \
    --backend 127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003 \
    --strategy round-robin \
    --protocol http \
    -s

echo ""
echo "=== Load Balancer Running ==="
echo ""
socketley ps
echo ""

echo "Architecture:"
echo ""
echo "              ┌──→ [api-1:9001]"
echo "              │"
echo "  [Client] → [lb:8080] ──→ [api-2:9002]"
echo "              │"
echo "              └──→ [api-3:9003]"
echo ""
echo "Strategy: round-robin"
echo "  Request 1 → api-1"
echo "  Request 2 → api-2"
echo "  Request 3 → api-3"
echo "  Request 4 → api-1 (wraps around)"
echo ""
echo "Test:"
echo "  for i in {1..6}; do curl -s localhost:8080/lb/test; done"
echo ""
echo "Other strategies:"
echo "  --strategy random      Random selection"
echo "  --strategy lua         Custom logic (see multi-backend.lua)"
echo ""
echo "Cleanup:"
echo "  socketley stop lb api-1 api-2 api-3"
echo "  socketley remove lb api-1 api-2 api-3"
