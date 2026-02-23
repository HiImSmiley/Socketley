#!/bin/bash
# =============================================================================
# group-discovery.sh - Dynamic Backend Discovery with Groups
# =============================================================================
#
# Demonstrates using groups for dynamic proxy backend discovery.
# Tag servers with -g <group>, then use @group as a proxy backend.
# The proxy discovers running group members at connection time.
#
# USAGE:
#   ./group-discovery.sh
#
# FLAGS DEMONSTRATED:
#   -g <name>          Assign runtime to a group
#   --backend @group   Target all running members of a group
#
# =============================================================================

set -e

echo "=== Group Discovery Example ==="
echo ""

# Create backend servers tagged with the "api" group
echo "[1/4] Creating api-1 (group: api)..."
socketley create server api-1 -p 9001 -g api -s

echo "[2/4] Creating api-2 (group: api)..."
socketley create server api-2 -p 9002 -g api -s

# Create proxy targeting the @api group
echo "[3/4] Creating proxy with @api group backend..."
socketley create proxy gw \
    -p 8080 \
    --backend @api \
    --strategy round-robin \
    --protocol http \
    -s

echo ""
echo "=== Group Proxy Running ==="
echo ""
socketley ps
echo ""

echo "Architecture:"
echo ""
echo "              ┌──→ [api-1:9001] (group: api)"
echo "              │"
echo "  [Client] → [gw:8080 @api] ──→ ..."
echo "              │"
echo "              └──→ [api-2:9002] (group: api)"
echo ""

# Scale up: add a new member without touching the proxy
echo "[4/4] Scaling up: adding api-3 to the group..."
socketley create server api-3 -p 9003 -g api -s

echo ""
echo "After scale-up:"
echo ""
echo "              ┌──→ [api-1:9001] (group: api)"
echo "              │"
echo "  [Client] → [gw:8080 @api] ──→ [api-2:9002] (group: api)"
echo "              │"
echo "              └──→ [api-3:9003] (group: api)"
echo ""
echo "The proxy discovers api-3 automatically — no restart needed."
echo ""
echo "Test:"
echo "  for i in {1..6}; do curl -s localhost:8080/gw/test; done"
echo ""
echo "Scale down (member excluded automatically):"
echo "  socketley stop api-2"
echo ""
echo "Change group membership:"
echo "  socketley edit api-1 -g workers"
echo ""
echo "Mix groups with static backends:"
echo "  socketley create proxy gw2 -p 8081 --backend @api,10.0.0.5:9000 -s"
echo ""
echo "Cleanup:"
echo "  socketley stop gw api-1 api-2 api-3"
echo "  socketley remove gw api-1 api-2 api-3"
