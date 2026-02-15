#!/bin/bash
# =============================================================================
# modes.sh - Message Mode Examples
# =============================================================================
#
# Demonstrates the three message modes: inout, in, out
#
# USAGE:
#   ./modes.sh
#
# FLAGS DEMONSTRATED:
#   --mode inout   Bidirectional (default)
#   --mode in      Receive only
#   --mode out     Send only
#
# =============================================================================

set -e

echo "=== Message Modes Example ==="
echo ""

echo "Creating servers with different modes..."
echo ""

# Mode: inout (default) - Can receive and broadcast
echo "[1/3] Creating bidirectional server (--mode inout)..."
socketley create server server-inout \
    -p 9001 \
    --mode inout \
    -s

# Mode: in - Can only receive, cannot broadcast
echo "[2/3] Creating receive-only server (--mode in)..."
socketley create server server-in \
    -p 9002 \
    --mode in \
    -w /tmp/server-in-received.txt \
    -s

# Mode: out - Can only broadcast, ignores incoming
echo "[3/3] Creating send-only server (--mode out)..."
socketley create server server-out \
    -p 9003 \
    --mode out \
    -s

echo ""
echo "=== Mode Comparison ==="
echo ""
echo "┌─────────────┬──────────┬───────────┬─────────────────────────────────┐"
echo "│ Runtime     │ Port     │ Mode      │ Behavior                        │"
echo "├─────────────┼──────────┼───────────┼─────────────────────────────────┤"
echo "│ server-inout│ 9001     │ inout     │ Receives + Broadcasts           │"
echo "│ server-in   │ 9002     │ in        │ Receives only (logs to file)    │"
echo "│ server-out  │ 9003     │ out       │ Broadcasts only (ignores input) │"
echo "└─────────────┴──────────┴───────────┴─────────────────────────────────┘"
echo ""
echo "Test each mode:"
echo "  nc localhost 9001  # Full duplex"
echo "  nc localhost 9002  # Messages received but not echoed"
echo "  nc localhost 9003  # Input ignored, receives broadcasts"
echo ""
echo "Cleanup:"
echo "  socketley stop server-inout server-in server-out"
echo "  socketley remove server-inout server-in server-out"
