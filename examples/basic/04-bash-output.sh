#!/bin/bash
# =============================================================================
# Example: Bash Output Mode
# =============================================================================
#
# Demonstrates the -b flag variants for outputting messages to stdout.
# Useful for scripting, logging, and monitoring.
#
# =============================================================================

set -e

echo "=== Bash Output Mode Examples ==="
echo ""

# Ensure daemon is running
if ! pgrep -x "socketley" > /dev/null 2>&1; then
    echo "Starting daemon..."
    socketley daemon &
    sleep 1
fi

echo "1. Raw output (-b):"
echo "   socketley create server raw-echo -p 9001 -b -s"
echo "   Output: hello world"
echo ""

echo "2. With prefix (-bp):"
echo "   socketley create server prefix-echo -p 9002 -bp -s"
echo "   Output: [prefix-echo] hello world"
echo ""

echo "3. With timestamp (-bt):"
echo "   socketley create server time-echo -p 9003 -bt -s"
echo "   Output: [14:32:05] hello world"
echo ""

echo "4. With both (-bpt):"
echo "   socketley create server full-echo -p 9004 -bpt -s"
echo "   Output: [14:32:05] [full-echo] hello world"
echo ""

echo "=== Live Demo ==="
echo ""

# Create server with bash output
echo "Creating server with -bpt flag..."
socketley create server demo-echo -p 9005 -bpt -s

echo ""
echo "Send messages with: echo 'hello' | nc localhost 9005"
echo "Watch daemon stdout for formatted output."
echo ""
echo "Press Ctrl+C to stop, then run:"
echo "  socketley stop demo-echo"
echo "  socketley remove demo-echo"
