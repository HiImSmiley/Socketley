#!/bin/bash
# =============================================================================
# server-cache-access.sh - Reaching a Cache Through a Server
# =============================================================================
#
# A server linked to a cache with --cache lets its own clients speak to that
# cache: any message beginning "cache " is run against the linked cache and the
# answer goes back to the sender alone.  Nothing else on the connection changes
# — ordinary messages are still handled by the server's mode.
#
# The request is asynchronous.  The server does not run the cache's command
# interpreter itself; it posts the command and answers when the reply arrives,
# one turn of the daemon's event loop later.  Two things follow from that and
# both are demonstrated below:
#
#   * replies on one connection come back in request order, so commands can be
#     pipelined and the answers matched to the questions positionally;
#   * a cache that is not running answers with an error line rather than with
#     silence.
#
# USAGE:
#   ./server-cache-access.sh
#
# =============================================================================

set -e

echo "=== Cache Access via Server Example ==="
echo ""

echo "Creating cache and a server linked to it..."
socketley create cache store -p 9001 -s
socketley create server api -p 9000 --cache store -s

echo ""
socketley ps
echo ""

echo "=== One command at a time ==="
echo 'cache set user:1 alice' | nc -q1 localhost 9000     # => ok
echo 'cache get user:1'       | nc -q1 localhost 9000     # => alice
echo ""

echo "=== Pipelined: answers come back in request order ==="
printf 'cache set a 1\ncache set b 2\ncache get a\ncache get b\n' \
    | nc -q1 localhost 9000                               # => ok ok 1 2
echo ""

echo "=== The same keys are there on the cache's own port ==="
echo 'get user:1' | nc -q1 localhost 9001                 # => alice
echo ""

echo "=== A cache that is not running is answered, not ignored ==="
socketley stop store
sleep 0.5
echo 'cache get user:1' | nc -q1 localhost 9000           # => error: no such runtime
socketley start store
echo ""

echo "Cleanup:"
echo "  socketley stop api store"
echo "  socketley remove api store"
