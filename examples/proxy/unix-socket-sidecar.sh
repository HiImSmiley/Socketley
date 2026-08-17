#!/bin/bash
# =============================================================================
# unix-socket-sidecar.sh - Proxy to a backend over AF_UNIX, not loopback TCP
# =============================================================================
#
# A sidecar proxy and the process it fronts run on the same host, and loopback
# TCP charges that pair for a whole stack - handshake, sequence numbers,
# checksums, windows - on a connection that never sees a wire.
#
#   --listen unix:/path   on a server, instead of -p
#   --backend unix:/path  on a proxy, instead of ip:port
#
# and the proxy can also name the server by its runtime name, which resolves to
# the same socket.  Both spellings are shown below.
#
# WHAT IT IS WORTH.  Measured with test/benchmark/floor_relay.c and
# floor_server -u on a quiet machine, 64-byte round trips:
#
#                                        TCP backend  UNIX backend  saved
#   one core   bench -> proxy -> floor      24.3 us      23.9 us     0.4 us
#   unpinned   bench -> proxy -> floor      40.2 us      37.8 us     2.3 us
#
# A few percent, not an order of magnitude.  The kernel-only floor for the same
# swap is 0.97 us / 2.95 us, so the proxy takes most of what is on offer - the
# rest of a proxied round trip is the two extra handoffs, which this does not
# remove.
#
# THINGS TO KNOW BEFORE USING IT:
#
#   - the path must be absolute and under 108 bytes (the kernel's sun_path);
#     both are refused at start rather than trimmed
#   - the socket node is created 0600, so the peer must run as the same user;
#     there is no flag to widen it
#   - --listen cannot be combined with -p, --udp or --tls
#   - a unix server is reachable as a backend by path and by runtime name, but
#     is not offered as an @group member
#
# USAGE:
#   ./unix-socket-sidecar.sh
#
# =============================================================================

set -e

SOCK=/tmp/socketley-example-app.sock
WWW=/tmp/socketley-example-www

echo "=== Unix Socket Sidecar Example ==="
echo ""

mkdir -p "$WWW"
echo "<h1>served over a unix socket</h1>" > "$WWW/index.html"

# The backend: no port at all, just a socket node.
echo "[1/3] Creating server 'app' on $SOCK ..."
socketley create server app \
    --listen "unix:$SOCK" \
    --http "$WWW" \
    -s

# The proxy, naming the socket directly.
echo "[2/3] Creating proxy 'gw' with --backend unix:$SOCK ..."
socketley create proxy gw \
    -p 8080 \
    --backend "unix:$SOCK" \
    -s

# The same thing by runtime name.  The daemon publishes 'app' as its socket
# path rather than as a port, so this resolves to the identical backend.
echo "[3/3] Creating proxy 'gw-byname' with --backend app ..."
socketley create proxy gw-byname \
    -p 8081 \
    --backend app \
    -s

echo ""
socketley ps
echo ""
ls -l "$SOCK"
echo ""

echo "Test:"
echo "  curl localhost:8080/gw/           # via unix:$SOCK"
echo "  curl localhost:8081/gw-byname/    # via the runtime name"
echo "  curl --unix-socket $SOCK http://localhost/   # straight to the server"
echo ""
echo "The socket node is removed when the server stops, and a stale one left"
echo "behind by a killed daemon is taken over on the next start - but only"
echo "after checking that nothing is still serving it."
echo ""
echo "Cleanup:"
echo "  socketley stop gw gw-byname app"
echo "  socketley remove gw gw-byname app"
