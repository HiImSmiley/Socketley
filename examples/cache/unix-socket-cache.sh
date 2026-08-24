#!/bin/bash
# =============================================================================
# unix-socket-cache.sh - A cache serving on an AF_UNIX socket instead of a port
# =============================================================================
#
# `--listen unix:/abs/path.sock` instead of `-p`, on a cache exactly as on a
# server or a proxy.  Both protocols are detected on the unix socket as they
# are on a port: redis-cli -s speaks RESP to it, and the plaintext protocol
# works over the same node.
#
# THINGS TO KNOW BEFORE USING IT:
#
#   - the path must be absolute and under 108 bytes (the kernel's sun_path);
#     both are refused at start rather than trimmed
#   - the socket node is created 0600, so the peer must run as the same user;
#     there is no flag to widen it
#   - --listen cannot be combined with -p or --tls, and on a cache also not
#     with --cluster (members advertise ports out of a formula, and a path
#     has no successor) or --shards (SO_REUSEPORT is not a path)
#   - the node is removed when the cache stops; a stale one left by a crash
#     is taken over on the next start, but a path something is live on is
#     refused rather than stolen
#
# PREREQUISITES:
#   redis-cli (from redis-tools package) for the RESP half; the plaintext
#   half needs only python3
#
# USAGE:
#   ./unix-socket-cache.sh
# =============================================================================

set -e

SOCK=/tmp/socketley-example-kv.sock

echo "=== Cache on a Unix Socket Example ==="
echo ""

socketley create cache kv --listen "unix:$SOCK" -s
sleep 0.3

echo "Cache is serving on $SOCK (mode 0600):"
ls -l "$SOCK"
echo ""

if command -v redis-cli &>/dev/null; then
    echo "RESP over the unix socket (redis-cli -s):"
    redis-cli -s "$SOCK" PING
    redis-cli -s "$SOCK" SET greeting "hello over unix"
    redis-cli -s "$SOCK" GET greeting
    echo ""
else
    echo "(redis-cli not installed; skipping the RESP half)"
    echo ""
fi

echo "The plaintext protocol works on the same node:"
python3 - "$SOCK" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
for cmd in (b"SET plain works\n", b"GET plain\n"):
    s.sendall(cmd)
    print(" ", s.recv(4096).decode().strip())
s.close()
EOF
echo ""

socketley stop kv
socketley remove kv
echo "Stopped; the socket node is removed with it:"
ls -l "$SOCK" 2>&1 || true
