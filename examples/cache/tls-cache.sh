#!/bin/bash
# =============================================================================
# tls-cache.sh - A Cache That Terminates TLS
# =============================================================================
# A cache runtime encrypts its own listening port with --tls --cert --key, the
# same three flags a server uses. --ca additionally demands a certificate from
# every client that connects (mutual TLS).
#
# RESP is auto-detected from the first byte of the *decrypted* stream, so an
# existing Redis client speaks exactly the protocol it always did -- one layer
# up. The line protocol works on the same port for the same reason.
#
# USAGE:
#   ./tls-cache.sh
#
# Requires: openssl (to generate the throwaway certificates)
# =============================================================================

set -e

echo "=== TLS Cache Example ==="
echo ""

CERTS=$(mktemp -d /tmp/socketley-tls-cache-XXXXXX)
trap 'rm -rf "$CERTS"' EXIT

# A self-signed leaf for the listener, and a small CA that signs a client
# certificate for the mutual-TLS half below. Both expire in two days.
echo "Generating throwaway certificates in $CERTS ..."
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$CERTS/cache-key.pem" -out "$CERTS/cache.pem" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$CERTS/ca-key.pem" -out "$CERTS/ca.pem" \
    -subj "/CN=socketley-example-ca" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
    -keyout "$CERTS/client-key.pem" -out "$CERTS/client.csr" \
    -subj "/CN=example-client" >/dev/null 2>&1
openssl x509 -req -in "$CERTS/client.csr" -days 2 \
    -CA "$CERTS/ca.pem" -CAkey "$CERTS/ca-key.pem" -CAcreateserial \
    -out "$CERTS/client.pem" >/dev/null 2>&1
echo ""

# ── 1. A TLS cache ──────────────────────────────────────────────────────────
echo "Creating a cache that terminates TLS on :9000 ..."
socketley create cache tls-store \
    -p 9000 \
    --tls \
    --cert "$CERTS/cache.pem" \
    --key "$CERTS/cache-key.pem" \
    -s
sleep 0.5

echo ""
echo "Talking RESP to it over the encrypted stream:"
python3 - "$CERTS/cache.pem" <<'PY'
import socket, ssl, sys

def cmd(*parts):
    out = f"*{len(parts)}\r\n".encode()
    for p in parts:
        b = p.encode()
        out += b"$" + str(len(b)).encode() + b"\r\n" + b + b"\r\n"
    return out

ctx = ssl.create_default_context(cafile=sys.argv[1])
raw = socket.create_connection(("127.0.0.1", 9000), timeout=10)
tls = ctx.wrap_socket(raw, server_hostname="localhost")
print("  negotiated:", tls.version(), tls.cipher()[0])

f = tls.makefile("rwb")
f.write(cmd("SET", "user", "alice")); f.flush(); print("  SET user alice ->", f.readline().decode().strip())
f.write(cmd("GET", "user")); f.flush()
hdr = f.readline().strip()
n = int(hdr[1:]); print("  GET user       ->", f.read(n).decode()); f.read(2)
tls.close()
PY

echo ""
echo "A plaintext client on the same port is refused, not downgraded:"
python3 - <<'PY'
import socket
s = socket.create_connection(("127.0.0.1", 9000), timeout=5)
s.sendall(b"*1\r\n$4\r\nPING\r\n")
s.settimeout(5)
try:
    print("  got:", "connection closed" if s.recv(64) == b"" else "an alert")
except OSError:
    print("  got: connection reset")
s.close()
PY

# ── 2. Mutual TLS ───────────────────────────────────────────────────────────
echo ""
echo "Creating a second cache on :9001 that also demands a client certificate..."
socketley create cache mtls-store \
    -p 9001 \
    --tls \
    --cert "$CERTS/cache.pem" \
    --key "$CERTS/cache-key.pem" \
    --ca "$CERTS/ca.pem" \
    -s
sleep 0.5

python3 - "$CERTS" <<'PY'
import socket, ssl, sys
certs = sys.argv[1]

def attempt(with_cert):
    ctx = ssl.create_default_context(cafile=f"{certs}/cache.pem")
    if with_cert:
        ctx.load_cert_chain(f"{certs}/client.pem", f"{certs}/client-key.pem")
    try:
        raw = socket.create_connection(("127.0.0.1", 9001), timeout=6)
        tls = ctx.wrap_socket(raw, server_hostname="localhost")
        tls.settimeout(3)
        tls.sendall(b"*1\r\n$4\r\nPING\r\n")
        ok = tls.recv(64).startswith(b"+PONG")
        tls.close()
        return "accepted" if ok else "rejected"
    except Exception:
        return "rejected"

print("  with a client certificate:", attempt(True))
print("  without one:              ", attempt(False))
PY

# ── 3. What a TLS cache will not do ─────────────────────────────────────────
echo ""
echo "Replication is NOT encrypted, so it cannot be combined with --tls:"
socketley create cache tls-follower -p 9002 \
    --tls --cert "$CERTS/cache.pem" --key "$CERTS/cache-key.pem" \
    --replicate 127.0.0.1:9000 || echo "  (refused, as it should be)"
echo ""
echo "  A follower dials its leader in cleartext, and a leader writes to its"
echo "  followers around the record layer -- so the pair would stream the whole"
echo "  dataset in the clear off a port that reports itself as encrypted. It is"
echo "  refused at create, by edit and import, and again at every start; a TLS"
echo "  cache also refuses the 'replicate' command, so it never becomes a leader."
echo "  Use a cleartext cache for replication, or replicate over a private"
echo "  network -- an honestly cleartext cache is better than a half-encrypted one."

echo ""
echo "=== Cleanup ==="
socketley stop tls-store mtls-store 2>/dev/null || true
sleep 0.3
socketley remove tls-store mtls-store 2>/dev/null || true
echo "Done."
