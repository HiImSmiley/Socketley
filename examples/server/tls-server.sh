#!/bin/bash
# =============================================================================
# tls-server.sh - A server listener that terminates TLS
# =============================================================================
#
# A server runtime encrypts its own listening port. The handshake and the
# record layer run on the same io_uring event loop as everything else --
# OpenSSL sits behind a memory BIO pair and never touches a socket -- and
# everything above the record layer sees plaintext. That last part is what
# makes this useful: protocol auto-detection still works, so the one listener
# serves https:// and wss:// as well as the line protocol.
#
# WHAT IS *NOT* ENCRYPTED
#   A cache's listener and a server's own --upstream connections have no
#   handshake behind them, and the flags for those are refused rather than
#   stored -- see the bottom of this script.  Nothing here ever falls back to
#   cleartext: a configuration that cannot be honoured fails the runtime.
#   A *proxy* has a handshake on both of its legs (examples/proxy/tls-proxy.sh)
#   and a *client* dials one (examples/server-client/tls-client.sh).
#
# USAGE:
#   ./tls-server.sh
#
# FLAGS DEMONSTRATED:
#   --tls           Terminate TLS on this listener (server and proxy)
#   --cert <file>   PEM certificate; a chain is fine
#   --key <file>    Its PEM private key
#   --ca <file>     Client CA -> mutual TLS: clients must present a
#                   certificate signed by it
#
# =============================================================================

set -e

CERTS="${CERTS:-/tmp/socketley-tls-example}"
PORT=9443
MTLS_PORT=9444

mkdir -p "$CERTS"

echo "=== Generating a self-signed certificate ==="
echo ""
# In production this is your real certificate. Note the SAN: a client that
# verifies the certificate (as it should) matches the name it dialled against
# the SAN, not against the Common Name.
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$CERTS/server-key.pem" -out "$CERTS/server.pem" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

echo "  $CERTS/server.pem"
echo "  $CERTS/server-key.pem"
echo ""

echo "=== 1. A TLS listener ==="
echo ""
socketley create server tls-demo \
    -p "$PORT" \
    --tls \
    --cert "$CERTS/server.pem" \
    --key "$CERTS/server-key.pem" \
    -s

echo "Server 'tls-demo' listening on $PORT (TLS)"
echo ""
echo "Try it:"
echo "  openssl s_client -connect localhost:$PORT -CAfile $CERTS/server.pem"
echo "  curl --cacert $CERTS/server.pem https://localhost:$PORT/"
echo ""
echo "A plaintext client is dropped rather than served:"
echo "  echo hello | nc localhost $PORT     # no reply, connection closed"
echo ""

echo "=== 2. Mutual TLS ==="
echo ""
# A one-level CA, and a client certificate signed by it. With --ca set, a
# client that presents no certificate -- or one signed by anybody else -- is
# rejected during the handshake.
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$CERTS/ca-key.pem" -out "$CERTS/ca.pem" \
    -subj "/CN=example-client-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes \
    -keyout "$CERTS/client-key.pem" -out "$CERTS/client.csr" \
    -subj "/CN=example-client" 2>/dev/null
openssl x509 -req -in "$CERTS/client.csr" -days 365 \
    -CA "$CERTS/ca.pem" -CAkey "$CERTS/ca-key.pem" -CAcreateserial \
    -out "$CERTS/client.pem" 2>/dev/null

socketley create server mtls-demo \
    -p "$MTLS_PORT" \
    --tls \
    --cert "$CERTS/server.pem" \
    --key "$CERTS/server-key.pem" \
    --ca "$CERTS/ca.pem" \
    -s

echo "Server 'mtls-demo' listening on $MTLS_PORT (TLS, client certificate required)"
echo ""
echo "With a client certificate (accepted):"
echo "  openssl s_client -connect localhost:$MTLS_PORT -CAfile $CERTS/server.pem \\"
echo "      -cert $CERTS/client.pem -key $CERTS/client-key.pem"
echo ""
echo "Without one (rejected):"
echo "  openssl s_client -connect localhost:$MTLS_PORT -CAfile $CERTS/server.pem"
echo ""

echo "=== 3. Renewing a certificate ==="
echo ""
echo "The files are read when the runtime starts, so a reload installs a new one:"
echo "  socketley reload tls-demo"
echo ""

echo "=== 4. What is refused ==="
echo ""
echo "Every one of these exits 1 and creates nothing, because each describes a"
echo "listener that could only run in cleartext:"
echo ""
echo "  socketley create server oops -p 9445 --tls"
echo "      # --tls: a TLS listener needs --cert <file> and --key <file>"
echo ""
echo "  socketley create server oops -p 9445 --cert server.pem --key server-key.pem"
echo "      # --cert: needs --tls as well"
echo ""
echo "  socketley create cache  oops -p 9445 --tls --cert ... --key ..."
echo "      # TLS transport is not implemented for this runtime"
echo ""
echo "Neither a proxy nor a client is on that list any more: a proxy terminates"
echo "TLS on its own listener and dials one to its backends, and a client dials"
echo "one to its target.  See examples/proxy/tls-proxy.sh and"
echo "examples/server-client/tls-client.sh."
echo ""
echo "And a certificate that cannot be loaded, or a key that does not match it,"
echo "puts the runtime in the 'failed' state without ever binding the port."
echo ""

echo "=== Cleanup ==="
echo ""
echo "  socketley stop tls-demo mtls-demo"
echo "  socketley remove tls-demo mtls-demo"
echo "  rm -rf $CERTS"
