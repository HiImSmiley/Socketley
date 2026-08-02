#!/bin/bash
# =============================================================================
# tls-proxy.sh - A proxy that terminates TLS, and one that dials it
# =============================================================================
#
# A proxy has two legs and each can be encrypted on its own:
#
#   [client] ──TLS──→ [proxy] ──TLS──→ [backend]
#             ^^^^             ^^^^
#             --tls            https:// backend, or --ca /
#             --cert --key     --client-cert --client-key
#             --client-ca      (they apply to every backend)
#
# The record layer is the same one a server listener uses: OpenSSL sits behind
# a memory BIO pair and never touches a socket, every byte on the wire is
# carried by the same io_uring submissions as any other, and the handshake
# advances one completion at a time so nothing blocks the loop.
#
# WHAT THE BACKEND LEG VERIFIES, ALWAYS
#   The certificate chain, against --ca when one is given and against the
#   system CA store otherwise; and the certificate against the endpoint the
#   request was routed to -- a host name matched against the DNS names with
#   partial wildcards refused, an address literal against the IP SAN. TLS 1.2
#   is the minimum version. There is no flag to skip any of it: an unverified
#   TLS leg is worse than a cleartext one, because it looks safe. A backend
#   that fails either check is answered 502 (or retried, with --retry) and is
#   charged to its circuit breaker -- the request is never re-sent in the clear.
#
# ONE COST WORTH KNOWING
#   * A TLS backend connection is never returned to the connection pool, so
#     each request to one pays for a handshake. The pool is keyed by host and
#     port, and a TLS connection carries a session and a verified identity
#     that a host and a port cannot express; handing one to the next request
#     would be a guess about who the peer is.
#
# HEALTH CHECKS OVER TLS
#   --health-check http works against a TLS backend. The probe handshakes
#   through the same record layer the data path uses and fetches --health-path
#   over it, so it can tell a listening socket from a working server -- which
#   --health-check tcp cannot. It verifies the backend's certificate to the
#   same standard as well: one that does not verify is marked unhealthy, never
#   reported healthy.
#
# USAGE:
#   ./tls-proxy.sh
#
# FLAGS DEMONSTRATED:
#   --tls --cert --key   Terminate TLS on the proxy's own port
#   --client-ca <file>   Mutual TLS on it: a client must present a certificate
#                        signed by this CA
#   --backend https://   Reach this one backend over TLS
#   --ca <file>          Trust store for the backend leg (and, like the two
#                        below, enough on its own to make every backend TLS)
#   --client-cert <file> The certificate this proxy presents to a backend
#   --client-key <file>  Its key -- both or neither
#
# =============================================================================

set -e

CERTS="${CERTS:-/tmp/socketley-tls-proxy-example}"
FRONT_PORT=8443
EGRESS_PORT=8080
BACKEND_PORT=9443

mkdir -p "$CERTS"

echo "=== Generating certificates ==="
echo ""
# One for the proxy's own listener, one for the backend. In production these
# are your real certificates; the SAN matters, because the backend leg matches
# the address it dialled against the SAN and not against the Common Name.
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$CERTS/proxy-key.pem" -out "$CERTS/proxy.pem" \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$CERTS/backend-key.pem" -out "$CERTS/backend.pem" \
    -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" \
    2>/dev/null
echo "  $CERTS/proxy.pem      the proxy's own listener"
echo "  $CERTS/backend.pem    the backend's, and the CA the proxy trusts for it"
echo ""

echo "=== 1. TLS in, TLS out ==="
echo ""

# The backend: an ordinary server runtime terminating TLS on its own port.
socketley create server secure-backend \
    -p "$BACKEND_PORT" \
    --tls --cert "$CERTS/backend.pem" --key "$CERTS/backend-key.pem" \
    -s

# The proxy: encrypted on both legs. --ca is the *backend* trust store here;
# the listener's own client-certificate CA is --client-ca, which this one does
# not set, so clients are not asked for a certificate.
socketley create proxy secure-gw \
    -p "$FRONT_PORT" \
    --backend "https://127.0.0.1:$BACKEND_PORT" \
    --ca "$CERTS/backend.pem" \
    --tls --cert "$CERTS/proxy.pem" --key "$CERTS/proxy-key.pem" \
    --protocol http \
    -s

echo ""
socketley ps
echo ""
echo "  [client] ──TLS──→ [secure-gw:$FRONT_PORT] ──TLS──→ [secure-backend:$BACKEND_PORT]"
echo ""
echo "Test (--cacert, because these are self-signed):"
echo "  curl --cacert $CERTS/proxy.pem https://localhost:$FRONT_PORT/secure-gw/hello"
echo ""
echo "And the check that matters -- a plaintext request to an encrypted port is"
echo "not served, it is dropped during the handshake:"
echo "  curl http://localhost:$FRONT_PORT/secure-gw/hello    # fails, as it must"
echo ""

echo "=== 2. TLS to the backend only ==="
echo ""
echo "The proxy listens in cleartext on loopback and encrypts the hop that"
echo "leaves the machine. No --ca here, so the system CA store is used:"
echo ""
echo "  socketley create proxy egress -p $EGRESS_PORT \\"
echo "      --backend https://api.example.com -s"
echo ""

echo "=== 3. Mutual TLS, both directions ==="
echo ""
echo "  socketley create proxy mesh-edge -p 8444 \\"
echo "      --tls --cert proxy.pem --key proxy-key.pem \\"
echo "      --client-ca mesh-ca.pem \\"
echo "      --backend https://10.0.0.7:8443 \\"
echo "      --ca mesh-ca.pem \\"
echo "      --client-cert edge.pem --client-key edge-key.pem \\"
echo "      --sidecar -s"
echo ""
echo "  --client-ca  = the CA a *client's* certificate must be signed by"
echo "  --client-cert/--client-key = what this proxy presents to a *backend*"
echo ""

echo "=== 4. What is refused ==="
echo ""
echo "Each of these describes a leg that could only run in cleartext, or a"
echo "check that would verify nothing, so create exits 1 and builds nothing:"
echo ""
echo "  socketley create proxy oops -p 8445 --backend b:1 --tls"
echo "      # --tls: a TLS listener needs --cert <file> and --key <file>"
echo ""
echo "  socketley create proxy oops -p 8445 --backend b:1 --client-ca ca.pem"
echo "      # --client-ca: ... needs --tls --cert --key on this proxy's own"
echo "      #              listener -- on a cleartext port it would"
echo "      #              authenticate nobody"
echo ""
echo "  socketley create proxy oops -p 8445 --backend b:1 --client-cert c.pem"
echo "      # --client-cert: needs --client-key <file> as well"
echo ""
echo "And a backend whose certificate does not verify is answered 502 with the"
echo "reason logged by the daemon -- never a cleartext retry."
echo ""

echo "=== Cleanup ==="
echo ""
echo "  socketley stop secure-gw secure-backend"
echo "  socketley remove secure-gw secure-backend"
echo "  rm -rf $CERTS"
