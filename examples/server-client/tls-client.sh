#!/bin/bash
# =============================================================================
# tls-client.sh - A client runtime that dials its target over TLS
# =============================================================================
#
# The mirror of examples/server/tls-server.sh.  A server terminates TLS on a
# port it owns; a client dials one to a port somebody else owns, which is the
# harder half -- because the client is the end that has to decide whether the
# thing that answered is the thing it meant to reach.
#
# The transport is the same machinery either way.  OpenSSL sits behind a memory
# BIO pair and never touches a socket, ciphertext is carried by the same
# io_uring submissions as every other byte in the daemon, and the handshake
# advances one completion at a time.  Everything above it -- the line framing,
# the Lua callbacks, `socketley send` -- sees the plaintext it always did.
#
# WHAT IS VERIFIED, AND WHY THERE IS NO WAY TO TURN IT OFF
#   Two checks, both mandatory:
#
#     1. the chain -- the certificate must be signed by something in the trust
#        store, which is --ca if you give one and the system store if you do not
#     2. the name -- the certificate must be valid for the host you put in -t,
#        matched against its DNS SAN, or its IP SAN for an address literal
#
#   Check 1 without check 2 is the trap.  SSL_VERIFY_PEER only proves *some*
#   trusted CA signed the chain; a certificate legitimately issued for any
#   other host in the world satisfies it.  So a connection that verified the
#   chain and not the name is one anybody holding any valid certificate can
#   stand in the middle of, and it looks identical to a correct one from the
#   outside -- same green, same encryption, same reported state.
#
#   That is why there is no --insecure and no skip-verify: an unverified TLS
#   client buys protection against somebody *recording* the wire and none at
#   all against somebody *sitting on* it, while claiming both.  Cleartext at
#   least does not claim to be safe.
#
#   A peer that fails either check costs the socket.  The client drops it and
#   re-dials on its usual backoff; it is never retried in cleartext.
#
# USAGE:
#   ./tls-client.sh
#
# FLAGS DEMONSTRATED:
#   --tls           Dial the target over TLS.  On a client this is a complete
#                   configuration on its own -- there is no listening port to
#                   hold a certificate
#   --ca <file>     Trust store for the peer.  Without it, the system store
#   --cert <file>   The certificate this client *presents*, when the peer asks
#   --key <file>    Its PEM private key.  Half a pair is refused
#
# =============================================================================

set -e

CERTS="${CERTS:-/tmp/socketley-tlsclient-example}"
PORT=9543
MTLS_PORT=9544

mkdir -p "$CERTS"

# The peer's certificate.  Note the SAN: the client matches the host from -t
# against it, so a certificate for "localhost" is not one for "127.0.0.1".
# Getting that wrong is the single most common way a working TLS setup refuses
# to connect, and it is the check doing its job.
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$CERTS/server-key.pem" -out "$CERTS/server.pem" \
    -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
    2>/dev/null

echo "=== 1. A TLS server, and a client that dials it ==="
echo ""

socketley create server tlsc-peer -p "$PORT" \
    --tls --cert "$CERTS/server.pem" --key "$CERTS/server-key.pem" -s

# --ca names the trust store.  This peer is self-signed, so its own certificate
# is the CA; in production this is your internal CA, or nothing at all when the
# peer holds a publicly-trusted certificate.
socketley create client tlsc-dialer -t "127.0.0.1:$PORT" \
    --tls --ca "$CERTS/server.pem" --reconnect 0 -s

echo "Client 'tlsc-dialer' is connected to $PORT over TLS."
echo ""
echo "Send through it -- the line is encrypted on the way out:"
echo "  socketley send tlsc-dialer 'hello over TLS'"
echo ""
echo "Against a publicly-trusted peer, --ca is unnecessary:"
echo "  socketley create client feed -t events.example.com:443 --tls -s"
echo ""

echo "=== 2. Presenting a certificate (mutual TLS) ==="
echo ""

# A one-level CA and a client certificate signed by it.  The server demands one
# with --ca; the client offers one with --cert/--key.  The names are worth
# reading twice: on a server --ca is "who I will accept certificates from", and
# on a client it is "who I will accept a certificate from".  Same flag, both
# ends of the same question.
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$CERTS/client-ca-key.pem" -out "$CERTS/client-ca.pem" \
    -subj "/CN=example-client-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes \
    -keyout "$CERTS/client-key.pem" -out "$CERTS/client.csr" \
    -subj "/CN=example-client" 2>/dev/null
openssl x509 -req -in "$CERTS/client.csr" -days 365 \
    -CA "$CERTS/client-ca.pem" -CAkey "$CERTS/client-ca-key.pem" -CAcreateserial \
    -out "$CERTS/client.pem" 2>/dev/null

socketley create server tlsc-mpeer -p "$MTLS_PORT" \
    --tls --cert "$CERTS/server.pem" --key "$CERTS/server-key.pem" \
    --ca "$CERTS/client-ca.pem" -s

socketley create client tlsc-mdialer -t "127.0.0.1:$MTLS_PORT" \
    --tls --ca "$CERTS/server.pem" \
    --cert "$CERTS/client.pem" --key "$CERTS/client-key.pem" \
    --reconnect 0 -s

echo "Client 'tlsc-mdialer' presents a certificate to a server that demands one."
echo ""
echo "The same client without --cert/--key is rejected during the handshake --"
echo "by the server, not by us -- and re-dials on its backoff:"
echo "  socketley create client nocert -t 127.0.0.1:$MTLS_PORT \\"
echo "      --tls --ca $CERTS/server.pem -s"
echo ""

echo "=== 3. Renewing a certificate ==="
echo ""
echo "The CA file and the client certificate are read when the runtime starts,"
echo "so a reload installs new ones -- the same as on a server:"
echo "  socketley reload tlsc-mdialer"
echo ""

echo "=== 4. What is refused ==="
echo ""
echo "Each of these exits 1 and creates nothing, because each describes a"
echo "connection that would be dialled in cleartext or verify nothing:"
echo ""
echo "  socketley create client oops -t host:9443 --ca ca.pem"
echo "      # --ca: needs --tls as well"
echo ""
echo "  socketley create client oops -t host:9443 --tls --cert client.pem"
echo "      # --cert: needs --key <file> as well -- a certificate with no key"
echo "      # presents nothing"
echo ""
echo "And these two fail the runtime rather than dialling:"
echo ""
echo "  socketley create client oops -t host:9443 --udp --tls -s"
echo "      # --tls on a UDP socket would need DTLS -- refusing to dial in"
echo "      # cleartext.  State: failed"
echo ""
echo "  # a peer whose certificate does not verify: the chain is untrusted, the"
echo "  # certificate has expired, or it was issued to a different host than"
echo "  # the one in -t.  The socket is dropped and re-dialled; nothing is ever"
echo "  # sent in the clear, and no flag exists to accept it anyway."
echo ""
echo "A cache is the only role left with no handshake at all."
echo ""

echo "=== Cleanup ==="
echo ""
echo "  socketley stop tlsc-peer tlsc-dialer tlsc-mpeer tlsc-mdialer"
echo "  socketley remove tlsc-peer tlsc-dialer tlsc-mpeer tlsc-mdialer"
echo "  rm -rf $CERTS"
