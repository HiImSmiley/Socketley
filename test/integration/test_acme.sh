#!/usr/bin/env bash
# Integration test: certificates from an ACME CA (Pebble), proven over HTTP-01 and taken up by running listeners
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a runtime with --acme not starting before its certificate is issued, or
#     never serving the issued one
#   * an HTTP-01 challenge not answered by a server, proxy or storage runtime
#     on the port the CA asks on
#   * the chain not sent, so a client that trusts only the CA's root refuses
#   * a certificate replaced on disk not taken up by the listener, or a broken
#     one taken up
#   * --acme flags taken for a runtime that cannot use them, or names a CA
#     would refuse
#   * `socketley acme issue` by hand not writing a certificate for its names
# suite: isolated
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: ACME certificates ==="
PEBBLE_DIR="${PEBBLE_DIR:-$HOME/socketley-perf/acme}"
PEBBLE="$PEBBLE_DIR/pebble-linux-amd64/linux/amd64/pebble"
CHALL="$PEBBLE_DIR/pebble-challtestsrv-linux-amd64/linux/amd64/pebble-challtestsrv"
for f in "$PEBBLE" "$CHALL" "$PEBBLE_DIR/pebble.minica.pem" "$PEBBLE_DIR/localhost-cert.pem" "$PEBBLE_DIR/localhost-key.pem"; do
    [ -r "$f" ] || { echo "  SKIP: Pebble is required ($f; set PEBBLE_DIR)"; exit 0; }
done
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate stgacme
T="$SOCKETLEY_TMPD"
PPID_PEBBLE="" PPID_CHALL=""
trap 'kill $PPID_PEBBLE $PPID_CHALL 2>/dev/null; daemon_stop' EXIT
P_DIR=$((SL_PORT_BASE + 1911)) P_MGMT=$((SL_PORT_BASE + 1912)) P_DNS=$((SL_PORT_BASE + 1913))
P_HTTP=$((SL_PORT_BASE + 1914)) P_TLS=$((SL_PORT_BASE + 1915)) P_TLS2=$((SL_PORT_BASE + 1916))

# The CA, its DNS answering 127.0.0.1 for every name, and HTTP-01 asked on P_HTTP.
"$CHALL" -defaultIPv4 127.0.0.1 -defaultIPv6 "" -dnsserver ":$P_DNS" -http01 "" -https01 "" -tlsalpn01 "" -doh "" \
    -management ":$((SL_PORT_BASE + 1917))" > "$T/chall.log" 2>&1 & PPID_CHALL=$!
cat > "$T/pebble.json" <<EOF
{"pebble": {"listenAddress": "127.0.0.1:$P_DIR", "managementListenAddress": "127.0.0.1:$P_MGMT",
 "certificate": "$PEBBLE_DIR/localhost-cert.pem", "privateKey": "$PEBBLE_DIR/localhost-key.pem",
 "httpPort": $P_HTTP, "tlsPort": $P_TLS, "ocspResponderURL": "", "externalAccountBindingRequired": false}}
EOF
PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 "$PEBBLE" -config "$T/pebble.json" -dnsserver "127.0.0.1:$P_DNS" > "$T/pebble.log" 2>&1 &
PPID_PEBBLE=$!
for _ in $(seq 1 100); do curl -s --cacert "$PEBBLE_DIR/pebble.minica.pem" -o /dev/null "https://127.0.0.1:$P_DIR/dir" && break; sleep 0.1; done
check "the CA serves its directory" "$(curl -s --cacert "$PEBBLE_DIR/pebble.minica.pem" -o /dev/null -w '%{http_code}' "https://127.0.0.1:$P_DIR/dir")" 200
# The CA's issuing root, which a client that trusts the CA alone is given.
ROOT="$T/root.pem"
curl -s --cacert "$PEBBLE_DIR/pebble.minica.pem" "https://127.0.0.1:$P_MGMT/roots/0" > "$ROOT"

export SOCKETLEY_ACME_DIRECTORY="https://127.0.0.1:$P_DIR/dir" SOCKETLEY_ACME_CA="$PEBBLE_DIR/pebble.minica.pem"
daemon_start "$BIN"

# The flags' refusals.
check "--acme on a client is refused" "$("$BIN" create client c1 -t 127.0.0.1:1 --acme a.example 2>&1 | grep -c 'issued for a runtime that listens')" 1
check "a wildcard is refused" "$("$BIN" create server s0 -p $P_TLS2 --acme '*.example.org' 2>&1 | grep -c 'not a name')" 1
check "an address is refused" "$("$BIN" create server s1 -p $P_TLS2 --acme 127.0.0.1 2>&1 | grep -c 'not a name')" 1
check "an email without an at is refused" "$("$BIN" create server s2 -p $P_TLS2 --acme a.example --acme-email nope 2>&1 | grep -c 'not an address')" 1

# The challenge answerer on the CA's port, and the runtime that wants a certificate.
"$BIN" create storage web80 -p $P_HTTP --dir "$T/s80" --anonymous -s >/dev/null 2>&1
"$BIN" create server www -p $P_TLS --http "$T/site" --acme www.socketley.test,static.socketley.test --acme-email ops@socketley.test -s >/dev/null 2>&1
mkdir -p "$T/site"; echo hello > "$T/site/index.html"
issuer() { echo | openssl s_client -connect "127.0.0.1:$1" -servername "$2" 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null; }
for _ in $(seq 1 300); do issuer $P_TLS www.socketley.test | grep -qi pebble && break; sleep 0.1; done
check "the runtime serves a certificate the CA issued" "$(issuer $P_TLS www.socketley.test | grep -ci pebble)" 1
check "for every name it was given" \
      "$(echo | openssl s_client -connect 127.0.0.1:$P_TLS -servername www.socketley.test 2>/dev/null | openssl x509 -noout -ext subjectAltName 2>/dev/null | grep -o 'DNS:[a-z.]*' | sort | tr '\n' ' ')" \
      "DNS:static.socketley.test DNS:www.socketley.test "
check "with its chain, so a client trusting the CA's root alone is served" \
      "$(curl -s --cacert "$ROOT" --resolve www.socketley.test:$P_TLS:127.0.0.1 "https://www.socketley.test:$P_TLS/" | head -1)" hello
check "the challenge's answer was left behind by nobody" "$(ls "$HOME/.local/share/socketley" -R 2>/dev/null | grep -c '^[A-Za-z0-9_-]\{40,\}$')" 0

# A certificate replaced on disk is taken up without a restart; a broken one is not.
CERT=$(find "$HOME/.local/share/socketley" -path '*www.socketley.test/fullchain.pem' | head -1)
KEY="${CERT%fullchain.pem}key.pem"
check "it is kept where --acme puts it" "$([ -s "$CERT" ] && [ -s "$KEY" ] && echo yes)" yes
serial() { echo | openssl s_client -connect "127.0.0.1:$P_TLS" -servername www.socketley.test 2>/dev/null | openssl x509 -noout -serial 2>/dev/null; }
before=$(serial)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$T/k2.pem" -out "$T/c2.pem" -days 2 \
    -subj /CN=www.socketley.test >/dev/null 2>&1
cp "$T/k2.pem" "$KEY.new"; mv "$KEY.new" "$KEY"; cp "$T/c2.pem" "$CERT.new"; mv "$CERT.new" "$CERT"
for _ in $(seq 1 60); do [ "$(serial)" != "$before" ] && break; sleep 0.1; done
check "a replaced certificate is served without a restart" "$(serial)" "$(openssl x509 -noout -serial -in "$T/c2.pem")"
now=$(serial)
echo "not a certificate" > "$CERT"
sleep 2.5
check "a broken one is not taken up" "$(serial)" "$now"

# By hand, as certbot is run.
"$BIN" acme issue --domains hand.socketley.test --cert "$T/hand.pem" --key "$T/hand.key" > "$T/hand.out" 2>&1
check "acme issue by hand writes a certificate for its name" \
      "$(openssl x509 -noout -ext subjectAltName -in "$T/hand.pem" 2>/dev/null | grep -o 'DNS:[a-z.]*')" DNS:hand.socketley.test
check "and its key" "$(openssl x509 -noout -pubkey -in "$T/hand.pem" | openssl sha256)" "$(openssl pkey -pubout -in "$T/hand.key" | openssl sha256)"
check "and says nothing" "$(cat "$T/hand.out")" ""
# TLS-ALPN-01: the CA asks the TLS listener itself for acme-tls/1, and no port 80 is needed.
"$BIN" acme issue --domains alpn.socketley.test --challenge tls-alpn-01 --cert "$T/alpn.pem" --key "$T/alpn.key" > "$T/alpn.out" 2>&1
check "TLS-ALPN-01 is answered by a running TLS listener" \
      "$(openssl x509 -noout -ext subjectAltName -in "$T/alpn.pem" 2>/dev/null | grep -o 'DNS:[a-z.]*')" DNS:alpn.socketley.test
check "and its challenge certificate is gone after" "$(ls "$(dirname "$(dirname "$CERT")")/challenges" | grep -c tls-alpn)" 0
check "and acme-tls/1 is spoken no more once it is gone" \
      "$(echo | openssl s_client -connect 127.0.0.1:$P_TLS -servername alpn.socketley.test -alpn acme-tls/1 2>/dev/null | grep -c 'ALPN protocol: acme-tls/1')" 0

# A proxy and a server answer the CA as storage does, whatever they route or serve.
"$BIN" stop web80 >/dev/null 2>&1
"$BIN" create proxy px80 -p $P_HTTP --backend 127.0.0.1:1 -s >/dev/null 2>&1
"$BIN" acme issue --domains proxy.socketley.test --cert "$T/px.pem" --key "$T/px.key" > "$T/px.out" 2>&1
check "a proxy answers the challenge" "$(openssl x509 -noout -ext subjectAltName -in "$T/px.pem" 2>/dev/null | grep -o 'DNS:[a-z.]*')" DNS:proxy.socketley.test
"$BIN" stop px80 >/dev/null 2>&1
mkdir -p "$T/site80"
"$BIN" create server sv80 -p $P_HTTP --http "$T/site80" -s >/dev/null 2>&1
"$BIN" acme issue --domains server.socketley.test --cert "$T/sv.pem" --key "$T/sv.key" > "$T/sv.out" 2>&1
check "and so does a server" "$(openssl x509 -noout -ext subjectAltName -in "$T/sv.pem" 2>/dev/null | grep -o 'DNS:[a-z.]*')" DNS:server.socketley.test
check "an unknown token is 404" "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P_HTTP/.well-known/acme-challenge/nope")" 404
check "a name the CA cannot reach is an error, and exit 2" \
      "$(SOCKETLEY_ACME_DIRECTORY=https://127.0.0.1:$P_MGMT/nope "$BIN" acme issue --domains x.socketley.test --cert "$T/x.pem" --key "$T/x.key" >/dev/null 2>&1; echo $?)" 2

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
