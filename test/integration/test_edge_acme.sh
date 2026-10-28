#!/usr/bin/env bash
# Integration test: the entrance's certificate, asked for by itself.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   the entrance a dns runtime makes (--tls, no --cert) is issued a certificate for the zones
#   its dns runtime serves, each with its wildcard, proven over DNS-01 by that
#   runtime's own answers -- no port 80, no file to name; a name the wildcard
#   does not cover (a storage runtime's buckets) is asked for again when it
#   appears; and the certificate is the one served, its chain to the CA's root
#
#   a zone the world's DNS does not delegate here yet (the probe `acme issue`
#   asks the resolver goes unanswered) has its names proven one by one over
#   HTTP-01 instead, without the wildcard, and the wildcard is asked for when
#   the probe is answered
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

. "$HERE/lib_pebble.sh"
for f in "$PEBBLE" "$PEBBLE_DIR/pebble.minica.pem" "$PEBBLE_DIR/localhost-cert.pem" "$PEBBLE_DIR/localhost-key.pem"; do
    [ -r "$f" ] || { echo "  SKIP: Pebble is required ($f; set PEBBLE_DIR)"; exit 0; }
done
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate edgeacme
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1960))
DNS=$P S=$((P+1)) P_DIR=$((P+2)) P_MGMT=$((P+3)) HTTP01=$((P+4)) PROBE=$((P+8))
PEBBLE_PID=""
trap 'kill $PEBBLE_PID 2>/dev/null; daemon_stop' EXIT

echo "=== Integration: the entrance's own certificate ==="
cat > "$T/pebble.json" <<JSON
{"pebble": {"listenAddress": "127.0.0.1:$P_DIR", "managementListenAddress": "127.0.0.1:$P_MGMT",
 "certificate": "$PEBBLE_DIR/localhost-cert.pem", "privateKey": "$PEBBLE_DIR/localhost-key.pem",
 "httpPort": $((P+4)), "tlsPort": $((P+5)), "ocspResponderURL": "", "externalAccountBindingRequired": false}}
JSON
# The CA asks the dns runtime below, and nobody else.
PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 "$PEBBLE" -config "$T/pebble.json" -dnsserver "127.0.0.1:$DNS" \
    > "$T/pebble.log" 2>&1 &
PEBBLE_PID=$!
for _ in $(seq 1 100); do curl -s --noproxy '*' --cacert "$PEBBLE_DIR/pebble.minica.pem" -o /dev/null "https://127.0.0.1:$P_DIR/dir" && break; sleep 0.1; done
curl -s --noproxy '*' --cacert "$PEBBLE_DIR/pebble.minica.pem" "https://127.0.0.1:$P_MGMT/roots/0" > "$T/root.pem"

# What the worker's `acme issue` child is told: this CA, trusted by its own root, a short wait for DNS, and the
# resolver its delegation probe asks -- nothing listens there until the zone is "delegated" below.
export SOCKETLEY_ACME_DIRECTORY="https://127.0.0.1:$P_DIR/dir" SOCKETLEY_ACME_CA="$PEBBLE_DIR/pebble.minica.pem" \
       SOCKETLEY_ACME_DNS_WAIT=1 SOCKETLEY_ACME_DNS_PROBE="127.0.0.1:$PROBE"
daemon_start "$BIN"

mkdir -p "$T/site"; echo hello > "$T/site/who.txt"
expect "a dns runtime is made, and with it its entrance" \
    "$("$BIN" create dns ns -p "$DNS" --zone example.com --proxy web --proxy-port "$S" --publish 127.0.0.1 --rrl 0 -s 2>&1)" ""
"$BIN" create server chat -p $((P+6)) --domain --http "$T/site" -s >/dev/null 2>&1

san() { echo | openssl s_client -connect "127.0.0.1:$S" -servername "$1" 2>/dev/null |
        openssl x509 -noout -ext subjectAltName 2>/dev/null | grep -o 'DNS:[*a-z0-9.-]*' | sort | tr '\n' ' '; }
# The CA's HTTP-01 port, served by a redirect to HTTPS, which answers a challenge before it redirects.
"$BIN" create proxy redir -p "$HTTP01" --redirect-https "$S" -s >/dev/null 2>&1
# A name that appears while that issuance runs (its probe alone takes seconds) is asked for right after it.
sleep 3
"$BIN" create server late -p $((P+9)) --domain --http "$T/site" -s >/dev/null 2>&1
want="DNS:chat.example.com DNS:example.com DNS:late.example.com "
got=""
for _ in $(seq 1 400); do got=$(san chat.example.com); [ "$got" = "$want" ] && break; sleep 0.2; done
expect "a zone not delegated here has its names proven one by one, without the wildcard" "$got" "$want"
expect "and the redirect sends a browser to HTTPS, path and all" \
    "$(curl -s --noproxy '*' -m 5 -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Host: chat.example.com' "http://127.0.0.1:$HTTP01/a/b?c=d")" \
    "308 https://chat.example.com:$S/a/b?c=d"

# Delegated: the probe's resolver answers from the same zone and feed, and the entrance, started again, asks anew.
"$BIN" create dns probe -p "$PROBE" --zone "$(find "$T" -path '*zones/example.com.zone' | head -1)" --proxy none --rrl 0 -s \
    >/dev/null 2>&1
"$BIN" stop web >/dev/null 2>&1; "$BIN" start web >/dev/null 2>&1
for _ in $(seq 1 300); do got=$(san chat.example.com); [ "$got" = "DNS:*.example.com DNS:example.com " ] && break; sleep 0.2; done
expect "it is issued one for its zone and the zone's wildcard, over DNS-01" "$got" "DNS:*.example.com DNS:example.com "
expect "which a client trusting the CA's root alone accepts, the request routed" \
    "$(curl -s --noproxy '*' -m 5 --cacert "$T/root.pem" --resolve "chat.example.com:$S:127.0.0.1" "https://chat.example.com:$S/who.txt")" "hello"
# The answer goes when the certificate is written, and the zone takes that up within a second.
for _ in $(seq 1 15); do got=$(dig @127.0.0.1 -p "$DNS" +short _acme-challenge.example.com TXT); [ -z "$got" ] && break; sleep 0.2; done
expect "no answer is left in the zone after" "$got" ""

# A storage runtime's buckets are a name the zone's wildcard does not cover, one label further down.
"$BIN" create storage ui -p $((P+7)) --dir "$T/ui" --anonymous --domain -s >/dev/null 2>&1
want="DNS:*.example.com DNS:*.ui.example.com DNS:example.com "
for _ in $(seq 1 150); do got=$(san photos.ui.example.com); [ "$got" = "$want" ] && break; sleep 0.2; done
expect "a name beneath the wildcard is asked for when it appears" "$got" "$want"
curl -s --noproxy '*' -m 5 --cacert "$T/root.pem" --resolve "ui.example.com:$S:127.0.0.1" -X PUT "https://ui.example.com:$S/photos" >/dev/null
expect "and a bucket is reached under it, verified" \
    "$(curl -s --noproxy '*' -m 5 --cacert "$T/root.pem" --resolve "photos.ui.example.com:$S:127.0.0.1" -o /dev/null -w '%{http_code}' "https://photos.ui.example.com:$S/")" 200

"$BIN" stop web >/dev/null 2>&1; "$BIN" start web >/dev/null 2>&1
for _ in $(seq 1 50); do got=$(san chat.example.com); [ -n "$got" ] && break; sleep 0.2; done
expect "a restart keeps the certificate it was issued" "$got" "$want"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
