#!/usr/bin/env bash
# Integration test: a dns runtime is an authoritative name server for its zone files.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   create       no --zone, a zone that does not parse (named by its line),
#                --listen and a taken port are refused before anything runs
#   answers      through dig, over UDP and TCP: a record, an alias followed, a
#                wildcard, NXDOMAIN and NODATA with the SOA's negative TTL, an MX
#                with its host's address, a delegation referred with its glue
#                and without AA, a name of no zone REFUSED, CHAOS refused, ANY
#                as RFC 8482 answers it, EDNS kept to 1232, and what does not
#                fit UDP sent truncated and then whole over TCP
#   transfer     AXFR to an address --transfer names, REFUSED to another
#   reload       an edited zone served within seconds, a broken edit leaving
#                the zone before it, and the secondaries told of the new serial
#                once each, answered once each
#   rrl          a burst from one network past --rrl is half truncated, half
#                dropped, and the rest answered
#   restart      a daemon started again brings the runtime back, answering
#
# Skipped when dig is not installed.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate dns
P=$((SL_PORT_BASE+1710))
SINK=$((SL_PORT_BASE+1711))
T="$SOCKETLEY_TMPD"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
has() { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1" "'$3' not in: $2" ;; esac; }
skip() { echo "  SKIP: $1"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

cleanup() {
    [ -n "${SINK_PID:-}" ] && kill "$SINK_PID" 2>/dev/null
    for r in ns ns2 bad pub chat files; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.2
    for r in ns ns2 bad pub chat files; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: dns ==="
command -v dig >/dev/null 2>&1 || skip "dig is not installed (dnsutils / bind9-dnsutils)"
command -v python3 >/dev/null 2>&1 || skip "python3 is not installed"

cat > "$T/example.zone" <<'EOF'
$ORIGIN example.com.
$TTL 3600
@         IN SOA ns1 hostmaster ( 2026100701 1h 15m 1w 300 )
          IN NS  ns1
          IN MX  10 mail
          IN A   192.0.2.1
          IN AAAA 2001:db8::1
ns1       IN A   192.0.2.53
mail      IN A   192.0.2.25
www       IN CNAME @
alias     IN CNAME www
*.apps    IN A   192.0.2.80
sub       IN NS  ns.sub
ns.sub    IN A   192.0.2.99
EOF
# Forty TXT records under one name: more than UDP carries.
for i in $(seq 1 40); do echo "big IN TXT \"record number $i, padded out to make the answer large: xxxxxxxxxxxxxxxxxxxx\""; done >> "$T/example.zone"

# A secondary that answers every NOTIFY, and writes down each it got.
cat > "$T/sink.py" <<'EOF'
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
out = open(sys.argv[2], "a")
while True:
    d, a = s.recvfrom(4096)
    i, f = struct.unpack("!HH", d[:4])
    out.write("notify opcode=%d\n" % ((f >> 11) & 15)); out.flush()
    r = bytearray(d); r[2] |= 0x80
    s.sendto(bytes(r), a)
EOF
python3 "$T/sink.py" "$SINK" "$T/notified" &
SINK_PID=$!

daemon_start "$BIN"

# ── create ──────────────────────────────────────────────────────────────────
has "a dns runtime without --zone is refused" "$("$BIN" create dns bad -p "$P" -s 2>&1)" "--zone is required"
"$BIN" remove bad >/dev/null 2>&1
printf '$ORIGIN x.\n$TTL 60\n@ SOA a b 1 1 1 1 1\n@ NS a\nwww A 300.1.1.1\n' > "$T/broken.zone"
has "a zone that does not parse is refused with its line" "$("$BIN" create dns bad -p "$P" --zone "$T/broken.zone" -s 2>&1)" "line 5"
"$BIN" remove bad >/dev/null 2>&1
has "--listen unix: is refused" "$("$BIN" create dns bad --listen "unix:$T/d.sock" --zone "$T/example.zone" -s 2>&1)" "not served"
"$BIN" remove bad >/dev/null 2>&1

out=$("$BIN" create dns ns -p "$P" --zone "$T/example.zone" --transfer 127.0.0.1 --notify "127.0.0.1:$SINK" --proxy none -s 2>&1)
expect "the runtime is created and started" "$out" ""
for _ in $(seq 1 50); do dig @127.0.0.1 -p "$P" +short +time=1 +tries=1 example.com SOA >/dev/null 2>&1 && break; sleep 0.1; done
has "a second runtime on the same port is refused" "$("$BIN" create dns ns2 -p "$P" --zone "$T/example.zone" --proxy none -s 2>&1)" "$P"
"$BIN" remove ns2 >/dev/null 2>&1

q() { dig @127.0.0.1 -p "$P" +time=2 +tries=1 "$@" 2>&1; }

# ── answers ─────────────────────────────────────────────────────────────────
r=$(q +norec example.com A)
has "a record is answered" "$r" "192.0.2.1"
has "authoritatively, and without recursion offered" "$r" "flags: qr aa;"
has "with EDNS kept to 1232" "$r" "udp: 1232"
expect "an IPv6 address" "$(q +short example.com AAAA)" "2001:db8::1"
expect "an alias is followed within the zone" "$(q +short alias.example.com A | tr '\n' ' ')" "www.example.com. example.com. 192.0.2.1 "
expect "a wildcard stands for the names beneath it" "$(q +short anything.apps.example.com A)" "192.0.2.80"
r=$(q nothing.example.com A)
has "an absent name is NXDOMAIN" "$r" "status: NXDOMAIN"
has "with the SOA at its negative TTL" "$r" "300	IN	SOA"
r=$(q mail.example.com AAAA)
has "a name without the type is NODATA" "$r" "status: NOERROR"
has "with the SOA" "$r" "ANSWER: 0, AUTHORITY: 1"
r=$(q example.com MX)
has "an MX names its host" "$r" "10 mail.example.com."
has "and gives its address" "$r" "mail.example.com.	3600	IN	A	192.0.2.25"
r=$(q +norec host.sub.example.com A)
has "a delegated name is referred" "$r" "sub.example.com.	3600	IN	NS	ns.sub.example.com."
has "with the glue" "$r" "ns.sub.example.com.	3600	IN	A	192.0.2.99"
has "and without AA" "$r" "flags: qr;"
has "a name in no zone is REFUSED" "$(q example.org A)" "status: REFUSED"
has "CHAOS version.bind is REFUSED" "$(q version.bind TXT CH)" "status: REFUSED"
has "ANY is answered with one HINFO (RFC 8482)" "$(q +short example.com ANY)" '"RFC8482"'
r=$(q +norec +ignore big.example.com TXT)
has "an answer too large for UDP is truncated" "$r" "flags: qr aa tc;"
expect "and whole over TCP" "$(q +tcp +short big.example.com TXT | wc -l)" 40
expect "dig, told of the truncation, comes back over TCP by itself" "$(q +short big.example.com TXT | wc -l)" 40

# ── transfer ────────────────────────────────────────────────────────────────
expect "AXFR to an address --transfer names: SOA, every record, SOA" "$(q example.com AXFR +noall +answer | grep -c IN)" 53
has "AXFR from another address is refused" "$(q -b 127.0.0.2 example.com AXFR)" "Transfer failed"

# ── reload ──────────────────────────────────────────────────────────────────
for _ in $(seq 1 30); do grep -q opcode=4 "$T/notified" 2>/dev/null && break; sleep 0.1; done
sed -i 's/2026100701/2026100702/' "$T/example.zone"
echo "new IN A 198.51.100.7" >> "$T/example.zone"
got=""
for _ in $(seq 1 30); do got=$(q +short new.example.com A); [ -n "$got" ] && break; sleep 0.2; done
expect "an edited zone is served without a restart" "$got" "198.51.100.7"
expect "with its new serial" "$(q +short example.com SOA | awk '{print $3}')" 2026100702
echo "broken IN A 999.1.1.1" >> "$T/example.zone"
sleep 2.5
expect "a broken edit leaves the zone before it" "$(q +short new.example.com A)" "198.51.100.7"
sleep 2
expect "the secondary was told once at start and once of the new serial" "$(grep -c 'opcode=4' "$T/notified")" 2
stat_of() { "$BIN" stats ns 2>/dev/null | awk -F: -v k="$1" '$1==k {s+=$2} END {print s+0}'; }
expect "and answered both, so neither was sent again" "$(stat_of notify_acked) $(stat_of notify_sent)" "2 2"
expect "the failed reload is counted" "$(stat_of zone_reload_failures)" 1

# ── response rate limiting ──────────────────────────────────────────────────
burst=$(python3 - "$P" <<'EOF'
import socket, struct, sys
p = int(sys.argv[1]); s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.5)
q = struct.pack("!HHHHHH", 7, 0, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
for _ in range(400):
    s.sendto(q, ("127.0.0.1", p))
full = tc = 0
try:
    while True:
        d = s.recv(4096)
        if struct.unpack("!H", d[2:4])[0] & 0x200: tc += 1
        else: full += 1
except socket.timeout:
    pass
print(full, tc, 400 - full - tc)
EOF
)
read -r full tc dropped <<<"$burst"
if [ "$full" -le 110 ] && [ "$tc" -ge 100 ] && [ "$dropped" -ge 100 ]; then ok "400 queries in a burst: $full answered, $tc truncated, $dropped dropped"
else bad "rate limit of 100 a second" "answered $full, truncated $tc, dropped $dropped"; fi

# ── names runtimes are reached by, published ────────────────────────────────
P2=$((SL_PORT_BASE+1712))
cp "$T/example.zone" "$T/pub.zone"
sed -i '$d' "$T/pub.zone"   # without the broken line the reload above left
"$BIN" create dns pub -p "$P2" --zone "$T/pub.zone" --publish 192.0.2.10,2001:db8::10 --rrl 0 --proxy none -s >/dev/null 2>&1
"$BIN" create server chat -p $((SL_PORT_BASE+1713)) --domain chat,api.example.com >/dev/null 2>&1
"$BIN" create storage files -p $((SL_PORT_BASE+1714)) --dir "$T/files" --anonymous --domain files.example.com >/dev/null 2>&1
qp() { dig @127.0.0.1 -p "$P2" +time=2 +tries=1 +short "$@" 2>&1; }
got=""
for _ in $(seq 1 40); do got=$(qp chat.example.com A); [ -n "$got" ] && break; sleep 0.2; done
expect "a runtime's --domain without a dot is published under the zone" "$got" "192.0.2.10"
expect "with every address --publish names" "$(qp chat.example.com AAAA)" "2001:db8::10"
expect "and one with dots as it is written" "$(qp api.example.com A)" "192.0.2.10"
# Published when the daemon has it, which is after the server's name in a slow build.
for _ in $(seq 1 40); do got="$(qp files.example.com A) $(qp photos.files.example.com A)"; [ "$got" = "192.0.2.10 192.0.2.10" ] && break; sleep 0.2; done
expect "a storage runtime's --domain, with its buckets beneath it" "$got" "192.0.2.10 192.0.2.10"
expect "a name the zone file gives an address keeps that address" "$(qp mail.example.com A)" "192.0.2.25"
has "a runtime's names are not published by a dns runtime without --publish" "$(q chat.example.com A)" "NXDOMAIN"
s1=$(qp example.com SOA | awk '{print $3}')
"$BIN" remove chat >/dev/null 2>&1
for _ in $(seq 1 40); do [ -z "$(qp chat.example.com A)" ] && break; sleep 0.2; done
expect "a runtime removed takes its names with it" "$(qp chat.example.com A)" ""
s2=$(qp example.com SOA | awk '{print $3}')
if [ "${s2:-0}" -gt "${s1:-0}" ] 2>/dev/null; then ok "and the serial grows, so a secondary sees it ($s1 -> $s2)"
else bad "the serial after a published name went" "$s1 -> $s2"; fi

# ── a wildcard certificate over DNS-01, from this runtime's own answers ─────
PEBBLE_DIR="${PEBBLE_DIR:-$HOME/socketley-perf/acme}"
PEBBLE="$PEBBLE_DIR/pebble-linux-amd64/linux/amd64/pebble"
if [ -x "$PEBBLE" ] && [ -r "$PEBBLE_DIR/pebble.minica.pem" ] && command -v openssl >/dev/null 2>&1; then
    P_DIR=$((SL_PORT_BASE+1715)) P_MGMT=$((SL_PORT_BASE+1716))
    printf '{"pebble": {"listenAddress": "127.0.0.1:%s", "managementListenAddress": "127.0.0.1:%s", "certificate": "%s", "privateKey": "%s", "httpPort": %s, "tlsPort": %s, "ocspResponderURL": "", "externalAccountBindingRequired": false}}\n' \
        "$P_DIR" "$P_MGMT" "$PEBBLE_DIR/localhost-cert.pem" "$PEBBLE_DIR/localhost-key.pem" \
        $((SL_PORT_BASE+1717)) $((SL_PORT_BASE+1718)) > "$T/pebble.json"
    # The CA asks this dns runtime, and nobody else, for the TXT record that proves the zone.
    PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 "$PEBBLE" -config "$T/pebble.json" -dnsserver "127.0.0.1:$P2" \
        > "$T/pebble.log" 2>&1 &
    PEBBLE_PID=$!
    for _ in $(seq 1 100); do curl -s --cacert "$PEBBLE_DIR/pebble.minica.pem" -o /dev/null "https://127.0.0.1:$P_DIR/dir" && break; sleep 0.1; done
    SOCKETLEY_ACME_DIRECTORY="https://127.0.0.1:$P_DIR/dir" SOCKETLEY_ACME_CA="$PEBBLE_DIR/pebble.minica.pem" \
        SOCKETLEY_ACME_DNS_WAIT=2 "$BIN" acme issue --domains '*.example.com,example.com' --cert "$T/w.pem" --key "$T/w.key" \
        > "$T/w.out" 2>&1
    kill "$PEBBLE_PID" 2>/dev/null
    expect "a wildcard certificate is issued over DNS-01, answered by the dns runtime" \
        "$(openssl x509 -noout -ext subjectAltName -in "$T/w.pem" 2>/dev/null | grep -o 'DNS:[*a-z.]*' | sort | tr '\n' ' ')" \
        "DNS:*.example.com DNS:example.com "
    sleep 1.5
    expect "and its answers are gone after" "$(qp _acme-challenge.example.com TXT)" ""
else
    echo "  SKIP: DNS-01 needs Pebble (set PEBBLE_DIR)"
fi

# ── restart ─────────────────────────────────────────────────────────────────
sed -i '$d' "$T/example.zone"   # the broken line out, so the restart reads a zone
# Stopped as a service stop would, its state left where it is, and started again.
kill -TERM "$SOCKETLEY_DPID" 2>/dev/null
for _ in $(seq 1 100); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
wait "$SOCKETLEY_DPID" 2>/dev/null
rm -f "$SOCKETLEY_SOCKET"
: > "$SOCKETLEY_DLOG"
daemon_start "$BIN"
got=""
# Under the sanitizer the old daemon's workers take seconds to go, and the new one starts after them.
for _ in $(seq 1 150); do got=$(q +short new.example.com A); [ "$got" = 198.51.100.7 ] && break; sleep 0.2; done
expect "a daemon started again brings the runtime back, answering" "$got" "198.51.100.7"
has "its configuration kept" "$("$BIN" show ns 2>&1)" "127.0.0.1:$SINK"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
