#!/usr/bin/env bash
# Integration test: a storage runtime with --tls speaks HTTP/3.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   discovery    every answer over TCP names the UDP port in Alt-Svc, or the
#                one SOCKETLEY_STORAGE_HTTP3_ADVERTISE gives
#   operations   through lib_storage_http3.py, every request a stream, run as
#                over HTTP/1.1: a bucket made, 24 MiB put and read back byte
#                for byte, HEAD, a Range, a listing, the web interface's page
#   streams      twenty in parallel, four hundred more on the same connection
#                (past the 128 open at once), and uploads and downloads
#                abandoned midway, after which the runtime still serves
#   shards       two shards share the UDP port; a client whose address
#                changes every 0.1 s mid-transfer reaches the other shard, which
#                hands its packets to the one holding the connection
#   handshakes   a hundred begun from forged-looking sources and never finished:
#                past 64 under way new clients are sent a Retry, and every one
#                is dropped by the 10 s handshake timeout
#   TLS          --ca asks a client certificate of QUIC as of TCP, and a renewed
#                certificate on disk is what the next QUIC handshake is shown
#
# Skipped when the binary was built without HTTP/3 (stats says h3:0) or the
# python aioquic library is missing.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgh3
P1=$((SL_PORT_BASE+1874))
P2=$((SL_PORT_BASE+1875))
P3=$((SL_PORT_BASE+1876))
T="$SOCKETLEY_TMPD"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
skip() { echo "  SKIP: $1"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

cleanup() {
    for r in stgh3 stgh3m stgh3r; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in stgh3 stgh3m stgh3r; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: storage over HTTP/3 ==="
for tool in openssl curl python3; do
    command -v "$tool" >/dev/null 2>&1 || skip "$tool is not available"
done
python3 -c 'import aioquic, sys; sys.exit(int(aioquic.__version__.split(".")[0]) < 1)' 2>/dev/null \
    || skip "the python aioquic library 1.0 or later is not installed (pip install aioquic)"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$T/key.pem" -out "$T/cert.pem" -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

# The daemon hands its environment to the runtimes it starts.
SOCKETLEY_STORAGE_HTTP3_ADVERTISE=443 daemon_start "$BIN"
"$BIN" create storage stgh3 -p "$P1" --dir "$T/data" --anonymous --tls --cert "$T/cert.pem" --key "$T/key.pem" \
    --shards 2 -s >/dev/null 2>&1 || bad "create" "the TLS runtime was not created"
U="https://localhost:$P1"
for _ in $(seq 1 100); do [ "$(curl -s -m 5 --cacert "$T/cert.pem" -o /dev/null -w '%{http_code}' "$U/")" = 200 ] && break; sleep 0.1; done

sum() { "$BIN" stats stgh3 2>/dev/null | awk -F: -v k="$1" '$1==k {s+=$2} END {print s+0}'; }
# A shard's section appears once it has served something, so the TCP answers above have published at least one.
for _ in $(seq 1 50); do [ "$(sum h3)" -ge 1 ] && break; sleep 0.1; done
[ "$(sum h3)" -ge 1 ] || skip "this build has no HTTP/3 (bin/build-thirdparty.sh http3, then rebuild)"

# ── discovery ───────────────────────────────────────────────────────────────
expect "an answer over TCP names HTTP/3 at the advertised port" \
    "$(curl -s -m 10 --cacert "$T/cert.pem" -o /dev/null -D - "$U/" | tr -d '\r' | grep -i '^alt-svc')" 'alt-svc: h3=":443"; ma=86400'
expect "and both shards listen on its UDP port" \
    "$(awk -v p="$(printf ':%04X' "$P1")" '$2 ~ p"$" && $4 == "07"' /proc/net/udp | wc -l)" 2

# ── over QUIC ───────────────────────────────────────────────────────────────
head -c 25165824 /dev/urandom > "$T/big"
python3 "$HERE/lib_storage_http3.py" "$P1" "$T/cert.pem" "$T/big" > "$T/h3.out" 2>&1
cat "$T/h3.out"
n_pass=$(grep -c '^  PASS' "$T/h3.out"); n_fail=$(grep -c '^  FAIL' "$T/h3.out")
PASS=$((PASS + n_pass)); FAIL=$((FAIL + n_fail)); TOTAL=$((TOTAL + n_pass + n_fail))
grep -q '^Results:' "$T/h3.out" || bad "the HTTP/3 client" "ended without its results"

for _ in $(seq 1 50); do [ "$(sum h3_streams)" -ge 430 ] && break; sleep 0.1; done
c=$(sum h3_conns); n=$(sum h3_streams)
if [ "$c" -ge 6 ] && [ "$n" -ge 430 ]; then ok "stats counts the connections ($c) and streams ($n)"
else bad "stats counts" "h3_conns=$c h3_streams=$n"; fi
# ── a client that moves ─────────────────────────────────────────────────────
head -c 8388608 /dev/urandom > "$T/eight"
moved=$(python3 "$HERE/lib_storage_http3_edge.py" migrate "$P1" "$T/cert.pem" "$T/eight" 2>&1)
expect "a client whose address keeps changing puts and reads back 8 MiB" "${moved% rebinds=*}" "200 200 same"
r=${moved##*rebinds=}
if [ "${r:-0}" -ge 10 ] 2>/dev/null; then ok "and its address changed $r times on the way"
else bad "the relay moved the client" "$moved"; fi
for _ in $(seq 1 50); do [ "$(sum h3_forwarded)" -ge 1 ] && break; sleep 0.1; done
f=$(sum h3_forwarded)
if [ "$f" -ge 1 ]; then ok "the shard it moved to handed its packets on ($f)"
else bad "packets handed between shards" "h3_forwarded=$f"; fi

# ── handshakes never finished ───────────────────────────────────────────────
python3 "$HERE/lib_storage_http3_edge.py" halfopen "$P1" 160 >/dev/null 2>&1
for _ in $(seq 1 50); do [ "$(sum h3_retries)" -ge 1 ] && break; sleep 0.1; done
rt=$(sum h3_retries)
if [ "$rt" -ge 1 ]; then ok "past 64 handshakes under way a new client is sent a Retry ($rt)"
else bad "Retry under a flood of handshakes" "h3_retries=$rt"; fi
expect "and a client that answers its Retry is served meanwhile" \
    "$(python3 "$HERE/lib_storage_http3_edge.py" peer "$P1" "$T/cert.pem" | awk '{print $NF}')" 200
for _ in $(seq 1 150); do [ "$(sum h3_open)" -eq 0 ] && break; sleep 0.1; done
expect "every handshake never finished is dropped within its 10 s" "$(sum h3_open)" 0

# ── TLS: a client certificate asked for, a certificate renewed ──────────────
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$T/ca.key" -out "$T/ca.pem" -subj "/CN=h3 test CA" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$T/cl.key" -out "$T/cl.csr" -subj "/CN=client" >/dev/null 2>&1
openssl x509 -req -in "$T/cl.csr" -CA "$T/ca.pem" -CAkey "$T/ca.key" -CAcreateserial -days 2 -out "$T/cl.pem" >/dev/null 2>&1
"$BIN" create storage stgh3m -p "$P2" --dir "$T/mtls" --anonymous --tls --cert "$T/cert.pem" --key "$T/key.pem" \
    --ca "$T/ca.pem" -s >/dev/null 2>&1 || bad "create" "the --ca runtime was not created"
for _ in $(seq 1 100); do [ "$(curl -s -m 5 --cacert "$T/cert.pem" --cert "$T/cl.pem" --key "$T/cl.key" -o /dev/null -w '%{http_code}' "https://localhost:$P2/")" = 200 ] && break; sleep 0.1; done
expect "with --ca, a QUIC client without a certificate is refused" \
    "$(python3 "$HERE/lib_storage_http3_edge.py" peer "$P2" "$T/cert.pem")" refused
expect "and one with a certificate the CA signed is served" \
    "$(python3 "$HERE/lib_storage_http3_edge.py" peer "$P2" "$T/cert.pem" "$T/cl.pem" "$T/cl.key" | awk '{print $NF}')" 200

cp "$T/cert.pem" "$T/live.pem"; cp "$T/key.pem" "$T/live.key"
"$BIN" create storage stgh3r -p "$P3" --dir "$T/renew" --anonymous --tls --cert "$T/live.pem" --key "$T/live.key" \
    -s >/dev/null 2>&1 || bad "create" "the renewal runtime was not created"
for _ in $(seq 1 100); do [ "$(curl -s -m 5 --cacert "$T/cert.pem" -o /dev/null -w '%{http_code}' "https://localhost:$P3/")" = 200 ] && break; sleep 0.1; done
old=$(python3 "$HERE/lib_storage_http3_edge.py" peer "$P3" "$T/cert.pem" | awk '{print $1}')
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$T/new.key" -out "$T/new.pem" -subj "/CN=localhost/O=renewed" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
cat "$T/cert.pem" "$T/new.pem" > "$T/both.pem"
cp "$T/new.key" "$T/live.key.tmp" && mv "$T/live.key.tmp" "$T/live.key"
cp "$T/new.pem" "$T/live.pem.tmp" && mv "$T/live.pem.tmp" "$T/live.pem"
want=$(openssl x509 -in "$T/new.pem" -noout -serial | cut -d= -f2 | tr 'A-F' 'a-f' | sed 's/^0*//')
got=""
for _ in $(seq 1 30); do
    curl -s -m 5 --cacert "$T/both.pem" -o /dev/null "https://localhost:$P3/"
    got=$(python3 "$HERE/lib_storage_http3_edge.py" peer "$P3" "$T/both.pem" | awk '{print $1}')
    [ "$got" = "$want" ] && break; sleep 0.5
done
if [ -n "$old" ] && [ "$old" != "$want" ] && [ "$got" = "$want" ]; then ok "a renewed certificate is what QUIC shows next"
else bad "a renewed certificate over QUIC" "before $old, after $got, want $want"; fi

expect "the runtime still serves HTTP/1.1 and HTTP/2 after all that" \
    "$(curl -s -m 10 --cacert "$T/cert.pem" --http1.1 -o /dev/null -w '%{http_code}' "$U/hthree/s.txt") $(curl -s -m 10 --cacert "$T/cert.pem" --http2 -o /dev/null -w '%{http_code}' "$U/hthree/s.txt")" "200 200"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
