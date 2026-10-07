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
#   shards       two shards share the UDP port; a connection stays on one
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
T="$SOCKETLEY_TMPD"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
skip() { echo "  SKIP: $1"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

cleanup() {
    "$BIN" stop stgh3 >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove stgh3 >/dev/null 2>&1 || true
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
expect "the runtime still serves HTTP/1.1 and HTTP/2 after all that" \
    "$(curl -s -m 10 --cacert "$T/cert.pem" --http1.1 -o /dev/null -w '%{http_code}' "$U/hthree/s.txt") $(curl -s -m 10 --cacert "$T/cert.pem" --http2 -o /dev/null -w '%{http_code}' "$U/hthree/s.txt")" "200 200"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
