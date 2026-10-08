#!/usr/bin/env bash
# Integration test: a storage runtime speaks HTTP/2.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   negotiation  over --tls a client offering h2 by ALPN is given it, and one
#                that does not keeps HTTP/1.1; in the clear a connection that
#                opens with the preface speaks HTTP/2 and any other HTTP/1.1
#   operations   every request a stream, run as over HTTP/1.1: a bucket made,
#                24 MiB put and read back byte for byte, HEAD, a Range, a body
#                of no stated length, a listing, the web interface's page and a
#                folder's ZIP
#   multiplexing twenty requests in parallel over one connection
#   frames       through lib_storage_http2.py: windows of 1 KiB, interleaved
#                uploads, a stream answered beside a stalled one, and the
#                limits a peer is held to
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgh2
P1=$((SL_PORT_BASE+1871))
P2=$((SL_PORT_BASE+1872))
T="$SOCKETLEY_TMPD"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

cleanup() {
    for r in stgh2 stgh2c; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in stgh2 stgh2c; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: storage over HTTP/2 ==="
for tool in openssl curl python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "  SKIP: $tool is not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
done
if ! curl -V | grep -q HTTP2; then echo "  SKIP: curl has no HTTP/2"; echo "  Results: 0/0 passed (0 failed)"; exit 0; fi
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$T/key.pem" -out "$T/cert.pem" -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

daemon_start "$BIN"
"$BIN" create storage stgh2 -p "$P1" --dir "$T/tls" --anonymous --tls --cert "$T/cert.pem" --key "$T/key.pem" -s >/dev/null 2>&1 \
    || bad "create" "the TLS runtime was not created"
"$BIN" create storage stgh2c -p "$P2" --dir "$T/clear" --anonymous --shards 2 -s >/dev/null 2>&1 \
    || bad "create" "the cleartext runtime was not created"
U="https://localhost:$P1"; C="http://127.0.0.1:$P2"
h2() { curl -s -m 30 --http2 --cacert "$T/cert.pem" "$@"; }
h2c() { curl -s -m 30 --http2-prior-knowledge "$@"; }
for _ in $(seq 1 100); do [ "$(h2 -o /dev/null -w '%{http_code}' "$U/")" = 200 ] && break; sleep 0.1; done
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$C/")" = 200 ] && break; sleep 0.1; done

# ── negotiation ─────────────────────────────────────────────────────────────
expect "a client offering h2 by ALPN is given it" \
    "$(echo | openssl s_client -connect "127.0.0.1:$P1" -alpn h2,http/1.1 2>/dev/null | grep -o 'ALPN protocol: h2')" "ALPN protocol: h2"
expect "curl speaks HTTP/2 over TLS" "$(h2 -o /dev/null -w '%{http_version}' "$U/")" 2
expect "and HTTP/1.1 when it asks for that" "$(h2 --http1.1 -o /dev/null -w '%{http_version}' "$U/")" 1.1
expect "in the clear, the preface is HTTP/2" "$(h2c -o /dev/null -w '%{http_version}' "$C/")" 2
expect "and anything else HTTP/1.1" "$(curl -s -o /dev/null -w '%{http_version}' "$C/")" 1.1

# ── operations, over TLS ────────────────────────────────────────────────────
head -c 25165824 /dev/urandom > "$T/big"
expect "a bucket is made" "$(h2 -o /dev/null -w '%{http_code}' -X PUT "$U/htwo")" 200
expect "24 MiB is put" "$(h2 -o /dev/null -w '%{http_code}' -T "$T/big" "$U/htwo/big")" 200
expect "and read back byte for byte" "$(h2 "$U/htwo/big" | cmp -s - "$T/big" && echo same)" same
expect "a HEAD gives its length and no body" "$(h2 -I "$U/htwo/big" | tr -d '\r' | grep -i '^content-length')" "content-length: 25165824"
expect "a Range is exact" "$(h2 -H 'Range: bytes=1000-1999' "$U/htwo/big" | cmp -s - <(tail -c +1001 "$T/big" | head -c 1000) && echo same)" same
expect "a body of no stated length is stored" "$(printf 'streamed' | h2 -T - -o /dev/null -w '%{http_code}' "$U/htwo/s.txt"; h2 "$U/htwo/s.txt")" "200streamed"
expect "a missing key is 404 with its XML" "$(h2 "$U/htwo/none" | grep -o '<Code>NoSuchKey</Code>')" "<Code>NoSuchKey</Code>"
expect "a listing names both" "$(h2 "$U/htwo?list-type=2" | grep -o '<Key>[^<]*' | tr '\n' ' ')" "<Key>big <Key>s.txt "
expect "the web interface's page is served" "$(h2 "$U/~ui/" | grep -c '<html')" 1
expect "a folder's ZIP streams with its length" \
    "$(h2 -o "$T/f.zip" -w '%{size_download}' "$U/~dav/htwo/?zip"; echo; python3 -c 'import zipfile,sys; print(sorted(zipfile.ZipFile(sys.argv[1]).namelist()))' "$T/f.zip")" \
    "$(stat -c %s "$T/f.zip" 2>/dev/null)
['big', 's.txt']"
expect "twenty requests in parallel go over one connection" \
    "$(h2 -Z --parallel-max 20 $(for _ in $(seq 20); do echo "$U/htwo/s.txt -o /dev/null"; done) -w '%{num_connects}\n' | sort | uniq -c | tr -s ' ' | tr '\n' ' ')" \
    " 19 0  1 1 "

# ── over two shards in the clear, frame by frame ────────────────────────────
python3 "$HERE/lib_storage_http2.py" "$P2" "$BIN" stgh2c > "$T/frames.out" 2>&1
cat "$T/frames.out"
n_pass=$(grep -c '^  PASS' "$T/frames.out"); n_fail=$(grep -c '^  FAIL' "$T/frames.out")
PASS=$((PASS + n_pass)); FAIL=$((FAIL + n_fail)); TOTAL=$((TOTAL + n_pass + n_fail))
# Each shard has a section of its own, published as its figures change; the counts are their sums -- of the streams,
# refusals and GOAWAYs the frame-by-frame part made, so without it there is nothing to count.
sum() { "$BIN" stats stgh2c 2>/dev/null | awk -F: -v k="$1" '$1==k {s+=$2} END {print s+0}'; }
if grep -q SKIP "$T/frames.out"; then
    echo "  SKIP: stats counts streams (the frame-by-frame part was skipped)"
else
    for _ in $(seq 1 100); do [ "$(sum h2_streams)" -ge 100 ] && [ "$(sum h2_refused)" -ge 1 ] && [ "$(sum h2_goaways)" -ge 1 ] && break; sleep 0.1; done
    n=$(sum h2_streams); r=$(sum h2_refused); g=$(sum h2_goaways)
    if [ "$n" -ge 100 ] && [ "$r" -ge 1 ] && [ "$g" -ge 1 ]; then ok "stats counts the streams ($n), the refused and the GOAWAYs"
    else bad "stats counts streams" "streams=$n refused=$r goaways=$g"; fi
fi
expect "the TLS runtime still serves HTTP/1.1 and HTTP/2 after all that" \
    "$(h2 --http1.1 -o /dev/null -w '%{http_code}' "$U/htwo/s.txt") $(h2 -o /dev/null -w '%{http_code}' "$U/htwo/s.txt")" "200 200"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
