#!/usr/bin/env bash
# Integration test: a storage runtime terminates TLS on its listener.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   handshake   an HTTPS client with the certificate as its trust store is
#               served; a plaintext client, and a client that does not trust the
#               certificate, are refused and never served in the clear
#   data path   a 24 MiB object goes in and comes out byte for byte over the
#               session, a Range read of it is exact, and none of the download is
#               counted as zero-copy -- a splice would move bytes the record
#               layer never saw and the client would read ciphertext-less garbage
#   boto3       the client library people run, over https with the certificate
#   mTLS        with --ca a client presents a certificate signed by it or is
#               refused
#   reload      certificates are read when the runtime starts, so `reload`
#               installs a replaced one
#   refusals    --tls with no --cert/--key, and --tls with --listen unix:, are
#               refused rather than stored
#   deadline    a peer that connects and says nothing is dropped once the
#               handshake deadline passes, and is not counted against the runtime
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgtls

P1=$((SL_PORT_BASE+1620))
P2=$((SL_PORT_BASE+1621))
P3=$((SL_PORT_BASE+1622))
T="$SOCKETLEY_TMPD"
DATA="$T/objects"
CERTS="$T/certs"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
has() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
contains() { if has "$2" "$3"; then ok "$1"; else bad "$1" "no '$3' in: $2"; fi; }

cleanup() {
    for r in stgtls stgmtls stgreload; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in stgtls stgmtls stgreload; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: storage over TLS ==="
for tool in openssl curl python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "  SKIP: $tool is not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
done

mkdir -p "$CERTS"
mkcert() {   # name cn
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$CERTS/$1-key.pem" -out "$CERTS/$1.pem" \
        -subj "/CN=$2" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 || true
}
mkcert srv localhost
mkcert srv2 localhost
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$CERTS/ca-key.pem" -out "$CERTS/ca.pem" \
    -subj "/CN=storage-test-ca" >/dev/null 2>&1 || true
openssl req -newkey rsa:2048 -nodes -keyout "$CERTS/client-key.pem" -out "$CERTS/client.csr" \
    -subj "/CN=test-client" >/dev/null 2>&1 || true
openssl x509 -req -in "$CERTS/client.csr" -days 2 -CA "$CERTS/ca.pem" -CAkey "$CERTS/ca-key.pem" \
    -CAcreateserial -out "$CERTS/client.pem" >/dev/null 2>&1 || true
if [ ! -s "$CERTS/srv.pem" ] || [ ! -s "$CERTS/client.pem" ] || [ ! -s "$CERTS/srv2.pem" ]; then
    echo "  SKIP: openssl could not generate the test certificates"
    echo "  Results: 0/0 passed (0 failed)"
    exit 0
fi

daemon_start "$BIN"

# ── refusals ────────────────────────────────────────────────────────────────
out=$("$BIN" create storage x1 -p "$P3" --dir "$DATA" --anonymous --tls 2>&1); rc=$?
expect "create with --tls and no certificate is refused" "$rc" 1
contains "and names --cert" "$out" "--cert"
out=$("$BIN" create storage x2 --listen "unix:$T/x2.sock" --dir "$DATA" --anonymous --tls --cert "$CERTS/srv.pem" --key "$CERTS/srv-key.pem" -s 2>&1); rc=$?
expect "starting with --tls and --listen unix: is refused" "$rc" 1
out=$("$BIN" create storage x3 -p "$P3" --dir "$DATA" --anonymous --cert "$CERTS/srv.pem" 2>&1); rc=$?
expect "create with --cert and no --tls is refused" "$rc" 1

# ── a TLS runtime ───────────────────────────────────────────────────────────
"$BIN" create storage stgtls -p "$P1" --dir "$DATA" --anonymous --tls --cert "$CERTS/srv.pem" --key "$CERTS/srv-key.pem" -s >/dev/null 2>&1 \
    || bad "create" "the TLS runtime was not created"
https() { curl -s --cacert "$CERTS/srv.pem" "$@"; }
for _ in $(seq 1 100); do
    [ "$(https -o /dev/null -w '%{http_code}' "https://localhost:$P1/")" = 200 ] && break
    sleep 0.1
done
expect "an HTTPS client that trusts the certificate is served" "$(https -o /dev/null -w '%{http_code}' "https://localhost:$P1/")" 200
expect "a plaintext client is not served" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$P1/")" 000
expect "a client that does not trust the certificate is not served" \
    "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "https://localhost:$P1/")" 000

# The plaintext client got no S3 XML: whatever came back is not a bucket listing.
plain=$(curl -s --max-time 3 "http://127.0.0.1:$P1/" | head -c 200)
if has "$plain" "ListAllMyBucketsResult"; then bad "a plaintext request is never answered in the clear" "$plain"; else ok "a plaintext request is never answered in the clear"; fi

https -X PUT "https://localhost:$P1/tlsbkt" -o /dev/null
expect "a bucket is made over TLS" "$(https -o /dev/null -w '%{http_code}' -I "https://localhost:$P1/tlsbkt")" 200
head -c 25165824 /dev/urandom > "$T/big"
want=$(md5sum < "$T/big" | cut -d' ' -f1)
expect "a 24 MiB object is put over TLS" "$(https -o /dev/null -w '%{http_code}' -X PUT --data-binary @"$T/big" "https://localhost:$P1/tlsbkt/big")" 200
got=$(https "https://localhost:$P1/tlsbkt/big" | md5sum | cut -d' ' -f1)
expect "and comes back byte for byte" "$got" "$want"
got=$(https -H 'Range: bytes=1000000-1999999' "https://localhost:$P1/tlsbkt/big" | md5sum | cut -d' ' -f1)
want_r=$(tail -c +1000001 "$T/big" | head -c 1000000 | md5sum | cut -d' ' -f1)
expect "a Range read over TLS is exact" "$got" "$want_r"
https -X PUT --data-binary "small over tls" "https://localhost:$P1/tlsbkt/small" -o /dev/null
expect "a small object round-trips" "$(https "https://localhost:$P1/tlsbkt/small")" "small over tls"
etag=$(https -D - -o /dev/null "https://localhost:$P1/tlsbkt/small" | tr -d '\r' | sed -n 's/^[Ee][Tt]ag: //p')
expect "and carries the MD5 ETag" "$etag" "\"$(printf 'small over tls' | md5sum | cut -d' ' -f1)\""

# Chunked upload over the session, the framing curl uses for a stream of unknown size.
printf 'chunked body over tls' | https -X PUT -H 'Transfer-Encoding: chunked' --data-binary @- "https://localhost:$P1/tlsbkt/chunked" -o /dev/null
expect "a chunked upload over TLS is stored" "$(https "https://localhost:$P1/tlsbkt/chunked")" "chunked body over tls"

# The worker publishes its figures when they change, so they are read until they
# show the gets this file made.
stats=""
for _ in $(seq 1 50); do
    stats=$("$BIN" stats stgtls 2>&1)
    g=$(printf '%s\n' "$stats" | sed -n 's/^gets://p')
    [ "${g:-0}" -ge 3 ] && break
    sleep 0.1
done
zc=$(printf '%s\n' "$stats" | sed -n 's/^zero_copy_bytes://p')
gets=$(printf '%s\n' "$stats" | sed -n 's/^gets://p')
if [ "${gets:-0}" -ge 3 ]; then ok "the runtime counted the gets it served"; else bad "gets counted" "gets=$gets in: $stats"; fi
expect "none of the download over TLS was counted as zero-copy" "${zc:-x}" 0
contains "the TLS handshakes are counted" "$stats" "tls_handshakes:"

# boto3 with the certificate as its trust store.
python3 - "$P1" "$CERTS/srv.pem" <<'PYEOF' > "$T/boto.out" 2>&1
import sys
try:
    import boto3, botocore
    from botocore import UNSIGNED
    from botocore.config import Config
except Exception as e:
    print("SKIP", e); sys.exit(0)
port, cert = sys.argv[1], sys.argv[2]
c = boto3.client("s3", endpoint_url=f"https://localhost:{port}", region_name="us-east-1",
                 aws_access_key_id="x", aws_secret_access_key="y", verify=cert,
                 config=Config(signature_version=UNSIGNED, s3={"addressing_style": "path"}))
c.create_bucket(Bucket="bototls")
c.put_object(Bucket="bototls", Key="k/one", Body=b"boto over tls" * 1000)
r = c.get_object(Bucket="bototls", Key="k/one")
assert r["Body"].read() == b"boto over tls" * 1000, "body"
l = c.list_objects_v2(Bucket="bototls", Prefix="k/")
assert [o["Key"] for o in l["Contents"]] == ["k/one"], l
print("BOTO OK")
PYEOF
if grep -q "^SKIP" "$T/boto.out"; then ok "boto3 is not installed here, skipped"
else contains "boto3 puts, gets and lists over https" "$(cat "$T/boto.out")" "BOTO OK"; fi

# A client speaking TLS but pipelining two requests in one write: the second is
# answered from what the session already holds.
python3 - "$P1" "$CERTS/srv.pem" <<'PYEOF' > "$T/pipe.out" 2>&1
import socket, ssl, sys
port, cert = int(sys.argv[1]), sys.argv[2]
ctx = ssl.create_default_context(cafile=cert)
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname="localhost")
req = b"GET /tlsbkt/small HTTP/1.1\r\nHost: x\r\n\r\n"
s.sendall(req * 3)
buf = b""
s.settimeout(5)
while buf.count(b"small over tls") < 3:
    d = s.recv(65536)
    if not d: break
    buf += d
print("PIPELINED", buf.count(b"small over tls"))
PYEOF
contains "three pipelined requests in one TLS write are all answered" "$(cat "$T/pipe.out")" "PIPELINED 3"

# ── mTLS ────────────────────────────────────────────────────────────────────
"$BIN" create storage stgmtls -p "$P2" --dir "$T/objects2" --anonymous --tls --cert "$CERTS/srv.pem" --key "$CERTS/srv-key.pem" --ca "$CERTS/ca.pem" -s >/dev/null 2>&1 \
    || bad "create mtls" "the mTLS runtime was not created"
for _ in $(seq 1 100); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CERTS/srv.pem" --cert "$CERTS/client.pem" --key "$CERTS/client-key.pem" "https://localhost:$P2/")" = 200 ] && break
    sleep 0.1
done
expect "with --ca a client with a certificate it signed is served" \
    "$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CERTS/srv.pem" --cert "$CERTS/client.pem" --key "$CERTS/client-key.pem" "https://localhost:$P2/")" 200
expect "with --ca a client with no certificate is refused" \
    "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 --cacert "$CERTS/srv.pem" "https://localhost:$P2/")" 000

# ── reload installs a replaced certificate ──────────────────────────────────
cp "$CERTS/srv.pem" "$T/live.pem"; cp "$CERTS/srv-key.pem" "$T/live-key.pem"
"$BIN" create storage stgreload -p "$P3" --dir "$T/objects3" --anonymous --tls --cert "$T/live.pem" --key "$T/live-key.pem" -s >/dev/null 2>&1 \
    || bad "create reload" "the runtime was not created"
fp() { echo | openssl s_client -connect "127.0.0.1:$1" -servername localhost 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null; }
for _ in $(seq 1 100); do [ -n "$(fp "$P3")" ] && break; sleep 0.1; done
before=$(fp "$P3")
want_before=$(openssl x509 -in "$CERTS/srv.pem" -noout -fingerprint -sha256)
want_after=$(openssl x509 -in "$CERTS/srv2.pem" -noout -fingerprint -sha256)
expect "the listener presents the configured certificate" "$before" "$want_before"
cp "$CERTS/srv2.pem" "$T/live.pem"; cp "$CERTS/srv2-key.pem" "$T/live-key.pem"
expect "before a reload the old certificate is still the one served" "$(fp "$P3")" "$want_before"
"$BIN" reload stgreload >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(fp "$P3")" = "$want_after" ] && break; sleep 0.1; done
expect "after reload the replaced certificate is the one served" "$(fp "$P3")" "$want_after"

# ── the handshake deadline ──────────────────────────────────────────────────
# A peer that connects and sends nothing is not a client, and is let go after
# tls_handshake_deadline_secs (30) -- read from the runtime's own connection
# count, which the peer is in until then.
conns() { "$BIN" ls 2>/dev/null | awk '$2=="stgtls" {print $5}'; }
python3 - "$P1" > "$T/silent.out" 2>&1 <<'PYEOF' &
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
t0 = time.time()
s.settimeout(45)
try:
    d = s.recv(10)
    print("CLOSED_AFTER", int(time.time() - t0), "bytes" if d else "eof")
except Exception as e:
    print("ERR", e)
PYEOF
SILENT=$!
sleep 2
c_during=$(conns)
if [ "${c_during:-0}" -ge 1 ]; then ok "a silent peer is held while the handshake may still come"; else bad "a silent peer is counted" "conns=$c_during"; fi
wait "$SILENT" 2>/dev/null
out=$(cat "$T/silent.out")
if has "$out" "CLOSED_AFTER"; then
    secs=$(echo "$out" | awk '{print $2}')
    if [ "$secs" -ge 25 ] && [ "$secs" -le 40 ]; then ok "a silent peer is dropped at the handshake deadline ($secs s)"
    else bad "a silent peer is dropped at the handshake deadline" "dropped after $secs s: $out"; fi
else bad "a silent peer is dropped at the handshake deadline" "$out"; fi
expect "and the runtime still serves" "$(https -o /dev/null -w '%{http_code}' "https://localhost:$P1/")" 200

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
