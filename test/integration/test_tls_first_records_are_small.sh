#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a TLS server sends a connection's first bytes in records a segment long, then full records, and
# small ones again after the connection has been quiet.
#
# What each part would catch:
#   * a first answer whose first record is 16 KiB, which a client on a path with a round trip can decrypt only once a
#     second round trip has brought its end, since a fresh connection's window is about ten segments
#   * small records for good, which cost a record's header and tag per 1.4 KB of a long download
#   * a connection quiet past a second whose next answer starts in full records again, though the kernel has shrunk
#     its window back
#   * an answer cut or altered by the change of record size
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a TLS server's first records are a segment long ==="
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }
daemon_isolate tlsramp
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 760))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -keyout "$T/k.pem" -out "$T/c.pem" \
    -subj /CN=localhost >/dev/null 2>&1
mkdir -p "$T/www"
python3 -I -c 'import sys; sys.stdout.buffer.write(bytes(range(256)) * 1024)' > "$T/www/f.bin"
"$BIN" create server s -p "$P" --http "$T/www" --tls --cert "$T/c.pem" --key "$T/k.pem" -s >/dev/null 2>&1 \
    || bad "the server is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do ss -ltnH "sport = :$P" | grep -q . && break; sleep 0.1; done

out=$(timeout 60 python3 -I - "$P" "$T/www/f.bin" <<'PY'
import socket, ssl, sys, time
port, want = int(sys.argv[1]), open(sys.argv[2], "rb").read()
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
s = socket.create_connection(("127.0.0.1", port)); s.settimeout(10)
inc, outg = ssl.MemoryBIO(), ssl.MemoryBIO()
tls = ctx.wrap_bio(inc, outg, server_hostname="localhost")
raw = bytearray()          # every byte the server sent since `mark`
def pump():
    d = s.recv(65536)
    if not d: raise EOFError
    raw.extend(d); inc.write(d)
def flush():
    d = outg.read()
    if d: s.sendall(d)
while True:
    try:
        tls.do_handshake(); flush(); break
    except ssl.SSLWantReadError:
        flush(); pump()
def records(buf):
    out, i = [], 0
    while i + 5 <= len(buf):
        n = int.from_bytes(buf[i+3:i+5], "big")
        if i + 5 + n > len(buf): break
        out.append(n); i += 5 + n
    return out
def get():
    del raw[:]
    tls.write(b"GET /f.bin HTTP/1.1\r\nHost: localhost\r\n\r\n"); flush()
    body = bytearray(); head = None
    while True:
        try:
            body += tls.read(1 << 20)
        except ssl.SSLWantReadError:
            pump(); continue
        if head is None and b"\r\n\r\n" in body:
            h, rest = bytes(body).split(b"\r\n\r\n", 1)
            head, body = h, bytearray(rest)
            n = int([l.split(b":")[1] for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")][0])
        if head is not None and len(body) >= n:
            return bytes(body[:n]), records(raw)
first, r1 = get()
second, r2 = get()
time.sleep(1.6)
third, r3 = get()
def show(r): return "%d records, first %s, largest %d" % (len(r), r[:3], max(r) if r else 0)
print("ok whole" if first == want and second == want and third == want else "FAIL whole")
print(("ok" if r1 and max(r1[:8]) <= 1400 else "FAIL") + " first-answer " + show(r1))
print(("ok" if r1 and max(r1) > 16000 else "FAIL") + " full-after " + show(r1))
print(("ok" if r2 and r2[0] > 16000 else "FAIL") + " second-answer " + show(r2))
print(("ok" if r3 and max(r3[:8]) <= 1400 else "FAIL") + " after-quiet " + show(r3))
PY
)
while IFS= read -r line; do
    case "$line" in
        ok*) ok ;;
        FAIL*) bad "${line#FAIL }" "the records the client saw" ;;
        *) bad "client" "$line" ;;
    esac
done <<<"$out"
[ "$PASS" -ge 5 ] || bad "the client" "ran $PASS of 5 checks: $out"

echo ""
echo "=== Results: $PASS/$((PASS+FAIL)) passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
