#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a TLS client takes every line whatever reads its records arrive in.
#
# What it would catch: the client's record layer reads each read's ciphertext where it lies rather than from a copy,
# and keeps only what it did not take.  A record whose header or body ends in the next read, a read of one byte, and
# a read holding many records must all come out as the same lines in the same order -- a lost or reordered byte is a
# record that fails to authenticate, and a lost record is lines missing from the count.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a TLS client takes every line however its records are split ==="
if ! python3 -c "import ssl" >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    echo "  SKIP: python3 with ssl and openssl are required"; exit 0
fi
daemon_isolate clisplit
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1981))
unset SOCKETLEY_CONFIG
SRV_PID=""
trap '[ -n "$SRV_PID" ] && kill $SRV_PID 2>/dev/null; daemon_stop' EXIT

openssl req -x509 -newkey rsa:2048 -keyout "$T/peer.key" -out "$T/peer.pem" -nodes -subj "/CN=127.0.0.1" \
    -addext "subjectAltName=IP:127.0.0.1" -days 2 >/dev/null 2>&1 \
  || { echo "  SKIP: could not generate a test certificate"; exit 0; }

# The peer encrypts into a memory BIO, records from 1 byte to 16 KiB, and puts the ciphertext on the wire in pieces
# of 1 byte to 70 KB, each its own write with a pause behind it, so the client's reads end inside headers, inside
# bodies and between records.  It then reports the client's answer.
cat > "$T/peer.py" <<'PY'
import itertools, socket, ssl, sys, time
port, cert, key, n = int(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(cert, key)
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(1)
print("ready", flush=True)
raw, _ = srv.accept()
raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
raw.settimeout(20)
inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
obj = ctx.wrap_bio(inc, out, server_side=True)
def pump():
    d = out.read()
    if d:
        raw.sendall(d)
while True:
    try:
        obj.do_handshake(); break
    except ssl.SSLWantReadError:
        pump()
        d = raw.recv(65536)
        if not d:
            sys.exit("eof in the handshake")
        inc.write(d)
pump()
body = b"".join(b"L%d%s\n" % (i, b"x" * (i % 97)) for i in range(n)) + b"END\n"
records = itertools.cycle([1, 7, 100, 4096, 16384, 50000, 3, 5])
off = 0
while off < len(body):
    k = next(records); obj.write(body[off:off + k]); off += k
cipher = out.read()
pieces = itertools.cycle([1, 2, 3, 5, 4096, 13, 16389, 40000, 6, 16384, 70000, 4])
off = 0
while off < len(cipher):
    k = next(pieces); raw.sendall(cipher[off:off + k]); off += k
    time.sleep(0.0003)
print("sent", len(cipher), flush=True)
buf = b""
while b"\n" not in buf:
    try:
        buf += obj.read(4096)
    except ssl.SSLWantReadError:
        d = raw.recv(65536)
        if not d:
            break
        inc.write(d)
print("got", buf.decode(errors="replace").strip(), flush=True)
time.sleep(2)
PY

# Every line checked against what it must be, in order, and the count and the misses sent back.
cat > "$T/check.lua" <<'LUA'
local n, bad = 0, 0
function on_message(msg)
  if msg == "END" then self.send("ok " .. n .. " " .. bad); return end
  if msg ~= "L" .. n .. string.rep("x", n % 97) then bad = bad + 1 end
  n = n + 1
end
LUA

N=20000
python3 "$T/peer.py" "$P" "$T/peer.pem" "$T/peer.key" "$N" >"$T/peer.log" 2>&1 & SRV_PID=$!
for _ in $(seq 1 50); do grep -q ready "$T/peer.log" 2>/dev/null && break; sleep 0.1; done
daemon_start "$BIN"
"$BIN" create client split -t "127.0.0.1:$P" --tls --ca "$T/peer.pem" --lua "$T/check.lua" -s >/dev/null 2>&1
for _ in $(seq 1 300); do grep -q '^got' "$T/peer.log" 2>/dev/null && break; sleep 0.1; done

# The peer really split the stream: without its pieces on the wire the count below says nothing about reads.
if grep -q '^sent [0-9]' "$T/peer.log"; then ok; else bad "the peer sent its records in pieces" "$(tail -3 "$T/peer.log")"; fi
got=$(sed -n 's/^got //p' "$T/peer.log")
if [ "$got" = "ok $N 0" ]; then ok; else
    bad "every line arrives, in order, whatever read it ends in" "client answered '${got:-nothing}', want 'ok $N 0'"
fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
