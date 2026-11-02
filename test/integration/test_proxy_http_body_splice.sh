#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: an HTTP proxy moves a long answer's body of a known length by splice, and reads the next answer's
# head on the same connections after it as the copy path would.
#
# What each part would catch:
#   * the body copied through user space: 400 to 440 ms of the proxy's CPU per GiB, where splice costs 45 to 50
#   * a splice that does not stop at the body's last byte, or a socket not given back to the copy path after it: the
#     next answer on a kept-alive or pipelined connection lost, glued to the body or never ended, and the bytes a
#     backend sends past its Content-Length handed to the client, which the copy path drops
#   * a HEAD's Content-Length taken for a body, a client's Connection: close not ended by a FIN, a TLS client's body
#     spliced before its send key is the kernel's
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: an HTTP proxy splices a long answer's body ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_isolate httpsplice
T=$SOCKETLEY_TMPD
S=$((SL_PORT_BASE + 1960)); PH=$((SL_PORT_BASE + 1961)); PE=$((SL_PORT_BASE + 1962))
PO=$((SL_PORT_BASE + 1963)); PX=$((SL_PORT_BASE + 1964))
unset SOCKETLEY_CONFIG
# A backend that sends 64 bytes more than the 1 MiB its Content-Length says.
python3 - "$PO" <<'PY' &
import socket, socketserver, sys
body = bytes(range(256)) * 4096
class H(socketserver.BaseRequestHandler):
    def handle(self):
        buf = b""
        while True:
            d = self.request.recv(65536)
            if not d: return
            buf += d
            while b"\r\n\r\n" in buf:
                _, buf = buf.split(b"\r\n\r\n", 1)
                self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body + b"X" * 64)
class S(socketserver.ThreadingTCPServer):
    daemon_threads = True; allow_reuse_address = True
S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
OVER=$!
trap 'kill $OVER 2>/dev/null; daemon_stop' EXIT
mkdir -p "$T/www"
head -c $((8 << 20)) /dev/urandom > "$T/www/big.bin"
head -c 3000 /dev/urandom > "$T/www/small.bin"
head -c $((64 << 20)) /dev/urandom > "$T/www/huge.bin"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=files.example.com \
    -addext "subjectAltName=DNS:files.example.com" -keyout "$T/e.key" -out "$T/e.pem" >/dev/null 2>&1
daemon_start "$BIN"
"$BIN" create server web -p "$S" --http "$T/www" --domain files.example.com -s >/dev/null 2>&1
"$BIN" create proxy ph -p "$PH" --backend "127.0.0.1:$S" -s >/dev/null 2>&1
"$BIN" create proxy ent -p "$PE" --tls --cert "$T/e.pem" --key "$T/e.key" -s >/dev/null 2>&1
"$BIN" create proxy px -p "$PX" --backend "127.0.0.1:$PO" -s >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PH/ph/small.bin")" = 200 ] && break; sleep 0.1; done

out=$(timeout 120 python3 - "$PH" "$T/www" <<'PY'
import socket, sys
port, www = int(sys.argv[1]), sys.argv[2]
files = {n: open("%s/%s" % (www, n), "rb").read() for n in ("big.bin", "small.bin")}
def read_answer(f, head_only=False):
    status = f.readline()
    hdr = {}
    while True:
        l = f.readline()
        if l in (b"\r\n", b""): break
        k, v = l.decode().split(":", 1); hdr[k.strip().lower()] = v.strip()
    n = 0 if head_only else int(hdr.get("content-length", 0))
    body = f.read(n) if n else b""
    return status.split()[1].decode() if status else "none", body
def conn():
    s = socket.create_connection(("127.0.0.1", port)); s.settimeout(20); return s, s.makefile("rb")
# Kept alive: a long body, a short one after it, and a long one again.
s, f = conn(); good = 0
for name in ("big.bin", "small.bin", "big.bin", "small.bin"):
    s.sendall(b"GET /ph/%s HTTP/1.1\r\nHost: x\r\n\r\n" % name.encode())
    st, body = read_answer(f); good += st == "200" and body == files[name]
print("keepalive", good)
s.close()
# Pipelined: four requests sent at once, the answers read in order.
s, f = conn()
s.sendall(b"".join(b"GET /ph/%s HTTP/1.1\r\nHost: x\r\n\r\n" % n.encode() for n in ("big.bin", "small.bin", "big.bin", "small.bin")))
good = 0
for name in ("big.bin", "small.bin", "big.bin", "small.bin"):
    st, body = read_answer(f); good += st == "200" and body == files[name]
print("pipelined", good)
s.close()
# A HEAD of the long one, whose length is no body, and a GET behind it on the same connection.
s, f = conn()
s.sendall(b"HEAD /ph/big.bin HTTP/1.1\r\nHost: x\r\n\r\nGET /ph/small.bin HTTP/1.1\r\nHost: x\r\n\r\n")
st1, _ = read_answer(f, head_only=True); st2, body = read_answer(f)
print("head", int(st1 == "200" and st2 == "200" and body == files["small.bin"]))
s.close()
# Connection: close, ended by the proxy's FIN once the body is out.
s, f = conn()
s.sendall(b"GET /ph/big.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
st, body = read_answer(f); rest = f.read()
print("close", int(st == "200" and body == files["big.bin"] and rest == b""))
PY
)
over=$(timeout 60 python3 - "$PX" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1]))); s.settimeout(10); f = s.makefile("rb")
s.sendall(b"GET /px/a HTTP/1.1\r\nHost: x\r\n\r\n")
f.readline(); n = 0
while True:
    l = f.readline()
    if l in (b"\r\n", b""): break
    if l.lower().startswith(b"content-length:"): n = int(l.split(b":")[1])
body = f.read(n)
# What comes after the body: the next answer's status line, or the end, and never the backend's extra bytes.
try:
    s.sendall(b"GET /px/a HTTP/1.1\r\nHost: x\r\n\r\n")
    nxt = f.read(9)
except OSError:
    nxt = b""
print("over", int(body == bytes(range(256)) * 4096 and nxt in (b"", b"HTTP/1.1 ")), repr(nxt))
PY
)
out="$out
$over"
for row in keepalive:4:"a kept-alive connection gets each answer whole, a short one after a spliced long one" \
           pipelined:4:"pipelined requests get their answers whole and in order" \
           head:1:"a HEAD's length is no body, and the GET behind it is answered" \
           close:1:"a client's Connection: close gets the body whole and then the end" \
           over:1:"the bytes a backend sends past its Content-Length never reach the client"; do
    k=${row%%:*}; rest=${row#*:}; want=${rest%%:*}; what=${rest#*:}
    got=$(awk -v k="$k" '$1==k {print $2}' <<<"$out")
    [ "$got" = "$want" ] && ok || bad "$what" "${got:-none} of $want; $out"
done

# What the copy path cost per GiB against what splice costs, read off the proxy's processes.
if nm -C "$BIN" 2>/dev/null | grep -q '__asan_'; then
    echo "  SKIP [cpu]: CPU per GiB measures the sanitizer, not the splice"
else
    cpu() { local t=0 p; for p in $(ss -ltnpH "sport = :$PH" | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u); do
        t=$((t + $(awk '{print $14+$15}' "/proc/$p/stat"))); done; echo "$t"; }
    c0=$(cpu)
    for _ in 1 2 3 4 5 6 7 8; do curl -s -o /dev/null "http://127.0.0.1:$PH/ph/huge.bin"; done
    c1=$(cpu)
    per=$(awk -v a="$c0" -v b="$c1" -v hz="$(getconf CLK_TCK)" 'BEGIN{printf "%.0f", (b-a)*1000/hz*2}')
    echo "  the proxy's CPU per GiB of answer bodies: ${per} ms"
    if [ "$per" -lt 200 ]; then ok; else bad "a long body costs the proxy little CPU" "${per} ms per GiB"; fi
fi

# A TLS entrance's HTTP/1.1 client: the body whole, and through kernel TLS where the kernel has it.
for _ in $(seq 1 60); do f=$(find "$T" -name 'routes-ent' | head -1); [ -n "$f" ] && grep -q files.example.com "$f" && break; sleep 0.2; done
tx() { awk '$1=="TlsTxSw" {print $2}' /proc/net/tls_stat 2>/dev/null; }
t0=$(tx)
got=$(curl -sk -m 60 --http1.1 --resolve "files.example.com:$PE:127.0.0.1" "https://files.example.com:$PE/big.bin" \
      "https://files.example.com:$PE/small.bin" | sha256sum | cut -c1-16)
want=$(cat "$T/www/big.bin" "$T/www/small.bin" | sha256sum | cut -c1-16)
[ "$got" = "$want" ] && ok || bad "a TLS client gets a long body and a short one after it whole" "$got, want $want"
if [ -r /proc/net/tls_stat ]; then
    [ "$(tx)" -gt "${t0:-0}" ] && ok || bad "and the long one through kernel TLS" "kernel TLS sockets ${t0} -> $(tx)"
fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
