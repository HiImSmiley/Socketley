#!/usr/bin/env bash
# Integration test: a proxied request says who asked, over what, for which host.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# The proxy rewrites Host to the backend's own address, as nginx does, and
# until now added nothing in its place: a backend behind it saw every request
# come from the proxy, over plain HTTP, for an address that is not the site's.
# Frameworks build redirects and absolute URLs from those three facts, and an
# HTTPS site behind a TLS-terminating proxy redirected its users to http://
# on the backend's address.  X-Forwarded-For, -Proto and -Host are what every
# framework reads them from.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# A client that sends its own forwarding headers keeps its X-Forwarded-For as
# the start of the chain and loses its claims about scheme and host, and each
# header reaches the backend exactly once -- so a build that appended blindly
# or trusted the client fails as surely as one that added nothing.
#
# A client that resets its connection right behind its request has no peer
# address left to look up by the time the request is read, and the empty
# address that left stands for a unix-socket peer on this machine: the chain
# went to the backend as the client wrote it, with no hop of this proxy's.
# The address is read at accept, so every request that reaches the backend
# carries its hop.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate pxfwd

BE=$((SL_PORT_BASE+1820))
PX=$((SL_PORT_BASE+1821))
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1))
        if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
        else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi; }
cleanup() { [ -n "${BEPID:-}" ] && kill "$BEPID" 2>/dev/null; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: the proxy says who asked, over what, for which host ==="

# Answers each request with the forwarding headers it received, one per line.
cat > "$SOCKETLEY_TMPD/be.py" <<'PYEOF'
import socket, sys, threading
port, log = int(sys.argv[1]), sys.argv[2]
def serve(c):
    buf = b""
    try:
        while True:
            while b"\r\n\r\n" not in buf:
                b = c.recv(65536)
                if not b: return
                buf += b
            head, buf = buf.split(b"\r\n\r\n", 1)
            lines = [l for l in head.split(b"\r\n")[1:] if l.lower().startswith(b"x-forwarded-")]
            body = b"\n".join(lines) + b"\n"
            with open(log, "ab") as f:
                f.write(body)
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
    finally:
        c.close()
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", port)); ls.listen(16)
sys.stderr.write("be up\n"); sys.stderr.flush()
while True:
    c, _ = ls.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PYEOF
python3 "$SOCKETLEY_TMPD/be.py" "$BE" "$SOCKETLEY_TMPD/seen.log" 2>"$SOCKETLEY_TMPD/be.log" & BEPID=$!
for _ in $(seq 1 50); do grep -q "be up" "$SOCKETLEY_TMPD/be.log" 2>/dev/null && break; sleep 0.1; done

daemon_start "$BIN"
"$BIN" create proxy fw -p "$PX" --backend "127.0.0.1:$BE" --protocol http -s >/dev/null 2>&1
for _ in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/"$PX") 2>/dev/null && break; sleep 0.1; done

ask() {
    python3 - "$PX" "$@" <<'PYEOF'
import socket, sys
port, extra = int(sys.argv[1]), sys.argv[2:]
s = socket.create_connection(("127.0.0.1", port), timeout=4)
req = "GET /fw/x HTTP/1.1\r\nHost: shop.example\r\n" + "".join(h + "\r\n" for h in extra) + "\r\n"
s.sendall(req.encode())
data = b""
while b"\r\n\r\n" not in data:
    data += s.recv(65536)
head, body = data.split(b"\r\n\r\n", 1)
n = int([l for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")][0].split(b":")[1])
while len(body) < n:
    body += s.recv(65536)
print(body.decode().strip().replace("\n", " | "))
PYEOF
}

ok "$(ask)" \
   "X-Forwarded-For: 127.0.0.1 | X-Forwarded-Proto: http | X-Forwarded-Host: shop.example" \
   "a plain request names its client, its scheme and the host it asked for"

ok "$(ask 'X-Forwarded-For: 10.0.0.1' 'X-Forwarded-Proto: https' 'X-Forwarded-Host: evil.example')" \
   "X-Forwarded-For: 10.0.0.1, 127.0.0.1 | X-Forwarded-Proto: http | X-Forwarded-Host: shop.example" \
   "a client's chain is extended and its scheme and host claims are replaced, once each"

# The last bytes of the head and a reset together, forty times over.
python3 - "$PX" <<'PYEOF'
import socket, struct, sys, time
port = int(sys.argv[1])
for _ in range(40):
    s = socket.create_connection(("127.0.0.1", port), timeout=4)
    s.sendall(b"GET /fw/rst HTTP/1.1\r\nHost: shop.example\r\nX-Forwarded-For: 10.9.9.9\r\n")
    time.sleep(0.05)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.sendall(b"\r\n")
    s.close()
PYEOF
sleep 1
ok "$(grep -c '^X-Forwarded-For: 10\.9\.9\.9$' "$SOCKETLEY_TMPD/seen.log")" "0" \
   "a client that resets behind its request is never forwarded without this proxy's hop"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
