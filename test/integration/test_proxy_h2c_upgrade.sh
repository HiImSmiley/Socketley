#!/usr/bin/env bash
# Integration test: an h2c upgrade offer is no offer through the proxy.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# After any 101 the proxy relays raw bytes, and every check it makes -- --auth,
# filters, routes, the X-Forwarded-User strip -- runs on an HTTP/1.1 request
# head.  A client that offered "Upgrade: h2c" to a backend that takes it (one
# that looks only at the Upgrade value and HTTP2-Settings, as Hypercorn does)
# got HTTP/2 to the backend with nothing in between, and could send it any
# stream it liked.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# The backend here is that lenient one: it answers 101 to any Upgrade it is
# handed, h2c included.  So an h2c offer must reach it as a plain request with
# no Upgrade and no HTTP2-Settings and come back 200, and a websocket offer to
# the same backend must still come back 101, or a build that strips every
# upgrade passes the first half.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate pxh2c

BE=$((SL_PORT_BASE+1830))
PX=$((SL_PORT_BASE+1831))
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1))
        if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
        else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi; }
cleanup() { [ -n "${BEPID:-}" ] && kill "$BEPID" 2>/dev/null; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: an h2c upgrade offer is not relayed ==="

# Answers 101 to any request carrying an Upgrade field, naming its value, and 200 to any other; it logs the
# Upgrade and HTTP2-Settings lines it was handed, one per line.
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
            lines = head.split(b"\r\n")[1:]
            seen = [l for l in lines if l.lower().startswith((b"upgrade:", b"http2-settings:"))]
            with open(log, "ab") as f:
                f.write(b"".join(l + b"\n" for l in seen) + b"--\n")
            up = [l.split(b":", 1)[1].strip() for l in lines if l.lower().startswith(b"upgrade:")]
            if up:
                c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + up[0] +
                          b"\r\n\r\n")
                return
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nplain")
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
"$BIN" create proxy hc -p "$PX" --backend "127.0.0.1:$BE" --protocol http -s >/dev/null 2>&1
for _ in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/"$PX") 2>/dev/null && break; sleep 0.1; done

# Prints the status code of the answer to one request with the given extra fields.
ask() {
    python3 - "$PX" "$@" <<'PYEOF'
import socket, sys
port, extra = int(sys.argv[1]), sys.argv[2:]
s = socket.create_connection(("127.0.0.1", port), timeout=4)
req = "GET /hc/x HTTP/1.1\r\nHost: app\r\n" + "".join(h + "\r\n" for h in extra) + "\r\n"
s.sendall(req.encode())
data = b""
try:
    while b"\r\n" not in data:
        d = s.recv(65536)
        if not d: break
        data += d
except OSError:
    pass
print(data.split(b"\r\n", 1)[0].split(b" ")[1].decode() if data.count(b" ") else "none")
PYEOF
}

ok "$(ask 'Connection: Upgrade, HTTP2-Settings' 'Upgrade: h2c' 'HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA')" "200" \
   "an h2c offer is answered as the plain request it carries"
ok "$(ask 'Connection: Upgrade' 'Upgrade: websocket, H2C' 'HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA')" "200" \
   "an offer naming h2c beside another protocol is not an offer either"
ok "$(grep -ciE '^(upgrade|http2-settings):' "$SOCKETLEY_TMPD/seen.log")" "0" \
   "the backend was handed neither Upgrade nor HTTP2-Settings for them"
ok "$(ask 'Connection: Upgrade' 'Upgrade: websocket')" "101" \
   "a websocket offer to the same backend still switches protocols"
ok "$(grep -ci '^upgrade: websocket$' "$SOCKETLEY_TMPD/seen.log")" "1" \
   "and reaches it with its Upgrade field"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
