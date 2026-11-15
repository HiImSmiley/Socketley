#!/usr/bin/env bash
# Integration test: a request with a body offers its backend no upgrade.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# A backend that takes upgrades -- a WebSocket server -- commonly reads no body
# behind an Upgrade head: it declines the handshake (403, 426) and goes on
# reading HTTP/1.1 from the byte after the head.  The proxy forwarded an
# Upgrade offer together with the body its Content-Length or chunks declared,
# so a body that was itself a request head reached the backend as a request
# of its own, past --auth, the filters and the routes this proxy applies per
# request head, on a backend connection that then went back to the pool (the
# class of nghttpx's CVE-2026-58055).
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# The backend here is that WebSocket server: an Upgrade head is declined at
# once and its body left unread, any other request has its declared body
# read.  It logs each request line it parses.  An offer with a body must reach
# it as the plain request it is (no Upgrade, its body read as a body), so the
# inner request line is never parsed; an offer with no body must still reach
# it with its Upgrade field, or a build that strips every upgrade passes.
# suite: isolated
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate pxupb

BE=$((SL_PORT_BASE+1834))
PX=$((SL_PORT_BASE+1835))
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1))
        if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
        else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi; }
cleanup() { [ -n "${BEPID:-}" ] && kill "$BEPID" 2>/dev/null; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: a request with a body offers no upgrade ==="

cat > "$SOCKETLEY_TMPD/be.py" <<'PYEOF'
import socket, sys, threading
port, log = int(sys.argv[1]), sys.argv[2]
def serve(c):
    buf = b""
    def more():
        nonlocal buf
        b = c.recv(65536)
        if not b:
            raise EOFError
        buf += b
    try:
        while True:
            while b"\r\n\r\n" not in buf:
                more()
            head, buf = buf.split(b"\r\n\r\n", 1)
            lines = head.split(b"\r\n")
            with open(log, "ab") as f:
                f.write(lines[0] + b"\n")
            low = {l.split(b":", 1)[0].strip().lower(): l.split(b":", 1)[1].strip() for l in lines[1:] if b":" in l}
            if b"upgrade" in low:
                with open(log, "ab") as f:
                    f.write(b"upgrade offered\n")
                c.sendall(b"HTTP/1.1 426 Upgrade Required\r\nContent-Length: 8\r\n\r\ndeclined")
                continue
            if low.get(b"transfer-encoding", b"").lower() == b"chunked":
                while True:
                    while b"\r\n" not in buf:
                        more()
                    sz, buf = buf.split(b"\r\n", 1)
                    n = int(sz.split(b";")[0], 16)
                    while len(buf) < n + 2:
                        more()
                    buf = buf[n + 2:]
                    if n == 0:
                        break
            else:
                n = int(low.get(b"content-length", b"0"))
                while len(buf) < n:
                    more()
                buf = buf[n:]
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nplain")
    except (EOFError, OSError, ValueError):
        pass
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
"$BIN" create proxy ub -p "$PX" --backend "127.0.0.1:$BE" --protocol http -s >/dev/null 2>&1
for _ in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/"$PX") 2>/dev/null && break; sleep 0.1; done

# Sends one request whose body is a whole request head of its own, framed by Content-Length or by chunks, and
# prints the status of the answer.
ask() {
    python3 - "$PX" "$1" "$2" <<'PYEOF'
import socket, sys, time
port, framing, offer = int(sys.argv[1]), sys.argv[2], sys.argv[3] == "offer"
inner = b"GET /ub/hidden HTTP/1.1\r\nHost: app\r\n\r\n"
head = b"POST /ub/ws HTTP/1.1\r\nHost: app\r\n"
if offer:
    head += b"Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
if framing == "cl":
    req = head + b"Content-Length: %d\r\n\r\n" % len(inner) + inner
elif framing == "chunked":
    req = head + b"Transfer-Encoding: chunked\r\n\r\n" + b"%x\r\n" % len(inner) + inner + b"\r\n0\r\n\r\n"
else:
    req = head + b"\r\n"
s = socket.create_connection(("127.0.0.1", port), timeout=4)
s.sendall(req)
data = b""
try:
    while b"\r\n" not in data:
        d = s.recv(65536)
        if not d: break
        data += d
except OSError:
    pass
time.sleep(0.3)
print(data.split(b"\r\n", 1)[0].split(b" ")[1].decode() if data.count(b" ") else "none")
PYEOF
}

ok "$(ask cl offer)" "200" "an Upgrade offer with a Content-Length body is answered as the plain request it carries"
ok "$(ask chunked offer)" "200" "and one with a chunked body too"
ok "$(grep -c 'hidden' "$SOCKETLEY_TMPD/seen.log")" "0" \
   "the backend never read either body as a request of its own"
ok "$(grep -c '^upgrade offered$' "$SOCKETLEY_TMPD/seen.log")" "0" \
   "nor was it offered an upgrade by them"
ok "$(ask none offer)" "426" "an Upgrade offer with no body still reaches the backend as an offer"
ok "$(grep -c '^upgrade offered$' "$SOCKETLEY_TMPD/seen.log")" "1" "with its Upgrade field"
ok "$(ask cl plain)" "200" "a plain request with the same body is answered as before"
ok "$(grep -c 'hidden' "$SOCKETLEY_TMPD/seen.log")" "0" "and its body is read as a body"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
