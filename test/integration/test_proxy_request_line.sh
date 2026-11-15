#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Integration test: a proxy forwards only a request line a backend cannot read as another request.
#
# ─── THE DEFECT (round 8b) ──────────────────────────────────────────────────
#
# The request line was split at its first two spaces and sent on with the words unchecked: a method with a control
# byte, a target holding a VT or a NUL, a version "HTTP/9.9" or "HTTP/1.1 junk" all reached the backend, and an
# HTTP/2 :path holding a VT, or a :method with a control byte, came out at the entrance as such a line.  A reader that
# splits at any whitespace (Python's http.server) or stops at a NUL reads another target than the one this proxy
# routed and checked.  A NUL in a field value went on too, which RFC 9110 5.5 has a recipient refuse or blank.
# Measured on dev 3b7db9690 through a plain proxy and through the entrance: every case below answered 200 by the
# backend with the bytes as sent.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
#   C  request line with a VT, a NUL or a second word in the target -> 400, backend sees nothing
#   D  method with a control byte              -> 400
#   E  version that is not HTTP/1.x            -> 400
#   F  a NUL in a field value                  -> 400
#   G  an ordinary request, 8-bit target bytes -> 200 (control)
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"

daemon_isolate reqline
PASS=0; FAIL=0; TOTAL=0
T=$SOCKETLEY_TMPD
BE=$((SL_PORT_BASE+1962)); PX=$((SL_PORT_BASE+1963))
BEPID=""
cleanup() { [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: a request line is checked before it is forwarded ==="

python3 - "$BE" "$T/tunnel.log" >"$T/backend.log" 2>&1 <<'PYEOF' &
import socket, sys, threading
port, tlog = int(sys.argv[1]), sys.argv[2]
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(64)
def serve(c):
    buf = b""
    try:
        while True:
            while b"\r\n\r\n" not in buf:
                d = c.recv(65536)
                if not d:
                    return
                buf += d
            head, buf = buf.split(b"\r\n\r\n", 1)
            target = head.split(b"\r\n")[0].split(b" ")[1]
            if target.endswith(b"/s101"):
                c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                while True:
                    if buf:
                        with open(tlog, "ab") as f:
                            f.write(buf)
                        c.sendall(b"TUNNEL:" + buf); buf = b""
                    d = c.recv(65536)
                    if not d:
                        return
                    buf += d
            body = b"ok " + target + b"\n"
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
    except OSError:
        pass
    finally:
        c.close()
while True:
    s, _ = srv.accept()
    threading.Thread(target=serve, args=(s,), daemon=True).start()
PYEOF
BEPID=$!

daemon_start "$BIN"
create_ok "proxy created" "$BIN" create proxy rlx -p "$PX" --backend "127.0.0.1:$BE" -s
for _ in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/$PX) 2>/dev/null && break; sleep 0.1; done

python3 - "$PX" "$T/tunnel.log" <<'PYEOF'
import os, socket, sys, time
port, tlog = int(sys.argv[1]), sys.argv[2]
P = F = 0
def check(name, cond, got):
    global P, F
    if cond:
        P += 1; print("  PASS: " + name)
    else:
        F += 1; print("  FAIL [%s]: got %r" % (name, got))
def talk(pieces, wait=0.8):
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    got = b""
    for p in pieces:
        s.sendall(p)
        end = time.time() + wait
        s.settimeout(0.2)
        while time.time() < end:
            try:
                d = s.recv(65536)
                if not d:
                    break
                got += d
            except socket.timeout:
                continue
            except OSError:
                break
    s.close()
    return got
H = b"Host: x\r\n"
smug = b"GET /rlx/smuggled HTTP/1.1\r\n" + H + b"\r\n"

for name, line in (("C: a VT in the target", b"GET /rlx/a\x0bHTTP/1.1 HTTP/1.1\r\n"),
                   ("C: a NUL in the target", b"GET /rlx/a\x00b HTTP/1.1\r\n"),
                   ("C: a second word after the target", b"GET /rlx/a /rlx/b HTTP/1.1\r\n"),
                   ("D: a control byte in the method", b"G\x01T /rlx/a HTTP/1.1\r\n"),
                   ("E: version HTTP/9.9", b"GET /rlx/a HTTP/9.9\r\n"),
                   ("E: version with a word behind it", b"GET /rlx/a HTTP/1.1 junk\r\n")):
    got = talk([line + H + b"\r\n"])
    check(name + " is refused 400", got.startswith(b"HTTP/1.1 400"), got[:80])

got = talk([b"GET /rlx/a HTTP/1.1\r\n" + H + b"X-A: a\x00b\r\n\r\n"])
check("F: a NUL in a field value is refused 400", got.startswith(b"HTTP/1.1 400"), got[:80])

got = talk([b"GET /rlx/plain HTTP/1.1\r\n" + H + b"X-A: caf\xc3\xa9\r\n\r\n"])
check("G: an ordinary request is answered", got.startswith(b"HTTP/1.1 200") and b"ok /plain" in got, got[:80])
print("Results: %d passed, %d failed" % (P, F))
sys.exit(1 if F else 0)
PYEOF
