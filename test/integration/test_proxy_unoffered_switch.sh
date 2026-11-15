#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Integration test: a proxy relays bytes only after a 101 the client asked for.
#
# ─── THE DEFECT (round 8b) ──────────────────────────────────────────────────
#
# The response scan set switched_protocols on any 101, and the proxy made the pair a byte relay from then on --
# whether or not the request had offered an upgrade.  A backend that answers a status its caller picks (an app's
# /status/<n>, a health check echoing an upstream) so gave the client a raw connection to it: every later request
# on it reached the backend with no route, --auth, Lua filter or entrance check run on it.  RFC 9110 15.2.2 lets a
# server switch only to a protocol the client's Upgrade named.  Measured on dev 3b7db9690, through a plain proxy and
# through the entrance alike: `GET /m/s101` without Upgrade, then `GET /smuggled` on the same connection -- the
# client read "HTTP/1.1 101" and then the backend's raw echo of the second request.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
#   A  101 to a request without Upgrade        -> 502, and the next bytes never reach the backend as a tunnel
#   B  101 to a request offering websocket     -> 101, tunnel works (control: the relay itself is untouched)
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"

daemon_isolate unoffered
PASS=0; FAIL=0; TOTAL=0
T=$SOCKETLEY_TMPD
BE=$((SL_PORT_BASE+1960)); PX=$((SL_PORT_BASE+1961))
BEPID=""
cleanup() { [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: 101 only after an offered upgrade ==="

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
create_ok "proxy created" "$BIN" create proxy upx -p "$PX" --backend "127.0.0.1:$BE" -s
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
smug = b"GET /upx/smuggled HTTP/1.1\r\n" + H + b"\r\n"

got = talk([b"GET /upx/s101 HTTP/1.1\r\n" + H + b"\r\n", smug])
check("A: a 101 to a request offering no upgrade is answered 502", got.startswith(b"HTTP/1.1 502"), got[:80])
check("A: no tunnel is relayed after it", b"TUNNEL" not in got and not os.path.exists(tlog), got[:160])

got = talk([b"GET /upx/s101 HTTP/1.1\r\n" + H + b"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n", b"ping"])
check("B: a 101 to an offered upgrade still switches", got.startswith(b"HTTP/1.1 101") and b"TUNNEL:ping" in got, got[:160])

print("Results: %d passed, %d failed" % (P, F))
sys.exit(1 if F else 0)
PYEOF
