#!/usr/bin/env bash
# Integration test: an HTTP proxy ends a client that asked to close on that
# client's own FIN, and still ends one that never sends it
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A client that asked to close had its armed read withdrawn behind the answer,
# and its descriptor was then handed to orderly_close, which shut the write side
# a second time, asked TCP_INFO and polled the socket on a timer until the
# client had closed: a cancel, a timeout and four syscalls per connection.  The
# read now stays armed behind our FIN, as a drain does, and takes the client's
# FIN itself; the descriptor is then closed at once.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a client that asked to close and then keeps its end open, silent, is
#     closed by the proxy within seconds -- the drain this rides on left
#     without its deadline
#   * fifty clients that ask to close and close get every byte first -- a
#     close taken for the client's FIN while bytes of the answer were unsent
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
BEPID=""
cleanup(){ [ -n "$BEPID" ] && { kill -9 "$BEPID" 2>/dev/null; wait "$BEPID" 2>/dev/null || true; }; rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: an HTTP proxy ends a closing client on its own FIN ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

P=$((SL_PORT_BASE + 1633)); BP=$((P + 1))

# /a/<n>: n body bytes, head and body in one write; /p/<n>: the head, 30 ms, the body.  Every body is a pattern that
# names its own offset.
cat > "$WORK/be.py" <<'PY'
import socket, sys, threading, time
port = int(sys.argv[1])
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(512)
def body(n):
    return bytes((i * 7 + i // 251) & 0xff for i in range(n))
def serve(c):
    buf = b""
    while True:
        while b"\r\n\r\n" not in buf:
            d = c.recv(65536)
            if not d: return
            buf += d
        head, buf = buf.split(b"\r\n\r\n", 1)
        line = head.split(b"\r\n")[0].split()
        path = line[1].decode()
        parts = path.strip("/").split("/")
        kind, n = parts[-2], int(parts[-1])
        h = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n" % n
        if kind == "p":
            c.sendall(h); time.sleep(0.03); c.sendall(body(n))
        else:
            c.sendall(h + body(n))
while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY

start_backend() {
    python3 "$WORK/be.py" "$BP" >/dev/null 2>&1 &
    BEPID=$!
    for _ in $(seq 1 50); do ss -ltn 2>/dev/null | grep -q ":$BP " && break; sleep 0.1; done
}
run_proxy() {   # tag -> a daemon and an HTTP proxy
    daemon_isolate "closefin-$1"
    daemon_start "$BIN"
    "$BIN" create proxy os -p "$P" --backend "127.0.0.1:$BP" --protocol http -s >/dev/null 2>&1 || true
    for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done
}

start_backend
run_proxy closing

# ── a client that asked to close ────────────────────────────────────────────
cat > "$WORK/close.py" <<'PY'
import socket, sys, time
port, keep = int(sys.argv[1]), sys.argv[2] == "keep"
s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(10)
s.sendall(b"GET /os/a/1000 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
buf = b""; t0 = time.time()
def body():
    return buf.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in buf else b""
while len(body()) < 1000:
    try: d = s.recv(65536)
    except OSError as e: print("%s after %d bytes" % (type(e).__name__, len(buf))); sys.exit()
    if not d: break
    buf += d
if len(body()) != 1000:
    print("short: %d body bytes" % len(body())); sys.exit()
if not keep:
    s.close(); print("ok"); sys.exit()
# Silent for 4 s, which a closed end then answers with a reset: the proxy's FIN came with the answer, and its close
# of a silent socket sends nothing more.
time.sleep(4)
try:
    for b in (b"x", b"y", b"z"):
        s.sendall(b); time.sleep(0.3)
    print("still open after 4 s")
except OSError:
    print("closed")
PY
GOT=$(timeout 30 python3 "$WORK/close.py" "$P" keep 2>&1) || true
case "$GOT" in closed) pass ;; *) fail "a closing client that keeps its end open is closed by the proxy" "$GOT" ;; esac
OK=0
for _ in $(seq 1 50); do [ "$(timeout 10 python3 "$WORK/close.py" "$P" go 2>&1)" = ok ] && OK=$((OK+1)); done
if [ "$OK" = 50 ]; then pass
else fail "50 closing clients get their whole answer" "$OK of 50"; fi
daemon_stop


echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
