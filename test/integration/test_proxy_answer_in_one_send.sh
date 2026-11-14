#!/usr/bin/env bash
# Integration test: an HTTP proxy sends an answer's first read and the rest
# behind it in one send
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# An answer that does not fit its first read went to the client in two sends
# and woke it twice: a 64 KiB file is a full 64 KiB ring buffer and then 252
# bytes, and a backend that writes its head before its body sends the head
# alone.  The rest of a body of known length is now read off the backend socket
# while the first read is in hand, and both leave in one sendmsg.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * bodies either side of the ring buffer's size, all at once and with the
#     body behind a pause, reach a keep-alive client byte for byte -- the
#     joined send in the wrong order, or a read past the answer's end into the
#     next answer
#   * the same to a client that reads slowly, which is where the joined send
#     is partial and its rest goes through the queue, lost or reordered there
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

echo "=== Integration: an HTTP proxy sends an answer's first read and its rest in one send ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

P=$((SL_PORT_BASE + 1631)); BP=$((P + 1))

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
    daemon_isolate "onesend-$1"
    daemon_start "$BIN"
    "$BIN" create proxy os -p "$P" --backend "127.0.0.1:$BP" --protocol http -s >/dev/null 2>&1 || true
    for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done
}

start_backend
run_proxy bodies

# ── bodies about the ring buffer's size reach a keep-alive client whole ───
cat > "$WORK/get.py" <<'PY'
import socket, sys, time
port, slow = int(sys.argv[1]), sys.argv[2] == "slow"
def body(n):
    return bytes((i * 7 + i // 251) & 0xff for i in range(n))
s = socket.socket()
if slow: s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
s.connect(("127.0.0.1", port)); s.settimeout(10)
bad = []
for kind in ("a", "p"):
    for n in (65000, 65293, 65536, 65537, 65800, 131072, 300000):
        s.sendall(b"GET /os/%s/%d HTTP/1.1\r\nHost: x\r\n\r\n" % (kind.encode(), n))
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = s.recv(65536)
            if not d: bad.append("%s/%d: closed in the head" % (kind, n)); break
            buf += d
        if b"\r\n\r\n" not in buf: break
        head, got = buf.split(b"\r\n\r\n", 1)
        while len(got) < n:
            if slow: time.sleep(0.002)
            d = s.recv(65536)
            if not d: break
            got += d
        if got != body(n): bad.append("%s/%d: %d bytes, %s" % (kind, n, len(got), "equal prefix" if body(n).startswith(got) else "differs"))
print(" ".join(bad) if bad else "ok")
PY
GOT=$(timeout 60 python3 "$WORK/get.py" "$P" fast 2>&1) || true
if [ "$GOT" = "ok" ]; then pass
else fail "bodies about the buffer's size arrive whole on keep-alive" "$GOT"; fi
GOT=$(timeout 120 python3 "$WORK/get.py" "$P" slow 2>&1) || true
if [ "$GOT" = "ok" ]; then pass
else fail "the same bodies arrive whole to a slow reader" "$GOT"; fi

daemon_stop

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
