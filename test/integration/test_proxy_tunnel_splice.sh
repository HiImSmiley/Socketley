#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: an HTTP proxy moves what a backend streams through a 101 tunnel by splice, as a TCP proxy does.
#
# What each part would catch:
#   * a tunnel's stream copied through user space: 520 to 560 ms of the proxy's CPU per GiB, where splice costs 120 to
#     190 on the same laptop
#   * a spliced tunnel that loses, repeats or reorders bytes, or that cannot carry the client's next message and the
#     backend's answer to it after the stream, or that does not end when the backend does
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: an HTTP proxy splices a 101 tunnel's stream ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_isolate tunsplice
T=$SOCKETLEY_TMPD
PB=$((SL_PORT_BASE + 1970)); PX=$((SL_PORT_BASE + 1971))
unset SOCKETLEY_CONFIG
MB=512

# A backend that takes the upgrade, streams MB MiB of a counting pattern on `go`, answers `bye` with `ok` and closes.
python3 -I - "$PB" "$MB" <<'PY' &
import socket, sys, threading
port, mb = int(sys.argv[1]), int(sys.argv[2])
block = bytes(range(256)) * 4096
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", port)); ls.listen(16)
def line(c, buf):
    while b"\n" not in buf[0]:
        d = c.recv(65536)
        if not d: return None
        buf[0] += d
    l, buf[0] = buf[0].split(b"\n", 1)
    return l
def serve(c):
    buf = [b""]
    while b"\r\n\r\n" not in buf[0]:
        d = c.recv(65536)
        if not d: return
        buf[0] += d
    buf[0] = buf[0].split(b"\r\n\r\n", 1)[1]
    c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
    if line(c, buf) != b"go": return
    for _ in range(mb): c.sendall(block)
    if line(c, buf) == b"bye": c.sendall(b"ok\n")
    c.close()
while True:
    c, _ = ls.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
BEPID=$!
trap 'kill $BEPID 2>/dev/null; daemon_stop' EXIT
daemon_start "$BIN"
for _ in $(seq 1 50); do ss -ltnH "sport = :$PB" | grep -q . && break; sleep 0.1; done

"$BIN" create proxy tp -p "$PX" --protocol http --backend "127.0.0.1:$PB" -s >/dev/null 2>&1 \
    || bad "the proxy is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do ss -ltnH "sport = :$PX" | grep -q . && break; sleep 0.1; done

cpu() { local t=0 p; for p in $(ss -ltnpH "sport = :$PX" | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u); do
    t=$((t + $(awk '{print $14+$15}' "/proc/$p/stat"))); done; echo "$t"; }
c0=$(cpu)
out=$(timeout 120 python3 -I - "$PX" "$MB" <<'PY'
import socket, sys
port, mb = int(sys.argv[1]), int(sys.argv[2])
s = socket.create_connection(("127.0.0.1", port)); s.settimeout(60)
s.sendall(b"GET /tp/ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
          b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
head = b""
while b"\r\n\r\n" not in head:
    d = s.recv(4096)
    if not d: break
    head += d
status = (head.split(b"\r\n", 1)[0].split(b" ") + [b"none", b"none"])[1].decode(errors="replace")
rest = head.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in head else b""
s.sendall(b"go\n")
want = mb << 20
got, bad_at, pos = 0, -1, 0
buf = bytearray(1 << 20)
def take(chunk):
    global got, bad_at, pos
    n = len(chunk)
    if n == 0:
        return
    if bad_at < 0:
        # The pattern counts bytes 0..255, so byte i of the stream is i % 256.
        exp = bytes((pos + k) & 255 for k in range(0, n, 4093))
        if bytes(chunk[k] for k in range(0, n, 4093)) != exp or chunk[-1] != (pos + n - 1) & 255:
            bad_at = got
    pos += n; got += n
take(rest)
mv = memoryview(buf)
while got < want:
    n = s.recv_into(buf, min(len(buf), want - got))
    if n == 0: break
    take(mv[:n])
s.sendall(b"bye\n")
tail = b""
while True:
    try:
        d = s.recv(64)
    except socket.timeout:
        tail += b"<timeout>"; break
    if not d: break
    tail += d
print(status, got, want, bad_at, tail.decode(errors="replace").strip())
PY
)
c1=$(cpu)
read -r st got want bad_at tail <<<"$out"
[ -n "${want:-}" ] || bad "the client" "printed nothing: $out"
[ "$st" = "101" ] && ok || bad "the upgrade is answered" "status $st"
[ "$got" = "$want" ] && ok || bad "the stream arrives whole" "got $got of $want bytes"
[ "$bad_at" = "-1" ] && ok || bad "the stream's bytes are the backend's, in order" "first wrong byte near $bad_at"
[ "$tail" = "ok" ] && ok || bad "the client's next message and the answer to it cross the tunnel, which then ends" "after the stream: '$tail'"

if build_sanitized; then
    echo "  SKIP [cpu]: CPU per GiB measures the sanitizer, not the splice"
else
    per=$(( (c1 - c0) * 1000 / $(getconf CLK_TCK) * 1024 / MB ))
    echo "  the proxy's CPU per GiB of a tunnel's stream: ${per} ms"
    if [ "$per" -lt 330 ]; then ok; else bad "a tunnel's stream costs the proxy little CPU" "${per} ms per GiB"; fi
fi

echo ""
echo "=== Results: $PASS/$((PASS+FAIL)) passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
