#!/usr/bin/env bash
# suite: isolated -- its own network namespace, daemon, socket and port window, so it runs beside the others
# Integration test: a websocket client on a slow path with a round trip gets its PONG ahead of the frames it has not
# read yet, so a busy server does not make its keepalive fail.
#
# What each part would catch:
#   * a PONG queued behind every frame owed: over 4 Mbit/s with 20 ms of round trip a client a relay floods waited
#     seconds for it
#   * a write that takes the whole backlog at once, behind which a PONG put at the front still waits
#   * the flood itself lost: the client reads none of it
# A delay on loopback needs a network namespace of its own, which an unprivileged user namespace gives.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
if [ -z "${SL_IN_NETNS:-}" ]; then
    if ! unshare -rn true 2>/dev/null; then
        echo "=== Integration: a websocket client's PONG fits the path ==="
        echo "  SKIP: no unprivileged network namespace here"
        exit 0
    fi
    exec unshare -rn env SL_IN_NETNS=1 BIN="$BIN" bash "$0" "$@"
fi
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a websocket client's PONG fits the path ==="
ip link set lo up; ip link set dev lo mtu 1500
command -v tc >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 || { echo "  SKIP: tc and python3 are required"; exit 0; }
sanitized=0
nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null && sanitized=1
daemon_isolate wspath
P=$((SL_PORT_BASE + 1936))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"
# A relay: what one client sends, every other is sent.
"$BIN" create server relay -p "$P" -s >/dev/null 2>&1
for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$P") 2>/dev/null && break; sleep 0.1; done
# What the server sends: 4 Mbit/s, 10 ms each way, a bottleneck queue of about 30 ms.
tc qdisc add dev lo root handle 1: prio bands 3 priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
tc qdisc add dev lo parent 1:3 handle 30: netem delay 10ms rate 4mbit limit 100
tc filter add dev lo parent 1: protocol ip u32 match ip sport "$P" 0xffff flowid 1:3

out=$(timeout 240 python3 - "$P" <<'PY'
import base64, os, socket, struct, sys, threading, time
port = int(sys.argv[1])
def handshake():
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall(("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % key).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    return s, buf.split(b"\r\n\r\n", 1)[1]
def frame(payload, opcode):
    m = os.urandom(4); n = len(payload)
    h = bytes([0x80 | opcode]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack("!H", n))
    return h + m + bytes(b ^ m[i % 4] for i, b in enumerate(payload))
rx, buf = handshake()
tx, _ = handshake()
time.sleep(0.5)
stop = [False]
# A little faster than the path, so the backlog grows by about 0.25 MB a second and stays under the 8 MiB a
# connection is cut off at for the whole of the test.
def flood():
    f = frame(b"x" * 1000, 0x2) * 15
    while not stop[0]:
        try: tx.sendall(f)
        except OSError: return
        time.sleep(0.02)
threading.Thread(target=flood, daemon=True).start()
waits, got = [], 0
def next_frame():
    global buf, got
    while True:
        if len(buf) >= 2:
            ln, off = buf[1] & 0x7F, 2
            if ln == 126 and len(buf) >= 4: ln, off = struct.unpack("!H", buf[2:4])[0], 4
            elif ln == 127 and len(buf) >= 10: ln, off = struct.unpack("!Q", buf[2:10])[0], 10
            if ln < 126 or off > 2:
                if len(buf) >= off + ln:
                    op = buf[0] & 0x0F; buf = buf[off + ln:]; return op
        d = rx.recv(1 << 16)
        if not d: return None
        got += len(d); buf += d
# Read all along, as a client does, while the backlog builds.
t0 = time.perf_counter()
while time.perf_counter() - t0 < 4:
    next_frame()
for _ in range(5):
    t = time.perf_counter(); rx.sendall(frame(b"k", 0x9))
    # Every frame read until the PONG, the frames ahead of it counted; a wait past 20 s is counted as 20 s.
    while time.perf_counter() - t < 20:
        op = next_frame()
        if op is None or op == 0xA: break
    waits.append(min(20000, (time.perf_counter() - t) * 1000))
    time.sleep(0.3)
stop[0] = True
waits.sort()
print("%.0f %.0f %d" % (waits[len(waits) // 2], waits[-1], got))
PY
)
read -r p50 worst got <<<"$out"
echo "  PONG on a flooded 4 Mbit/s path: ${p50:-?} ms at the median, ${worst:-?} ms at worst, ${got:-0} bytes read meanwhile"
[ "${got:-0}" -gt 100000 ] && ok || bad "the client reads the flood" "$out"
if [ "$sanitized" = 1 ]; then echo "  SKIP [wait]: milliseconds measure the sanitizer, not the queue"
elif [ "${p50:-99999}" -lt 2000 ]; then ok
else bad "its PONG comes ahead of what it has not read" "${p50:-none} ms at the median"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
