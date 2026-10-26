#!/usr/bin/env bash
# Integration test: every relayed byte reaches every subscriber, in order, when
# the subscribers' queues are deep and the broadcast segments roll over
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A relayed line is written once into a shared segment and each subscriber's
# queue holds a slice of it, grown in place while the next line follows the
# last.  So what can go wrong is bytes, not counts: a segment that moved under
# a slice sends freed memory, a slice grown by the wrong length sends a line
# twice or not at all, and a slice of the wrong segment sends somebody else's
# line.  Every line here is numbered and sized by its number, so any of those
# shows as a wrong line at a known position.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a subscriber reading at once and one reading a second late, which is
#     what makes the queue deep enough to span many segments
#   * a websocket subscriber, whose frames live in a segment of their own
#   * and the sender itself hearing nothing, since relay skips the origin
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
daemon_isolate bcastexact
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
cleanup(){ rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: a broadcast reaches every subscriber byte for byte ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

P=$((SL_PORT_BASE + 119))
daemon_start "$BIN"
"$BIN" create server bx -p "$P" --mode inout -s >/dev/null 2>&1 || true
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done

N=20000
timeout 120 python3 - "$P" "$N" > "$WORK/out" <<'PY'
import base64, os, socket, sys, threading, time
port, n = int(sys.argv[1]), int(sys.argv[2])

def line(i):
    return b"seq:%06d:" % i + bytes([97 + i % 26]) * (i % 173) + b"\n"
want = b"".join(line(i) for i in range(n))
last = line(n - 1)

# Each subscriber speaks first, because a connection whose protocol is still
# unknown has relayed bytes held and bounded rather than written -- and hears
# the others' greetings, which the comparison drops.
def unhello(b):
    return b"".join(l for l in b.splitlines(keepends=True) if not l.startswith(b"hello-"))

def tcp_sub(delay, out, idx):
    s = socket.create_connection(("127.0.0.1", port), 10); s.settimeout(30)
    s.sendall(b"hello-%d\n" % idx)
    ready.wait()
    time.sleep(delay)
    got = bytearray()
    try:
        while not got.endswith(last):
            b = s.recv(1 << 16)
            if not b: break
            got += b
    except socket.timeout:
        pass
    out[idx] = unhello(bytes(got))

def ws_sub(out, idx):
    s = socket.create_connection(("127.0.0.1", port), 10); s.settimeout(30)
    key = base64.b64encode(os.urandom(16))
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              b"Sec-WebSocket-Key: " + key + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    buf = buf.split(b"\r\n\r\n", 1)[1]
    ready.wait()
    msgs = []
    seen = 0
    try:
        while seen < n:
            while True:
                if len(buf) >= 2:
                    ln = buf[1] & 0x7f; h = 2
                    if ln == 126: ln = int.from_bytes(buf[2:4], "big"); h = 4
                    elif ln == 127: ln = int.from_bytes(buf[2:10], "big"); h = 10
                    if len(buf) >= h + ln:
                        msgs.append(buf[h:h + ln]); buf = buf[h + ln:]
                        if not msgs[-1].startswith(b"hello-"): seen += 1
                        break
                b = s.recv(1 << 16)
                if not b: raise EOFError
                buf += b
    except (socket.timeout, EOFError):
        pass
    out[idx] = unhello(b"".join(m + b"\n" for m in msgs))

ready = threading.Event()
out = [None] * 5
ts = [threading.Thread(target=tcp_sub, args=(0, out, 0)),
      threading.Thread(target=tcp_sub, args=(0, out, 1)),
      threading.Thread(target=tcp_sub, args=(1.0, out, 2)),
      threading.Thread(target=tcp_sub, args=(1.0, out, 3)),
      threading.Thread(target=ws_sub, args=(out, 4))]
for t in ts: t.start()
time.sleep(0.5)
pub = socket.create_connection(("127.0.0.1", port), 10); pub.settimeout(2)
ready.set()
pub.sendall(want)
for t in ts: t.join()
try:
    heard = len(pub.recv(1 << 16))
except socket.timeout:
    heard = 0
for i, g in enumerate(out):
    if g == want:
        print("sub%d whole" % i)
    else:
        g = g or b""
        at = next((k for k in range(min(len(g), len(want))) if g[k] != want[k]), min(len(g), len(want)))
        print("sub%d differs at byte %d of %d (got %d)" % (i, at, len(want), len(g)))
print("publisher heard %d" % heard)
PY
cat "$WORK/out" | sed 's/^/  /'

# ── 1-4. the TCP subscribers, prompt and late ───────────────────────────────
for i in 0 1 2 3; do
    if grep -q "^sub$i whole" "$WORK/out"; then pass
    else fail "subscriber $i receives every line in order" "$(grep "^sub$i " "$WORK/out" || echo 'no result')"; fi
done
# ── 5. the websocket subscriber ─────────────────────────────────────────────
if grep -q "^sub4 whole" "$WORK/out"; then pass
else fail "a websocket subscriber receives every frame in order" "$(grep '^sub4 ' "$WORK/out" || echo 'no result')"; fi
# ── 6. and the origin hears nothing ─────────────────────────────────────────
if grep -q "^publisher heard 0" "$WORK/out"; then pass
else fail "the sender hears none of its own lines" "$(grep '^publisher' "$WORK/out")"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
