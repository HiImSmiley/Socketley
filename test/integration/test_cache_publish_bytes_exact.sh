#!/usr/bin/env bash
# Integration test: every published byte reaches every subscriber, in order,
# with the subscribers' queues deep and the publish segments rolling over
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A published message is written once per wire format into a shared segment
# and each subscriber's queue holds a slice of it, grown in place while the
# next message follows the last.  What can go wrong is bytes: a slice of the
# other format's segment, a slice grown by the wrong length, a segment that
# moved.  Every message is numbered and sized by its number, so any of those
# is a wrong byte at a known position.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a text and a RESP subscriber reading at once, and one of each reading a
#     second late, which is what makes the queues span many segments
#   * and the publisher told every message reached all four
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
daemon_isolate pubexact
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
cleanup(){ rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: a publish reaches every subscriber byte for byte ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

P=$((SL_PORT_BASE + 121))
daemon_start "$BIN"
"$BIN" create cache px -p "$P" -s >/dev/null 2>&1 || true
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done

N=20000
timeout 120 python3 - "$P" "$N" > "$WORK/out" <<'PY'
import socket, sys, threading, time
port, n = int(sys.argv[1]), int(sys.argv[2])

def payload(i):
    return b"seq:%06d:" % i + bytes([97 + i % 26]) * (i % 173)
def resp_bulk(b):
    return b"$%d\r\n%s\r\n" % (len(b), b)
want_text = b"".join(b"message ch " + payload(i) + b"\n" for i in range(n))
want_resp = b"".join(b"*3\r\n" + resp_bulk(b"message") + resp_bulk(b"ch") + resp_bulk(payload(i))
                     for i in range(n))

def sub(resp, delay, out, idx):
    s = socket.create_connection(("127.0.0.1", port), 10); s.settimeout(30)
    if resp:
        s.sendall(b"*2\r\n" + resp_bulk(b"SUBSCRIBE") + resp_bulk(b"ch"))
        ack_end = b":1\r\n"
    else:
        s.sendall(b"subscribe ch\n")
        ack_end = b"\n"
    buf = b""
    while ack_end not in buf:
        buf += s.recv(4096)
    buf = buf.split(ack_end, 1)[1]
    acked.release()
    go.wait()
    time.sleep(delay)
    want = want_resp if resp else want_text
    got = bytearray(buf)
    try:
        while len(got) < len(want):
            b = s.recv(1 << 16)
            if not b: break
            got += b
    except socket.timeout:
        pass
    out[idx] = (bytes(got), want)

acked = threading.Semaphore(0)
go = threading.Event()
out = [None] * 4
ts = [threading.Thread(target=sub, args=(False, 0, out, 0)),
      threading.Thread(target=sub, args=(False, 1.0, out, 1)),
      threading.Thread(target=sub, args=(True, 0, out, 2)),
      threading.Thread(target=sub, args=(True, 1.0, out, 3))]
for t in ts: t.start()
for _ in ts: acked.acquire()
pub = socket.create_connection(("127.0.0.1", port), 10); pub.settimeout(30)
go.set()
pub.sendall(b"".join(b"*3\r\n" + resp_bulk(b"PUBLISH") + resp_bulk(b"ch") + resp_bulk(payload(i))
                     for i in range(n)))
replies = b""
try:
    while replies.count(b"\r\n") < n:
        b = pub.recv(1 << 16)
        if not b: break
        replies += b
except socket.timeout:
    pass
for t in ts: t.join()
for i, (g, w) in enumerate(out):
    if g == w:
        print("sub%d whole" % i)
    else:
        at = next((k for k in range(min(len(g), len(w))) if g[k] != w[k]), min(len(g), len(w)))
        print("sub%d differs at byte %d of %d (got %d)" % (i, at, len(w), len(g)))
print("publisher told %d" % replies.count(b":4\r\n"))
PY
sed 's/^/  /' "$WORK/out"

for i in 0 1 2 3; do
    kind=$([ "$i" -lt 2 ] && echo text || echo RESP)
    if grep -q "^sub$i whole" "$WORK/out"; then pass
    else fail "a $kind subscriber receives every message in order" "$(grep "^sub$i " "$WORK/out" || echo 'no result')"; fi
done
if grep -q "^publisher told $N" "$WORK/out"; then pass
else fail "every publish reports all four subscribers" "$(grep '^publisher' "$WORK/out")"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
