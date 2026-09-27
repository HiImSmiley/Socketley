#!/usr/bin/env bash
# Integration test: a server's echoes and a cache's replies arrive byte for
# byte and in order, through every mix of sends taken at once and sends that
# had to go through the ring
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# The first write a connection makes in a loop turn is sent with send() when
# nothing is queued ahead of it; a second one in the same turn, or whatever a
# full socket did not take, goes through the ring.  A direct send while an
# earlier write is still queued delivers the stream out of order, and the
# remainder of a partial send queued from the start delivers bytes twice.
# Both are silent -- every byte arrives, just not the right ones.
#
# So the client sends its whole load before it reads a byte, which fills the
# kernel buffers and forces partial sends and a queue, then reads everything:
# lines of 1 byte to 30 KB to an echo server, and pipelined GETs of values up
# to 500 KB to a cache.  What comes back must be exactly what was expected.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the echo stream reordered, duplicated or short
#   * the cache's reply stream the same way
# suite: isolated
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
PASS=0; FAIL=0; TOTAL=0
trap daemon_stop EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: direct sends keep a server's and a cache's output in order ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

PS=$((SL_PORT_BASE + 1311)); PC=$((SL_PORT_BASE + 1312))
daemon_isolate directsend
daemon_start "$BIN"
WORK=$SOCKETLEY_TMPD

cat > "$WORK/peer.py" <<'PY'
import hashlib, random, socket, sys, threading, time

def drain(sock, want, stall, out):
    """Reads until `want` bytes arrived or the peer went quiet, after a stall
    that lets everything the other side sends pile up first."""
    time.sleep(stall)
    h, n = hashlib.sha256(), 0
    sock.settimeout(20)
    try:
        while n < want:
            b = sock.recv(1 << 16)
            if not b: break
            h.update(b); n += len(b)
    except socket.timeout:
        pass
    out.append((h.hexdigest(), n))

def run(sock, payload, expect):
    got = []
    t = threading.Thread(target=drain, args=(sock, len(expect), 1.0, got)); t.start()
    sock.sendall(payload)
    t.join(60)
    want = hashlib.sha256(expect).hexdigest()
    print("expect=%s %d got=%s %d" % (want, len(expect), got[0][0] if got else "-", got[0][1] if got else 0))

def resp(*args):
    out = b"*%d\r\n" % len(args)
    for a in args:
        out += b"$%d\r\n%s\r\n" % (len(a), a)
    return out

mode, port = sys.argv[1], int(sys.argv[2])
rnd = random.Random(7)
if mode == "server":
    # Each line carries its index, so a reorder changes the digest.
    lines = []
    for i in range(1500):
        size = rnd.choice([1, 7, 64, 1000, 8000, 30000])
        lines.append((b"%06d|" % i) + bytes([97 + i % 26]) * size + b"\n")
    data = b"".join(lines)
    run(socket.create_connection(("127.0.0.1", port)), data, data)
else:
    c = socket.create_connection(("127.0.0.1", port))
    values = {}
    for k, size in (("big", 500000), ("mid", 60000), ("small", 5)):
        v = bytes([65 + len(k)]) * (size - 8) + b"%08d" % size
        values[k] = v
        c.sendall(resp(b"SET", k.encode(), v))
        assert c.recv(16) == b"+OK\r\n"
    order = [rnd.choice(["big", "mid", "small", "small", "small"]) for _ in range(40)]
    payload = b"".join(resp(b"GET", k.encode()) for k in order)
    expect = b"".join(b"$%d\r\n%s\r\n" % (len(values[k]), values[k]) for k in order)
    run(c, payload, expect)
PY

"$BIN" create server dso -p "$PS" --send-to sender -s >/dev/null 2>&1 || true
"$BIN" create cache dsc -p "$PC" -s >/dev/null 2>&1 || true
for p in "$PS" "$PC"; do
    for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$p " && break; sleep 0.1; done
done

check(){   # name output
    local e g
    e=$(sed -n 's/.*expect=\([0-9a-f]*\) \([0-9]*\).*/\1 \2/p' <<<"$2")
    g=$(sed -n 's/.*got=\([0-9a-f-]*\) \([0-9]*\).*/\1 \2/p' <<<"$2")
    if [ -n "$e" ] && [ "$e" = "$g" ]; then pass
    else fail "$1" "expected '$e', read '$g'"; fi
}

# ── 1. an echo server's output is its input, whole and in order ────────────
OUT=$(timeout 90 python3 "$WORK/peer.py" server "$PS" 2>&1 || true)
echo "  server: $OUT"
check "the echo stream arrives whole and in order" "$OUT"

# ── 2. a cache's pipelined replies arrive whole and in order ──────────────
OUT=$(timeout 90 python3 "$WORK/peer.py" cache "$PC" 2>&1 || true)
echo "  cache:  $OUT"
check "the cache's replies arrive whole and in order" "$OUT"

if [ "$FAIL" -gt 0 ]; then
    if grep -v '\[INFO\]' "$SOCKETLEY_DLOG" 2>/dev/null | tail -8 | sed 's/^/        log: /'; then :; fi
fi
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
