#!/usr/bin/env bash
# Integration test: a server's echoes, a cache's replies, a client's sends and
# a server's sends to its upstream arrive byte for byte and in order, through
# every mix of sends taken at once and sends that had to go through the ring
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
# lines of 1 byte to 30 KB to an echo server, pipelined GETs of values up to
# 500 KB to a cache, and the same lines from a client runtime's script and
# from a server's script to its upstream, each to a peer that reads late.
# What arrives must be exactly what was expected.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the echo stream reordered, duplicated or short
#   * the cache's reply stream the same way
#   * a client runtime's sends the same way
#   * a server's sends to its upstream the same way
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

PS=$((SL_PORT_BASE + 1311)); PC=$((SL_PORT_BASE + 1312)); PK=$((SL_PORT_BASE + 1313))
PU=$((SL_PORT_BASE + 1314)); PUS=$((SL_PORT_BASE + 1315))
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
def lines():
    """Each line carries its index, so a reorder changes the digest; the
    client's script builds the same ones."""
    sizes = [1, 7, 64, 1000, 8000, 30000]
    return [(b"%06d|" % i) + bytes([97 + i % 26]) * sizes[(i * 7) % 6] + b"\n" for i in range(900)]

if mode == "sink":
    # Reads late and then slowly through a small window, so the socket always
    # has some room and never enough: a write the client sends directly then
    # goes out in part, and the rest has to follow it through the ring.
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    ls.bind(("127.0.0.1", port)); ls.listen(1)
    print("ready", flush=True)
    c, _ = ls.accept()
    want = b"".join(lines())
    time.sleep(1.0)
    h, n = hashlib.sha256(), 0
    c.settimeout(20)
    try:
        while n < len(want):
            b = c.recv(8192)
            if not b: break
            h.update(b); n += len(b)
            time.sleep(0.0005)
    except socket.timeout:
        pass
    got = [(h.hexdigest(), n)]
    print("expect=%s %d got=%s %d" % (hashlib.sha256(want).hexdigest(), len(want), got[0][0], got[0][1]), flush=True)
elif mode == "server":
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

# ── 3. a client runtime's sends arrive whole and in order ─────────────────
python3 "$WORK/peer.py" sink "$PK" > "$WORK/sink.out" 2>&1 &
SINK_PID=$!
for _ in $(seq 1 50); do grep -q ready "$WORK/sink.out" 2>/dev/null && break; sleep 0.1; done
cat > "$WORK/client.lua" <<'LUA'
function on_connect()
    local sizes = { 1, 7, 64, 1000, 8000, 30000 }
    for i = 0, 899 do
        self.send(string.format("%06d|", i) .. string.rep(string.char(97 + i % 26), sizes[(i * 7) % 6 + 1]) .. "\n")
    end
end
LUA
"$BIN" create client dsk -t "127.0.0.1:$PK" --lua "$WORK/client.lua" -s >/dev/null 2>&1 || true
for _ in $(seq 1 300); do grep -q '^expect' "$WORK/sink.out" 2>/dev/null && break; sleep 0.1; done
kill "$SINK_PID" 2>/dev/null || true
OUT=$(grep '^expect' "$WORK/sink.out" || true)
echo "  client: $OUT"
check "the client's sends arrive whole and in order" "$OUT"

# ── 4. a server's sends to its upstream arrive whole and in order ─────────
python3 "$WORK/peer.py" sink "$PU" > "$WORK/usink.out" 2>&1 &
USINK_PID=$!
for _ in $(seq 1 50); do grep -q ready "$WORK/usink.out" 2>/dev/null && break; sleep 0.1; done
# Every other line leaves its newline to upstream_send, which adds one.
cat > "$WORK/up.lua" <<'LUA'
function on_upstream_connect(uid)
    local sizes = { 1, 7, 64, 1000, 8000, 30000 }
    for i = 0, 899 do
        local line = string.format("%06d|", i) .. string.rep(string.char(97 + i % 26), sizes[(i * 7) % 6 + 1])
        self.upstream_send(uid, i % 2 == 0 and line .. "\n" or line)
    end
end
LUA
"$BIN" create server dsu -p "$PUS" --upstream "127.0.0.1:$PU" --lua "$WORK/up.lua" -s >/dev/null 2>&1 || true
for _ in $(seq 1 300); do grep -q '^expect' "$WORK/usink.out" 2>/dev/null && break; sleep 0.1; done
kill "$USINK_PID" 2>/dev/null || true
OUT=$(grep '^expect' "$WORK/usink.out" || true)
echo "  upstream: $OUT"
check "a server's sends to its upstream arrive whole and in order" "$OUT"

if [ "$FAIL" -gt 0 ]; then
    if grep -v '\[INFO\]' "$SOCKETLEY_DLOG" 2>/dev/null | tail -8 | sed 's/^/        log: /'; then :; fi
fi
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
