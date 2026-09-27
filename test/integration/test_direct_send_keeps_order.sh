#!/usr/bin/env bash
# Integration test: a server's echoes, a cache's replies, a client's sends, a
# server's sends to its upstream, a server script's sends to a client and to a
# websocket and a server's HTTP answers arrive byte for byte and in order,
# through every mix of sends taken at once and sends that had to go through the
# ring
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
# 500 KB to a cache, and the same lines from a client runtime's script, from a
# server's script to its upstream, from one to a connected client and from one
# to a websocket as frames, each to a peer that reads late -- and pipelined
# requests for static files of 1 byte to 200 KB to an --http-cache server.
# What arrives must be exactly what was expected.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the echo stream reordered, duplicated or short
#   * the cache's reply stream the same way
#   * a client runtime's sends the same way
#   * a server's sends to its upstream the same way
#   * a server script's sends to a client the same way
#   * a server script's frames to a websocket the same way, or malformed
#   * a server's pipelined HTTP answers the same way -- an answer sent
#     directly while an earlier one is still queued lands ahead of it
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
PU=$((SL_PORT_BASE + 1314)); PUS=$((SL_PORT_BASE + 1315)); PL=$((SL_PORT_BASE + 1316))
PW=$((SL_PORT_BASE + 1317)); PH=$((SL_PORT_BASE + 1318))
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

def slow_read(c, want):
    """Reads late and then slowly through a small window, so the socket always
    has some room and never enough: a write sent directly then goes out in
    part, and the rest has to follow it through the ring."""
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
    print("expect=%s %d got=%s %d" % (hashlib.sha256(want).hexdigest(), len(want), h.hexdigest(), n), flush=True)

if mode == "slowclient":
    c = socket.socket()
    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    c.connect(("127.0.0.1", port))
    slow_read(c, b"".join(lines()))
elif mode == "wsclient":
    # The server's frames carry each line without its newline, one frame a
    # line, as text: every line is ASCII.
    import base64, os, struct
    want = [l[:-1] for l in lines()]
    c = socket.socket()
    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    c.connect(("127.0.0.1", port))
    c.sendall(("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
               "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
               "Sec-WebSocket-Version: 13\r\n\r\n"
               % base64.b64encode(os.urandom(16)).decode()).encode())
    c.settimeout(10)
    data = bytearray()
    try:
        while b"\r\n\r\n" not in data:
            b = c.recv(4096)
            if not b: break
            data += b
    except socket.timeout:
        pass
    head, sep, rest = bytes(data).partition(b"\r\n\r\n")
    if not sep or b" 101 " not in head.split(b"\r\n")[0]:
        print("no 101: %r" % head[:80], flush=True)
        sys.exit(0)
    data = bytearray(rest)
    got, bad, pos = [], [], 0

    def parse():
        """Takes every whole frame off the front, noting any that is not a
        final, unmasked text frame with its length in the shortest form."""
        global pos
        while len(data) - pos >= 2:
            b0, b1 = data[pos], data[pos + 1]
            n, hl = b1 & 0x7F, 2
            if n == 126:
                if len(data) - pos < 4: return
                n, hl = struct.unpack_from("!H", data, pos + 2)[0], 4
            elif n == 127:
                if len(data) - pos < 10: return
                n, hl = struct.unpack_from("!Q", data, pos + 2)[0], 10
            if len(data) - pos < hl + n: return
            if b0 != 0x81 or b1 & 0x80 or (hl == 4 and n < 126) or (hl == 10 and n <= 65535):
                bad.append("frame %d header %02x %02x len %d" % (len(got), b0, b1, n))
            got.append(bytes(data[pos + hl:pos + hl + n]))
            pos += hl + n

    time.sleep(1.0)
    c.settimeout(20)
    try:
        parse()
        while len(got) < len(want):
            b = c.recv(8192)
            if not b: break
            data += b
            parse()
            time.sleep(0.0005)
        # Anything after the last frame is a byte sent twice.
        c.settimeout(0.5)
        while True:
            b = c.recv(8192)
            if not b: break
            data += b
    except socket.timeout:
        pass
    extra = len(data) - pos
    enc = lambda fs: b"".join(struct.pack("!I", len(f)) + f for f in fs)
    e = enc(want)
    g = enc(got) + ("|bad=%d|extra=%d" % (len(bad), extra)).encode() * (1 if bad or extra else 0)
    print("expect=%s %d got=%s %d frames=%d bad=%d extra=%d%s" % (
        hashlib.sha256(e).hexdigest(), len(e), hashlib.sha256(g).hexdigest(), len(g),
        len(got), len(bad), extra, (" first: " + bad[0]) if bad else ""), flush=True)
elif mode == "sink":
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    ls.bind(("127.0.0.1", port)); ls.listen(1)
    print("ready", flush=True)
    c, _ = ls.accept()
    slow_read(c, b"".join(lines()))
elif mode == "http":
    # The expected stream is the server's own answers, fetched one at a time
    # first, so no header this file does not control has to be spelled here.
    def http_req(method, path, close):
        return b"%s %s HTTP/1.1\r\nHost: x\r\n%s\r\n" % (
            method, path, b"Connection: close\r\n" if close else b"")

    def fetch_one(sock, method, path, close):
        sock.sendall(http_req(method, path, close))
        sock.settimeout(10)
        buf = b""
        while b"\r\n\r\n" not in buf:
            b = sock.recv(65536)
            if not b: return buf
            buf += b
        head, _, rest = buf.partition(b"\r\n\r\n")
        cl = 0
        for ln in head.split(b"\r\n")[1:]:
            k, _, v = ln.partition(b":")
            if k.strip().lower() == b"content-length":
                cl = int(v)
        if method == b"HEAD":
            cl = 0
        while len(rest) < cl:
            b = sock.recv(65536)
            if not b: break
            rest += b
        return head + b"\r\n\r\n" + rest[:cl]

    kinds = [(b"GET", b"/a.txt"), (b"GET", b"/b.txt"), (b"GET", b"/c.html"),
             (b"GET", b"/d.bin"), (b"GET", b"/e.bin"), (b"HEAD", b"/d.bin"),
             (b"GET", b"/missing")]
    kept = socket.create_connection(("127.0.0.1", port))
    alone = {k: fetch_one(kept, k[0], k[1], False) for k in kinds}
    kept.close()
    last = socket.create_connection(("127.0.0.1", port))
    last_alone = fetch_one(last, b"GET", b"/e.bin", True)
    last.close()
    # A server that answered nothing would make both sides empty and equal.
    if not all(v.startswith(b"HTTP/1.1 ") for v in list(alone.values()) + [last_alone]):
        print("no answer to a lone request: %r" % {k: v[:40] for k, v in alone.items()}, flush=True)
        sys.exit(0)

    # Fifty requests in one write, the last asking to close, read late through
    # a small window so later answers find earlier ones still queued.
    order = [rnd.choice(kinds) for _ in range(49)]
    payload = b"".join(http_req(m, p, False) for m, p in order) + http_req(b"GET", b"/e.bin", True)
    expect = b"".join(alone[k] for k in order) + last_alone
    c = socket.socket()
    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    c.connect(("127.0.0.1", port))
    run(c, payload, expect)
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

# ── 5. a server script's sends to a client arrive whole and in order ──────
# One line a tick, so each is the only write of its turn and is tried
# directly, against a socket the slow reader keeps nearly full.
cat > "$WORK/tell.lua" <<'LUA'
function on_connect(id)
    local sizes = { 1, 7, 64, 1000, 8000, 30000 }
    local i = 0
    local iv
    iv = socketley.set_interval(1, function()
        local line = string.format("%06d|", i) .. string.rep(string.char(97 + i % 26), sizes[(i * 7) % 6 + 1])
        self.send(id, i % 2 == 0 and line .. "\n" or line)
        i = i + 1
        if i == 900 then socketley.clear_interval(iv) end
    end)
end
LUA
"$BIN" create server dsl -p "$PL" --lua "$WORK/tell.lua" -s >/dev/null 2>&1 || true
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$PL " && break; sleep 0.1; done
OUT=$(timeout 90 python3 "$WORK/peer.py" slowclient "$PL" 2>&1 || true)
echo "  tell:     $OUT"
check "a server script's sends to a client arrive whole and in order" "$OUT"

# ── 6. a server script's frames to a websocket arrive whole and in order ──
# The same, framed: each frame is tried directly from its header and the
# script's string, so a partial send leaves part of a header or a payload to
# be copied, and only that part may follow through the ring.  Started from
# on_websocket, because on_connect runs before the upgrade.
cat > "$WORK/ws.lua" <<'LUA'
function on_websocket(id, headers)
    local sizes = { 1, 7, 64, 1000, 8000, 30000 }
    local i = 0
    local iv
    iv = socketley.set_interval(1, function()
        local line = string.format("%06d|", i) .. string.rep(string.char(97 + i % 26), sizes[(i * 7) % 6 + 1])
        self.send(id, i % 2 == 0 and line .. "\n" or line)
        i = i + 1
        if i == 900 then socketley.clear_interval(iv) end
    end)
end
LUA
"$BIN" create server dsw -p "$PW" --lua "$WORK/ws.lua" -s >/dev/null 2>&1 || true
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$PW " && break; sleep 0.1; done
OUT=$(timeout 90 python3 "$WORK/peer.py" wsclient "$PW" 2>&1 || true)
echo "  ws:       $OUT"
check "a server script's frames to a websocket arrive whole and in order" "$OUT"

# ── 7. a server's pipelined HTTP answers arrive whole and in order ────────
# --http-cache, so every answer is ready at once: the first goes out directly,
# and those behind a full socket have to follow through the queue.  A HEAD, a
# 404 and a closing last request are in the mix, as each takes its own turn
# through queue_http_response() before the send.
mkdir -p "$WORK/www"
printf 'a' > "$WORK/www/a.txt"
head -c 700 /dev/zero | tr '\0' 'b' > "$WORK/www/b.txt"
{ printf '<html><body>'; head -c 3000 /dev/zero | tr '\0' 'c'; printf '</body></html>'; } > "$WORK/www/c.html"
head -c 60000 /dev/urandom > "$WORK/www/d.bin"
head -c 200000 /dev/urandom > "$WORK/www/e.bin"
"$BIN" create server dsh -p "$PH" --http "$WORK/www" --http-cache -s >/dev/null 2>&1 || true
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$PH " && break; sleep 0.1; done
OUT=$(timeout 90 python3 "$WORK/peer.py" http "$PH" 2>&1 || true)
echo "  http:     $OUT"
check "a server's pipelined HTTP answers arrive whole and in order" "$OUT"

if [ "$FAIL" -gt 0 ]; then
    if grep -v '\[INFO\]' "$SOCKETLEY_DLOG" 2>/dev/null | tail -8 | sed 's/^/        log: /'; then :; fi
fi
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
