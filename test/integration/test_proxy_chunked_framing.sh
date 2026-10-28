#!/usr/bin/env bash
# Integration test: the proxy finds where a chunked message ends, in both
# directions, and the connection it arrived on goes on working.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# The response scan had no reading of a chunked body at all, and said so:
# http_response_frame_complete() answered no for every chunked response, for
# ever.  Express, Node and Go answer chunked whenever the handler writes more
# than once, so after an ordinary answer the client's next request on the same
# connection sat behind a response nobody could call finished, until the header
# deadline tore the pair down ten seconds later.  A response whose header block
# was cut by a read boundary took the same road, marked `unknown` on the spot.
#
# The request side forwarded a chunked body without reading it either, as
# `body_unbounded`, and everything behind it on the connection went to the
# backend raw -- so a request pipelined after `0\r\n\r\n` never met the prefix
# check, the declared routes or a filter.
#
# And three smaller answers on the same path: a backend socket was pooled while
# the client still owed it part of a request body, so the next borrower's
# request was read as that body; an HTTP/1.0 client that asked for nothing was
# kept open, because the proxy always asks its backend for keep-alive; and a
# POST whose head and a large body arrived in one read was refused 431, the
# body counted as header bytes.  An HTTP/1.0 request with Transfer-Encoding
# went to the backend as it came, which RFC 9112 6.1 calls faulty framing: a
# 1.0 backend may read no chunks and take the body for the next request.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# Every row is timed or counted from the client's side with a bound well under
# the deadline that used to end it, and the backend logs every request line it
# parses, so a smuggled request is seen where it lands rather than inferred.
# The chunked answer's payload is checked byte for byte, so a scan that ended
# the response early would fail as loudly as one that never ended it.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate pxchunk

BE=$((SL_PORT_BASE+1740))
PX=$((SL_PORT_BASE+1741))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local l; for l in "${@:3}"; do echo "        $l"; done; }

cleanup() {
    [ -n "${BEPID:-}" ] && kill "$BEPID" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: the proxy frames chunked messages in both directions ==="

cat > "$SOCKETLEY_TMPD/be.py" <<'PYEOF'
import socket, sys, threading, time
port, log = int(sys.argv[1]), sys.argv[2]
lock = threading.Lock()

def note(line):
    with lock:
        with open(log, "a") as f:
            f.write(line + "\n")

class Conn:
    def __init__(self, c):
        self.c, self.buf = c, b""
    def fill(self):
        b = self.c.recv(65536)
        if not b:
            raise EOFError
        self.buf += b
    def line(self):
        while b"\r\n" not in self.buf:
            self.fill()
        l, self.buf = self.buf.split(b"\r\n", 1)
        return l
    def take(self, n):
        while len(self.buf) < n:
            self.fill()
        d, self.buf = self.buf[:n], self.buf[n:]
        return d

def serve(c):
    k = Conn(c)
    try:
        while True:
            reqline = k.line().decode("latin1")
            hdrs = {}
            while True:
                l = k.line()
                if not l:
                    break
                n, _, v = l.decode("latin1").partition(":")
                hdrs[n.strip().lower()] = v.strip()
            parts = reqline.split(" ")
            path = parts[1] if len(parts) > 1 else ""
            note(reqline)
            if path.endswith("/early"):
                # What Node and Go do: answer before the body, then read the
                # declared body off the socket before the next request.
                c.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\nno")
                k.take(int(hdrs.get("content-length", "0")))
                continue
            body = b""
            if "chunked" in hdrs.get("transfer-encoding", ""):
                while True:
                    size = int(k.line().split(b";")[0], 16)
                    if size == 0:
                        while k.line():
                            pass
                        break
                    body += k.take(size)
                    k.take(2)
            else:
                body = k.take(int(hdrs.get("content-length", "0")))
            if path.endswith("/chunked"):
                c.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                for piece in (b"hel", b"lo, ", b"world"):
                    time.sleep(0.03)
                    c.sendall(b"%x\r\n%s\r\n" % (len(piece), piece))
                time.sleep(0.03)
                c.sendall(b"0\r\n\r\n")
            elif path.endswith("/split"):
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-")
                time.sleep(0.1)
                c.sendall(b"Length: 2\r\n\r\nok")
            else:
                reply = b"got %d" % len(body)
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(reply), reply))
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass

ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", port))
ls.listen(64)
ls.settimeout(0.3)
open(log, "w").close()
sys.stderr.write("be up\n"); sys.stderr.flush()
end = time.time() + 240
while time.time() < end:
    try:
        c, _ = ls.accept()
    except socket.timeout:
        continue
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PYEOF

python3 "$SOCKETLEY_TMPD/be.py" "$BE" "$SOCKETLEY_TMPD/be.req" \
    >/dev/null 2>"$SOCKETLEY_TMPD/be.log" &
BEPID=$!
for i in $(seq 1 60); do grep -q "be up" "$SOCKETLEY_TMPD/be.log" 2>/dev/null && break; sleep 0.1; done

daemon_start "$BIN"
"$BIN" create proxy cx -p "$PX" --backend "127.0.0.1:$BE" --protocol http \
    --backend-timeout 5 -s >/dev/null 2>&1
for i in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/"$PX") 2>/dev/null && break; sleep 0.1; done

cat > "$SOCKETLEY_TMPD/cl.py" <<'PYEOF'
import socket, sys, time
port, case = int(sys.argv[1]), sys.argv[2]

class R:
    def __init__(self, s):
        self.s, self.buf = s, b""
    def fill(self):
        b = self.s.recv(65536)
        if not b:
            raise EOFError
        self.buf += b
    def line(self):
        while b"\r\n" not in self.buf:
            self.fill()
        l, self.buf = self.buf.split(b"\r\n", 1)
        return l
    def take(self, n):
        while len(self.buf) < n:
            self.fill()
        d, self.buf = self.buf[:n], self.buf[n:]
        return d
    def response(self):
        status = self.line().decode("latin1")
        hdrs = {}
        while True:
            l = self.line()
            if not l:
                break
            n, _, v = l.decode("latin1").partition(":")
            hdrs[n.strip().lower()] = v.strip()
        body = b""
        if "chunked" in hdrs.get("transfer-encoding", ""):
            while True:
                size = int(self.line().split(b";")[0], 16)
                if size == 0:
                    while self.line():
                        pass
                    break
                body += self.take(size)
                self.take(2)
        else:
            body = self.take(int(hdrs.get("content-length", "0")))
        return status.split(" ", 2)[1], body

def conn(timeout=4):
    s = socket.create_connection(("127.0.0.1", port))
    s.settimeout(timeout)
    return s, R(s)

def get(path, ver="HTTP/1.1"):
    return ("GET %s %s\r\nHost: h\r\n\r\n" % (path, ver)).encode()

try:
    if case == "keepalive":
        s, r = conn()
        s.sendall(get("/cx/chunked")); st, body = r.response()
        t = time.time()
        s.sendall(get("/cx/plain")); st2, _ = r.response()
        print("%s %r %s %.2f" % (st, body.decode(), st2, time.time() - t))
    elif case == "split":
        s, r = conn()
        s.sendall(get("/cx/split")); st, body = r.response()
        t = time.time()
        s.sendall(get("/cx/plain")); st2, _ = r.response()
        print("%s %s %s %.2f" % (st, body.decode(), st2, time.time() - t))
    elif case == "smuggle":
        s, r = conn()
        s.sendall(b"POST /cx/a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
                  b"3\r\nabc\r\n0\r\n\r\n"
                  b"GET /evil HTTP/1.1\r\nHost: h\r\n\r\n")
        st, body = r.response()
        st2, _ = r.response()
        print("%s %s %s" % (st, body.decode(), st2))
    elif case == "http10":
        s, r = conn()
        s.sendall(get("/cx/plain", "HTTP/1.0"))
        st, _ = r.response()
        t = time.time()
        try:
            r.fill(); print("%s open" % st)
        except EOFError:
            print("%s closed %.2f" % (st, time.time() - t))
    elif case == "te10":
        s, r = conn()
        s.sendall(b"POST /cx/te10 HTTP/1.0\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
                  b"3\r\nabc\r\n0\r\n\r\n")
        st, _ = r.response()
        print(st)
    elif case == "big":
        s, r = conn()
        body = b"x" * 20000
        s.sendall(b"POST /cx/big HTTP/1.1\r\nHost: h\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
        st, got = r.response()
        print("%s %s" % (st, got.decode()))
    elif case == "early":
        s1, r1 = conn()
        s1.sendall(b"POST /cx/early HTTP/1.1\r\nHost: h\r\nContent-Length: 500\r\n\r\n")
        st1, _ = r1.response()
        time.sleep(0.3)
        s2, r2 = conn()
        t = time.time()
        s2.sendall(get("/cx/plain")); st2, _ = r2.response()
        print("%s %s %.2f" % (st1, st2, time.time() - t))
except Exception as e:
    print("error %s" % type(e).__name__)
PYEOF

run() { timeout 30 python3 "$SOCKETLEY_TMPD/cl.py" "$PX" "$1" 2>&1; }
secs_under() { awk -v t="$1" -v b="$2" 'BEGIN { exit !(t + 0 < b + 0) }'; }

# ── 1. a chunked answer ends, and the next request on the connection is served
R=$(run keepalive); set -- $R
if [ "${1:-}" = 200 ] && [ "${2:-}" = "'hello," ] && [ "${4:-}" = 200 ] && secs_under "${5:-99}" 1.5; then
    ok "after a chunked answer the next keep-alive request is served (${5}s)"
else bad "keep-alive after a chunked answer" "client saw: $R" \
         "want: 200 'hello, world' 200 in under 1.5 s -- the old scan never called" \
         "a chunked answer finished, so the second request waited for the deadline"; fi

# ── 2. a response head cut by a read boundary still frames ──────────────────
R=$(run split); set -- $R
if [ "${1:-}" = 200 ] && [ "${2:-}" = ok ] && [ "${3:-}" = 200 ] && secs_under "${4:-99}" 1.5; then
    ok "a response head split across two reads still ends the response (${4}s)"
else bad "split response head" "client saw: $R" "want: 200 ok 200 in under 1.5 s"; fi

# ── 3. what follows a chunked request body is parsed, not relayed ───────────
R=$(run smuggle); set -- $R
if [ "${1:-}" = 200 ] && [ "${2:-}" = "got" ] && [ "${4:-}" = 404 ]; then
    ok "a request pipelined behind a chunked body meets the prefix check (404)"
else bad "pipelined behind a chunked body" "client saw: $R" \
         "want: 200 'got 3' then the proxy's own 404 for a path outside its prefix"; fi
if grep -q '/evil' "$SOCKETLEY_TMPD/be.req"; then
    bad "the backend never saw the pipelined request" \
        "backend parsed: $(grep '/evil' "$SOCKETLEY_TMPD/be.req" | head -1)"
else ok "the backend never saw the request pipelined behind the body"; fi

# ── 4. HTTP/1.0 without keep-alive is closed after its answer ───────────────
R=$(run http10); set -- $R
if [ "${1:-}" = 200 ] && [ "${2:-}" = closed ]; then
    ok "an HTTP/1.0 client that asked for nothing is closed after its answer"
else bad "HTTP/1.0 close" "client saw: $R" \
         "want: 200 closed -- a client reading to EOF otherwise waits for ever"; fi

# ── 5. a body in the head's read is not header bytes ────────────────────────
R=$(run big); set -- $R
if [ "${1:-}" = 200 ] && [ "${3:-}" = 20000 ]; then
    ok "a 20 KB body arriving with its head is forwarded, not refused 431"
else bad "head and body in one read" "client saw: $R" "want: 200 got 20000"; fi

# ── 6. a socket still owed a body is not handed to the next client ──────────
R=$(run early); set -- $R
if [ "${1:-}" = 401 ] && [ "${2:-}" = 200 ] && secs_under "${3:-99}" 1.5; then
    ok "a backend still owed a body is not pooled for the next client (${3}s)"
else bad "pooled with a body owed" "client saw: $R" \
         "want: 401 then 200 in under 1.5 s -- a pooled socket reads the next" \
         "client's request as the first client's body and answers nothing"; fi

# ── 7. HTTP/1.0 with Transfer-Encoding is faulty framing ────────────────────
R=$(run te10)
if [ "$R" = 400 ] && ! grep -q '/cx/te10' "$SOCKETLEY_TMPD/be.req"; then
    ok "an HTTP/1.0 request with Transfer-Encoding is refused 400 and never forwarded"
else bad "HTTP/1.0 with Transfer-Encoding" "client saw: $R" \
         "backend parsed: $(grep '/cx/te10' "$SOCKETLEY_TMPD/be.req" | head -1)" \
         "want: 400, and nothing reaching a backend that may read no chunks"; fi

# Control: every row above talked to the backend it was meant to.
N=$(grep -cE '^(GET|POST) ' "$SOCKETLEY_TMPD/be.req" 2>/dev/null || true); N=${N:-0}
if [ "$N" -ge 8 ]; then ok "the backend parsed $N proxied requests"
else bad "the rows reached the backend" "it parsed $N request lines"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
