#!/usr/bin/env bash
# Integration test: a WebSocket connection through an HTTP proxy.
#
# A 101 Switching Protocols means this connection has stopped being a sequence
# of request/response exchanges.  Everything behind that blank line belongs to
# the protocol the two endpoints just agreed on, and the proxy's only remaining
# job is to move bytes in both directions until one of them closes.
#
# The claims below are what "the proxy relays a WebSocket" actually consists of.
# Each one names a way the connection can be broken while every other one still
# passes, which is why there are seven rather than one:
#
#   upgrade        the request reaches the backend still carrying the two
#                  headers that constitute the upgrade
#   echo           a frame the client sends comes back
#   push           a frame the backend sends unprompted arrives
#   pipelined      a frame sent in the SAME segment as the upgrade request is
#                  relayed rather than sitting in a buffer
#   idle           a tunnel with nothing on it survives longer than both
#                  --backend-timeout and the header deadline
#   close          either end can close and the other sees it
#   not-pooled     a tunnel's backend socket never goes to the connection pool
#   breaker        closing a tunnel is not a backend fault
#   idle-sweep     --idle-timeout does not reap a tunnel the backend is feeding
#   wss            the same thing works on a --tls listener
#
# The last one is there because of how the relay is built.  It moves bytes with
# ordinary reads and writes rather than with splice, and that is the difference
# between wss:// working and not working: a splice moves bytes inside the kernel
# where the record layer never sees them, and setup_splice_pipes refuses any
# connection with a session for exactly that reason.  A tunnel built on splice
# would be a tunnel that stops existing the moment an operator puts --tls on the
# listener, which is not a corner case.
#
# ─── WHY THE BACKEND HERE IS STRICT ─────────────────────────────────────────
#
# It answers 426 to an upgrade request that arrives without BOTH
# "Upgrade: websocket" and a Connection header carrying the upgrade token, and
# it says in the body which one was missing.
#
# That is what every real WebSocket server does, socketley's own server runtime
# included (server_instance.cpp requires has_upgrade before it will look at
# Sec-WebSocket-Key).  It matters here because Connection and Upgrade are
# hop-by-hop headers: a proxy strips them by default, and a *lenient* backend
# that answers 101 on the strength of Sec-WebSocket-Key alone will hide that
# completely — the handshake succeeds, the client is satisfied, and the request
# the backend actually received was not an upgrade request at all.  That is
# exactly what test/load/measure_ws.sh could not see.
#
# ─── WHY "NOT POOLED" IS TESTED WITH BYTES THAT LOOK LIKE A RESPONSE ────────
#
# A tunnelled backend socket can never go back in the pool: there is no message
# boundary to return it at, and the next borrower would be handed a live
# WebSocket session.  Refusing it because "the response never finished" is an
# accident of what WebSocket frames happen to look like — a frame whose first
# bytes spell a status line is all it takes to make the response framing scan
# declare a response complete over the top of a live tunnel.
#
# So this sends, on an established tunnel and from the backend, exactly the
# bytes that would fool it:
#
#     HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n
#
# The proxy does not parse WebSocket frames and must not: after a 101 those
# bytes are opaque payload and nothing else.  A proxy that reads them as a
# response detaches the pair, pools the socket, and hands it to the next
# request — so the assertion is made from outside, with an ordinary HTTP
# request that must be answered by the backend rather than by a WebSocket
# session, and with the tunnel that must still work afterwards.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate wstunnel

PORT_BASE=$((SL_PORT_BASE+680))
BE=$((PORT_BASE+1))
PX=$((PORT_BASE+2))
PXI=$((PORT_BASE+3))
PXT=$((PORT_BASE+4))

# The idle sweep runs on a 30s chain armed when the proxy starts, so a client
# can only be reaped at a multiple of 30s from then whatever --idle-timeout
# says.  The feed therefore has to outlast the first tick, which is what these
# two numbers are for and why the claim is driven on a thread of its own,
# alongside the rest of the run rather than after it.
FEED_FRAMES=${FEED_FRAMES:-34}
FEED_INTERVAL=${FEED_INTERVAL:-1.0}

# The idle window the tunnel has to survive.  It has to clear two separate
# bounds, and it is the larger of them that sets this number:
#   --backend-timeout (2s by default) — the wait for a backend's first response
#     byte.  The 101 is that byte, so this must already be over.
#   PROXY_HEADER_TIMEOUT_SEC (10s, not a flag) — the wait for the rest of a
#     half-arrived request.  A frame pipelined behind the upgrade request arms
#     it, and nothing but the switch can disarm it.
IDLE_WINDOW=${IDLE_WINDOW:-11.5}

BEPID=""
PASS=0; FAIL=0; HERR=0; TOTAL=0

cleanup() {
    for r in pxws pxwsi pxwst; do
        "$BIN" stop "$r"   >/dev/null 2>&1 || true
        "$BIN" remove "$r" >/dev/null 2>&1 || true
    done
    [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad()  { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
herr() { TOTAL=$((TOTAL+1)); HERR=$((HERR+1)); echo "  NOT MEASURABLE [$1]: $2"; }

results() { echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $HERR not measurable)"; }

echo "=== Integration: WebSocket relaying through the proxy ==="

if ! command -v python3 >/dev/null 2>&1; then echo "  SKIP: python3 required"; exit 0; fi

TMPD="$SOCKETLEY_TMPD"
ACCLOG="$TMPD/backend.events"
: >"$ACCLOG"

# ---- the backend ----------------------------------------------------------
cat > "$TMPD/be.py" <<'PYEOF'
import base64, hashlib, re, socket, struct, sys, threading, time

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
port, acclog = int(sys.argv[1]), sys.argv[2]
FEED_FRAMES, FEED_INTERVAL = int(sys.argv[3]), float(sys.argv[4])

# The bytes a tunnel carries that a response-framing scan would read as a
# complete HTTP response.  See the header of this test.
POISON = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

_lock = threading.Lock()


def note(what):
    with _lock:
        with open(acclog, "a") as f:
            f.write(what + "\n")


def encode(payload, opcode=0x1):
    head = bytearray([0x80 | opcode])
    n = len(payload)
    if n < 126:
        head.append(n)
    elif n < 65536:
        head.append(126); head += struct.pack("!H", n)
    else:
        head.append(127); head += struct.pack("!Q", n)
    return bytes(head) + payload


class Reader:
    """Reads from the socket through a buffer, so that bytes which arrived in
    the same segment as the request head are not lost.  A frame pipelined
    behind the upgrade request is exactly that case and is one of the claims."""

    def __init__(self, sock):
        self.s = sock
        self.buf = b""

    def _fill(self):
        chunk = self.s.recv(65536)
        if not chunk:
            raise EOFError
        self.buf += chunk

    def read(self, n):
        while len(self.buf) < n:
            self._fill()
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def head(self):
        while b"\r\n\r\n" not in self.buf:
            self._fill()
        i = self.buf.index(b"\r\n\r\n") + 4
        out, self.buf = self.buf[:i], self.buf[i:]
        return out


def read_frame(r):
    hdr = r.read(2)
    masked = bool(hdr[1] & 0x80)
    n = hdr[1] & 0x7F
    if n == 126:
        n = struct.unpack("!H", r.read(2))[0]
    elif n == 127:
        n = struct.unpack("!Q", r.read(8))[0]
    m = r.read(4) if masked else None
    data = r.read(n)
    if m:
        data = bytes(b ^ m[i % 4] for i, b in enumerate(data))
    return hdr[0] & 0x0F, data


def handle(c):
    note("accept")
    c.settimeout(60)
    r = Reader(c)
    try:
        while True:
            head = r.head()
            line = head.split(b"\r\n", 1)[0]
            parts = line.split(b" ")
            path = parts[1] if len(parts) > 1 else b"/"

            key = re.search(rb"Sec-WebSocket-Key:\s*(\S+)", head, re.I)
            if not key:
                # An ordinary request.  Keep-alive, so that a socket the proxy
                # pooled would be reused rather than reconnected — which is the
                # whole point of the not-pooled claim.
                body = b"plain"
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s"
                          % (len(body), body))
                continue

            has_upgrade = re.search(rb"^Upgrade:[ \t]*websocket[ \t]*\r$", head, re.I | re.M)
            has_conn_upgrade = re.search(rb"^Connection:[^\r\n]*\bupgrade\b", head, re.I | re.M)
            if not (has_upgrade and has_conn_upgrade):
                missing = []
                if not has_upgrade:
                    missing.append(b"Upgrade")
                if not has_conn_upgrade:
                    missing.append(b"Connection:upgrade")
                note(b"stripped:".decode() + b",".join(missing).decode())
                body = b"missing " + b",".join(missing) + b"\n"
                c.sendall(b"HTTP/1.1 426 Upgrade Required\r\nContent-Length: %d\r\n"
                          b"Connection: close\r\n\r\n%s" % (len(body), body))
                return

            note("upgraded")
            acc = base64.b64encode(hashlib.sha1(key.group(1) + GUID).digest())
            c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                      b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + acc + b"\r\n\r\n")

            mode = path.rstrip(b"/").rsplit(b"/", 1)[-1]
            # Deliberately a separate write after a pause: it has to land in a
            # read of its own, so that what the proxy does with it is not an
            # accident of where a read boundary fell.
            if mode == b"push":
                time.sleep(0.3)
                c.sendall(encode(b"push-1"))
            elif mode == b"poison":
                time.sleep(0.3)
                c.sendall(POISON)
            elif mode == b"bye":
                time.sleep(0.3)
                c.sendall(encode(b"", 0x8))
                return
            elif mode == b"mute":
                # Take one frame and hang up without ever writing a byte back.
                # A tunnel over which the backend said nothing at all is the one
                # shape where "this backend produced bytes whose framing never
                # resolved" can be reached by an ordinary WebSocket close.
                read_frame(r)
                return
            elif mode == b"feed":
                # A one-directional stream: the backend talks, the client never
                # does.  That is exactly what --idle-timeout measures as idle.
                for _ in range(FEED_FRAMES):
                    time.sleep(FEED_INTERVAL)
                    c.sendall(encode(b"feed"))
                c.sendall(encode(b"", 0x8))
                return

            while True:
                op, data = read_frame(r)
                if op == 0x8:
                    note("close-from-client")
                    c.sendall(encode(b"", 0x8))
                    return
                c.sendall(encode(data))
    except (EOFError, OSError, IndexError, struct.error):
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(64)
print("ready", flush=True)
while True:
    conn, _ = s.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PYEOF

python3 "$TMPD/be.py" "$BE" "$ACCLOG" "$FEED_FRAMES" "$FEED_INTERVAL" >"$TMPD/be.log" 2>&1 &
BEPID=$!
for _ in $(seq 1 60); do grep -q ready "$TMPD/be.log" 2>/dev/null && break; sleep 0.1; done
if ! grep -q ready "$TMPD/be.log" 2>/dev/null; then
    herr "the WebSocket backend came up" "nothing on 127.0.0.1:$BE after 6s"
    results; exit 1
fi

daemon_start "$BIN"

if "$BIN" create proxy pxws -p "$PX" --backend "127.0.0.1:$BE" --protocol http -s \
     >"$TMPD/create.log" 2>&1; then
    ok
else
    bad "the http proxy was created" "$(cat "$TMPD/create.log")"
    results; exit 1
fi

# A second proxy, identical but for --idle-timeout.  Separate because the
# eleven-second silence the `idle` claim needs and a one-second idle timeout
# cannot be asked of the same runtime.
if "$BIN" create proxy pxwsi -p "$PXI" --backend "127.0.0.1:$BE" --protocol http \
     --idle-timeout 1 -s >"$TMPD/create_i.log" 2>&1; then
    ok
else
    bad "the --idle-timeout proxy was created" "$(cat "$TMPD/create_i.log")"
    results; exit 1
fi

# A third, with TLS on its own listener — the wss:// claim.  Skipped rather
# than failed where the machine cannot make a certificate: an absent openssl is
# not evidence about this build.
TLS_PROXY=0
if command -v openssl >/dev/null 2>&1 && python3 -c "import ssl" >/dev/null 2>&1 &&
   openssl req -x509 -newkey rsa:2048 -keyout "$TMPD/key.pem" -out "$TMPD/cert.pem" \
       -days 2 -nodes -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" \
       >/dev/null 2>&1; then
    if "$BIN" create proxy pxwst -p "$PXT" --backend "127.0.0.1:$BE" --protocol http \
         --tls --cert "$TMPD/cert.pem" --key "$TMPD/key.pem" -s \
         >"$TMPD/create_t.log" 2>&1; then
        TLS_PROXY=1
        ok
    else
        bad "the --tls proxy was created" "$(cat "$TMPD/create_t.log")"
    fi
else
    echo "  (wss claim skipped: no openssl, no python ssl module, or no certificate)"
fi

for p in "$PX" "$PXI"; do
    for _ in $(seq 1 60); do
        python3 -c "import socket,sys; s=socket.socket(); s.settimeout(0.2); sys.exit(s.connect_ex(('127.0.0.1',$p)))" \
            2>/dev/null && break
        sleep 0.1
    done
done
sleep 0.4

# ---- the driver -----------------------------------------------------------
cat > "$TMPD/drive.py" <<'PYEOF'
import base64, hashlib, os, socket, ssl, struct, sys, threading, time

px = int(sys.argv[1])
prefix = sys.argv[2].encode()
idle_window = float(sys.argv[3])
pxi = int(sys.argv[4])
prefix_i = sys.argv[5].encode()
feed_frames = int(sys.argv[6])
pxt = int(sys.argv[7])
prefix_t = sys.argv[8].encode()
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

out = {}
_say_lock = threading.Lock()


def say(k, v):
    with _say_lock:
        out[k] = v
        print("%s=%s" % (k, v), flush=True)


def encode(payload, opcode=0x1):
    head = bytearray([0x80 | opcode, 0x80 | len(payload)])
    m = os.urandom(4)
    head += m
    return bytes(head) + bytes(b ^ m[i % 4] for i, b in enumerate(payload))


class Reader:
    def __init__(self, sock):
        self.s = sock
        self.buf = b""

    def _fill(self):
        chunk = self.s.recv(65536)
        if not chunk:
            raise EOFError
        self.buf += chunk

    def read(self, n):
        while len(self.buf) < n:
            self._fill()
        o, self.buf = self.buf[:n], self.buf[n:]
        return o

    def head(self):
        while b"\r\n\r\n" not in self.buf:
            self._fill()
        i = self.buf.index(b"\r\n\r\n") + 4
        o, self.buf = self.buf[:i], self.buf[i:]
        return o

    def at_eof(self):
        try:
            self._fill()
        except EOFError:
            return True
        except socket.timeout:
            return False
        return False


def read_frame(r):
    hdr = r.read(2)
    n = hdr[1] & 0x7F
    if n == 126:
        n = struct.unpack("!H", r.read(2))[0]
    elif n == 127:
        n = struct.unpack("!Q", r.read(8))[0]
    m = r.read(4) if (hdr[1] & 0x80) else None
    data = r.read(n)
    if m:
        data = bytes(b ^ m[i % 4] for i, b in enumerate(data))
    return hdr[0] & 0x0F, data


def upgrade_bytes(path, trailer=b""):
    key = base64.b64encode(os.urandom(16))
    req = (b"GET " + path + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n"
           b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
           b"Sec-WebSocket-Key: " + key + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
    return key, req + trailer


def connect(timeout=8.0, port=None, tls=False):
    s = socket.create_connection(("127.0.0.1", port or px), timeout=timeout)
    if tls:
        # The certificate is a throwaway this run generated; what is being
        # checked is that the record layer and the relay compose, not PKI.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname="127.0.0.1")
    s.settimeout(timeout)
    return s


def handshake(path, trailer=b"", port=None, timeout=8.0, tls=False):
    """Returns (sock, reader, status_line, accept_ok)."""
    s = connect(timeout, port, tls)
    key, blob = upgrade_bytes(path, trailer)
    s.sendall(blob)
    r = Reader(s)
    head = r.head()
    status = head.split(b"\r\n", 1)[0].decode("latin1", "replace")
    want = base64.b64encode(hashlib.sha1(key + GUID).digest())
    return s, r, status, (b"101" in status.encode() and want in head)


# ── --idle-timeout must not reap a tunnel the backend is feeding ───────────
#
# On its own thread and started first, because the idle sweep runs on a 30s
# chain armed when the proxy started: the reap can only happen at the first
# tick, so the feed has to be running when it comes round.  Everything below
# runs alongside it.
def feed_claim():
    try:
        s, r, status, acc = handshake(prefix_i + b"feed", port=pxi, timeout=20.0)
        if not acc:
            say("idle_sweep", 0)
            say("idle_sweep_status", status)
            return
        got = 0
        try:
            while True:
                op, _ = read_frame(r)
                if op == 0x8:
                    break
                got += 1
        finally:
            say("idle_sweep_frames", "%d of %d" % (got, feed_frames))
        say("idle_sweep", 1 if got == feed_frames else 0)
        s.close()
    except Exception as e:
        say("idle_sweep", 0)
        say("idle_sweep_error", repr(e)[:80])


feeder = threading.Thread(target=feed_claim, daemon=True)
feeder.start()

# ── upgrade + echo ─────────────────────────────────────────────────────────
try:
    s, r, status, acc = handshake(prefix)
    say("upgrade", 1 if acc else 0)
    if not acc:
        say("upgrade_status", status)
    else:
        s.sendall(encode(b"echo-1"))
        op, data = read_frame(r)
        say("echo", 1 if data == b"echo-1" else 0)
        if data != b"echo-1":
            say("echo_got", repr(data)[:60])
    s.close()
except Exception as e:
    say("upgrade_error", repr(e)[:80])

# ── a frame the backend sends unprompted ───────────────────────────────────
try:
    s, r, status, acc = handshake(prefix + b"push")
    if not acc:
        say("push", 0)
        say("push_status", status)
    else:
        op, data = read_frame(r)
        say("push", 1 if data == b"push-1" else 0)
    s.close()
except Exception as e:
    say("push", 0)
    say("push_error", repr(e)[:80])

# ── a frame pipelined into the upgrade request, then a long idle window ────
#
# One connection, two claims.  The frame goes out in the SAME sendall as the
# request, so it is buffered on the proxy before the 101 comes back; then the
# tunnel sits silent for longer than every deadline the proxy has.
try:
    s, r, status, acc = handshake(prefix, trailer=encode(b"pipelined-1"))
    if not acc:
        say("pipelined", 0)
        say("idle", 0)
        say("pipelined_status", status)
    else:
        op, data = read_frame(r)
        say("pipelined", 1 if data == b"pipelined-1" else 0)
        time.sleep(idle_window)
        s.sendall(encode(b"after-idle"))
        op, data = read_frame(r)
        say("idle", 1 if data == b"after-idle" else 0)
    s.close()
except Exception as e:
    say("pipelined_or_idle_error", repr(e)[:80])
    out.setdefault("pipelined", 0)
    out.setdefault("idle", 0)
    print("pipelined=%s" % out["pipelined"], flush=True)
    print("idle=%s" % out["idle"], flush=True)

# ── either side can close ──────────────────────────────────────────────────
try:
    s, r, status, acc = handshake(prefix)
    if not acc:
        say("close_by_client", 0)
    else:
        s.sendall(encode(b"", 0x8))
        op, _ = read_frame(r)
        say("close_by_client", 1 if (op == 0x8 and r.at_eof()) else 0)
    s.close()
except Exception as e:
    say("close_by_client", 0)
    say("close_by_client_error", repr(e)[:80])

try:
    s, r, status, acc = handshake(prefix + b"bye")
    if not acc:
        say("close_by_backend", 0)
    else:
        op, _ = read_frame(r)
        say("close_by_backend", 1 if (op == 0x8 and r.at_eof()) else 0)
    s.close()
except Exception as e:
    say("close_by_backend", 0)
    say("close_by_backend_error", repr(e)[:80])

# ── a tunnel's socket is never pooled ──────────────────────────────────────
#
# The backend sends, on the live tunnel, bytes that a response-framing scan
# reads as a complete HTTP response.  If the proxy acts on them it detaches the
# pair and files the socket in the pool; the next ordinary request through this
# proxy is then answered on a live WebSocket session instead of by the backend.
try:
    s, r, status, acc = handshake(prefix + b"poison")
    if not acc:
        say("not_pooled_http", 0)
        say("not_pooled_tunnel", 0)
    else:
        r.read(len(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
        time.sleep(0.5)

        h = connect()
        h.sendall(b"GET " + prefix + b"plain HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        hr = Reader(h)
        try:
            head = hr.head()
            body = hr.read(5) if b"Content-Length: 5" in head else b""
        except Exception:
            head, body = b"", b""
        say("not_pooled_http", 1 if body == b"plain" else 0)
        if body != b"plain":
            say("not_pooled_http_got", repr(head[:60]))
        h.close()

        s.sendall(encode(b"after-poison"))
        op, data = read_frame(r)
        say("not_pooled_tunnel", 1 if data == b"after-poison" else 0)
    s.close()
except Exception as e:
    for k in ("not_pooled_http", "not_pooled_tunnel"):
        if k not in out:
            say(k, 0)
    say("not_pooled_error", repr(e)[:80])

# ── closing a tunnel is not a backend fault ────────────────────────────────
#
# The backend takes one frame and hangs up without ever writing back, six
# times — one more than the default circuit threshold of five.  That is an
# ordinary WebSocket session ending, and it is also the exact shape the EOF
# path charges a backend for: bytes arrived on this socket and their framing
# never resolved.  A 101 IS a resolved header block, and a proxy that does not
# say so takes its own backend out of rotation for using WebSockets.
try:
    closed = 0
    for _ in range(6):
        s, r, status, acc = handshake(prefix + b"mute")
        if not acc:
            break
        s.sendall(encode(b"mute-1"))
        try:
            r.read(1)
        except EOFError:
            closed += 1
        except socket.timeout:
            pass
        s.close()

    h = connect()
    h.sendall(b"GET " + prefix + b"plain HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    hr = Reader(h)
    head = hr.head()
    body = hr.read(5) if b"Content-Length: 5" in head else b""
    say("breaker", 1 if body == b"plain" else 0)
    if body != b"plain":
        say("breaker_got", "%d tunnels closed, then %s"
            % (closed, repr(head.split(b"\r\n", 1)[0])))
    h.close()
except Exception as e:
    say("breaker", 0)
    say("breaker_error", repr(e)[:80])

# ── the same thing on a --tls listener ─────────────────────────────────────
#
# Not a variation for its own sake: the relay moves bytes through the read and
# write path, which is where the record layer lives.  A splice-based relay
# cannot exist on this connection at all.
if pxt > 0:
    try:
        s, r, status, acc = handshake(prefix_t, port=pxt, tls=True)
        if not acc:
            say("wss", 0)
            say("wss_status", status)
        else:
            s.sendall(encode(b"wss-1"))
            op, data = read_frame(r)
            say("wss", 1 if data == b"wss-1" else 0)
        s.close()
    except Exception as e:
        say("wss", 0)
        say("wss_error", repr(e)[:80])

feeder.join(90)
if "idle_sweep" not in out:
    say("idle_sweep", 0)
    say("idle_sweep_error", "the feed thread did not finish")
PYEOF

DRIVE_OUT=$(python3 "$TMPD/drive.py" "$PX" "/pxws/" "$IDLE_WINDOW" \
                                     "$PXI" "/pxwsi/" "$FEED_FRAMES" \
                                     "$([ "$TLS_PROXY" = 1 ] && echo "$PXT" || echo 0)" \
                                     "/pxwst/" 2>&1) || true
printf '%s\n' "$DRIVE_OUT" | sed 's/^/    /'

val() { printf '%s\n' "$DRIVE_OUT" | sed -n "s/^$1=//p" | head -1; }

if [ -z "$(val upgrade)" ]; then
    herr "the driver ran" "it produced: ${DRIVE_OUT:-<nothing>}"
    results; exit 1
fi

claim() {
    local key=$1 label=$2 why=$3
    if [ "$(val "$key")" = "1" ]; then ok; else bad "$label" "$why"; fi
}

# grep -c prints its count and still exits 1 when the count is zero, so the
# status has to be swallowed rather than replaced — `|| echo 0` appends a
# second line to the first one's "0".
STRIPPED=$(grep -c '^stripped:' "$ACCLOG" 2>/dev/null || true)
STRIPPED_WHICH=$(grep -m1 '^stripped:' "$ACCLOG" 2>/dev/null || true)

claim upgrade "the upgrade reaches the backend intact" \
    "no 101 with a matching Sec-WebSocket-Accept — the backend saw ${STRIPPED:-0} request(s) with the upgrade headers removed (${STRIPPED_WHICH:-none recorded})"
claim echo "a frame the client sends is relayed and echoed back" \
    "the upgrade completed and the first data frame was never answered"
claim push "a frame the backend sends unprompted reaches the client" \
    "nothing arrived on a tunnel the backend wrote to"
claim pipelined "a frame sent in the same segment as the upgrade is relayed" \
    "the frame buffered before the 101 was never forwarded"
claim idle "a tunnel outlives every deadline the proxy has" \
    "the connection did not survive ${IDLE_WINDOW}s of silence — --backend-timeout or the ${PROXY_HEADER_TIMEOUT:-10}s header deadline fired on it"
claim close_by_client "a client can close the tunnel and be answered" \
    "no close frame came back, or the connection stayed open after it"
claim close_by_backend "a backend can close the tunnel and the client sees it" \
    "the close never reached the client"
claim not_pooled_http "a tunnel's socket is not handed to the next request" \
    "an ordinary request after the tunnel was not answered by the backend"
claim not_pooled_tunnel "the tunnel survives bytes that look like an HTTP response" \
    "the tunnel stopped relaying after the backend sent a response-shaped payload"
claim breaker "closing a tunnel is not charged to the backend" \
    "an ordinary request after six WebSocket closes was not answered by the backend — the circuit breaker took it out of rotation"
claim idle_sweep "--idle-timeout does not reap a tunnel the backend is feeding" \
    "a tunnel carrying a frame a second was reaped as idle: $(printf '%s\n' "$DRIVE_OUT" | sed -n 's/^idle_sweep_frames=//p' | head -1)"
if [ "$TLS_PROXY" = 1 ]; then
    claim wss "a tunnel works on a --tls listener" \
        "the upgrade or the frame after it did not survive the record layer — a relay built on splice cannot reach this connection at all"
fi

# The backend counts its own accepts, so "not pooled" is also stated from the
# far end: the ordinary request above had to open a connection of its own.
ACCEPTS=$(grep -c '^accept$' "$ACCLOG" 2>/dev/null || true)
UPGRADES=$(grep -c '^upgraded$' "$ACCLOG" 2>/dev/null || true)
echo "  backend: ${ACCEPTS:-0} accepts, ${UPGRADES:-0} upgrades, ${STRIPPED:-0} stripped"

results
if [ "$FAIL" -gt 0 ] || [ "$HERR" -gt 0 ]; then exit 1; fi
echo "  OK"
exit 0
