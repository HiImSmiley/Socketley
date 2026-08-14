#!/usr/bin/env bash
# Integration test: a backend that writes more than its response declared does
# not get those bytes relayed to the client, and the client's next request is
# still served.
#
# ─── THE SHAPE ──────────────────────────────────────────────────────────────
#
# A backend answers with a complete, correctly framed response and, in the same
# write, the head of another one — the shape a server produces by flushing an
# answer and the beginning of the next together, and the shape a broken one
# produces by simply writing too much.  Those extra bytes answer no request the
# proxy sent: it puts one request down a backend socket and waits for its
# answer, so nothing legitimate follows the last byte of that answer.
#
# http_response_consume_body() has always noticed them — it tests `avail > left`
# — and used to record the fact for the connection pool alone, on the reasoning
# that "the bytes are already on their way to the client either way".  They were,
# and that is what this test is about: the client reads them as the beginning of
# the answer to a request it is still waiting on.
#
# ─── WHY BOTH ASSERTIONS ────────────────────────────────────────────────────
#
# "The stray bytes never arrived" passes on a build that drops the whole
# response, and "the second request was answered" passes on a build that relays
# everything and happens to answer anyway.  Neither alone says the proxy did the
# right thing; the pair does.  The stray bytes carry their own marker so that
# "some bytes arrived" cannot pass for either claim.
#
# Against the build before the fix: the client receives the stray response AND
# its second request is never answered — the overrun was spelled `unknown`, so
# the exchange was never judged finished, the client was never reset, and the
# second request sat in the proxy's buffer until the connection closed under it.
# That is what fuzz_proxy_ops reports as answer-lost-to-a-half-close.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate overrun

BE_PORT=$((SL_PORT_BASE+985))
PX_PORT=$((SL_PORT_BASE+986))
PX_NAME=overrun_px
PASS=0; FAIL=0; TOTAL=0
BEPID=""
TMPD=""

cleanup() {
    "$BIN" stop "$PX_NAME" 2>/dev/null || true
    sleep 0.2
    "$BIN" remove "$PX_NAME" 2>/dev/null || true
    [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null || true
    [ -n "${TMPD:-}" ] && rm -rf "$TMPD"
    daemon_stop
}
trap cleanup EXIT

assert_eq() {
    TOTAL=$((TOTAL+1))
    local got="$1" expected="$2" label="$3"
    if [ "$got" = "$expected" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: got '$got', expected '$expected'"
    fi
}

echo "=== Integration: a backend that writes past its Content-Length ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 is required"
    exit 0
fi

TMPD=$(mktemp -d)

# The backend.  The request asking for /one is the one answered with an overrun;
# anything else gets an ordinary response, which is what lets the second
# assertion distinguish "served on a fresh connection" from "never served".
#
# Keyed on the REQUEST and not on which connection arrives first, because
# ready_tcp dials this port to find out whether it is up and that probe would
# otherwise take the overrunning slot -- it opens a connection, sends nothing
# and closes.  Measured: first=0, second=1, which reads as the fix having eaten
# the first response and is a fixture counting the wrong thing.
cat > "$TMPD/be.py" <<'PY'
import socket, sys, threading

port = int(sys.argv[1])
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(64)

def read_request(c):
    req = b""
    while b"\r\n\r\n" not in req:
        chunk = c.recv(4096)
        if not chunk:
            return None
        req += chunk
    return req

def serve(c):
    try:
        c.settimeout(10)
        req = read_request(c)
        if req is None:
            return
        if b"/one" in req.split(b"\r\n", 1)[0]:
            # A complete answer, and behind it a whole second response the
            # proxy never asked for.  Both in one write, so they arrive in one
            # read completion and the overrun is inside a single chunk.
            body = b"FIRST"
            stray_body = b"STRAYRESPONSE"
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " +
                      str(len(body)).encode() + b"\r\n\r\n" + body +
                      b"HTTP/1.1 200 OK\r\nContent-Length: " +
                      str(len(stray_body)).encode() + b"\r\n\r\n" + stray_body)
        else:
            body = b"SECOND"
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " +
                      str(len(body)).encode() + b"\r\n\r\n" + body)
        # Hold the socket open either way: a backend that hangs up gives the
        # proxy a zero-length read, and that path tears the pair down for
        # reasons of its own, which would reap the client by accident.
        while True:
            import time; time.sleep(3600)
    except Exception:
        pass

while True:
    try:
        c, _ = srv.accept()
    except Exception:
        break
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY

python3 "$TMPD/be.py" "$BE_PORT" &
BEPID=$!
ready_tcp 127.0.0.1 "$BE_PORT" 15 || { echo "  SKIP: backend did not start"; exit 0; }

create_ok "proxy created" "$BIN" create proxy "$PX_NAME" -p "$PX_PORT" \
    --backend "127.0.0.1:$BE_PORT" --protocol http -s
ready_tcp 127.0.0.1 "$PX_PORT" 20 || { echo "  FATAL: proxy never came up"; exit 1; }

# The client.  Raw sockets, because the claim is about which bytes reach the
# wire and an HTTP library would parse the stray response away or choke on it.
cat > "$TMPD/cl.py" <<'PY'
import socket, sys

port   = int(sys.argv[1])
# The proxy answers 404 to any path outside its own "/<name>/" prefix, so a
# bare "/one" never reaches the backend at all -- which this test first did,
# and which its "the first request is answered" assertion caught.
prefix = "/" + sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(8)
s.connect(("127.0.0.1", port))

def req(path):
    s.sendall(("GET %s HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n" % path).encode())

seen = b""

def read_until(pred, limit=6.0):
    global seen
    s.settimeout(limit)
    try:
        while not pred(seen):
            chunk = s.recv(4096)
            if not chunk:
                break
            seen += chunk
    except Exception:
        pass

req(prefix + "/one")
# Wait for the whole of the first answer, and give the proxy a moment in which
# it *could* have relayed the stray bytes as well.
read_until(lambda b: b"FIRST" in b, 6.0)
after_first = seen

req(prefix + "/two")
read_until(lambda b: b"SECOND" in b, 6.0)

print("stray=%d" % (1 if b"STRAY" in seen else 0))
print("first=%d"  % (1 if b"FIRST"  in after_first else 0))
print("second=%d" % (1 if b"SECOND" in seen else 0))
PY

OUT=$(python3 "$TMPD/cl.py" "$PX_PORT" "$PX_NAME" 2>/dev/null || true)

got_first=$(printf '%s\n'  "$OUT" | sed -n 's/^first=//p')
got_stray=$(printf '%s\n'  "$OUT" | sed -n 's/^stray=//p')
got_second=$(printf '%s\n' "$OUT" | sed -n 's/^second=//p')

# The answer the client asked for arrives in full.  Without this the two below
# would both pass on a proxy that relays nothing at all.
assert_eq "$got_first" "1" "the first request is answered"

# And nothing behind it.  This is the claim: the stray response answers no
# request this client made, and reading it as the head of one is the harm.
assert_eq "$got_stray" "0" "the bytes past Content-Length never reach the client"

# The exchange was judged finished despite the overrun, so the connection was
# reset for its next request rather than left mid-response for ever.
assert_eq "$got_second" "1" "the next request on the same connection is answered"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
echo "  OK"
