#!/usr/bin/env bash
# Integration test: a HEAD through the proxy costs no more backend connections
# than a GET does.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# http_response_framing::no_body is set by the header scan for 204 and 304, and
# by nothing else.  A HEAD reply quotes the headers its GET would have sent and
# none of the bytes, and no header on the wire says so -- so body_remaining
# never reaches zero and http_response_frame_complete() never says yes.
#
# That predicate gates three things: whether the backend socket may be pooled,
# whether a half-closed client's hold ever ends, and an invariant that fires if
# close_pair runs while an answer is still owed.  Only the first is measured
# here, because it is the one a count can see from outside.
#
# The headers a HEAD quotes include the coding, so there are two roads to the
# same wait and each needed its own fix: the method has to reach the framing at
# all, and once there it has to be asked BEFORE Transfer-Encoding is, or a
# chunked HEAD reply is held for a terminating chunk RFC 9112 Section 6.3
# forbids the server to send.  Measured through a pool against a keep-alive
# backend, each with the other fix already in place:
#
#     10 GET                              1 backend connection
#     10 HEAD, Content-Length             9 backend connections
#     10 HEAD, Transfer-Encoding chunked  9 backend connections
#
# ─── WHAT IT ASSERTS ────────────────────────────────────────────────────────
#
#   GET pools          the baseline, without which the HEAD numbers mean
#                      nothing: a proxy that pooled nothing would pass a
#                      comparison and fail the point
#   HEAD pools too     no more connections than the GET round took
#   chunked HEAD too   the same, by the road the ordering guards
#   all three served   a 404 costs no backend connection either, and would
#                      otherwise read as perfect pooling
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate headpool

BE=$((SL_PORT_BASE+1786))
PX=$((SL_PORT_BASE+1787))
N=10

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop   hp >/dev/null 2>&1 || true
    "$BIN" remove hp >/dev/null 2>&1 || true
    [ -n "${BEPID:-}" ] && kill "$BEPID" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a HEAD through the proxy is pooled like a GET ==="

cat > "$SOCKETLEY_TMPD/be.py" <<'PYEOF'
import os, socket, sys, threading, time
port, out = int(sys.argv[1]), sys.argv[2]
conns = 0
lock = threading.Lock()

def bump():
    global conns
    with lock:
        conns += 1
        t = out + ".tmp"
        with open(t, "w") as f:
            f.write(str(conns))
        os.replace(t, out)

def serve(c):
    # Keep-alive on purpose: a backend that closed every time would pool
    # nothing either way and hide what is being counted.
    try:
        c.settimeout(10)
        buf = b""
        while True:
            b = c.recv(8192)
            if not b:
                return
            buf += b
            while b"\r\n\r\n" in buf:
                head, buf = buf.split(b"\r\n\r\n", 1)
                parts = head.split(b" ", 2)
                method = parts[0].decode("latin1")
                target = parts[1].decode("latin1") if len(parts) > 1 else ""
                body = b"BODYBODYBODY"
                if method == "HEAD" and target.endswith("/c"):
                    # The other legal shape: a HEAD reply may quote the
                    # Transfer-Encoding its GET would have used and still send
                    # no bytes, which RFC 9112 Section 6.3 requires of it.
                    c.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                elif method == "HEAD":
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body))
                else:
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s"
                              % (len(body), body))
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass

ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", port))
ls.listen(32)
ls.settimeout(0.3)
with open(out, "w") as f:
    f.write("0")
sys.stderr.write("be up\n"); sys.stderr.flush()
end = time.time() + 180
while time.time() < end:
    try:
        c, _ = ls.accept()
    except socket.timeout:
        continue
    except Exception:
        break
    bump()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PYEOF

python3 "$SOCKETLEY_TMPD/be.py" "$BE" "$SOCKETLEY_TMPD/conns" \
    >/dev/null 2>"$SOCKETLEY_TMPD/be.log" &
BEPID=$!
for i in $(seq 1 60); do grep -q "be up" "$SOCKETLEY_TMPD/be.log" 2>/dev/null && break; sleep 0.1; done
if ! grep -q "be up" "$SOCKETLEY_TMPD/be.log" 2>/dev/null; then
    bad "the backend came up" "$(tail -3 "$SOCKETLEY_TMPD/be.log" 2>/dev/null | tr '\n' ' ')"
    echo "  $PASS/$TOTAL passed"; exit 1
fi

daemon_start "$BIN"
"$BIN" create proxy hp -p "$PX" --backend "127.0.0.1:$BE" --protocol http >/dev/null 2>&1
"$BIN" start hp >/dev/null 2>&1
for i in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/"$PX") 2>/dev/null && break; sleep 0.1; done

# One fresh CLIENT connection per request either way, so what differs between
# the two rounds is only what the proxy does with its backend socket.  The
# status is returned so a round that was 404'd cannot read as perfect pooling.
fire() {
    python3 - "$PX" "$1" "$2" "${3:-/hp/x}" <<'PYEOF'
import socket, sys
port, method, n, path = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4]
first = b""
for i in range(n):
    s = socket.socket(); s.settimeout(5)
    s.connect(("127.0.0.1", port))
    s.sendall(("%s %s HTTP/1.1\r\nHost: h\r\n\r\n" % (method, path)).encode())
    try:
        r = s.recv(65536)
        if i == 0:
            first = r.split(b"\r\n", 1)[0]
    except Exception:
        pass
    s.close()
print(first.decode("latin1", "replace"))
PYEOF
}

conns() { cat "$SOCKETLEY_TMPD/conns" 2>/dev/null || echo 0; }

A=$(conns)
GET_STATUS=$(fire GET "$N");  sleep 1; B=$(conns)
HEAD_STATUS=$(fire HEAD "$N"); sleep 1; C=$(conns)
CHUNK_STATUS=$(fire HEAD "$N" /hp/c); sleep 1; D=$(conns)
GET_CONNS=$((B - A))
HEAD_CONNS=$((C - B))
CHUNK_CONNS=$((D - C))

echo "  $N GET          -> $GET_CONNS backend connection(s), first status: $GET_STATUS"
echo "  $N HEAD  len    -> $HEAD_CONNS backend connection(s), first status: $HEAD_STATUS"
echo "  $N HEAD  chunked-> $CHUNK_CONNS backend connection(s), first status: $CHUNK_STATUS"

case "$GET_STATUS$HEAD_STATUS$CHUNK_STATUS" in
    *"200 OK"*"200 OK"*"200 OK"*) ok ;;
    *) bad "all three rounds reached the backend" \
           "GET '$GET_STATUS', HEAD '$HEAD_STATUS', chunked HEAD '$CHUNK_STATUS'" \
           "a refusal the proxy answers itself costs no backend connection," \
           "so the counts below would look perfect and mean nothing" ;;
esac

# The baseline.  Without it a proxy that pooled nothing at all would satisfy
# the comparison below by being equally bad on both.
if [ "$GET_CONNS" -ge 1 ] && [ "$GET_CONNS" -le 3 ]; then ok
else bad "$N GETs share a pooled backend connection" \
         "$GET_CONNS connections for $N requests" \
         "the pool is not working at all, so the HEAD number says nothing"; fi

if [ "$HEAD_CONNS" -le "$((GET_CONNS + 1))" ]; then ok
else bad "$N HEADs are pooled like the GETs" \
         "$HEAD_CONNS connections against the GET round's $GET_CONNS" \
         "a HEAD reply carries the length its GET would have had and no body," \
         "so the framing has to be told, or it waits for bytes that never come"; fi

# The same fact by the other road: the coding is quoted from the GET too, and
# asking about it before asking whether there is a body at all waits for a
# terminating chunk the server is forbidden to send.
if [ "$CHUNK_CONNS" -le "$((GET_CONNS + 1))" ]; then ok
else bad "$N chunked HEADs are pooled like the GETs" \
         "$CHUNK_CONNS connections against the GET round's $GET_CONNS" \
         "Transfer-Encoding on a HEAD reply describes the GET's body, not one" \
         "that is coming, so no_body has to be asked before the coding is"; fi

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
