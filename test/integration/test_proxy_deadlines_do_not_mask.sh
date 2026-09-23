#!/usr/bin/env bash
# Integration test: the two client-side deadlines are independent, and neither
# writes a status line behind a response already on the wire.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# response_deadline_sweep() tested awaiting_headers first and `continue`d while
# that deadline was unexpired, under a comment claiming the two "cannot
# coincide".  They coincide on the commonest pipelining shape there is:
# bound_pipelined_hold() arms the header deadline immediately before
# connect_to_backend() arms the response one, and the comment at that call
# explains why it has to be there.
#
# So for any client that pipelines, --backend-timeout was unreachable.  A
# backend that accepts a connection and then says nothing -- which the man page
# calls the case this deadline exists for -- was answered at the header bound
# instead: 408 Request Timeout, ten seconds later, for a request the client had
# sent in full, with nothing charged to the backend and the circuit breaker
# never opened.
#
# The second half is the 408 itself.  clear_response_deadline() lowers
# awaiting_response when a backend begins answering and leaves awaiting_headers
# armed, so a response that outlives the header bound reached the sweep with
# its own bytes already on the client's wire -- and the 408 was the one
# self-answer in this runtime that did not ask client_answerable() first.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   504 and not 408           the header deadline masking the backend one
#   within the backend bound  the same, measured on the clock rather than on
#                             the status line
#   no status line behind a   a 408 written into the middle of a response,
#   started response          which lands at an offset that is not a message
#                             boundary
#   and it is closed          `closing` alone driving no teardown, which would
#                             leave the client waiting out its own budget
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate pxdeadline

BE_MUTE=$((SL_PORT_BASE+1702))
BE_SLOW=$((SL_PORT_BASE+1703))
PX_MUTE=$((SL_PORT_BASE+1704))
PX_SLOW=$((SL_PORT_BASE+1705))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local l; for l in "${@:3}"; do echo "        $l"; done; }

cleanup() {
    "$BIN" stop px_mute >/dev/null 2>&1 || true
    "$BIN" stop px_slow >/dev/null 2>&1 || true
    [ -n "${BEPID:-}" ] && kill "$BEPID" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a pipelining client still reaches --backend-timeout ==="

cat > "$SOCKETLEY_TMPD/be.py" <<'PYEOF'
import os, socket, sys, threading, time
mute_port, slow_port = int(sys.argv[1]), int(sys.argv[2])

def mute(c):
    # Accepted and then nothing, ever: the shape --backend-timeout exists for.
    try:
        c.recv(65536)
        time.sleep(60)
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass

def slow(c):
    # Headers at once, then a chunked body that takes longer than the header
    # deadline.  Chunked so http_response_frame_complete() never calls it
    # finished, which is what leaves awaiting_headers armed underneath it.
    #
    # And then silence, without closing: a proxy that only marks the pair
    # closing has no completion left to notice it, so the teardown either
    # happens on its own account here or the client waits out its own budget.
    try:
        c.recv(65536)
        c.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        for i in range(12):
            c.sendall(b"5\r\nPIECE\r\n")
            time.sleep(1)
        time.sleep(120)
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass

def listener(port, fn):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port)); ls.listen(16); ls.settimeout(0.3)
    deadline = time.time() + 180
    while time.time() < deadline:
        try:
            c, _ = ls.accept()
        except socket.timeout:
            continue
        except Exception:
            break
        threading.Thread(target=fn, args=(c,), daemon=True).start()
    ls.close()

threading.Thread(target=listener, args=(slow_port, slow), daemon=True).start()
sys.stderr.write("backends up\n"); sys.stderr.flush()
listener(mute_port, mute)
PYEOF

python3 "$SOCKETLEY_TMPD/be.py" "$BE_MUTE" "$BE_SLOW" 2>"$SOCKETLEY_TMPD/be.log" &
BEPID=$!
for _ in $(seq 1 60); do
    grep -q "backends up" "$SOCKETLEY_TMPD/be.log" 2>/dev/null && break
    sleep 0.1
done

daemon_start "$BIN"
"$BIN" create proxy px_mute -p "$PX_MUTE" --backend "127.0.0.1:$BE_MUTE" \
       --protocol http --backend-timeout 2 -s >/dev/null 2>&1
"$BIN" create proxy px_slow -p "$PX_SLOW" --backend "127.0.0.1:$BE_SLOW" \
       --protocol http --backend-timeout 30 -s >/dev/null 2>&1
for _ in $(seq 1 150); do
    ss -ltn 2>/dev/null | grep -q ":$PX_MUTE " && ss -ltn 2>/dev/null | grep -q ":$PX_SLOW " && break
    sleep 0.1
done

OUT=$(timeout 120 python3 - "$PX_MUTE" "$PX_SLOW" <<'PYEOF'
import socket, sys, time
mute_port, slow_port = int(sys.argv[1]), int(sys.argv[2])

def drain(port, request, budget):
    s = socket.create_connection(("127.0.0.1", port), 10)
    s.settimeout(budget)
    t0 = time.time()
    s.sendall(request)
    got = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            got += d
    except Exception:
        pass
    s.close()
    return got, time.time() - t0

# Two requests in one write: the second leaves `partial` non-empty, which is
# what arms the header deadline beside the response one.  The path carries the
# runtime name because the proxy 404s anything outside its own prefix, and a
# 404 arrives before either deadline exists.
def pair(name):
    return (("GET /%s/one HTTP/1.1\r\nHost: x\r\n\r\n" % name) +
            ("GET /%s/two HTTP/1.1\r\nHost: x\r\n\r\n" % name)).encode()

got, secs = drain(mute_port, pair("px_mute"), 25)
first = got.split(b"\r\n")[0].decode("latin1", "replace") if got else "<nothing>"
print("mute_status=%s" % first)
print("mute_seconds=%.1f" % secs)

# A response that outlives the 10s header bound, with a pipelined request
# behind it so the header deadline is armed underneath.
got2, secs2 = drain(slow_port, pair("px_slow"), 40)
body = got2.decode("latin1", "replace")
head_end = body.find("\r\n\r\n")
after = body[head_end + 4:] if head_end >= 0 else body
print("slow_status=%s" % (body.split("\r\n")[0] if body else "<nothing>"))
print("slow_408_behind_response=%s" % ("408" in after))
print("slow_pieces=%d" % after.count("PIECE"))
print("slow_seconds=%.1f" % secs2)
PYEOF
)
echo "$OUT" | sed 's/^/  /'

case "$OUT" in
    *"mute_status=HTTP/1.1 504"*) ok ;;
    *) bad "a mute backend is answered 504, not 408" \
           "got: $(echo "$OUT" | grep mute_status || echo '<no line>')" \
           "408 here is the header deadline firing for a request the client" \
           "sent in full, while the backend that said nothing is charged with" \
           "nothing and the breaker stays shut" ;;
esac

MS=$(echo "$OUT" | sed -n 's/mute_seconds=//p')
if [ -n "$MS" ] && [ "${MS%.*}" -le 6 ]; then ok
else bad "and it is answered at the backend bound rather than the header one" \
         "took ${MS:-?}s, with --backend-timeout 2 and a 10s header deadline"; fi

SS=$(echo "$OUT" | sed -n 's/slow_seconds=//p')
if [ -n "$SS" ] && [ "${SS%.*}" -lt 20 ]; then ok
else bad "and the connection it cannot answer is closed rather than left open" \
         "took ${SS:-?}s against a 40s client budget, so the close was the" \
         "client's own timeout and nothing drove the teardown"; fi

case "$OUT" in
    *"slow_408_behind_response=False"*) ok ;;
    *) bad "no 408 is written behind a response already on the wire" \
           "got: $(echo "$OUT" | grep slow_408 || echo '<no line>')" \
           "the client is reading a 200 whose body is still arriving, and a" \
           "status line spliced into it lands at an offset that is not a" \
           "message boundary" ;;
esac

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
