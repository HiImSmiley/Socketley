#!/usr/bin/env bash
# Integration test: a client that closes during an answer only the backend can
# end does not hold the pair for as long as the backend cares to stay silent.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# An HTTP client's FIN is held while its answer is owed, because a client may
# half-close after its request and still read -- and an answer framed by the
# backend's close (no Content-Length, not chunked) is owed until that close.
# The hold was bounded by --backend-timeout only until the first byte of the
# answer: from there no deadline applied and no read was armed on the client,
# so a backend that answered in part and then kept its socket open held the
# client in CLOSE-WAIT and its own socket for ever.  A client that closes with
# nothing unread sends only a FIN, which reads exactly like a half-close, so
# the proxy cannot tell "gone" from "still reading" and the bound has to be
# on the backend's silence.
#
# The backend writes down when the proxy closed its socket, measured from the
# client's close, so the release is seen from the side that was being held.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   (a)  connections or backend_connections above 0 three seconds after a
#        client closed during an answer framed by close whose backend went
#        quiet (--backend-timeout 1): the hold with no bound -- fails on the
#        tree before this fix every time
#   (a2) the backend's socket not closed by the proxy within those seconds:
#        the pair counted gone while the backend socket is still open
#   (b)  the same for an answer with a Content-Length its backend stops short
#        of: a bound that asked the framing rather than the backend's silence
#   (c)  a half-closed client not receiving the whole of an answer framed by
#        close that streams for longer than the bound, with pauses shorter than
#        it, whether its FIN came before the answer or during it: a bound on
#        the answer's age rather than on the backend's silence (the FIN during
#        it, with the deadline not restarted by each read, got 3000 of 5000
#        bytes), or a FIN read as the client leaving
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate eofhold

BE=$((SL_PORT_BASE+1538))
PX=$((SL_PORT_BASE+1539))
NAME=eh

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop   "$NAME" >/dev/null 2>&1 || true
    "$BIN" remove "$NAME" >/dev/null 2>&1 || true
    [ -n "${BEPID:-}" ] && kill "$BEPID" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a closed client's unending answer is let go of ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  0/0 passed"; exit 0; }

# ─── the backend ────────────────────────────────────────────────────────────
# Writes `<target> <seconds>` to <out>.closed when the proxy closes a socket,
# measured from the moment the client wrote <out>.<target-name>.gone.
cat > "$SOCKETLEY_TMPD/be.py" <<'PYEOF'
import os, socket, sys, threading, time
port, out = int(sys.argv[1]), sys.argv[2]

def serve(c):
    target = "?"
    try:
        c.settimeout(60)
        buf = b""
        while b"\r\n\r\n" not in buf:
            b = c.recv(65536)
            if not b:
                return
            buf += b
        target = buf.split(b"\r\n", 1)[0].split(b" ")[1].decode("latin1")
        if target.startswith("/stream"):
            # Framed by close, streamed in five pieces 0.4 s apart and then
            # ended by closing, which is the one way such an answer ends.
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n")
            for _ in range(5):
                time.sleep(0.4)
                c.sendall(b"s" * 1000)
            return
        if target.startswith("/quiet-cl"):
            # A Content-Length the backend stops well short of.
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n" + b"q" * 100)
        else:
            # Framed by close, a part of it, and then silence with the socket
            # left open.
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + b"u" * 100)
        c.settimeout(20)
        try:
            while c.recv(65536):
                pass
        except socket.timeout:
            pass
        gone = out + "." + target.strip("/").split("?")[0] + ".gone"
        took = time.time() - os.path.getmtime(gone) if os.path.exists(gone) else -1
        with open(out + ".closed", "a") as f:
            f.write("%s %.2f\n" % (target, took))
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
sys.stderr.write("be up\n"); sys.stderr.flush()
end = time.time() + 300
while time.time() < end:
    try:
        c, _ = ls.accept()
    except socket.timeout:
        continue
    except Exception:
        break
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PYEOF

# ─── the client ─────────────────────────────────────────────────────────────
cat > "$SOCKETLEY_TMPD/cl.py" <<'PYEOF'
import socket, sys, time
mode, port, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.create_connection(("127.0.0.1", port))
s.settimeout(10)
s.sendall(("GET /eh/%s HTTP/1.1\r\nHost: t\r\n\r\n" % mode).encode())
if mode.startswith("stream"):
    # Half-closed at once, or once the first piece of the body is in, and
    # then read to the end.
    got = b""
    if mode == "stream-late":
        while not (b"\r\n\r\n" in got and len(got.split(b"\r\n\r\n", 1)[1]) >= 1000):
            b = s.recv(65536)
            if not b:
                break
            got += b
    s.shutdown(socket.SHUT_WR)
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            got += b
    except Exception as e:
        print("ERR %s" % type(e).__name__, flush=True)
    body = got.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in got else b""
    print("BODY %d" % len(body), flush=True)
    sys.exit(0)
# Everything the backend sent, so the close is a FIN and not a reset.
got = b""
while not (b"\r\n\r\n" in got and len(got.split(b"\r\n\r\n", 1)[1]) >= 100):
    b = s.recv(65536)
    if not b:
        break
    got += b
open(out + "." + mode + ".gone", "w").close()
s.close()
print("CLOSED %d" % len(got), flush=True)
PYEOF

python3 "$SOCKETLEY_TMPD/be.py" "$BE" "$SOCKETLEY_TMPD/be" \
    >/dev/null 2>"$SOCKETLEY_TMPD/be.log" &
BEPID=$!
for _ in $(seq 1 60); do grep -q "be up" "$SOCKETLEY_TMPD/be.log" 2>/dev/null && break; sleep 0.1; done
if ! grep -q "be up" "$SOCKETLEY_TMPD/be.log" 2>/dev/null; then
    bad "the backend came up" "$(tail -3 "$SOCKETLEY_TMPD/be.log" 2>/dev/null | tr '\n' ' ')"
    echo "  $PASS/$TOTAL passed"; exit 1
fi

daemon_start "$BIN"
"$BIN" create proxy "$NAME" -p "$PX" --backend "127.0.0.1:$BE" --protocol http \
    --backend-timeout 1 >/dev/null 2>&1
"$BIN" start "$NAME" >/dev/null 2>&1
for _ in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/"$PX") 2>/dev/null && break; sleep 0.1; done

stat_of() { "$BIN" stats "$NAME" 2>/dev/null | awk -F: -v k="$1" '$1 == k { print $2 + 0; exit }'; }
# A worker's figures reach stats on its next report, so a count that should
# be there now is asked for until it is, or for three seconds.
stat_when() {   # key want
    local v=""
    for _ in $(seq 1 30); do
        v=$(stat_of "$1"); [ "$v" = "$2" ] && break; sleep 0.1
    done
    echo "${v:-absent}"
}
closed_after() { awk -v t="/$1" '$1 == t { print $2; exit }' "$SOCKETLEY_TMPD/be.closed" 2>/dev/null; }
# A close timed from the client's, as the backend writes -1 when the client never marked its own.
measured() { [ -n "$1" ] && [ "$1" != "-1.00" ]; }

# One client that closes during an answer whose backend then says nothing.
held_case() {   # mode
    local mode=$1 out conns backends took
    out=$(timeout 20 python3 "$SOCKETLEY_TMPD/cl.py" "$mode" "$PX" "$SOCKETLEY_TMPD/be" 2>&1)
    # The backend's record first, because it cannot be stale: a stats reading
    # taken at once may be the report from before the client connected.
    for _ in $(seq 1 30); do
        took=$(closed_after "$mode"); [ -n "$took" ] && break; sleep 0.1
    done
    conns=$(stat_when connections 0)
    backends=$(stat_when backend_connections 0)
    echo "$out|$conns|$backends|${took:-}"
}

# ─── (a) (a2): framed by close, then silence ────────────────────────────────
IFS='|' read -r A_OUT A_CONNS A_BACKENDS A_TOOK <<<"$(held_case quiet)"
echo "  (a) client: ${A_OUT:-nothing}; three seconds on: connections=$A_CONNS" \
     "backend_connections=$A_BACKENDS; backend socket closed after ${A_TOOK:-never} s"

if [ "$A_CONNS" = 0 ] && [ "$A_BACKENDS" = 0 ]; then ok
else bad "(a) a client closed during an answer framed by close is let go of" \
         "connections=$A_CONNS backend_connections=$A_BACKENDS three seconds after its close," \
         "want 0 and 0 (--backend-timeout 1)"; fi

if measured "$A_TOOK"; then ok
else bad "(a2) the backend's socket is closed with it" \
         "backend socket closed after '${A_TOOK:-never}' s: never, or before the client marked its close" \
         "client said: ${A_OUT:-nothing}"; fi

# ─── (b): a Content-Length the backend stops short of ───────────────────────
IFS='|' read -r B_OUT B_CONNS B_BACKENDS B_TOOK <<<"$(held_case quiet-cl)"
echo "  (b) client: ${B_OUT:-nothing}; three seconds on: connections=$B_CONNS" \
     "backend_connections=$B_BACKENDS; backend socket closed after ${B_TOOK:-never} s"

if [ "$B_CONNS" = 0 ] && [ "$B_BACKENDS" = 0 ] && measured "$B_TOOK"; then ok
else bad "(b) a client closed during an answer its backend stopped short of is let go of" \
         "connections=$B_CONNS backend_connections=$B_BACKENDS, backend socket closed after" \
         "${B_TOOK:-never} s, three seconds after the client's close"; fi

# ─── (c): a half-closed client still gets a streaming answer ────────────────
C_OUT=$(timeout 20 python3 "$SOCKETLEY_TMPD/cl.py" stream "$PX" "$SOCKETLEY_TMPD/be" 2>&1)
C2_OUT=$(timeout 20 python3 "$SOCKETLEY_TMPD/cl.py" stream-late "$PX" "$SOCKETLEY_TMPD/be" 2>&1)
echo "  (c) 2 s of answer 0.4 s apart, to a client half-closed before it: ${C_OUT:-nothing};" \
     "half-closed during it: ${C2_OUT:-nothing}"

if [ "$C_OUT" = "BODY 5000" ] && [ "$C2_OUT" = "BODY 5000" ]; then ok
else bad "(c) a half-closed client receives the whole of an answer that keeps coming" \
         "half-closed before the answer: '${C_OUT:-nothing}', during it: '${C2_OUT:-nothing}'" \
         "(want 'BODY 5000' each: 5000 bytes, then the close)"; fi

if [ "$FAIL" -gt 0 ]; then
    grep -v '\[INFO\]' "$SOCKETLEY_DLOG" 2>/dev/null | tail -8 | sed 's/^/        log: /' || true
fi

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
