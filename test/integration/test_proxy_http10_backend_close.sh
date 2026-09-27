#!/usr/bin/env bash
# Integration test: a backend that answers HTTP/1.0 without keep-alive is
# closing its socket, and the proxy lets go of it rather than reusing it.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# RFC 9112 Section 9.3 makes an HTTP/1.0 response persistent only with
# `Connection: keep-alive`, and the response framing knew only the explicit
# `Connection: close`.  So a backend answering "HTTP/1.0 200 OK" with a
# Content-Length was parked on its keep-alive client (or pooled), and the
# client's next request was written into a socket the backend was about to
# close unread.  The backend's FIN then set off the reissue for a parked
# socket, which is why the client mostly still got a 200 and the defect
# looked like nothing: the request went out twice, and where the reissue was
# not allowed it was a 502.
#
# The backend here stamps its accept ordinal into every body, lingers a while
# after its HTTP/1.0 answer before closing, and writes down any request that
# reaches it on that socket in the meantime -- which is the defect itself,
# seen from the only side that can see it whatever the proxy does next.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   (a)  the next request on the same client connection answered other than
#        200 by a new backend connection: the HTTP/1.0 socket reused, or the
#        client dropped with it instead of kept for its next request
#   (a2) any request reaching the backend on the socket it answered HTTP/1.0
#        on: the socket parked or pooled and the next request written into
#        it before the FIN -- fails on the tree before this fix every time
#   (b)  while the client idles after an HTTP/1.0 answer, the stats showing
#        the socket parked, pooled, or still open: the pool gate not asking
#        the protocol version, whatever rescues the next request later
#   (b2) the same next-request check as (a), after that idle
#   (c)  an HTTP/1.0 answer that says keep-alive not reused: the version
#        test closing what the RFC keeps open, one connect per request
#   (d)  backend connections left over once every client has gone
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate h10close

BE=$((SL_PORT_BASE+1536))
PX=$((SL_PORT_BASE+1537))
NAME=hz

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
    [ -n "${CLPID:-}" ] && kill "$CLPID" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: an HTTP/1.0 backend's socket is not reused ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  0/0 passed"; exit 0; }

# ─── the backend ────────────────────────────────────────────────────────────
cat > "$SOCKETLEY_TMPD/be.py" <<'PYEOF'
import os, socket, sys, threading, time
port, out = int(sys.argv[1]), sys.argv[2]
conns = 0
lock = threading.Lock()

def note(path, text):
    with lock:
        with open(path, "a") as f:
            f.write(text + "\n")

def bump():
    global conns
    with lock:
        conns += 1
        return conns

def serve(c, ordinal):
    try:
        c.settimeout(60)
        buf = b""
        k = 0
        while True:
            while b"\r\n\r\n" not in buf:
                b = c.recv(65536)
                if not b:
                    return
                buf += b
            # No request in this test carries a body.
            head, buf = buf.split(b"\r\n\r\n", 1)
            target = head.split(b"\r\n", 1)[0].split(b" ")[1].decode("latin1")
            k += 1
            body = ("conn=%d req=%d target=%s" % (ordinal, k, target)).encode()
            if target.startswith("/h10ka"):
                # HTTP/1.0 that asks to stay open, which RFC 9112 honours.
                c.sendall(b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\n"
                          b"Content-Length: %d\r\n\r\n%s" % (len(body), body))
                continue
            if target.startswith("/h10"):
                # HTTP/1.0 with no keep-alive, so this socket closes -- after
                # a linger, noting any request that arrives on it first.
                linger = float(target.split("linger=")[1]) if "linger=" in target else 0.3
                c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
                end = time.time() + linger
                while time.time() < end:
                    c.settimeout(max(0.01, end - time.time()))
                    try:
                        b = c.recv(65536)
                    except socket.timeout:
                        break
                    if not b:
                        break
                    note(out + ".stray", "conn=%d after=%s got=%r" % (ordinal, target, b[:40]))
                return
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
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
    threading.Thread(target=serve, args=(c, bump()), daemon=True).start()
PYEOF

# ─── the client ─────────────────────────────────────────────────────────────
# Prints one line per answer, `R <label> <status> <body>`, with ERR in place
# of the status when no answer came.
cat > "$SOCKETLEY_TMPD/cl.py" <<'PYEOF'
import os, socket, sys, time
mode, port = sys.argv[1], int(sys.argv[2])

def req(target):
    return ("GET /hz%s HTTP/1.1\r\nHost: t\r\n\r\n" % target).encode()

def read_response(s, buf):
    while b"\r\n\r\n" not in buf:
        b = s.recv(65536)
        if not b:
            raise ConnectionError("closed before an answer")
        buf += b
    hdr, rest = buf.split(b"\r\n\r\n", 1)
    lines = hdr.split(b"\r\n")
    status = (lines[0].split(b" ")[1].decode("latin1")
              if lines[0].startswith(b"HTTP/1.") else "BAD")
    clen = 0
    for l in lines[1:]:
        k, _, v = l.partition(b":")
        if k.strip().lower() == b"content-length":
            clen = int(v.strip())
    while len(rest) < clen:
        b = s.recv(65536)
        if not b:
            break
        rest += b
    return status, rest[:clen].decode("latin1").strip(), rest[clen:]

def show(label, s, buf):
    try:
        st, body, buf = read_response(s, buf)
        print("R %s %s %s" % (label, st, body), flush=True)
    except Exception as e:
        print("R %s ERR %s" % (label, type(e).__name__), flush=True)
    return buf

s = socket.create_connection(("127.0.0.1", port))
s.settimeout(5)
buf = b""
s.sendall(req("/ok?warm"))
buf = show("w", s, buf)
if mode == "fast":
    # The next request goes out the moment the answer is in, well inside the
    # backend's linger.
    s.sendall(req("/h10?linger=0.3"))
    buf = show("a1", s, buf)
    s.sendall(req("/ok?after=h10"))
    buf = show("a2", s, buf)
elif mode == "idle":
    s.sendall(req("/h10?linger=1.5"))
    buf = show("b1", s, buf)
    print("IDLE", flush=True)
    sig = sys.argv[3]
    end = time.time() + 10
    while not os.path.exists(sig) and time.time() < end:
        time.sleep(0.02)
    s.sendall(req("/ok?after=idle"))
    buf = show("b2", s, buf)
elif mode == "keepalive":
    s.sendall(req("/h10ka?n=1"))
    buf = show("c1", s, buf)
    s.sendall(req("/h10ka?n=2"))
    buf = show("c2", s, buf)
s.close()
print("DONE", flush=True)
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
"$BIN" create proxy "$NAME" -p "$PX" --backend "127.0.0.1:$BE" --protocol http >/dev/null 2>&1
"$BIN" start "$NAME" >/dev/null 2>&1
for _ in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/"$PX") 2>/dev/null && break; sleep 0.1; done

stat_of() { "$BIN" stats "$NAME" 2>/dev/null | awk -F: -v k="$1" '$1 == k { print $2 + 0; exit }'; }
# A worker's figures reach stats on its next report, so a count that should
# be there now is asked for until it is, or for three seconds.
stat_when() {   # key want
    local v=""
    for _ in $(seq 1 30); do
        v=$(stat_of "$1"); [ "${v:-0}" = "$2" ] && break; sleep 0.1
    done
    echo "${v:-0}"
}
conn_of()   { sed -n "s/^R $1 200 conn=\([0-9]*\) .*/\1/p" "$2" | head -1; }
status_of() { awk -v l="$1" '$1 == "R" && $2 == l { print $3; exit }' "$2"; }
strays()    { cat "$SOCKETLEY_TMPD/be.stray" 2>/dev/null; }

# ─── (b) (b2): the client idles behind an HTTP/1.0 answer ───────────────────
# First, on an empty pool, so the pooled count below is this socket's alone.
SIG="$SOCKETLEY_TMPD/go_b"
timeout 20 python3 "$SOCKETLEY_TMPD/cl.py" idle "$PX" "$SIG" >"$SOCKETLEY_TMPD/b.out" 2>&1 &
CLPID=$!
for _ in $(seq 1 100); do grep -q '^IDLE' "$SOCKETLEY_TMPD/b.out" 2>/dev/null && break; sleep 0.02; done
# Two reports' worth, and well inside the backend's 1.5 s linger, so a socket
# kept open by the proxy is still open to be counted.
sleep 0.6
B_STATS=$("$BIN" stats "$NAME" 2>/dev/null)
B_PARKED=$(echo "$B_STATS" | awk -F: '$1 == "parked_connections" { print $2 + 0 }')
B_POOLED=$(echo "$B_STATS" | awk -F: '$1 == "pooled_connections" { print $2 + 0 }')
B_BACKENDS=$(echo "$B_STATS" | awk -F: '$1 == "backend_connections" { print $2 + 0 }')
touch "$SIG"
wait "$CLPID" 2>/dev/null; CLPID=""
B1=$(status_of b1 "$SOCKETLEY_TMPD/b.out"); B2=$(status_of b2 "$SOCKETLEY_TMPD/b.out")
B1C=$(conn_of b1 "$SOCKETLEY_TMPD/b.out"); B2C=$(conn_of b2 "$SOCKETLEY_TMPD/b.out")
B_STRAY=$(strays)
echo "  (b) HTTP/1.0 answer ${B1:-none} on conn ${B1C:-?}; while idle: parked=${B_PARKED:-0}" \
     "pooled=${B_POOLED:-0} backends=${B_BACKENDS:-none}; next: ${B2:-none} on conn ${B2C:-?}"

if [ "${B_PARKED:-0}" = 0 ] && [ "${B_POOLED:-0}" = 0 ] && [ "${B_BACKENDS:-x}" = 0 ]; then ok
else bad "(b) the socket behind an HTTP/1.0 answer is neither parked, pooled nor kept" \
         "parked_connections=${B_PARKED:-0} pooled_connections=${B_POOLED:-0}" \
         "backend_connections=${B_BACKENDS:-absent} 0.6 s after the answer, want 0 0 0"; fi

if [ "$B1" = 200 ] && [ "$B2" = 200 ] && [ -n "$B1C" ] && [ -n "$B2C" ] && [ "$B1C" != "$B2C" ]; then ok
else bad "(b2) the request after the idle goes to a new backend connection" \
         "statuses ${B1:-none} then ${B2:-none}, backend connections ${B1C:-?} then ${B2C:-?}" \
         "(want 200, 200, two different)"; fi

# ─── (a) (a2): the next request at once ─────────────────────────────────────
: >"$SOCKETLEY_TMPD/be.stray"
timeout 20 python3 "$SOCKETLEY_TMPD/cl.py" fast "$PX" >"$SOCKETLEY_TMPD/a.out" 2>&1
A1=$(status_of a1 "$SOCKETLEY_TMPD/a.out"); A2=$(status_of a2 "$SOCKETLEY_TMPD/a.out")
A1C=$(conn_of a1 "$SOCKETLEY_TMPD/a.out"); A2C=$(conn_of a2 "$SOCKETLEY_TMPD/a.out")
# The linger ends 0.3 s after the answer, and a stray is written before it.
sleep 0.5
A_STRAY=$(strays)
echo "  (a) HTTP/1.0 answer ${A1:-none} on conn ${A1C:-?}; next at once: ${A2:-none} on conn ${A2C:-?}"

if [ "$A1" = 200 ] && [ "$A2" = 200 ] && [ -n "$A1C" ] && [ -n "$A2C" ] && [ "$A1C" != "$A2C" ]; then ok
else bad "(a) the request right behind an HTTP/1.0 answer goes to a new backend connection" \
         "statuses ${A1:-none} then ${A2:-none}, backend connections ${A1C:-?} then ${A2C:-?}" \
         "(want 200, 200, two different)" \
         "$(grep '^R a' "$SOCKETLEY_TMPD/a.out" | head -2 | tr '\n' ' ')"; fi

if [ -z "$B_STRAY" ] && [ -z "$A_STRAY" ]; then ok
else bad "(a2) no request reaches a backend on the socket it answered HTTP/1.0 on" \
         "the backend received, after its HTTP/1.0 answer:" \
         ${B_STRAY:+"(b) $B_STRAY"} ${A_STRAY:+"(a) $A_STRAY"}; fi

# ─── (c): HTTP/1.0 with keep-alive stays reusable ───────────────────────────
timeout 20 python3 "$SOCKETLEY_TMPD/cl.py" keepalive "$PX" >"$SOCKETLEY_TMPD/c.out" 2>&1
C1=$(status_of c1 "$SOCKETLEY_TMPD/c.out"); C2=$(status_of c2 "$SOCKETLEY_TMPD/c.out")
C1C=$(conn_of c1 "$SOCKETLEY_TMPD/c.out"); C2C=$(conn_of c2 "$SOCKETLEY_TMPD/c.out")
echo "  (c) HTTP/1.0 keep-alive: ${C1:-none} on conn ${C1C:-?}, then ${C2:-none} on conn ${C2C:-?}"

if [ "$C1" = 200 ] && [ "$C2" = 200 ] && [ -n "$C1C" ] && [ "$C1C" = "$C2C" ]; then ok
else bad "(c) an HTTP/1.0 answer that says keep-alive keeps its socket" \
         "statuses ${C1:-none} then ${C2:-none}, backend connections ${C1C:-?} then ${C2C:-?}" \
         "(want 200, 200, the same)"; fi

# ─── (d): nothing left once every client has gone ───────────────────────────
BACKENDS_END=$(stat_when backend_connections 0)
if [ "$BACKENDS_END" = 0 ]; then ok
else bad "(d) no backend connection outlives the clients" "backend_connections=$BACKENDS_END"; fi

if [ "$FAIL" -gt 0 ]; then
    grep -v '\[INFO\]' "$SOCKETLEY_DLOG" 2>/dev/null | tail -8 | sed 's/^/        log: /' || true
fi

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
