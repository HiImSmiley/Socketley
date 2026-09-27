#!/usr/bin/env bash
# Integration test: a keep-alive client's backend connection stays with it
# between requests, and is let go of cleanly by every road out.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# After each response an HTTP proxy with one backend used to file the backend
# socket in the pool -- cancelling its read first when one was armed -- and
# take it out again for the next request behind a recv(MSG_PEEK) probe.  From
# a client's second answer on it now parks the socket on the client instead,
# with its read still armed, and the next request goes straight out on it
# (HAProxy's `http-reuse safe`).  So every phase below warms its connection up
# with one request first, or the socket it is about would never be parked.
#
# That moves four things off the pool's well-trodden road, and each is a way
# to be wrong that a fast benchmark never shows:
#
#   * the parked socket is noticed going away only by its armed read, and a
#     backend closing an idle connection is ordinary -- it must cost the
#     client nothing and the backend's circuit breaker nothing
#   * a backend that said `Connection: close` is not at a reusable boundary
#     however the next request arrives
#   * the client leaving is now what releases the socket, so a road out that
#     forgets it leaks one backend connection per client
#   * a pipelined request is routed from inside the response's own handler,
#     onto the socket that has just been parked, before its armed read has
#     reached the ring -- so a FIN or stray bytes already waiting there have
#     to be asked about, and a request that meets the backend's close anyway
#     is sent again on a fresh connection rather than answered 502
#
# The backend stamps its accept ordinal into every body, so which backend
# connection served a request is read off the answer rather than guessed, and
# the proxy runs with --circuit-threshold 1 so a single failure wrongly charged
# to the backend turns the next request into a 503 that cannot be missed.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   (a)  ten requests on one client connection opening more than one backend
#        connection: a park that never happens and a pool that misses
#   (a2) no parked_connections:1 while that client idles: the park not
#        happening at all -- the parent tree fails this, the pool reuses too
#   (d)  backend_connections above 0 once the client has closed: a client road
#        out that does not release its parked socket
#   (d2) no pooled_connections once it has: a release that closes the socket
#        instead of handing it to the pool, one backend connect per client
#   (b0) no parked_connections:1 while the backend's idle close is pending:
#        (b) would then be about a pooled socket and prove nothing about the
#        parked read
#   (b)  a 502/503, an error line or an open breaker after the backend closed
#        a parked idle connection: the idle EOF read as a failed exchange, or
#        not heard at all and the next request written into a dead socket;
#        B2 = 200 is the breaker's witness, since at threshold 1 a charged
#        idle close answers the next request 503.  Deleting the parked check
#        in handle_backend_read does NOT fail this: the EOF then takes the
#        ordinary road with no client attached and closes the socket just as
#        quietly -- (g) is the assertion that check answers to
#   (g)  the request after stray bytes arrived on a parked socket going out on
#        that same socket: the bytes consumed and the socket kept, which is
#        what the parked check in handle_backend_read exists to prevent
#   (c)  the request after a `Connection: close` answer sent on that socket:
#        this backend says close and then lingers without reading, so reuse
#        is a 502 after 1.5 s rather than a lucky reconnect
#   (e)  a pipelined pair answered out of order or not at all
#   (e2) the pipelined second request on a different backend connection: the
#        request routed from inside park_backend's own reset not finding the
#        socket that has just been parked
#   (h)  a pipelined pair behind a backend that closes right after answering,
#        without saying close: the second request written onto the just
#        parked socket and answered 502 -- fails on 039baf42 every time
#   (i)  a pipelined pair behind a HEAD answered with a body: the stray bytes
#        framed as the second answer; whether they share the head's read (the
#        overrun road) or arrive in the next one (the same-turn probe) is the
#        kernel's timing, so this guards both and pins neither
#   (f)  backend connections left over once every client has gone
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate kareuse

BE=$((SL_PORT_BASE+1534))
PX=$((SL_PORT_BASE+1535))
NAME=kr
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
    "$BIN" stop   "$NAME" >/dev/null 2>&1 || true
    "$BIN" remove "$NAME" >/dev/null 2>&1 || true
    [ -n "${BEPID:-}" ] && kill "$BEPID" 2>/dev/null
    [ -n "${CLPID:-}" ] && kill "$CLPID" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a keep-alive client keeps its backend connection ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  0/0 passed"; exit 0; }

# ─── the backend ────────────────────────────────────────────────────────────
cat > "$SOCKETLEY_TMPD/be.py" <<'PYEOF'
import os, socket, sys, threading, time
port, out = int(sys.argv[1]), sys.argv[2]
conns = 0
lock = threading.Lock()

def bump():
    global conns
    with lock:
        conns += 1
        n = conns
        t = out + ".tmp"
        with open(t, "w") as f:
            f.write(str(n))
        os.replace(t, out)
    return n

def respond(c, ordinal, k, target, extra=b""):
    body = ("conn=%d req=%d target=%s" % (ordinal, k, target)).encode()
    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n%s\r\n%s" % (len(body), extra, body))

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
            if target.startswith("/closehdr"):
                # Says close and lingers without reading, so a proxy that
                # reuses the socket waits on an answer that never comes.
                respond(c, ordinal, k, target, b"Connection: close\r\n")
                time.sleep(1.5)
                return
            if target.startswith("/headlate"):
                # A HEAD answer, and then the body it must not have, late.
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n")
                time.sleep(0.1)
                c.sendall(b"BODYBODYBODY")
                continue
            if target.startswith("/headbody"):
                # The same at once, as http.server's HEAD with a body does.
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n")
                c.sendall(b"BODYBODYBODY")
                continue
            respond(c, ordinal, k, target)
            if target.startswith("/closeidle"):
                # A keep-alive answer, then the backend's own idle close, late
                # enough for the test to see the socket parked first.
                time.sleep(1.0)
                return
            if target.startswith("/closenow"):
                # Closes right behind a keep-alive answer without saying so.
                return
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
with open(out, "w") as f:
    f.write("0")
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

def req(target, extra=""):
    return ("GET /kr%s HTTP/1.1\r\nHost: t\r\n%s\r\n" % (target, extra)).encode()

def read_response(s, buf, head=False):
    while b"\r\n\r\n" not in buf:
        b = s.recv(65536)
        if not b:
            raise ConnectionError("closed before an answer")
        buf += b
    head, rest = buf.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    status = lines[0].split(b" ")[1].decode("latin1")
    clen = 0
    for l in lines[1:]:
        k, _, v = l.partition(b":")
        if k.strip().lower() == b"content-length" and not head:
            clen = int(v.strip())
    while len(rest) < clen:
        b = s.recv(65536)
        if not b:
            break
        rest += b
    return status, rest[:clen].decode("latin1").replace("\n", " ").strip(), rest[clen:]

def show(label, s, buf, head=False):
    try:
        st, body, buf = read_response(s, buf, head)
        print("R %s %s %s" % (label, st, body), flush=True)
    except Exception as e:
        print("R %s ERR %s" % (label, type(e).__name__), flush=True)
    return buf

s = socket.create_connection(("127.0.0.1", port))
s.settimeout(5)
buf = b""
if mode == "seq":
    for i in range(int(sys.argv[3])):
        s.sendall(req("/ok?i=%d" % i))
        buf = show("a", s, buf)
    print("IDLE", flush=True)
    sig = sys.argv[4]
    end = time.time() + 30
    while not os.path.exists(sig) and time.time() < end:
        time.sleep(0.05)
elif mode == "closeidle":
    s.sendall(req("/ok?warm"))
    buf = show("w", s, buf)
    s.sendall(req("/closeidle"))
    buf = show("b1", s, buf)
    print("B1DONE", flush=True)
    time.sleep(1.5)
    s.sendall(req("/ok?after=idleclose"))
    buf = show("b2", s, buf)
elif mode == "closehdr":
    s.sendall(req("/ok?warm"))
    buf = show("w", s, buf)
    s.sendall(req("/closehdr"))
    buf = show("c1", s, buf)
    time.sleep(0.2)
    s.sendall(req("/ok?after=closehdr"))
    buf = show("c2", s, buf)
elif mode == "pipeline":
    s.sendall(req("/ok?warm"))
    buf = show("w", s, buf)
    s.sendall(req("/ok?p=1") + req("/ok?p=2"))
    buf = show("e1", s, buf)
    buf = show("e2", s, buf)
elif mode == "headlate":
    s.sendall(req("/ok?warm"))
    buf = show("w", s, buf)
    s.sendall(("HEAD /kr/headlate HTTP/1.1\r\nHost: t\r\n\r\n").encode())
    buf = show("g1", s, buf, head=True)
    time.sleep(0.5)
    s.sendall(req("/ok?after=headlate"))
    buf = show("g2", s, buf)
elif mode == "pipeclose":
    s.sendall(req("/ok?warm"))
    buf = show("w", s, buf)
    s.sendall(req("/closenow") + req("/ok?after=closenow"))
    buf = show("h1", s, buf)
    buf = show("h2", s, buf)
elif mode == "pipehead":
    s.sendall(req("/ok?warm"))
    buf = show("w", s, buf)
    s.sendall(("HEAD /kr/headbody HTTP/1.1\r\nHost: t\r\n\r\n").encode() +
              req("/ok?after=headbody"))
    buf = show("i1", s, buf, head=True)
    buf = show("i2", s, buf)
s.close()
print("DONE", flush=True)
PYEOF

python3 "$SOCKETLEY_TMPD/be.py" "$BE" "$SOCKETLEY_TMPD/conns" \
    >/dev/null 2>"$SOCKETLEY_TMPD/be.log" &
BEPID=$!
for _ in $(seq 1 60); do grep -q "be up" "$SOCKETLEY_TMPD/be.log" 2>/dev/null && break; sleep 0.1; done
if ! grep -q "be up" "$SOCKETLEY_TMPD/be.log" 2>/dev/null; then
    bad "the backend came up" "$(tail -3 "$SOCKETLEY_TMPD/be.log" 2>/dev/null | tr '\n' ' ')"
    echo "  $PASS/$TOTAL passed"; exit 1
fi

daemon_start "$BIN"
"$BIN" create proxy "$NAME" -p "$PX" --backend "127.0.0.1:$BE" --protocol http \
    --circuit-threshold 1 >/dev/null 2>&1
"$BIN" start "$NAME" >/dev/null 2>&1
# A connection opened and closed without a request, so no backend connection
# is made before the counts below start.
for _ in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/"$PX") 2>/dev/null && break; sleep 0.1; done

conns()   { cat "$SOCKETLEY_TMPD/conns" 2>/dev/null || echo 0; }
stat_of() { "$BIN" stats "$NAME" 2>/dev/null | awk -F: -v k="$1" '$1 == k { print $2 + 0; exit }'; }
conn_of() { sed -n "s/^R $1 200 conn=\([0-9]*\) .*/\1/p" "$2" | head -1; }
status_of() { awk -v l="$1" '$1 == "R" && $2 == l { print $3; exit }' "$2"; }
# Waits for backend_connections to reach 0, printing the last reading.
wait_backends_gone() {
    local v=""
    for _ in $(seq 1 50); do
        v=$(stat_of backend_connections)
        [ "${v:-x}" = 0 ] && break
        sleep 0.1
    done
    echo "${v:-none}"
}

# ─── (a) (a2) (d) (d2): one client, many requests, then it leaves ───────────
A0=$(conns)
SIG="$SOCKETLEY_TMPD/close_a"
python3 "$SOCKETLEY_TMPD/cl.py" seq "$PX" "$N" "$SIG" >"$SOCKETLEY_TMPD/a.out" 2>&1 &
CLPID=$!
for _ in $(seq 1 100); do grep -q '^IDLE' "$SOCKETLEY_TMPD/a.out" 2>/dev/null && break; sleep 0.1; done
A1=$(conns)
PARKED_IDLE=$(stat_of parked_connections)
BACKENDS_IDLE=$(stat_of backend_connections)
touch "$SIG"
wait "$CLPID" 2>/dev/null; CLPID=""
AFTER_CLOSE=$(wait_backends_gone)
POOLED_AFTER=$(stat_of pooled_connections)

A_OK=$(grep -c '^R a 200 ' "$SOCKETLEY_TMPD/a.out")
A_CONNS=$(sed -n 's/^R a 200 conn=\([0-9]*\) .*/\1/p' "$SOCKETLEY_TMPD/a.out" | sort -u | wc -l)
echo "  (a) $A_OK/$N answered, $A_CONNS distinct backend connection(s), $((A1 - A0)) accepted;" \
     "idle: parked=${PARKED_IDLE:-none} backends=${BACKENDS_IDLE:-none};" \
     "after close: backends=$AFTER_CLOSE pooled=${POOLED_AFTER:-none}"

if [ "$A_OK" -eq "$N" ] && [ "$A_CONNS" -eq 1 ] && [ "$((A1 - A0))" -eq 1 ]; then ok
else bad "(a) $N keep-alive requests share one backend connection" \
         "$A_OK of $N answered 200, over $A_CONNS backend connection(s), $((A1 - A0)) accepted" \
         "$(grep -v '^R a 200 ' "$SOCKETLEY_TMPD/a.out" | head -3 | tr '\n' ' ')"; fi

if [ "${PARKED_IDLE:-0}" = 1 ] && [ "${BACKENDS_IDLE:-0}" = 1 ]; then ok
else bad "(a2) the idle client's backend connection is parked on it" \
         "stats while the client idled: parked_connections=${PARKED_IDLE:-absent}," \
         "backend_connections=${BACKENDS_IDLE:-absent}, want 1 and 1"; fi

if [ "$AFTER_CLOSE" = 0 ]; then ok
else bad "(d) the parked backend is released when its client closes" \
         "backend_connections=$AFTER_CLOSE five seconds after the client closed"; fi

if [ "${POOLED_AFTER:-0}" -ge 1 ]; then ok
else bad "(d2) the released backend goes to the pool" \
         "pooled_connections=${POOLED_AFTER:-absent} after the client closed," \
         "so the next client pays a connect the parked socket could have saved"; fi

# ─── (b): the backend closes a parked idle connection ───────────────────────
LOG_OFF=$(wc -c <"$SOCKETLEY_DLOG" 2>/dev/null || echo 0)
timeout 20 python3 "$SOCKETLEY_TMPD/cl.py" closeidle "$PX" >"$SOCKETLEY_TMPD/b.out" 2>&1 &
CLPID=$!
for _ in $(seq 1 100); do grep -q '^B1DONE' "$SOCKETLEY_TMPD/b.out" 2>/dev/null && break; sleep 0.02; done
# The backend closes a second after answering, so this reads the socket while
# it is still parked and idle.
B_PARKED=$(stat_of parked_connections)
wait "$CLPID" 2>/dev/null; CLPID=""
B1=$(status_of b1 "$SOCKETLEY_TMPD/b.out"); B2=$(status_of b2 "$SOCKETLEY_TMPD/b.out")
B1C=$(conn_of b1 "$SOCKETLEY_TMPD/b.out"); B2C=$(conn_of b2 "$SOCKETLEY_TMPD/b.out")
B_LOG=$(tail -c +"$((LOG_OFF + 1))" "$SOCKETLEY_DLOG" 2>/dev/null | grep -E '\[(WARN|ERROR)\]' | head -3)
B_CIRCUIT=$("$BIN" stats "$NAME" 2>/dev/null | grep -E '_circuit:|^open_circuits:' | head -2 | tr '\n' ' ')
echo "  (b) before the idle close: ${B1:-none} on conn ${B1C:-?}, parked=${B_PARKED:-none};" \
     "after: ${B2:-none} on conn ${B2C:-?}"

if [ "${B_PARKED:-0}" = 1 ]; then ok
else bad "(b0) the socket the backend is about to close is parked" \
         "parked_connections=${B_PARKED:-absent} between the answer and the backend's close"; fi

if [ "$B1" = 200 ] && [ "$B2" = 200 ] && [ -n "$B1C" ] && [ -n "$B2C" ] && [ "$B1C" != "$B2C" ] &&
   [ -z "$B_LOG" ] && [ -z "$B_CIRCUIT" ]; then ok
else bad "(b) a backend closing a parked connection costs the next request nothing" \
         "statuses ${B1:-none} then ${B2:-none}, backend connections ${B1C:-?} then ${B2C:-?} (want 200, 200, two different)" \
         "log: ${B_LOG:-none}" "breaker: ${B_CIRCUIT:-closed}"; fi

# ─── (c): a backend that says Connection: close ─────────────────────────────
timeout 20 python3 "$SOCKETLEY_TMPD/cl.py" closehdr "$PX" >"$SOCKETLEY_TMPD/c.out" 2>&1
C1=$(status_of c1 "$SOCKETLEY_TMPD/c.out"); C2=$(status_of c2 "$SOCKETLEY_TMPD/c.out")
C1C=$(conn_of c1 "$SOCKETLEY_TMPD/c.out"); C2C=$(conn_of c2 "$SOCKETLEY_TMPD/c.out")
echo "  (c) the close answer: ${C1:-none} on conn ${C1C:-?}; the next: ${C2:-none} on conn ${C2C:-?}"

if [ "$C1" = 200 ] && [ "$C2" = 200 ] && [ -n "$C1C" ] && [ -n "$C2C" ] && [ "$C1C" != "$C2C" ]; then ok
else bad "(c) a backend connection that answered Connection: close is not reused" \
         "statuses ${C1:-none} then ${C2:-none}, backend connections ${C1C:-?} then ${C2C:-?} (want 200, 200, two different)"; fi

# ─── (e) (e2): a pipelined pair ─────────────────────────────────────────────
timeout 20 python3 "$SOCKETLEY_TMPD/cl.py" pipeline "$PX" >"$SOCKETLEY_TMPD/e.out" 2>&1
E1=$(sed -n 's/^R e1 200 .*target=\([^ ]*\).*/\1/p' "$SOCKETLEY_TMPD/e.out")
E2=$(sed -n 's/^R e2 200 .*target=\([^ ]*\).*/\1/p' "$SOCKETLEY_TMPD/e.out")
E1C=$(conn_of e1 "$SOCKETLEY_TMPD/e.out"); E2C=$(conn_of e2 "$SOCKETLEY_TMPD/e.out")
echo "  (e) pipelined: ${E1:-none} on conn ${E1C:-?}, then ${E2:-none} on conn ${E2C:-?}"

if [ "$E1" = "/ok?p=1" ] && [ "$E2" = "/ok?p=2" ]; then ok
else bad "(e) a pipelined pair is answered in order" \
         "first answer for '${E1:-none}', second for '${E2:-none}'" \
         "$(grep '^R e' "$SOCKETLEY_TMPD/e.out" | head -2 | tr '\n' ' ')"; fi

if [ -n "$E1C" ] && [ "$E1C" = "$E2C" ]; then ok
else bad "(e2) the pipelined second request goes out on the parked connection" \
         "backend connections ${E1C:-?} then ${E2C:-?}"; fi

# ─── (g): stray bytes on a parked socket ────────────────────────────────────
timeout 20 python3 "$SOCKETLEY_TMPD/cl.py" headlate "$PX" >"$SOCKETLEY_TMPD/g.out" 2>&1
G1=$(status_of g1 "$SOCKETLEY_TMPD/g.out"); G2=$(status_of g2 "$SOCKETLEY_TMPD/g.out")
W_G=$(conn_of w "$SOCKETLEY_TMPD/g.out"); G2C=$(conn_of g2 "$SOCKETLEY_TMPD/g.out")
echo "  (g) HEAD with a late body: ${G1:-none} (warm-up on conn ${W_G:-?}); the next: ${G2:-none} on conn ${G2C:-?}"

# The HEAD went out on the warm-up's socket, which the pool hands straight
# back, so that is the socket the stray body landed on.
if [ "$G1" = 200 ] && [ "$G2" = 200 ] && [ -n "$W_G" ] && [ -n "$G2C" ] && [ "$W_G" != "$G2C" ]; then ok
else bad "(g) a parked socket that received stray bytes is not reused" \
         "HEAD ${G1:-none}, then ${G2:-none} on conn ${G2C:-?} against the HEAD's conn ${W_G:-?}" \
         "(want 200, 200, two different)"; fi

# ─── (h): a pipelined pair behind a backend that closes after answering ─────
timeout 20 python3 "$SOCKETLEY_TMPD/cl.py" pipeclose "$PX" >"$SOCKETLEY_TMPD/h.out" 2>&1
H1=$(sed -n 's/^R h1 200 .*target=\([^ ]*\).*/\1/p' "$SOCKETLEY_TMPD/h.out")
H2=$(sed -n 's/^R h2 200 .*target=\([^ ]*\).*/\1/p' "$SOCKETLEY_TMPD/h.out")
echo "  (h) pipelined behind a silent close: '${H1:-none}' then '${H2:-none}'"

if [ "$H1" = "/closenow" ] && [ "$H2" = "/ok?after=closenow" ]; then ok
else bad "(h) a pipelined request behind a backend's unannounced close is answered" \
         "answers for '${H1:-none}' and '${H2:-none}'" \
         "$(grep '^R h' "$SOCKETLEY_TMPD/h.out" | head -2 | tr '\n' ' ')"; fi

# ─── (i): a pipelined pair behind a HEAD answered with a body ───────────────
timeout 20 python3 "$SOCKETLEY_TMPD/cl.py" pipehead "$PX" >"$SOCKETLEY_TMPD/i.out" 2>&1
I1=$(status_of i1 "$SOCKETLEY_TMPD/i.out")
I2=$(sed -n 's/^R i2 200 .*target=\([^ ]*\).*/\1/p' "$SOCKETLEY_TMPD/i.out")
echo "  (i) pipelined behind a HEAD with a body: ${I1:-none}, then '${I2:-none}'"

if [ "$I1" = 200 ] && [ "$I2" = "/ok?after=headbody" ]; then ok
else bad "(i) a pipelined request behind a HEAD answered with a body gets its own answer" \
         "HEAD ${I1:-none}, then an answer for '${I2:-none}'" \
         "$(grep '^R i' "$SOCKETLEY_TMPD/i.out" | head -2 | tr '\n' ' ')"; fi

# ─── (f): nothing left once every client has gone ───────────────────────────
FINAL=$(wait_backends_gone)
if [ "$FINAL" = 0 ]; then ok
else bad "(f) no backend connection outlives the clients" "backend_connections=$FINAL"; fi

if [ "$FAIL" -gt 0 ]; then
    grep -v '\[INFO\]' "$SOCKETLEY_DLOG" 2>/dev/null | tail -8 | sed 's/^/        log: /' || true
fi

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
