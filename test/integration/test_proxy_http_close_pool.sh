#!/usr/bin/env bash
# Integration test: a client that says `Connection: close` must not cost a
# backend connection.
#
# ─── WHAT WAS WRONG ─────────────────────────────────────────────────────────
#
# `Connection` is hop-by-hop.  A client sending `Connection: close` is talking
# about its own connection to the proxy and says nothing whatever about the
# proxy's connection to the backend.  The proxy treated it as though it did, in
# two places at once: rewrite_http_request copied the token onto the request it
# wrote upstream, so the backend closed and its socket was then unpoolable by
# its own instruction; and handle_backend_read refused the pool detach outright
# for such a client.  Either alone is a backend connection per client request.
#
# Measured on this tree, 12,000 requests at concurrency 8 through one `--http`
# backend, a fresh daemon per arm: 16-18 backend sockets with a keep-alive
# client, 11,992 with a connection-per-request one, and 9,593 of those still
# sitting in TIME-WAIT the instant the run ended.  This box has 28,231 ephemeral
# ports and the run does 24,000 requests a second, so that shape empties the
# range in about a second and the proxy then cannot reach its backend at all.
#
# ─── WHAT IS ASSERTED, AND WHY IT IS THE SOCKET COUNT ───────────────────────
#
# The number of backend connections, counted by the backend itself, and never
# the request rate.  A rate assertion cannot tell a pool from a fast handshake:
# on loopback a fresh connect costs tens of microseconds, so a build that pools
# nothing still answers quickly and passes any threshold loose enough not to
# flake.  The backend here stamps its own connection ordinal into every response
# body, so each request carries the evidence of which backend socket served it,
# and the count is read out of the answers rather than out of `ss`.
#
# Against the broken build every request comes back stamped with a new ordinal
# and the accept count equals the request count.  Watched red there: 6 backend
# connections for 6 requests, ordinals 1..6.
#
# The third proxy is the control that keeps the fix from becoming a sweep.  Its
# backend answers `Connection: close` on every response, and that socket must
# still NOT be pooled — the backend's own token is a fact about the backend and
# is the one of the three refusals that was never the bug.  A build that removed
# that refusal too passes every other assertion in this file and fails this one.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# shellcheck source=lib_create.sh
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

# Own daemon, socket and state directory — the shared one auto-restarts a
# crashed runtime and would hide it, and a leftover runtime from an earlier run
# answers on the port before this test creates its own.
TMPDIR_T=$(mktemp -d /tmp/socketley-closepool-XXXXXX)
export HOME="$TMPDIR_T/home"
export SOCKETLEY_SOCKET="$TMPDIR_T/daemon.sock"
mkdir -p "$HOME"
DPID=""
BEPID=""
BECPID=""

BE_PORT=$((SL_PORT_BASE+424))       # backend answering keep-alive
BEC_PORT=$((SL_PORT_BASE+425))      # backend answering Connection: close
PX_PORT=$((SL_PORT_BASE+426))
PXC_PORT=$((SL_PORT_BASE+427))
PX_NAME=closepool_px
PXC_NAME=closepool_cx
NREQ=6
OUT="$TMPDIR_T/client.out"
OUTC="$TMPDIR_T/client_ctl.out"
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    [ -n "$BEPID" ]  && kill "$BEPID"  2>/dev/null || true
    [ -n "$BECPID" ] && kill "$BECPID" 2>/dev/null || true
    if [ -n "$DPID" ]; then
        kill "$DPID" 2>/dev/null || true
        for _ in $(seq 1 50); do
            kill -0 "$DPID" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
    # Matched by exact process name and then by this run's own socket path.
    # `pgrep -f` also matches the shell that merely carries the string on its
    # command line — including this one — and the environ test cannot rule that
    # out, because such a shell exports the very variable being matched.
    for p in $(pgrep -x socketley 2>/dev/null || true); do
        case "$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null)" in
            *" daemon "*|*" daemon") ;;
            *) continue ;;
        esac
        if grep -qx "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" \
                < <(tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null); then
            kill -9 "$p" 2>/dev/null || true
        fi
    done
    rm -rf "$TMPDIR_T"
}
trap cleanup EXIT

echo "=== Integration: a close-mode client must not cost a backend connection ==="

# ─── The backend ────────────────────────────────────────────────────────────
#
# An HTTP/1.1 origin that stamps its own accepted-connection ordinal into every
# response body, alongside the marker taken from the request path.  The ordinal
# is what makes the pool visible from the client side: two requests answered
# with the same ordinal were carried by one backend socket, and no build can
# produce that by being fast.
#
# It answers `Connection: keep-alive` (or `close`, in the control instance) and
# always sends a Content-Length, because a response whose framing the proxy
# cannot resolve is refused by the pool for that reason instead and the test
# would then be measuring the wrong refusal.
cat > "$TMPDIR_T/backend.py" <<'PYEOF'
import socket, sys, threading

port = int(sys.argv[1])
mode = sys.argv[2]              # "keepalive" | "close"
countfile = sys.argv[3]

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(64)

lock = threading.Lock()
accepted = 0


def handle(c, ordinal):
    c.settimeout(15)
    buf = b""
    try:
        while True:
            while b"\r\n\r\n" not in buf:
                chunk = c.recv(4096)
                if not chunk:
                    return
                buf += chunk
            head, buf = buf.split(b"\r\n\r\n", 1)
            req_line = head.split(b"\r\n", 1)[0].split(b" ")
            path = req_line[1] if len(req_line) > 1 else b"/"
            body = b"conn=%d;%s" % (ordinal, path.lstrip(b"/"))
            token = b"keep-alive" if mode == "keepalive" else b"close"
            c.sendall(b"HTTP/1.1 200 OK\r\n"
                      b"Content-Type: text/plain\r\n"
                      b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                      b"Connection: " + token + b"\r\n"
                      b"\r\n" + body)
            if mode != "keepalive":
                return
    except OSError:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


while True:
    try:
        conn, _ = srv.accept()
    except OSError:
        break
    with lock:
        accepted += 1
        n = accepted
        # Rewritten in full on every accept and flushed, so the file always
        # holds a complete number: a reader that catches it mid-write would
        # otherwise read a truncated count and call it a pass.
        with open(countfile, "w") as f:
            f.write("%d\n" % accepted)
            f.flush()
    threading.Thread(target=handle, args=(conn, n), daemon=True).start()
PYEOF

python3 "$TMPDIR_T/backend.py" "$BE_PORT"  keepalive "$TMPDIR_T/accepts.ka" \
    >"$TMPDIR_T/backend.log" 2>&1 &
BEPID=$!
python3 "$TMPDIR_T/backend.py" "$BEC_PORT" close     "$TMPDIR_T/accepts.cl" \
    >"$TMPDIR_T/backend_ctl.log" 2>&1 &
BECPID=$!

cat > "$TMPDIR_T/waitsock.py" <<'PYEOF'
import socket, sys, time

path = sys.argv[1]
end = time.time() + float(sys.argv[2])
while time.time() < end:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(0.4)
        s.connect(path)
        s.close()
        sys.exit(0)
    except OSError:
        time.sleep(0.02)
    finally:
        try:
            s.close()
        except OSError:
            pass
sys.exit(1)
PYEOF

"$BIN" daemon >"$TMPDIR_T/daemon.log" 2>&1 &
DPID=$!
python3 "$TMPDIR_T/waitsock.py" "$SOCKETLEY_SOCKET" 8 >/dev/null 2>&1 || true

# A zombie $DPID has an empty /proc/<pid>/fd while an orphaned daemon serves the
# run, and `kill -0` cannot tell the two apart.  The descriptor table can.
TOTAL=$((TOTAL+1))
NFD=$(ls -1 "/proc/$DPID/fd" 2>/dev/null | wc -l || true)
case "$(printf '%s' "$NFD" | tr -d '[:space:]')" in
    ''|0|*[!0-9]*)
        FAIL=$((FAIL+1))
        echo "  FAIL [setup]: pid $DPID is not a live process — the daemon that answers"
        echo "        is not the one this test launched, and this run measures the wrong process"
        ;;
    *) PASS=$((PASS+1)) ;;
esac

for _ in $(seq 1 50); do nc -z 127.0.0.1 "$BE_PORT" 2>/dev/null && break; sleep 0.1; done
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$BEC_PORT" 2>/dev/null && break; sleep 0.1; done

TOTAL=$((TOTAL+1))
if nc -z 127.0.0.1 "$BE_PORT" 2>/dev/null && nc -z 127.0.0.1 "$BEC_PORT" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: an HTTP backend never came up ($BE_PORT / $BEC_PORT)"
fi

create_ok "proxy created" "$BIN" create proxy "$PX_NAME" -p "$PX_PORT" \
    --backend "127.0.0.1:$BE_PORT" --protocol http -s
create_ok "control proxy created" "$BIN" create proxy "$PXC_NAME" -p "$PXC_PORT" \
    --backend "127.0.0.1:$BEC_PORT" --protocol http -s

# A real request through each proxy, not an accepted connection and a guess.
# These land on the backend and are counted, so the counts are read AFTER this
# point rather than from zero — see the baselines below.
ready_http 127.0.0.1 "$PX_PORT"  "/$PX_NAME/ready"  20 || true
ready_http 127.0.0.1 "$PXC_PORT" "/$PXC_NAME/ready" 20 || true

TOTAL=$((TOTAL+1))
if "$BIN" stats "$PX_NAME" >/dev/null 2>&1 && "$BIN" stats "$PXC_NAME" >/dev/null 2>&1; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: a proxy runtime is not up — everything below is meaningless"
fi

read_count() { tr -dc '0-9' <"$1" 2>/dev/null || true; }
KA_BASE=$(read_count "$TMPDIR_T/accepts.ka"); KA_BASE=${KA_BASE:-0}
CL_BASE=$(read_count "$TMPDIR_T/accepts.cl"); CL_BASE=${CL_BASE:-0}

# ─── The client ─────────────────────────────────────────────────────────────
#
# One fresh TCP connection per request, each carrying `Connection: close`, which
# is what curl, wget, every health checker and every `requests` call without a
# Session does.  Sequential and spaced, because the question is whether the
# backend socket comes BACK — a burst would open several legitimately and could
# not distinguish "pooled" from "not yet returned".
cat > "$TMPDIR_T/client.py" <<'PYEOF'
import socket, sys, time

port = int(sys.argv[1])
name = sys.argv[2]
count = int(sys.argv[3])


def read_response(s):
    buf = b""
    while b"\r\n\r\n" not in buf:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            return ("TIMEOUT-before-headers", "")
        except OSError as e:
            return ("RESET-before-headers:%s" % type(e).__name__, "")
        if not chunk:
            return ("EOF-before-headers", "")
        buf += chunk
    head, body = buf.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    clen = None
    for line in lines[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                clen = int(line.split(b":", 1)[1].strip())
            except ValueError:
                return ("BAD-CONTENT-LENGTH", "")
    if clen is None:
        return ("NO-CONTENT-LENGTH", "")
    while len(body) < clen:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            return ("TIMEOUT-mid-body", "")
        except OSError as e:
            return ("RESET-mid-body:%s" % type(e).__name__, "")
        if not chunk:
            return ("EOF-mid-body", "")
        body += chunk
    if b" 200 " not in lines[0]:
        return ("STATUS:%s" % lines[0].decode("latin1", "replace"), "")
    return ("OK", body[:clen].decode("latin1", "replace"))


ok = 0
for i in range(1, count + 1):
    marker = "closepool-marker-%d" % i
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=4)
    except OSError as e:
        print("RESP %d CONNECT-FAILED:%s" % (i, type(e).__name__))
        break
    s.settimeout(4)
    req = ("GET /%s/%s HTTP/1.1\r\n"
           "Host: 127.0.0.1:%d\r\n"
           "Connection: close\r\n"
           "\r\n" % (name, marker, port))
    try:
        s.sendall(req.encode())
    except OSError as e:
        print("RESP %d SEND-FAILED:%s" % (i, type(e).__name__))
        s.close()
        break
    status, body = read_response(s)
    if status != "OK":
        print("RESP %d %s" % (i, status))
        s.close()
        break
    if ";" not in body:
        print("RESP %d UNSTAMPED-BODY got=%r" % (i, body[:60]))
        s.close()
        break
    ordinal, got_marker = body.split(";", 1)
    if got_marker != marker:
        print("RESP %d WRONG-BODY want=%r got=%r" % (i, marker, got_marker[:60]))
        s.close()
        break
    print("RESP %d OK %s" % (i, ordinal))
    ok += 1
    # The client asked the proxy to close, so the proxy must close.  A build
    # that pools the backend and then forgets the client would leave this
    # socket open for --idle-timeout with nothing to answer it.
    try:
        tail = s.recv(64)
        print("EOF %d %s" % (i, "YES" if tail == b"" else "NO"))
    except socket.timeout:
        print("EOF %d NO" % i)
    except OSError:
        print("EOF %d YES" % i)
    try:
        s.close()
    except OSError:
        pass
    time.sleep(0.05)

print("DONE %d/%d" % (ok, count))
PYEOF

python3 "$TMPDIR_T/client.py" "$PX_PORT"  "$PX_NAME"  "$NREQ" >"$OUT"  2>&1 || true
python3 "$TMPDIR_T/client.py" "$PXC_PORT" "$PXC_NAME" "$NREQ" >"$OUTC" 2>&1 || true

# Give the last detach its completion before the counts are read.
sleep 0.5

KA_NOW=$(read_count "$TMPDIR_T/accepts.ka"); KA_NOW=${KA_NOW:-0}
CL_NOW=$(read_count "$TMPDIR_T/accepts.cl"); CL_NOW=${CL_NOW:-0}
KA_NEW=$((KA_NOW - KA_BASE))
CL_NEW=$((CL_NOW - CL_BASE))

# ─── Assertions ─────────────────────────────────────────────────────────────

# The harness has to have reached its last line.  Without this an aborted run
# shows up only as a pile of per-request failures, and a check phrased as
# "compare what we read" would have nothing to compare and pass.
TOTAL=$((TOTAL+1))
if grep -q '^DONE ' "$OUT" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [harness ran]: the client produced no DONE line; raw output:"
    grep -v '^$' "$OUT" 2>/dev/null | head -5 | sed 's/^/        /' || true
fi

TOTAL=$((TOTAL+1))
if grep -qx "DONE $NREQ/$NREQ" "$OUT" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [all $NREQ close-mode requests answered]: $(grep '^DONE ' "$OUT" 2>/dev/null | head -1 || echo 'no DONE line')"
    grep '^RESP ' "$OUT" 2>/dev/null | sed 's/^/        /' || true
fi

# ── the assertion this file exists for ──
#
# $NREQ requests, each on its own client connection.  A pooling proxy serves all
# of them on the socket the readiness probe already left in the pool and opens
# none; the broken build opened $NREQ.  Counted from a baseline taken after that
# probe, so zero is the expected value and not an absence of traffic — that the
# requests happened at all is asserted separately, above and below, and both of
# those checks fail outright if they did not.
#
# 2 rather than 0 as the ceiling because the detach is asynchronous: the socket
# goes back to the pool on the completion of a cancelled read, and a request
# arriving inside that window legitimately opens one of its own.  Measured over
# nine runs on the fixed build the count was 0 every time; the ceiling is
# headroom, and it is still four short of the defect, which produced 6 of 6.
TOTAL=$((TOTAL+1))
if [ "$KA_NEW" -le 2 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [backend connections for $NREQ close-mode requests]: got $KA_NEW, want 0..2"
    echo "        a client's Connection: close is hop-by-hop and must not reach the backend leg"
fi

# The same fact read off the answers instead of off the backend's counter, so a
# backend that miscounted cannot make this pass on its own.  Every response must
# carry the ordinal of the same backend socket.
TOTAL=$((TOTAL+1))
ORDINALS=$(grep -oE '^RESP [0-9]+ OK conn=[0-9]+' "$OUT" 2>/dev/null | grep -oE 'conn=[0-9]+' | sort -u | tr '\n' ' ' || true)
NORD=$(printf '%s\n' $ORDINALS | grep -c 'conn=' || true)
if [ "${NORD:-0}" -ge 1 ] && [ "${NORD:-0}" -le 2 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [distinct backend sockets seen by the client]: $NORD ($ORDINALS)"
    echo "        each request was carried by a backend connection of its own"
fi

# The client asked for close and must get it.  Written as the guard against
# trading a backend leak for a client leak, and it turned out to discriminate on
# its own: on the broken build 0 of 6 saw EOF.  Refusing the detach meant
# reset_client_for_next_request was never reached, so nothing ever closed the
# client either — it was answered in full and then held, with the backend socket
# and the splice pipes behind it, until the runtime stopped.  Both halves of
# that are the same missing call.
TOTAL=$((TOTAL+1))
NEOF=$(grep -c '^EOF [0-9]* YES$' "$OUT" 2>/dev/null || true)
if [ "${NEOF:-0}" -eq "$NREQ" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [proxy closed the client connection]: $NEOF of $NREQ saw EOF"
    grep '^EOF ' "$OUT" 2>/dev/null | sed 's/^/        /' || true
fi

# ── the control ──
#
# The backend behind $PXC_NAME answers `Connection: close`.  That token IS about
# the backend socket, so it still forbids pooling and every request must cost a
# new backend connection.  A build that swept all three refusals away instead of
# the one that was wrong passes everything above and fails here.
TOTAL=$((TOTAL+1))
if grep -qx "DONE $NREQ/$NREQ" "$OUTC" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [control: all $NREQ requests answered]: $(grep '^DONE ' "$OUTC" 2>/dev/null | head -1 || echo 'no DONE line')"
fi

TOTAL=$((TOTAL+1))
if [ "$CL_NEW" -eq "$NREQ" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [control: backend that says Connection: close is not pooled]: got $CL_NEW connections for $NREQ requests, want $NREQ"
fi

# Detaching a backend must not take the runtime with it.
TOTAL=$((TOTAL+1))
if "$BIN" stats "$PX_NAME" >/dev/null 2>&1 && "$BIN" stats "$PXC_NAME" >/dev/null 2>&1; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [runtime alive]: a proxy did not survive the close-mode session"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
echo "  backend connections: $KA_NEW for $NREQ pooled-backend requests, $CL_NEW for $NREQ control requests"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
