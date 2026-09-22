#!/usr/bin/env bash
# Only the first message in the buffer is validated while everything past the
# first blank line was appended verbatim, so a second request carrying both
# Content-Length and Transfer-Encoding reached the backend untouched --
# asserted by grepping what the backend actually read for a header no
# legitimate request here carries, with phase 2 pipelining two clean requests
# because a fix that closed the hole by discarding pipelined bytes passes phase
# 1.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# shellcheck source=lib_create.sh
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

# Own daemon, socket and state directory: against the shared one this test does
# not discriminate — auto-restart hides a crash, and a leftover runtime from an
# earlier run answers on the port before this test ever creates its own.
TMPDIR_T=$(mktemp -d /tmp/socketley-smug-XXXXXX)
export HOME="$TMPDIR_T/home"
export SOCKETLEY_SOCKET="$TMPDIR_T/daemon.sock"
mkdir -p "$HOME"
DPID=""
BEPID=""

BE_PORT=$((SL_PORT_BASE+440))
PX_PORT=$((SL_PORT_BASE+441))
PX_NAME=smug_px
RAW="$TMPDIR_T/backend.raw"
OUT="$TMPDIR_T/client.out"
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null || true
    if [ -n "$DPID" ]; then
        kill "$DPID" 2>/dev/null || true
        for _ in $(seq 1 50); do
            kill -0 "$DPID" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
    # Killed by socket as well as by pid and matched on exact process name,
    # because a CLI command against an absent daemon starts a detached one that
    # would hold this test's ports, and a `pgrep -f` pattern also matches the
    # shell doing the matching.
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

echo "=== Integration: a pipelined request is checked, not smuggled ==="

# A backend that answers with Content-Length and keep-alive so the proxy
# reaches its pooling path, echoes the path as the body, and appends every byte
# it reads to the capture the smuggling assertions look at.
python3 - "$BE_PORT" "$RAW" >"$TMPDIR_T/backend.log" 2>&1 <<'PYEOF' &
import socket, sys, threading

port = int(sys.argv[1])
raw_path = sys.argv[2]
raw_lock = threading.Lock()

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(64)


def record(chunk):
    with raw_lock:
        with open(raw_path, "ab") as f:
            f.write(chunk)
            f.flush()


def handle(c):
    c.settimeout(15)
    buf = b""
    try:
        while True:
            while b"\r\n\r\n" not in buf:
                chunk = c.recv(4096)
                if not chunk:
                    return
                record(chunk)
                buf += chunk
            head, buf = buf.split(b"\r\n\r\n", 1)
            req_line = head.split(b"\r\n", 1)[0].split(b" ")
            path = req_line[1] if len(req_line) > 1 else b"/"
            body = path.lstrip(b"/")
            # A declared body is consumed so the next framing starts in the
            # right place; this backend is deliberately ordinary.
            clen = 0
            for line in head.split(b"\r\n")[1:]:
                if line.lower().startswith(b"content-length:"):
                    try:
                        clen = int(line.split(b":", 1)[1].strip())
                    except ValueError:
                        clen = 0
            while len(buf) < clen:
                chunk = c.recv(4096)
                if not chunk:
                    return
                record(chunk)
                buf += chunk
            buf = buf[clen:]
            c.sendall(b"HTTP/1.1 200 OK\r\n"
                      b"Content-Type: text/plain\r\n"
                      b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                      b"Connection: keep-alive\r\n"
                      b"\r\n" + body)
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
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PYEOF
BEPID=$!

# Wait on the daemon's IPC socket directly and never by polling with a CLI
# command, which auto-starts a second orphaned daemon that survives cleanup.
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

SOCKETLEY_DLOG="$TMPDIR_T/daemon.log"
"$BIN" daemon >"$TMPDIR_T/daemon.log" 2>&1 &
DPID=$!
python3 "$TMPDIR_T/waitsock.py" "$SOCKETLEY_SOCKET" 8 >/dev/null 2>&1 || true

# The daemon that answers is the one this test launched, since a zombie $DPID
# has an empty /proc/<pid>/fd that `kill -0` cannot tell from a live process.
TOTAL=$((TOTAL+1))
# `|| true` because under pipefail the failing `ls` in exactly the case this
# check exists for would kill the script with no output at all.
NFD=$(ls -1 "/proc/$DPID/fd" 2>/dev/null | wc -l || true)
case "$(printf '%s' "$NFD" | tr -d '[:space:]')" in
    ''|0|*[!0-9]*)
        FAIL=$((FAIL+1))
        echo "  FAIL [setup]: pid $DPID is not a live process — the daemon that answers"
        echo "        is not the one this test launched, and this run measures the wrong process"
        ;;
    *) PASS=$((PASS+1)) ;;
esac

TOTAL=$((TOTAL+1))
if ready_tcp 127.0.0.1 "$BE_PORT" 10; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the HTTP backend never came up on $BE_PORT"
fi

create_ok "proxy created" "$BIN" create proxy "$PX_NAME" -p "$PX_PORT" \
    --backend "127.0.0.1:$BE_PORT" --protocol http -s
# A real request through the proxy, not an accepted connection and a guess.
ready_http 127.0.0.1 "$PX_PORT" "/$PX_NAME/ready" 20 || true

TOTAL=$((TOTAL+1))
if "$BIN" stats "$PX_NAME" >/dev/null 2>&1; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the proxy runtime is not up — everything below is meaningless"
fi

# Everything the backend read before the smuggling attempt, which is not
# assumed empty because the readiness probe has already been through it.
BEFORE_BYTES=$(wc -c <"$RAW" 2>/dev/null || echo 0)

python3 - "$PX_PORT" "$PX_NAME" >"$OUT" 2>&1 <<'PYEOF' || true
import socket, sys, time

port = int(sys.argv[1])
name = sys.argv[2]


def read_response(s, rest=b""):
    """(status, body, rest).  Every way of not getting an answer has its own
    status, so a response that could not be read can never be mistaken for an
    empty one that happened to match.

    `rest` is what the last call over-read and this one must start from.  A
    reader that dropped it passed whenever the two answers to a pipelined pair
    arrived in separate reads and timed out whenever they arrived in one --
    which a proxy is free to do and this one does, so the test was red in
    Release roughly one run in five and never once under Sanitize, where it is
    too slow to coalesce.  Measured after the carry: 1,200 pipelined pairs,
    zero timeouts."""
    buf = rest
    while b"\r\n\r\n" not in buf:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            return ("TIMEOUT-before-headers", "", b"")
        except OSError as e:
            return ("RESET-before-headers:%s" % type(e).__name__, "", b"")
        if not chunk:
            return ("EOF-before-headers", "", b"")
        buf += chunk
    head, body = buf.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    status = lines[0].decode("latin1", "replace")
    clen = None
    for line in lines[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                clen = int(line.split(b":", 1)[1].strip())
            except ValueError:
                return ("BAD-CONTENT-LENGTH", "", b"")
    if clen is None:
        return ("NO-CONTENT-LENGTH:%s" % status, "", b"")
    while len(body) < clen:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            return ("TIMEOUT-mid-body", "", b"")
        except OSError as e:
            return ("RESET-mid-body:%s" % type(e).__name__, "", b"")
        if not chunk:
            return ("EOF-mid-body", "", b"")
        body += chunk
    over = body[clen:]
    if b" 200 " not in lines[0]:
        return ("STATUS:%s" % status, "", over)
    return ("OK", body[:clen].decode("latin1", "replace"), over)


# ── phase 1: the payload goes second ───────────────────────────────────────
#
# One clean request, and behind it — in the same write, so the proxy sees both
# in one read — a request carrying Content-Length AND Transfer-Encoding, plus a
# header no other request in this test sends.  Sent as one sendall(): splitting
# it would let the proxy see the second request as a fresh read, which is the
# case that always worked.
clean = ("GET /%s/pipe-first HTTP/1.1\r\n"
         "Host: 127.0.0.1:%d\r\n"
         "Connection: keep-alive\r\n"
         "\r\n" % (name, port))
smuggled = ("POST /%s/pipe-smuggled HTTP/1.1\r\n"
            "Host: 127.0.0.1:%d\r\n"
            "X-Smuggled-Marker: 6a1f9c\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n\r\n" % (name, port))

try:
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
except OSError as e:
    print("PHASE1 CONNECT-FAILED %s" % type(e).__name__)
    print("DONE")
    sys.exit(0)
s.settimeout(20)
try:
    s.sendall((clean + smuggled).encode())
except OSError as e:
    print("PHASE1 SEND-FAILED:%s" % type(e).__name__)
    print("DONE")
    sys.exit(0)

st1, body1, over1 = read_response(s)
print("PHASE1 RESP1 %s %s" % (st1, body1))

# Whatever the proxy decides to say about the second request is its business —
# a 400 and a close is the right answer, an EOF is acceptable — but it must not
# be a 200 echoing the smuggled path back, because that would mean a backend
# served it.
st2, body2, _ = read_response(s, over1)
print("PHASE1 RESP2 %s %s" % (st2, body2))
try:
    s.close()
except OSError:
    pass

# ── phase 2: pipelining still works ────────────────────────────────────────
#
# Two clean requests in one write on a fresh socket.  Both must come back, in
# order, on that same socket.  A "fix" that closed phase 1 by throwing away
# buffered bytes fails here.
a = ("GET /%s/pipe-a HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
     "Connection: keep-alive\r\n\r\n" % (name, port))
b = ("GET /%s/pipe-b HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
     "Connection: keep-alive\r\n\r\n" % (name, port))
try:
    s2 = socket.create_connection(("127.0.0.1", port), timeout=20)
    s2.settimeout(20)
    s2.sendall((a + b).encode())
except OSError as e:
    print("PHASE2 CONNECT-OR-SEND-FAILED:%s" % type(e).__name__)
    print("DONE")
    sys.exit(0)

sa, ba, overa = read_response(s2)
print("PHASE2 RESP1 %s %s" % (sa, ba))
sb, bb, _ = read_response(s2, overa)
print("PHASE2 RESP2 %s %s" % (sb, bb))
try:
    s2.close()
except OSError:
    pass

# The same pair again, with both answers guaranteed to be in the socket before
# the first read.  Above, which of the two arrival shapes gets tested is the
# proxy's timing to choose -- and for a long time only one of them was ever
# reached here, so the reader's inability to hold an over-read second answer
# showed up as this file failing about one Release run in five and no Sanitize
# run at all.  Half a second buys the other shape outright.
try:
    s2b = socket.create_connection(("127.0.0.1", port), timeout=20)
    s2b.settimeout(20)
    s2b.sendall((a + b).encode())
    time.sleep(0.5)
except OSError as e:
    print("PHASE2C CONNECT-OR-SEND-FAILED:%s" % type(e).__name__)
    print("DONE")
    sys.exit(0)

sc1, bc1, overc = read_response(s2b)
print("PHASE2C RESP1 %s %s" % (sc1, bc1))
sc2, bc2, _ = read_response(s2b, overc)
print("PHASE2C RESP2 %s %s" % (sc2, bc2))
try:
    s2b.close()
except OSError:
    pass

# ── phase 3: a body is a body, and what follows it is not ──────────────────
#
# The first request declares eleven bytes and the smuggled one begins at byte
# twelve.  A proxy that forwards the whole buffer hands it over; a proxy that
# forwards eleven bytes does not.
post = ("POST /%s/pipe-body HTTP/1.1\r\n"
        "Host: 127.0.0.1:%d\r\n"
        "Content-Length: 11\r\n"
        "\r\n"
        "hello world" % (name, port))
after = ("GET /%s/pipe-behind-body HTTP/1.1\r\n"
         "Host: 127.0.0.1:%d\r\n"
         "X-Smuggled-Marker: 6a1f9c\r\n"
         "Content-Length: 3\r\n"
         "Transfer-Encoding: chunked\r\n"
         "\r\n" % (name, port))
try:
    s3 = socket.create_connection(("127.0.0.1", port), timeout=20)
    s3.settimeout(20)
    s3.sendall((post + after).encode())
except OSError as e:
    print("PHASE3 CONNECT-OR-SEND-FAILED:%s" % type(e).__name__)
    print("DONE")
    sys.exit(0)

sc, bc, _ = read_response(s3)
print("PHASE3 RESP1 %s %s" % (sc, bc))
try:
    s3.close()
except OSError:
    pass

print("DONE")
PYEOF

# The harness has to have reached its last line, or a check phrased as "compare
# what we read" would have nothing to compare and pass.
TOTAL=$((TOTAL+1))
if grep -qx 'DONE' "$OUT" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [harness ran]: the client produced no DONE line; raw output:"
    grep -v '^$' "$OUT" 2>/dev/null | head -8 | sed 's/^/        /' || true
fi

# The first request has to have been served, or nothing below discriminates:
# a proxy that answers nothing at all would pass every "did not reach the
# backend" assertion for the wrong reason.
TOTAL=$((TOTAL+1))
if grep -qx 'PHASE1 RESP1 OK pipe-first' "$OUT" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [phase 1: the clean request in front is served]: $(grep '^PHASE1 RESP1 ' "$OUT" 2>/dev/null | head -1 || echo 'no result')"
fi

TOTAL=$((TOTAL+1))
if [ "$(wc -c <"$RAW" 2>/dev/null || echo 0)" -gt "$BEFORE_BYTES" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [the backend recorded the traffic]: nothing new reached the backend at all,"
    echo "        so the smuggling assertions below would pass without proving anything"
fi

# The assertion: the marker is carried by the smuggled request and by nothing
# else, so its presence in what the backend read means the request reached it.
TOTAL=$((TOTAL+1))
if grep -qa 'X-Smuggled-Marker' "$RAW" 2>/dev/null; then
    FAIL=$((FAIL+1))
    echo "  FAIL [the pipelined request never reaches the backend]: the backend read a"
    echo "        request the proxy never checked — pipelining a payload behind a clean"
    echo "        request bypasses parse_http_request_line entirely"
else
    PASS=$((PASS+1))
fi

# Same fact from the other side: the proxy refuses Transfer-Encoding alongside
# Content-Length, so no forwarded request may carry a Transfer-Encoding at all
# in this test — none of the legitimate requests sends one.
TOTAL=$((TOTAL+1))
if grep -qai 'transfer-encoding' "$RAW" 2>/dev/null; then
    FAIL=$((FAIL+1))
    echo "  FAIL [no Transfer-Encoding reaches the backend]: a request carrying"
    echo "        Transfer-Encoding was forwarded although every one in this test also"
    echo "        carries Content-Length, which parse_http_request_line rejects"
else
    PASS=$((PASS+1))
fi

# And the smuggled path must never have been served, whatever it was framed as.
TOTAL=$((TOTAL+1))
if grep -qa 'pipe-smuggled' "$RAW" 2>/dev/null; then
    FAIL=$((FAIL+1))
    echo "  FAIL [the smuggled request is not served]: the backend was asked for"
    echo "        /pipe-smuggled, which only the unchecked second request asks for"
else
    PASS=$((PASS+1))
fi

TOTAL=$((TOTAL+1))
if grep -qa 'pipe-behind-body' "$RAW" 2>/dev/null; then
    FAIL=$((FAIL+1))
    echo "  FAIL [a declared body bounds what is forwarded]: the request that starts one"
    echo "        byte past Content-Length reached the backend, so the body forwarded was"
    echo "        the whole buffer rather than the eleven bytes the request declared"
else
    PASS=$((PASS+1))
fi

TOTAL=$((TOTAL+1))
if grep -qa 'pipe-body' "$RAW" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [phase 3 reached the backend at all]: /pipe-body never arrived, so the"
    echo "        assertion above passed for the wrong reason"
fi

# Pipelining is held back to be checked rather than dropped, so both clean
# requests must be answered on the one socket, in order.
TOTAL=$((TOTAL+1))
if grep -qx 'PHASE2 RESP1 OK pipe-a' "$OUT" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [phase 2: first pipelined request answered]: $(grep '^PHASE2 RESP1 ' "$OUT" 2>/dev/null | head -1 || echo 'no result')"
fi

TOTAL=$((TOTAL+1))
TOTAL=$((TOTAL+1))
if grep -qx 'PHASE2C RESP1 OK pipe-a' "$OUT" 2>/dev/null &&
   grep -qx 'PHASE2C RESP2 OK pipe-b' "$OUT" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [phase 2: both answers still arrive when they arrive together]:"
    echo "        $(grep '^PHASE2C RESP' "$OUT" 2>/dev/null | tr '\n' ' ' || echo 'no result')"
    echo "        two answers coalesced into one read is a shape the proxy may"
    echo "        choose, and both of them still have to be readable"
fi

if grep -qx 'PHASE2 RESP2 OK pipe-b' "$OUT" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [phase 2: second pipelined request answered on the same socket]:"
    echo "        $(grep '^PHASE2 RESP2 ' "$OUT" 2>/dev/null | head -1 || echo 'no result')"
    echo "        holding the second request back must not mean discarding it"
fi

# Refusing a smuggling attempt must not take the runtime with it.
TOTAL=$((TOTAL+1))
if "$BIN" stats "$PX_NAME" >/dev/null 2>&1; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [runtime alive]: the proxy did not survive the smuggling attempt"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
