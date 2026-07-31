#!/usr/bin/env bash
# Integration test: an HTTP keep-alive connection survives every response.
#
# detach_and_pool_backend has a fallback for a backend that still has a
# completion owed to it, and that fallback closed the whole pair.  A backend
# read is armed essentially all of the time, so that fallback is the branch that
# runs — the client was torn down after every single response although both
# sides had negotiated keep-alive, pooling never happened, and every request
# paid for a fresh TCP handshake.
#
# The test sends several requests down one socket and requires every one of them
# to be answered on that same socket.  Each request carries its own marker in
# the path, the backend echoes that marker back as the response body, and the
# body is compared against what was asked for: "some bytes came back" is not a
# result.  Against the broken build the first request is answered and the second
# one gets EOF, so the second assertion is the one that discriminates.
#
# Two green runs against a broken build in this project came from comparing a
# value that could not be read against an equally empty expectation, so nothing
# here is checked by string equality with a captured variable.  Every assertion
# below demands the *presence* of a positive result line, absence is a failure,
# and the harness prints a final DONE line that is asserted separately so that
# a harness which died halfway cannot look like a clean run.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

# Own daemon, socket and state directory: against the shared one this test does
# not discriminate — auto-restart hides a crash, and a leftover runtime from an
# earlier run answers on the port before this test ever creates its own.
TMPDIR_T=$(mktemp -d /tmp/socketley-kalive-XXXXXX)
export HOME="$TMPDIR_T/home"
export SOCKETLEY_SOCKET="$TMPDIR_T/daemon.sock"
mkdir -p "$HOME"
DPID=""
BEPID=""

BE_PORT=19420
PX_PORT=19421
PX_NAME=kalive_px
NREQ=4
OUT="$TMPDIR_T/client.out"
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null || true
    # Wait for the daemon to actually go, and insist if it does not.  A plain
    # kill returns immediately, and this test leaves a daemon holding thousands
    # of connections, which takes long enough to shut down that the next test in
    # the suite starts while it is still bound — the leftovers accumulate and one
    # of them ends up answering somebody else's requests.
    if [ -n "$DPID" ]; then
        kill "$DPID" 2>/dev/null || true
        for _ in $(seq 1 50); do
            kill -0 "$DPID" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
    # Kill by socket, not only by pid.  A CLI command run against a daemon that
    # is not up yet — or not up any more — starts one of its own, detached from
    # this shell; killing $DPID would leave that one running for good, holding
    # this test's ports.  The socket path comes from mktemp, so matching on it
    # can only ever hit daemons belonging to this run.
    for p in $(pgrep -f 'socketley daemon' 2>/dev/null || true); do
        if tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null \
           | grep -qx "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET"; then
            kill -9 "$p" 2>/dev/null || true
        fi
    done
    rm -rf "$TMPDIR_T"
}
trap cleanup EXIT

echo "=== Integration: HTTP keep-alive through the proxy ==="

# Backend.  There is no HTTP echo mode in the server runtime, so this is a
# minimal HTTP/1.1 origin that answers with Content-Length and keep-alive —
# both are required for the proxy to reach the pooling path at all, and a
# backend that answered "Connection: close" would skip the defect entirely.
# It echoes the request path back as the body, which is the marker.
python3 - "$BE_PORT" >"$TMPDIR_T/backend.log" 2>&1 <<'PYEOF' &
import socket, sys, threading

port = int(sys.argv[1])
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(64)


def handle(c):
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
            body = path.lstrip(b"/")
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

# Wait on the daemon's IPC socket directly, never by polling with a CLI command.
# Every CLI command auto-starts a daemon when the socket does not answer yet —
# cli.cpp's ensure_daemon() forks, setsids and re-execs 'socketley daemon' — so
# polling 'ps' against the daemon this test has just launched races it and spawns
# a second, orphaned one.  Whichever loses the bind exits, and when the loser is
# $DPID the pid this test watches becomes a zombie while an orphan serves the
# run — and the orphan survives cleanup, because cleanup only knows $DPID.
# Measured at 2 spawned orphans in 30 startups of this sequence.
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

# The daemon that answers is the one this test launched.  A zombie $DPID has an
# empty /proc/<pid>/fd while an orphaned daemon serves the run, and 'kill -0'
# cannot tell the two apart — so this looks at the descriptor table, which only a
# live process has.  Without it the run measures somebody else's daemon and says
# nothing about it.
TOTAL=$((TOTAL+1))
NFD=$(ls -1 "/proc/$DPID/fd" 2>/dev/null | wc -l)
case "$(printf '%s' "$NFD" | tr -d '[:space:]')" in
    ''|0|*[!0-9]*)
        FAIL=$((FAIL+1))
        echo "  FAIL [setup]: pid $DPID is not a live process — the daemon that answers"
        echo "        is not the one this test launched, and this run measures the wrong process"
        ;;
    *) PASS=$((PASS+1)) ;;
esac

for _ in $(seq 1 50); do nc -z 127.0.0.1 "$BE_PORT" 2>/dev/null && break; sleep 0.1; done

TOTAL=$((TOTAL+1))
if nc -z 127.0.0.1 "$BE_PORT" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the HTTP backend never came up on $BE_PORT"
fi

# The proxy only routes paths under /<name>/ and strips that prefix before
# forwarding, so the marker has to sit behind it.
"$BIN" create proxy "$PX_NAME" -p "$PX_PORT" \
    --backend "127.0.0.1:$BE_PORT" --protocol http -s 2>&1 || true
# A real request through the proxy, not an accepted connection and a guess.
ready_http 127.0.0.1 "$PX_PORT" "/$PX_NAME/ready" 20 || true

TOTAL=$((TOTAL+1))
if "$BIN" stats "$PX_NAME" >/dev/null 2>&1; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the proxy runtime is not up — everything below is meaningless"
fi

# One socket, several requests.  The socket object is never reopened: if the
# proxy closes it, request 2 has nowhere to go and says so.
python3 - "$PX_PORT" "$PX_NAME" "$NREQ" >"$OUT" 2>&1 <<'PYEOF' || true
import socket, sys

port = int(sys.argv[1])
name = sys.argv[2]
count = int(sys.argv[3])


def read_response(s):
    """Returns (status, body).  Every way of not getting an answer has its own
    status, so a response that could not be read can never be mistaken for an
    empty one that matched."""
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


try:
    s = socket.create_connection(("127.0.0.1", port), timeout=4)
except OSError as e:
    print("CONNECT-FAILED %s" % type(e).__name__)
    print("DONE 0/%d" % count)
    sys.exit(0)
s.settimeout(4)

ok = 0
for i in range(1, count + 1):
    marker = "keepalive-marker-%d" % i
    req = ("GET /%s/%s HTTP/1.1\r\n"
           "Host: 127.0.0.1:%d\r\n"
           "Connection: keep-alive\r\n"
           "\r\n" % (name, marker, port))
    try:
        s.sendall(req.encode())
    except OSError as e:
        print("RESP %d SEND-FAILED:%s" % (i, type(e).__name__))
        break
    status, body = read_response(s)
    if status != "OK":
        print("RESP %d %s" % (i, status))
        break
    if body != marker:
        print("RESP %d WRONG-BODY want=%r got=%r" % (i, marker, body[:60]))
        break
    print("RESP %d OK" % i)
    ok += 1

print("DONE %d/%d" % (ok, count))
try:
    s.close()
except OSError:
    pass
PYEOF

# The harness has to have reached its last line.  Without this an aborted run
# would only show up as a pile of confusing per-request failures, and any check
# phrased as "compare what we read" would have nothing to compare and pass.
TOTAL=$((TOTAL+1))
if grep -q '^DONE ' "$OUT" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [harness ran]: the client produced no DONE line; raw output:"
    grep -v '^$' "$OUT" 2>/dev/null | head -5 | sed 's/^/        /' || true
fi

# One assertion per request.  Request 1 failing means the proxy is broken
# outright; request 2 onwards failing while request 1 passed is the keep-alive
# defect, which is why they are counted separately instead of as one "all
# requests answered" check.
for i in $(seq 1 "$NREQ"); do
    TOTAL=$((TOTAL+1))
    if grep -qx "RESP $i OK" "$OUT" 2>/dev/null; then
        PASS=$((PASS+1))
    else
        WHY=$(grep "^RESP $i " "$OUT" 2>/dev/null | head -1 || true)
        [ -n "$WHY" ] || WHY="no result at all — the harness stopped before request $i"
        FAIL=$((FAIL+1))
        echo "  FAIL [request $i answered on the same connection]: $WHY"
    fi
done

TOTAL=$((TOTAL+1))
if grep -qx "DONE $NREQ/$NREQ" "$OUT" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [all $NREQ requests on one connection]: $(grep '^DONE ' "$OUT" 2>/dev/null | head -1 || echo 'no DONE line')"
fi

# Detaching a backend must not take the runtime with it.
TOTAL=$((TOTAL+1))
if "$BIN" stats "$PX_NAME" >/dev/null 2>&1; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [runtime alive]: the proxy did not survive the keep-alive session"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
