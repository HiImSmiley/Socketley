#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# detach_and_pool_backend's fallback for a backend with a completion owed
# closed the whole pair, and a backend read is armed essentially all of the
# time, so the client was torn down after every response despite keep-alive --
# so several requests go down one socket with a marker echoed back as the body,
# and every assertion demands the presence of a positive result line rather
# than comparing possibly-empty captures, with a final DONE line asserted
# separately.
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
TMPDIR_T=$(mktemp -d /tmp/socketley-kalive-XXXXXX)
export HOME="$TMPDIR_T/home"
export SOCKETLEY_SOCKET="$TMPDIR_T/daemon.sock"
mkdir -p "$HOME"
DPID=""
BEPID=""

BE_PORT=$((SL_PORT_BASE+420))
PX_PORT=$((SL_PORT_BASE+421))
PX_NAME=kalive_px
NREQ=4
OUT="$TMPDIR_T/client.out"
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null || true
    # Wait for the daemon to actually go and insist if it does not, because
    # this test leaves one holding thousands of connections and the next test
    # starts while it is still bound.
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

echo "=== Integration: HTTP keep-alive through the proxy ==="

# A minimal HTTP/1.1 origin answering with Content-Length and keep-alive, both
# required for the proxy to reach the pooling path, echoing the request path
# back as the marker.
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

# Wait on the daemon's IPC socket directly and never by polling with a CLI
# command, because every CLI command auto-starts a daemon when the socket does
# not answer and the orphan survives cleanup, which only knows $DPID.
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

# The daemon that answers is the one this test launched, asked of the
# descriptor table because `kill -0` cannot tell a zombie from a live process.
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

# One socket, several requests, never reopened -- so if the proxy closes it,
# request 2 has nowhere to go and says so.
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

# The harness has to have reached its last line, or a check phrased as "compare
# what we read" would have nothing to compare and pass.
TOTAL=$((TOTAL+1))
if grep -q '^DONE ' "$OUT" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [harness ran]: the client produced no DONE line; raw output:"
    grep -v '^$' "$OUT" 2>/dev/null | head -5 | sed 's/^/        /' || true
fi

# One assertion per request, because request 1 failing means the proxy is
# broken outright while request 2 onwards failing is the keep-alive defect.
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
