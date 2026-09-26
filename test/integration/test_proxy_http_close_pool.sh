#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Integration test: a client that says `Connection: close` must not cost a
# backend connection.
#
# ─── WHAT WAS WRONG ─────────────────────────────────────────────────────────
# `Connection` is hop-by-hop, so a client's `close` says nothing about the
# proxy's socket to the backend -- and the proxy honoured it in two places at
# once, which is a backend connection per client request and empties this box's
# ephemeral range in about a second; asserted on the number of backend sockets
# rather than a request rate, because on loopback a build that pools nothing
# still answers quickly, with the backend stamping its connection ordinal into
# every response and a third proxy as the control whose backend sends `close`
# itself and must still not be pooled.
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
    # Matched by exact process name and then by this run's own socket path,
    # because `pgrep -f` also matches the shell that carries the string on its
    # command line.
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
# An HTTP/1.1 origin stamping its accepted-connection ordinal into every
# response, which is what makes the pool visible from the client side, and
# always sending a Content-Length because a response whose framing the proxy
# cannot resolve is refused by the pool for that reason instead.
cat > "$TMPDIR_T/backend.py" <<'PYEOF'
import os, socket, sys, threading, time

port = int(sys.argv[1])
mode = sys.argv[2]              # "keepalive" | "close"
countfile = sys.argv[3]
acceptlog = sys.argv[4]

# ─── WHY EVERY ACCEPT IDENTIFIES ITSELF ─────────────────────────────────────
#
# The assertion below is KA_NOW - KA_BASE, both read from this backend's own
# counter, so it counts CONNECTIONS TO A PORT and not answers attributable to
# this test.  Anything on this machine that dials this port inflates it, and on
# 2026-08-21 it read 7 for 6 requests -- one more connection than there were
# requests, which the proxy cannot produce by failing to pool and which no rerun
# reproduced (80 attempts, 40 of them against 12 busy loops, zero failures).
#
# A count cannot answer that question, so it is not the only thing recorded.
# Each accept writes its peer port and the time it arrived, and a thread off the
# accept path resolves that peer port to the process holding it -- /proc/net/tcp
# for the socket inode, then /proc/<pid>/fd for the owner.  The next occurrence
# therefore says whether the extra connection came from the daemon (a retry or a
# speculative open, and a real defect) or from something else on the box (this
# assertion is contamination-sensitive by construction, and the test is what
# needs fixing).
#
# Off the accept path deliberately: the client spaces its requests 50 ms apart
# and the pool detach is asynchronous, so delaying an accept by a /proc scan
# would change the very timing the rare event lives in.


def log(line):
    try:
        with open(acceptlog, "a") as f:
            f.write(line + "\n")
            f.flush()
    except OSError:
        pass


def peer_inode(peer_port, my_port):
    """The socket inode of the far end of an accepted connection.

    Looked up from the PEER's point of view: its local port is peer_port and
    its remote port is ours.  Returns (inode, tcp_state) or (None, None) when
    the entry is already gone, which is itself an answer -- a peer that has
    vanished by the time this runs did not behave like a proxy holding a
    backend socket."""
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                f.readline()
                for line in f:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    try:
                        lp = int(parts[1].rsplit(":", 1)[1], 16)
                        rp = int(parts[2].rsplit(":", 1)[1], 16)
                    except (IndexError, ValueError):
                        continue
                    if lp == peer_port and rp == my_port:
                        return parts[9], parts[3]
        except OSError:
            continue
    return None, None


def inode_owner(inode):
    """The pid holding that socket inode, with enough of its identity to name
    it.  A miss is reported as a miss rather than guessed at."""
    target = "socket:[%s]" % inode
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        fddir = "/proc/%s/fd" % pid
        try:
            fds = os.listdir(fddir)
        except OSError:
            continue                      # exited, or not ours to look at
        for fd in fds:
            try:
                if os.readlink("%s/%s" % (fddir, fd)) != target:
                    continue
            except OSError:
                continue
            def read(rel, sep=None):
                try:
                    with open("/proc/%s/%s" % (pid, rel), "rb") as f:
                        raw = f.read()
                except OSError:
                    return "?"
                if sep is not None:
                    raw = raw.replace(sep, b" ")
                return raw.decode("latin1", "replace").strip()
            try:
                exe = os.readlink("/proc/%s/exe" % pid)
            except OSError:
                exe = "?"
            return pid, read("comm"), exe, read("cmdline", b"\0")
    return None, None, None, None


def identify(ordinal, peer_port):
    inode, state = peer_inode(peer_port, port)
    if inode is None:
        log("OWNER %d peer=%d UNRESOLVED no-/proc/net/tcp-entry "
            "(the peer socket was already gone)" % (ordinal, peer_port))
        return
    pid, comm, exe, cmdline = inode_owner(inode)
    if pid is None:
        log("OWNER %d peer=%d inode=%s state=%s UNRESOLVED "
            "no-process-holds-this-inode" % (ordinal, peer_port, inode, state))
        return
    log("OWNER %d peer=%d inode=%s state=%s pid=%s comm=%s exe=%s cmdline=%s"
        % (ordinal, peer_port, inode, state, pid, comm, exe, cmdline))


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
        conn, peer = srv.accept()
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
    peer_port = peer[1] if isinstance(peer, tuple) and len(peer) > 1 else -1
    # Written before the lookup and before the handler, so the ordering and the
    # arrival time survive even if the peer disappears or the lookup throws.
    log("ACCEPT %d t=%.6f peer=%s:%d" % (n, time.time(), peer[0], peer_port))
    threading.Thread(target=identify, args=(n, peer_port), daemon=True).start()
    threading.Thread(target=handle, args=(conn, n), daemon=True).start()
PYEOF

ACCLOG_KA="$TMPDIR_T/acceptlog.ka"
ACCLOG_CL="$TMPDIR_T/acceptlog.cl"
: >"$ACCLOG_KA"
: >"$ACCLOG_CL"

python3 "$TMPDIR_T/backend.py" "$BE_PORT"  keepalive "$TMPDIR_T/accepts.ka" \
    "$ACCLOG_KA" >"$TMPDIR_T/backend.log" 2>&1 &
BEPID=$!
python3 "$TMPDIR_T/backend.py" "$BEC_PORT" close     "$TMPDIR_T/accepts.cl" \
    "$ACCLOG_CL" >"$TMPDIR_T/backend_ctl.log" 2>&1 &
BECPID=$!

# The phases mark themselves in the accept log, because an accept alone does
# not say where in the run it landed.
mark() { printf 'MARK %s t=%s\n' "$1" "$(date +%s.%N)" >>"$ACCLOG_KA"; }

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

# A zombie $DPID has an empty /proc/<pid>/fd while an orphaned daemon serves
# the run, which `kill -0` cannot tell apart and the descriptor table can.
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

# A real request through each proxy rather than an accepted connection and a
# guess, which lands on the backend and is counted, so the baselines below are
# taken after this point.
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
mark "BASELINE ka_base=$KA_BASE cl_base=$CL_BASE daemon_pid=$DPID"

# ─── The client ─────────────────────────────────────────────────────────────
# One fresh connection per request each carrying `Connection: close`,
# sequential and spaced, because the question is whether the backend socket
# comes back and a burst would open several legitimately.
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
    # The timestamp is appended, not inserted: the assertions below grep this
    # line with a ^-anchored pattern that ends at the ordinal.
    print("RESP %d OK %s t=%.6f" % (i, ordinal, time.time()))
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

mark "CLIENT-START"
python3 "$TMPDIR_T/client.py" "$PX_PORT"  "$PX_NAME"  "$NREQ" >"$OUT"  2>&1 || true
mark "CLIENT-DONE"
python3 "$TMPDIR_T/client.py" "$PXC_PORT" "$PXC_NAME" "$NREQ" >"$OUTC" 2>&1 || true
mark "CONTROL-DONE"

# Give the last detach its completion before the counts are read.
sleep 0.5
mark "COUNTS-READ"

KA_NOW=$(read_count "$TMPDIR_T/accepts.ka"); KA_NOW=${KA_NOW:-0}
CL_NOW=$(read_count "$TMPDIR_T/accepts.cl"); CL_NOW=${CL_NOW:-0}
KA_NEW=$((KA_NOW - KA_BASE))
CL_NEW=$((CL_NOW - CL_BASE))

# ─── Assertions ─────────────────────────────────────────────────────────────

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

TOTAL=$((TOTAL+1))
if grep -qx "DONE $NREQ/$NREQ" "$OUT" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [all $NREQ close-mode requests answered]: $(grep '^DONE ' "$OUT" 2>/dev/null | head -1 || echo 'no DONE line')"
    grep '^RESP ' "$OUT" 2>/dev/null | sed 's/^/        /' || true
fi

# Counted from a baseline taken after the readiness probe, so zero is the
# expected value rather than an absence of traffic -- with a ceiling of 2
# because the detach is asynchronous and a request arriving inside that window
# legitimately opens one, still four short of the defect.
TOTAL=$((TOTAL+1))
if [ "$KA_NEW" -le 2 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [backend connections for $NREQ close-mode requests]: got $KA_NEW, want 0..2"
    echo "        a client's Connection: close is hop-by-hop and must not reach the backend leg"
fi

# Whenever this run opened a backend connection at all the accept log is
# printed with the client's timeline beside it, because this counts connections
# to a port and a dialler with nothing to do with this test inflates it just as
# well as a proxy that stopped pooling.
if [ "$KA_NEW" -gt 0 ]; then
    echo "  NOTE: $KA_NEW backend connection(s) opened after the baseline; who dialled:"
    sed -n "/MARK BASELINE/,\$p" "$ACCLOG_KA" 2>/dev/null | sed 's/^/        /' || true
    echo "        client timeline:"
    grep -E '^(RESP|EOF) ' "$OUT" 2>/dev/null | sed 's/^/        /' || true
fi

# The same fact read off the answers rather than off the backend's counter, so
# a backend that miscounted cannot make this pass on its own.
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

# The client asked for close and must get it -- written as the guard against
# trading a backend leak for a client leak, and it discriminates on its own,
# because refusing the detach meant nothing ever closed the client either.
TOTAL=$((TOTAL+1))
NEOF=$(grep -c '^EOF [0-9]* YES$' "$OUT" 2>/dev/null || true)
if [ "${NEOF:-0}" -eq "$NREQ" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [proxy closed the client connection]: $NEOF of $NREQ saw EOF"
    grep '^EOF ' "$OUT" 2>/dev/null | sed 's/^/        /' || true
fi

# The backend's own `Connection: close` is a fact about the backend socket and
# still forbids pooling, so a build that swept all three refusals away passes
# everything above and fails here.
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
