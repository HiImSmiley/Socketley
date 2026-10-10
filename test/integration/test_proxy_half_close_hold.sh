#!/usr/bin/env bash
# Integration test: a client that half-closes before its answer arrives is
# answered, and then let go.
#
# handle_client_read does not tear a pair down when the client shuts its write
# side while an answer is still owed.  It sets client_eof and HOLDS, so that the
# response already asked for is finished rather than thrown away.  Something has
# to end that hold when the answer lands, and until now only one path did — the
# keep-alive detach, through reset_client_for_next_request.
#
# An exchange the detach refuses never reaches that path, and the hold then had
# nothing that could ever end it.  The client was answered in full and then kept
# for ever — its socket, the backend's socket, and the splice pipes behind them —
# because the only thing armed anywhere was the backend's idle read, and that
# read completes only if the backend sends something it has no reason to send.
# The descriptors came back when the proxy stopped and not before.
#
# The refusal used here is a backend that answered `Connection: close`: its own
# end has said the socket is finished, so it must not be pooled.  This test was
# originally written around a different one — a CLIENT that sent
# `Connection: close` — and that refusal has since been removed, because a
# client's Connection token is hop-by-hop and refusing on it cost a backend
# connection per client request (see test_proxy_http_close_pool.sh).  The client
# still sends the header, because it is also what makes the client half-close
# below the natural end of the exchange; what keeps this test on the path past
# the detach is now the backend's answer.
#
# ─── WHY BOTH ASSERTIONS ARE HERE ───────────────────────────────────────────
#
# "The descriptors were released" passes on a build that closes the pair the
# moment the FIN arrives and throws the answer away — which is the defect the
# hold exists to prevent, and would be a straight trade of one bug for another.
# So the release is asserted next to the thing that has to survive it: every
# response body comes back whole, and each one carries its own marker so that
# "some bytes arrived" cannot pass for it.
#
# Against the broken build the bodies still arrive — the hold worked, it just
# never ended — so the descriptor assertion is the one that discriminates.
#
# ─── WHAT DISCRIMINATES ─────────────────────────────────────────────────────
#
# The descriptor count was taken of the daemon, where no pair lives -- every
# proxy runs in a worker of its own -- and against the broken build it passed
# 8/8. The client now says how its read ended: at EOF, which is the hold
# letting the pair go, or at its ten-second timeout with the whole body in
# hand, which is the hold that never ended. The descriptors are counted in the
# proxy's own process.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate halfclose

BE_PORT=$((SL_PORT_BASE+960))
PX_PORT=$((SL_PORT_BASE+961))
PX_NAME=halfclose_px
NREQ=6
PASS=0; FAIL=0; TOTAL=0
BEPID=""

cleanup() {
    "$BIN" stop "$PX_NAME" 2>/dev/null || true
    sleep 0.2
    "$BIN" remove "$PX_NAME" 2>/dev/null || true
    [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null || true
    [ -n "${TMPD:-}" ] && rm -rf "$TMPD"
    daemon_stop
}
trap cleanup EXIT

assert_eq() {
    TOTAL=$((TOTAL+1))
    local got="$1" expected="$2" label="$3"
    if [ "$got" = "$expected" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: got '$got', expected '$expected'"
    fi
}

echo "=== Integration: proxy half-close hold ends when the answer lands ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 is required"
    exit 0
fi

TMPD=$(mktemp -d)

# The backend waits before answering, which is what puts the client's FIN ahead
# of the response — the ordering the whole test is about.  It reads the request
# first so the delay cannot be mistaken for a slow accept.
cat > "$TMPD/be.py" <<'PY'
import socket, sys, threading, time

port = int(sys.argv[1])
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(64)

def serve(c):
    try:
        c.settimeout(10)
        req = b""
        while b"\r\n\r\n" not in req:
            chunk = c.recv(4096)
            if not chunk:
                return
            req += chunk
        # Echo the marker out of the request path back as the body, so the
        # assertion is about this exchange and not about bytes in general.
        line = req.split(b"\r\n", 1)[0]
        path = line.split(b" ")[1] if len(line.split(b" ")) > 1 else b"/"
        marker = path.rsplit(b"/", 1)[-1] or b"none"
        # Long enough that the client's FIN is through the proxy well before
        # any of this is written.
        time.sleep(0.6)
        body = b"marker=" + marker
        # `Connection: close` in the response, and then the socket is HELD open
        # anyway.  Both halves are needed, and for different reasons.
        #
        # The header is what puts this exchange on the path the test is about.
        # The pool detach is refused for a backend that said close — its own end
        # has declared the socket finished — so this exchange falls PAST the
        # detach, which is where the hold used to have no ending at all.  A
        # response without that header is detached and pooled instead, and the
        # hold then ends by the ordinary keep-alive route: green either way, and
        # measuring the wrong thing.
        #
        # Holding the socket open is what stops the pair being reaped by
        # accident.  A backend that actually closes hands the proxy a
        # zero-length read on the backend leg, and that path tears the pair down
        # for reasons of its own, so the leak below could not be seen.
        #
        # This fixture used to send no Connection header and hold — which said
        # the socket stayed usable and then refused to read a second request on
        # it.  That was answered by the refusal to pool a `Connection: close`
        # CLIENT, and when that refusal was removed (it cost a backend
        # connection per client request) the proxy started reusing this socket,
        # correctly, and waited on a backend that had stopped reading.  A
        # fixture may not promise keep-alive and then not serve it.
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " +
                  str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        while True:
            time.sleep(3600)
    except Exception:
        pass

while True:
    try:
        conn, _ = srv.accept()
    except Exception:
        break
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
PY

# One exchange: send a complete request carrying Connection: close, shut the
# write side immediately, then read the answer out to EOF.  The shutdown is the
# point — it is what makes the proxy take the hold.
cat > "$TMPD/client.py" <<'PY'
import socket, sys

port, path = int(sys.argv[1]), sys.argv[2]
keep = len(sys.argv) > 3 and sys.argv[3] == "keep"
s = socket.create_connection(("127.0.0.1", port), 10)
s.settimeout(10)
s.sendall((f"GET {path} HTTP/1.1\r\n"
           f"Host: 127.0.0.1\r\n" +
           ("" if keep else "Connection: close\r\n") + "\r\n").encode())
s.shutdown(socket.SHUT_WR)
data = b""
end = "eof"
try:
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
except socket.timeout:
    # The answer may all be here and the pair still held: the hold never ended.
    end = "timeout"
except Exception:
    end = "error"
s.close()
sys.stdout.write("BODY:" + (data.split(b"\r\n\r\n", 1)[1].decode()
                            if b"\r\n\r\n" in data else "<none>") + "|END:" + end)
PY

python3 "$TMPD/be.py" "$BE_PORT" >/dev/null 2>&1 &
BEPID=$!
ready_tcp 127.0.0.1 "$BE_PORT" 15 || { echo "  FATAL: backend did not start"; exit 1; }

daemon_start "$BIN"

create_ok "proxy created" \
    "$BIN" create proxy "$PX_NAME" -p "$PX_PORT" --backend "127.0.0.1:$BE_PORT" -s
ready_http 127.0.0.1 "$PX_PORT" "/$PX_NAME/ready" 20 || true

# The baseline is read after the readiness probe, so the listener, the pool and
# everything else the first request builds is already standing.  What this test
# adds on top of it is NREQ half-closed exchanges and nothing else.
# The proxy's own process, which holds the pairs; the daemon's descriptors say nothing about them.
PXPID=$("$BIN" stats "$PX_NAME" 2>/dev/null | sed -n 's/^pid://p')
FD0=$(ls -1 "/proc/$PXPID/fd" 2>/dev/null | wc -l || true)

for i in $(seq 1 "$NREQ"); do
    out=$(python3 "$TMPD/client.py" "$PX_PORT" "/$PX_NAME/m$i" 2>/dev/null || true)
    assert_eq "$out" "BODY:marker=m$i|END:eof" "half-closed request $i answered in full, and the pair let go"
done

# The same without the client's `Connection: close`, where nothing on the
# client's side asks for the end and only the hold's own ending lets go.
for i in $(seq 1 "$NREQ"); do
    out=$(python3 "$TMPD/client.py" "$PX_PORT" "/$PX_NAME/k$i" keep 2>/dev/null || true)
    assert_eq "$out" "BODY:marker=k$i|END:eof" "half-closed keep-alive request $i answered in full, and the pair let go"
done

# Give the teardowns a moment to land, and poll rather than sleep a fixed time:
# on the fixed build this settles almost at once, and on the broken one no
# amount of waiting brings it down, so the loop costs nothing it does not need.
FD1=$FD0
for _ in $(seq 1 40); do
    FD1=$(ls -1 "/proc/$PXPID/fd" 2>/dev/null | wc -l || true)
    [ -n "$FD1" ] && [ "$FD1" -le $((FD0 + 4)) ] && break
    sleep 0.25
done

# The ceiling is four descriptors of slack over a baseline taken with the proxy
# already serving.  Each held pair is worth at least two — the client's socket
# and the backend's — so six leaked exchanges is at least twelve, and no
# rounding of "what the pool happens to keep" reaches the ceiling from below.
TOTAL=$((TOTAL+1))
if [ -z "$FD1" ] || [ -z "$FD0" ] || [ "$FD0" -eq 0 ]; then
    FAIL=$((FAIL+1))
    echo "  FAIL [descriptors released]: could not read /proc/$PXPID/fd" \
         "(baseline '${FD0:-}', now '${FD1:-}')"
elif [ "$FD1" -le $((FD0 + 4)) ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [descriptors released]: baseline $FD0, now $FD1 after $NREQ" \
         "half-closed exchanges — the pairs were answered and then held"
fi

echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
echo "DONE"
