#!/usr/bin/env bash
# Integration test: a TCP proxy passes a client's half-close on to the backend
# and keeps the return direction open until the backend has answered.
#
# ─── THE DEFECT ─────────────────────────────────────────────────────────────
#
# shutdown(SHUT_WR) says "I will send no more" and nothing whatever about
# reading.  It is how a request/response client that does not want to parse the
# reply frames its request — `nc -N`, redis-cli in one shot, any shell pipeline
# into a TCP proxy — and, because a byte relay has no protocol to frame with, it
# is the only thing that can tell a backend where the request ended.
#
# A --protocol tcp proxy tore the whole pair down on that FIN, on BOTH
# forwarding paths: handle_client_read did it on the copy path and handle_splice
# on the splice path.  The request had already reached the backend and was
# executed; the ANSWER was thrown away.  What the client saw was a clean EOF —
# the one failure it cannot act on, because nothing distinguishes it from a
# backend that legitimately had nothing to say.  Talking to the same backend
# directly answers, and so does haproxy in front of it.
#
# ─── WHAT DISCRIMINATES ─────────────────────────────────────────────────────
#
# The assertion is the REPLY, not the exchange.  "The key is set afterwards"
# passes on the broken build — the request always arrived, that was never the
# missing half — so a test written that way would have been green throughout.
# Each request carries a marker of its own, so "some bytes came back" cannot
# pass for "this request was answered".
#
# Both forwarding paths are exercised, because they lost the answer
# independently and a fix to one says nothing about the other.  The path is
# chosen by SOCKETLEY_PROXY_SPLICE, which is read once per process, so the
# splice leg needs a daemon started with it set — hence the second daemon
# below rather than a second flag.
#
# The third case is the circuit breaker, and it is here because it is what the
# first two run into: response_started is only ever assigned on the HTTP path,
# so the breaker's "did the backend answer" term read a constant false for a
# byte relay and charged EVERY clean backend close as a backend failure.  Five
# of those — circuit_threshold — took the only backend out of rotation, and the
# proxy answered every later client with an instant EOF from a backend that was
# perfectly healthy.  Reproduced on 8affb1f, so it predates the half-close fix;
# it stayed unreachable in practice only because splice was the default and the
# splice teardown never consults the breaker.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate tcphalfclose

CACHE_PORT=$((SL_PORT_BASE+970))
PX_COPY=$((SL_PORT_BASE+971))
PX_SPLICE=$((SL_PORT_BASE+972))
CLOSER_PORT=$((SL_PORT_BASE+973))
PX_BREAKER=$((SL_PORT_BASE+974))
PASS=0; FAIL=0; TOTAL=0
CLOSERPID=""
SPLICE_DPID=""
SPLICE_HOME=""
SPLICE_SOCK=""

cleanup() {
    for r in hc_copy hc_breaker hc_cache; do
        "$BIN" stop "$r" 2>/dev/null || true
    done
    sleep 0.2
    for r in hc_copy hc_breaker hc_cache; do
        "$BIN" remove "$r" 2>/dev/null || true
    done
    # The splice daemon is this test's too, and daemon_stop knows nothing about
    # it.  Its worker processes go with it — they are its children — but give
    # them a moment, because a proxy worker still holding the listener under
    # SO_REUSEPORT is exactly the contamination that makes the NEXT run's
    # failures unreproducible.
    if [ -n "$SPLICE_DPID" ]; then
        kill "$SPLICE_DPID" 2>/dev/null || true
        sleep 0.5
        kill -9 "$SPLICE_DPID" 2>/dev/null || true
    fi
    [ -n "$SPLICE_HOME" ] && rm -rf "$SPLICE_HOME"
    [ -n "$SPLICE_SOCK" ] && rm -f "$SPLICE_SOCK"
    [ -n "$CLOSERPID" ] && kill "$CLOSERPID" 2>/dev/null || true
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

echo "=== Integration: TCP proxy half-close reaches the backend, answer comes back ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 is required"
    exit 0
fi

TMPD=$(mktemp -d)

# One RESP SET, then shut the write side, then read to EOF.  The shutdown is the
# whole point: it is what the proxy used to answer with a teardown.
cat > "$TMPD/halfclose.py" <<'PY'
import socket, sys
port, key = int(sys.argv[1]), sys.argv[2]
cmd = ("*3\r\n$3\r\nSET\r\n$%d\r\n%s\r\n$3\r\nv42\r\n" % (len(key), key)).encode()
s = socket.create_connection(("127.0.0.1", port), 10)
s.settimeout(10)
s.sendall(cmd)
s.shutdown(socket.SHUT_WR)
data = b""
try:
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
except Exception:
    pass
s.close()
sys.stdout.write(data.decode(errors="replace").strip() or "<none>")
PY

# Reads a key back on a connection of its own, so "the request arrived" is
# reported separately from "the answer came back".
cat > "$TMPD/get.py" <<'PY'
import socket, sys
port, key = int(sys.argv[1]), sys.argv[2]
s = socket.create_connection(("127.0.0.1", port), 10)
s.settimeout(10)
s.sendall(("*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n" % (len(key), key)).encode())
data = s.recv(4096)
s.close()
sys.stdout.write("set" if b"v42" in data else "missing")
PY

# A backend that answers and then hangs up — an ordinary one-shot TCP server,
# and the shape the circuit breaker was charging as a failure.
cat > "$TMPD/closer.py" <<'PY'
import socket, sys, threading
port = int(sys.argv[1])
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(128)
def serve(c):
    try:
        c.settimeout(10)
        if c.recv(65536):
            c.sendall(b"PONG\n")
        c.shutdown(socket.SHUT_WR)
        c.close()
    except Exception:
        pass
while True:
    try:
        conn, _ = srv.accept()
    except Exception:
        break
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
PY

cat > "$TMPD/oneshot.py" <<'PY'
import socket, sys
port = int(sys.argv[1])
try:
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.settimeout(5)
    s.sendall(b"ping\n")
    data = s.recv(4096)
    s.close()
    sys.stdout.write("pong" if b"PONG" in data else "empty")
except Exception:
    sys.stdout.write("error")
PY

daemon_start "$BIN"

create_ok "cache backend created" \
    "$BIN" create cache hc_cache -p "$CACHE_PORT" -s
ready_tcp 127.0.0.1 "$CACHE_PORT" 15 || { echo "  FAIL: cache did not start"; exit 1; }

create_ok "tcp proxy (copy path) created" \
    "$BIN" create proxy hc_copy -p "$PX_COPY" --backend "127.0.0.1:$CACHE_PORT" --protocol tcp -s
ready_tcp 127.0.0.1 "$PX_COPY" 15 || { echo "  FAIL: copy-path proxy did not start"; exit 1; }

# ── 1. the answer to a half-closed request comes back ───────────────────────
#
# Direct first: it is the reference, and it proves the backend answers a
# half-closed client at all, so a failure through the proxy cannot be blamed on
# the cache.
out=$(python3 "$TMPD/halfclose.py" "$CACHE_PORT" hcdirect 2>/dev/null || true)
assert_eq "$out" "+OK" "backend answers a half-closed client directly"

for i in 1 2 3; do
    out=$(python3 "$TMPD/halfclose.py" "$PX_COPY" "hccopy$i" 2>/dev/null || true)
    assert_eq "$out" "+OK" "copy path: half-closed request $i answered"
    got=$(python3 "$TMPD/get.py" "$CACHE_PORT" "hccopy$i" 2>/dev/null || true)
    assert_eq "$got" "set" "copy path: half-closed request $i reached the backend"
done

# ── 2. the same on the splice path ──────────────────────────────────────────
#
# Its own daemon, because the switch is read once per process and the runtime
# runs in a worker the daemon forks.  It proxies to the cache in the FIRST
# daemon: nothing about the backend needs to differ, and sharing it keeps the
# two legs comparable.
SPLICE_HOME="$TMPD/splice-home"
SPLICE_SOCK="$TMPD/splice.sock"
mkdir -p "$SPLICE_HOME"
(
    export HOME="$SPLICE_HOME"
    export SOCKETLEY_SOCKET="$SPLICE_SOCK"
    export SOCKETLEY_PROXY_SPLICE=1
    "$BIN" daemon >"$TMPD/splice-daemon.log" 2>&1 &
    echo $! > "$TMPD/splice.pid"
    for _ in $(seq 1 100); do [ -S "$SOCKETLEY_SOCKET" ] && break; sleep 0.1; done
    "$BIN" create proxy hc_splice -p "$PX_SPLICE" \
           --backend "127.0.0.1:$CACHE_PORT" --protocol tcp -s >"$TMPD/splice-create.log" 2>&1
)
SPLICE_DPID=$(cat "$TMPD/splice.pid" 2>/dev/null || true)

if ready_tcp 127.0.0.1 "$PX_SPLICE" 15; then
    for i in 1 2 3; do
        out=$(python3 "$TMPD/halfclose.py" "$PX_SPLICE" "hcspl$i" 2>/dev/null || true)
        assert_eq "$out" "+OK" "splice path: half-closed request $i answered"
        got=$(python3 "$TMPD/get.py" "$CACHE_PORT" "hcspl$i" 2>/dev/null || true)
        assert_eq "$got" "set" "splice path: half-closed request $i reached the backend"
    done
else
    echo "  SKIP: splice-path proxy did not start ($(cat "$TMPD/splice-create.log" 2>/dev/null))"
fi

# ── 3. the descriptors come back ────────────────────────────────────────────
#
# The hold must end.  Paired with the assertions above on purpose: releasing the
# descriptors is also what the BROKEN build did — by closing the pair at the FIN
# and discarding the answer — so this check alone would have passed on it.  It
# discriminates only next to "and every answer came back".
FD0=$(ls -1 "/proc/$SOCKETLEY_DPID/fd" 2>/dev/null | wc -l || true)
for i in $(seq 1 8); do
    out=$(python3 "$TMPD/halfclose.py" "$PX_COPY" "hcfd$i" 2>/dev/null || true)
    assert_eq "$out" "+OK" "descriptor round $i answered"
done
FD1=$FD0
for _ in $(seq 1 40); do
    FD1=$(ls -1 "/proc/$SOCKETLEY_DPID/fd" 2>/dev/null | wc -l || true)
    [ -n "$FD1" ] && [ "$FD1" -le $((FD0 + 4)) ] && break
    sleep 0.25
done
TOTAL=$((TOTAL+1))
if [ -z "$FD1" ] || [ -z "$FD0" ] || [ "$FD0" -eq 0 ]; then
    FAIL=$((FAIL+1))
    echo "  FAIL [descriptors released]: could not read /proc/$SOCKETLEY_DPID/fd"
elif [ "$FD1" -le $((FD0 + 4)) ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [descriptors released]: baseline $FD0, now $FD1 after 8 half-closed exchanges"
fi

# ── 4. a backend that closes after answering does not open the breaker ──────
python3 "$TMPD/closer.py" "$CLOSER_PORT" >/dev/null 2>&1 &
CLOSERPID=$!
ready_tcp 127.0.0.1 "$CLOSER_PORT" 15 || { echo "  FAIL: closing backend did not start"; exit 1; }

create_ok "tcp proxy to a closing backend created" \
    "$BIN" create proxy hc_breaker -p "$PX_BREAKER" --backend "127.0.0.1:$CLOSER_PORT" --protocol tcp -s
ready_tcp 127.0.0.1 "$PX_BREAKER" 15 || { echo "  FAIL: breaker proxy did not start"; exit 1; }

# circuit_threshold is 5, so twelve exchanges is more than twice what it takes
# to open a breaker that charges clean closes.  On the broken build the first
# few are answered and every one after that is an instant empty reply.
BREAK_OK=0
for _ in $(seq 1 12); do
    r=$(python3 "$TMPD/oneshot.py" "$PX_BREAKER" 2>/dev/null || true)
    [ "$r" = "pong" ] && BREAK_OK=$((BREAK_OK+1))
done
assert_eq "$BREAK_OK" "12" "12 exchanges against a backend that closes after answering"

circ=$("$BIN" stats hc_breaker 2>/dev/null | grep -c "circuit:open" || true)
assert_eq "$circ" "0" "no circuit opened by a backend closing cleanly"

# ── 5. and nor does a client that aborts ────────────────────────────────────
#
# The other half of the same fault, and the one that costs more.  close_pair
# sets the backend `closing` and then calls shutdown(fd, SHUT_RD) so that a read
# still armed on it completes now instead of whenever TCP gets round to it —
# and SHUT_RD makes that read return 0.  Each of those completions arrived at
# the breaker looking exactly like a backend that had hung up.
#
# A client that aborts mid-exchange is the ordinary way to reach it, so a proxy
# in front of a perfectly healthy backend opened its breaker after five of them
# and answered every later client with an instant EOF.  Measured on 8affb1f
# with a storm of RSTing connections: 5018 connections, 60 messages delivered,
# 5012 clients given EPIPE and the circuit open — so this predates the
# half-close work; it was unreachable in TCP mode only because splice was the
# default and the splice legs are torn down without a backend read completing.
#
# Twenty aborts is four times circuit_threshold.  The assertion that
# discriminates is the exchange AFTER them: an open breaker is invisible until
# somebody asks the proxy to do something.
cat > "$TMPD/abort.py" <<'PY'
import socket, struct, sys
port = int(sys.argv[1])
try:
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.sendall(b"z" * 8192)
    s.close()
except Exception:
    pass
PY
for _ in $(seq 1 20); do
    python3 "$TMPD/abort.py" "$PX_BREAKER" 2>/dev/null || true
done
sleep 0.5
AFTER_OK=0
for _ in $(seq 1 5); do
    r=$(python3 "$TMPD/oneshot.py" "$PX_BREAKER" 2>/dev/null || true)
    [ "$r" = "pong" ] && AFTER_OK=$((AFTER_OK+1))
done
assert_eq "$AFTER_OK" "5" "proxy still serves after 20 aborting clients"

circ=$("$BIN" stats hc_breaker 2>/dev/null | grep -c "circuit:open" || true)
assert_eq "$circ" "0" "no circuit opened by clients aborting"

echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
echo "DONE"
