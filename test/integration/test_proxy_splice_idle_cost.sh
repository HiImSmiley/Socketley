#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Integration test: what a --protocol tcp proxy costs while nothing is happening.
#
# A TCP proxy forwards with splice, and io_uring never runs IORING_OP_SPLICE on
# the submitting thread: the opcode is prepped REQ_F_FORCE_ASYNC, so every splice
# is handed to an io-wq worker and executed there synchronously.  A splice armed
# on a socket that has no data yet does not wait for free -- it sits inside
# tcp_splice_read on a kernel thread, holding the destination pipe's mutex.
#
# So "arm a splice and let the kernel wait" costs one thread per connection for
# as long as the peer is quiet, which on a keep-alive connection is nearly all
# the time.  Whether it also burns a CPU turns on an accident: tcp_splice_read
# decides whether to wait from the socket file's O_NONBLOCK rather than from the
# splice flags.  Accepted client sockets are blocking, so that leg parks a
# thread; backend sockets are opened SOCK_NONBLOCK for the async connect, so that
# leg answers -EAGAIN at once and the completion handler resubmits it -- a
# resubmit loop with no bound, for as long as the backend has nothing to say.
#
# Measured on the tree that had it, with a proxy nobody was using:
#
#     idle connections   daemon CPU   io-wq threads   parked in the socket wait
#                    0         0.0%               0                          0
#                    4        95.7%               7                          4
#                   16       143.0%              20                         16
#                   48       210.6%              53                         48
#
# and after arming a readiness poll instead, every row reads 0.0% / 1 / 0.
#
# That is the whole cost of doing nothing, and it is also the reason a request
# could go missing: with every worker parked in somebody else's idle read and the
# run queue churning, the splice carrying an actual response waited behind them.
# Twelve keep-alive clients through a group gateway saw 504s on requests their
# backend had answered in 0.4 ms.
#
# WHAT THIS TEST WILL NOT DO
#
# It will not pass on a proxy that is merely broken.  Zero threads and zero CPU
# is also what a proxy that never accepted anything looks like, so the idle
# measurement is bracketed by two transfers: one before it, proving the pipeline
# forwards at all, and one *on a connection that was open for the whole idle
# window*, proving those connections were live splice pipelines rather than
# sockets nothing was watching.  Without the second, the cheap way to pass would
# be to stop arming the pipeline at all.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"

TMPD=$(mktemp -d /tmp/socketley-spidle-XXXXXX)
export HOME="$TMPD/home"
export SOCKETLEY_SOCKET="$TMPD/daemon.sock"
mkdir -p "$HOME"

PORT_BASE=$((SL_PORT_BASE+660))
BE=$((PORT_BASE+1))
PX=$((PORT_BASE+2))

# Sixteen is well past the point the cost showed: at four the daemon already
# burned 95.7% of a core.  It is also small enough that a machine with a
# different number of CPUs does not change what is being asked -- the claim is
# "per connection", not "per core".
IDLE=${IDLE:-16}

DPID=""; BEPID=""
PASS=0; FAIL=0; HERR=0; TOTAL=0

cleanup() {
    "$BIN" stop spidle >/dev/null 2>&1 || true
    "$BIN" remove spidle >/dev/null 2>&1 || true
    [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null
    if [ -n "$DPID" ]; then
        kill "$DPID" 2>/dev/null || true
        for _ in $(seq 1 50); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.1; done
        kill -9 "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
    rm -rf "$TMPD"
}
trap cleanup EXIT

ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad()  { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
herr() { TOTAL=$((TOTAL+1)); HERR=$((HERR+1)); echo "  NOT MEASURABLE [$1]: $2"; }

echo "=== Integration: what an idle TCP splice proxy costs ==="

if ! command -v python3 >/dev/null 2>&1; then echo "  SKIP: python3 required"; exit 0; fi

# ---- echo backend ---------------------------------------------------------
cat > "$TMPD/be.py" <<'PYEOF'
import socket, threading, sys
port = int(sys.argv[1])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(256)
print("ready", flush=True)


def handle(c):
    try:
        while True:
            d = c.recv(4096)
            if not d:
                break
            c.sendall(d)
    except Exception:
        pass
    finally:
        c.close()


while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PYEOF

python3 "$TMPD/be.py" "$BE" >"$TMPD/be.log" 2>&1 &
BEPID=$!
for _ in $(seq 1 60); do grep -q ready "$TMPD/be.log" 2>/dev/null && break; sleep 0.1; done
if ! grep -q ready "$TMPD/be.log" 2>/dev/null; then
    herr "the echo backend came up" "nothing on 127.0.0.1:$BE after 6s"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $HERR not measurable)"
    exit 1
fi

"$BIN" daemon >"$TMPD/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 100); do [ -S "$SOCKETLEY_SOCKET" ] && break; sleep 0.1; done
sleep 0.5
if ! kill -0 "$DPID" 2>/dev/null; then
    herr "the daemon came up" "it exited during start; see $TMPD/daemon.log"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $HERR not measurable)"
    exit 1
fi

if "$BIN" create proxy spidle -p "$PX" --backend "127.0.0.1:$BE" --protocol tcp -s \
     >"$TMPD/create.log" 2>&1; then
    ok
else
    bad "the tcp proxy was created" "$(cat "$TMPD/create.log")"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $HERR not measurable)"
    exit 1
fi
sleep 0.6

# ---- the measurement ------------------------------------------------------
# One python process does the whole thing so the connections it opens stay open
# across the idle window; a shell loop cannot hold sockets.
OUT=$(python3 - "$PX" "$IDLE" "$DPID" <<'PYEOF'
import os, socket, sys, time

px, idle_n, dpid = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
HZ = os.sysconf("SC_CLK_TCK")


def cpu_ticks(pid):
    with open("/proc/%d/stat" % pid) as f:
        p = f.read().rsplit(")", 1)[1].split()
    return int(p[11]) + int(p[12])


def iowq(pid):
    total = parked = 0
    for t in os.listdir("/proc/%d/task" % pid):
        try:
            with open("/proc/%d/task/%s/comm" % (pid, t)) as f:
                if not f.read().startswith("iou-wrk"):
                    continue
            total += 1
            with open("/proc/%d/task/%s/wchan" % (pid, t)) as f:
                if "wait_woken" in f.read():
                    parked += 1
        except OSError:
            pass
    return total, parked


def roundtrip(sock, payload):
    sock.settimeout(10.0)
    sock.sendall(payload)
    try:
        return sock.recv(len(payload)) == payload
    except socket.timeout:
        return False


# Control 1: the pipeline forwards at all.
warm = socket.create_connection(("127.0.0.1", px), timeout=10)
time.sleep(0.3)
print("warm=%d" % (1 if roundtrip(warm, b"hello-warm\n") else 0))
warm.close()

conns = []
for _ in range(idle_n):
    conns.append(socket.create_connection(("127.0.0.1", px), timeout=10))
time.sleep(1.0)                       # let every pipeline arm

t0, w0 = cpu_ticks(dpid), time.time()
time.sleep(3.0)
t1, w1 = cpu_ticks(dpid), time.time()
cpu = 100.0 * ((t1 - t0) / HZ) / (w1 - w0)
total, parked = iowq(dpid)
print("cpu=%.1f" % cpu)
print("workers=%d" % total)
print("parked=%d" % parked)

# Control 2: one of the connections that was open for the whole idle window
# still carries data.  This is what stops "cost nothing" from being satisfied by
# a proxy that stopped watching its sockets.
print("late=%d" % (1 if roundtrip(conns[0], b"hello-late\n") else 0))
for c in conns:
    try:
        c.close()
    except OSError:
        pass
PYEOF
) || true

WARM=$(printf '%s\n' "$OUT" | sed -n 's/^warm=//p')
CPU=$(printf '%s\n' "$OUT" | sed -n 's/^cpu=//p')
WORKERS=$(printf '%s\n' "$OUT" | sed -n 's/^workers=//p')
PARKED=$(printf '%s\n' "$OUT" | sed -n 's/^parked=//p')
LATE=$(printf '%s\n' "$OUT" | sed -n 's/^late=//p')

if [ -z "$CPU" ] || [ -z "$PARKED" ] || [ -z "$WARM" ] || [ -z "$LATE" ]; then
    herr "the idle cost could be measured" "the probe produced: ${OUT:-<nothing>}"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $HERR not measurable)"
    exit 1
fi

echo "  idle=$IDLE cpu=${CPU}% iowq_workers=$WORKERS parked=$PARKED"

# Control 1.
if [ "$WARM" = "1" ]; then ok; else
    bad "the tcp proxy forwards" "no echo back through the proxy on a fresh connection"
fi

# The two claims.  Both thresholds sit inside a gap that was measured, not
# guessed: at this connection count the defect produced 143% and 16 parked
# threads, so 15% and 2 are an order of magnitude clear of it on one side and
# comfortably above the 0.0% / 0 the fixed build produces on the other.
CPU_INT=${CPU%.*}
if [ "${CPU_INT:-999}" -le 15 ]; then ok; else
    bad "an idle tcp proxy burns no CPU" \
        "$IDLE silent connections cost ${CPU}% of a core over 3s"
fi

if [ "${PARKED:-999}" -le 2 ]; then ok; else
    bad "an idle connection does not hold a kernel thread" \
        "$PARKED io-wq workers parked in a socket wait with $IDLE silent connections"
fi

# Control 2 — and it has to be last, because it is the one that says the
# connections the two claims above were measured against were real.
if [ "$LATE" = "1" ]; then ok; else
    bad "a connection idle through the window still carries data" \
        "no echo on a connection that was open for the whole measurement"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $HERR not measurable)"
if [ "$FAIL" -gt 0 ] || [ "$HERR" -gt 0 ]; then exit 1; fi
echo "  OK"
exit 0
