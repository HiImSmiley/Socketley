#!/usr/bin/env bash
# Integration test: a TCP client that resets while its backend is being opened
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A TCP proxy connects first and reads second, so the client's first bytes are
# already in the kernel when the read is finally armed.  A client that sends and
# then resets in the same breath therefore produces this order:
#
#   the abort watch fires POLLERR|POLLHUP and close_pair() begins the teardown
#   it defers, because a read is armed and the ring still owes a completion
#   that read completes with the bytes queued AHEAD of the reset, not the reset
#
# and the read path took them for a fresh request.  backend_fd was already -1,
# so select_and_resolve_backend() and connect_to_backend() ran and opened a NEW
# backend socket for a client that was already closing -- after which the
# re-arm declines, correctly, because it is gated on !closing.  Nothing was left
# that could finish the pair: every later path is gated on !closing too, and
# close_pair() is only ever re-entered from a completion.
#
# Measured on the build without the stop, 300 clients that send 212 bytes and
# reset with SO_LINGER(1,0):
#
#   live connections after the storm   217 / 168 / 170   flat for 12s, no drain
#   a 10ms pause before the reset                    0   the window is that narrow
#   the same storm closing with FIN                  0   only the reset shape
#   stats: total_connections 170, connections 170       every one that was read
#
# ─── WHY THE ENVIRONMENT VARIABLE ───────────────────────────────────────────
#
# SOCKETLEY_RECV_MULTISHOT=0 is not a preference here, it is what makes the
# defect observable.  A multishot recv is never disarmed, so it makes the same
# mistake -- the log shows it opening the same doomed backend leg -- and then
# recovers on the very next completion, which carries -ECONNRESET.  With the
# default arm this file would be green on a build that leaks, which is the one
# thing a regression test must not be.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a storm that never happened, so a run that proves nothing fails loudly
#   * connections left live with nothing armed on them, which is the defect
#   * the descriptors behind them, which is what the leak actually costs
#   * the same storm closed politely, which is the control that keeps this file
#     about the reset path rather than about aborts in general
#   * the proxy still serving afterwards, so "drained" cannot mean "wedged"
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

if ! command -v python3 >/dev/null 2>&1; then
    echo "=== Integration: a TCP client resetting while its backend opens ==="
    echo "  SKIP: python3 not available"
    echo "  Results: 0/0 passed (0 failed)"
    exit 0
fi

daemon_isolate tcpreset
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
BEPID=""
cleanup(){ [ -n "$BEPID" ] && kill -9 "$BEPID" 2>/dev/null; rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: a TCP client resetting while its backend opens ==="

PPORT=$((SL_PORT_BASE + 1740))
BPORT=$((SL_PORT_BASE + 1741))
STORM=300
DRAIN_SECS=8
# A floor rather than a target: the kernel drops connections reset before they
# are accepted, so well under STORM is normal and near zero means the storm
# never reached the proxy.
MIN_SEEN=200           # of STORM.  Was 40, which is what a floor becomes when the
                       # storm is a race: the count read 19 of 300 under load and 206
                       # idle on the same build, so 40 caught neither a degraded storm
                       # nor a healthy one.  With the reset paced behind the read it is
                       # 300 of 300 in four loaded runs, and a floor can mean something
                       # again: two thirds of the storm, or the box is too slow to be
                       # measuring this at all.

# The backend holds a payload beginning with SLOW for 150ms, so the reply is
# still owed when the client stops existing.
cat >"$WORK/be.py" <<'PY'
import socket, sys, threading, time
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1]))); srv.listen(512)
def handle(c):
    c.settimeout(30)
    try:
        while True:
            d = c.recv(65536)
            if not d: return
            if d.startswith(b"SLOW"): time.sleep(0.15)
            c.sendall(d)
    except OSError: pass
    finally:
        try: c.close()
        except OSError: pass
while True:
    try: cl, _ = srv.accept()
    except OSError: break
    threading.Thread(target=handle, args=(cl,), daemon=True).start()
PY

# how=rst sets SO_LINGER(1,0) so close() sends a reset instead of a FIN, which
# is the whole difference this file is about.
cat >"$WORK/storm.py" <<'PY'
import socket, struct, sys, time
port, n, how = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
sent = 0
for _ in range(n):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=2)
    except OSError:
        continue
    try:
        s.sendall(b"SLOW-abort:" + b"v" * 200 + b"\n"); sent += 1
    except OSError:
        pass
    # A moment before the reset, and it is not a nicety.  SO_LINGER 0 discards
    # whatever the peer has not read yet, so without this the count below is a
    # measure of how promptly the proxy got round to reading -- 19 of 300 under
    # load against 206 idle, on the same build.  And a connection whose bytes
    # were discarded contributes nothing here anyway: the defect needs the
    # request READ before the reset, because what leaked was a second backend
    # opened for bytes delivered after the client had gone.  The reset still
    # lands inside the backend open, which takes 150ms.
    time.sleep(0.005)
    if how == "rst":
        try: s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        except OSError: pass
    try: s.close()
    except OSError: pass
    time.sleep(0.002)
print(sent)
PY

# One exchange that completes, used after each storm so "no live connections"
# cannot be satisfied by a proxy that stopped working.
cat >"$WORK/probe.py" <<'PY'
import socket, sys
try:
    s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
    s.settimeout(5)
    s.sendall(b"FAST-probe\n")
    buf = b""
    while b"\n" not in buf:
        d = s.recv(4096)
        if not d: break
        buf += d
    s.close()
    print("OK" if buf.strip() == b"FAST-probe" else "WRONG")
except OSError:
    print("DEAD")
PY

python3 "$WORK/be.py" "$BPORT" >"$WORK/be.log" 2>&1 &
BEPID=$!
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$BPORT " && break; sleep 0.1; done
if ! ss -ltn 2>/dev/null | grep -q ":$BPORT "; then
    echo "  FATAL: the echo backend never bound $BPORT"; echo "  Results: 0/0 passed (0 failed)"; exit 2
fi

# See the header: the default arm hides this defect, so the test would be green
# on a leaking build without it.
export SOCKETLEY_RECV_MULTISHOT=0
daemon_start "$BIN"
"$BIN" create proxy tcpr -p "$PPORT" --backend "127.0.0.1:$BPORT" --protocol tcp -s >/dev/null 2>&1 || true
for _ in $(seq 1 150); do ss -ltn 2>/dev/null | grep -q ":$PPORT " && break; sleep 0.1; done
if ! ss -ltn 2>/dev/null | grep -q ":$PPORT "; then
    echo "  FATAL: the proxy never bound $PPORT"; echo "  Results: 0/0 passed (0 failed)"; exit 2
fi
WORKER=$(ss -ltnp 2>/dev/null | awk -v p=":$PPORT" '$4 ~ p"$" {
    if (match($0, /pid=[0-9]+/)) print substr($0, RSTART+4, RLENGTH-4) }' | head -1)
if [ -z "${WORKER:-}" ]; then
    echo "  FATAL: no pid for the proxy listener"; echo "  Results: 0/0 passed (0 failed)"; exit 2
fi
# The worker must carry the arm this file claims, or every row below is about
# a configuration nobody selected.
CARRIED=$(tr '\0' '\n' <"/proc/$WORKER/environ" 2>/dev/null |
          awk -F= '/^SOCKETLEY_RECV_MULTISHOT=/{print $2}')
if [ "${CARRIED:-unset}" != "0" ]; then
    echo "  FATAL: the worker carries SOCKETLEY_RECV_MULTISHOT='${CARRIED:-unset}', not 0"
    echo "  Results: 0/0 passed (0 failed)"; exit 2
fi

socks(){ ls -l "/proc/$WORKER/fd" 2>/dev/null | grep -c 'socket:' || echo 0; }
conns(){ "$BIN" stats tcpr 2>/dev/null | grep -m1 '^connections:' | cut -d: -f2 | tr -d '[:space:]'; }
seen(){ "$BIN" stats tcpr 2>/dev/null | grep -m1 '^total_connections:' | cut -d: -f2 | tr -d '[:space:]'; }
drain(){   # seconds -> the last count seen, 0 as soon as it drains
    local end v; end=$(( $(date +%s) + $1 ))
    while :; do
        v=$(conns)
        case "$v" in ''|*[!0-9]*) v=unreadable ;; 0) echo 0; return ;; esac
        [ "$(date +%s)" -ge "$end" ] && break
        sleep 0.2
    done
    echo "$v"
}

BASE_SOCKS=$(socks)

# ── 1. the storm has to have reached the proxy ──────────────────────────────
SENT=$(timeout 120 python3 "$WORK/storm.py" "$PPORT" "$STORM" rst 2>/dev/null || echo 0)
SEEN=$(seen)
case "$SEEN" in ''|*[!0-9]*) SEEN=0 ;; esac
if [ "$SEEN" -ge "$MIN_SEEN" ]; then
    echo "  the proxy accepted and read $SEEN of $SENT reset connections"
    pass
else fail "the reset storm reached the proxy" \
          "stats reports total_connections=$SEEN after $SENT resets, floor is $MIN_SEEN" \
          "-- nothing below proves anything about a storm that never arrived"; fi

# ── 2. and none of them is still live ───────────────────────────────────────
LEFT=$(drain "$DRAIN_SECS")
if [ "$LEFT" = 0 ]; then pass
else fail "a reset during the backend open is reaped" \
          "still $LEFT live connections ${DRAIN_SECS}s after the last client went away" \
          "-- nothing is armed on them, so no completion is coming and they never end"; fi

# ── 3. nor are their descriptors ────────────────────────────────────────────
END_SOCKS=$(socks)
GREW=$(( END_SOCKS - BASE_SOCKS ))
if [ "$GREW" -le 8 ]; then
    echo "  worker sockets: $BASE_SOCKS before, $END_SOCKS after"
    pass
else fail "the descriptors behind them come back" \
          "worker socket descriptors went $BASE_SOCKS -> $END_SOCKS (+$GREW) over the storm" \
          "-- a stranded pair holds two, one dead client and one live backend leg"; fi

# ── 4. the control: the same storm closed politely was never the problem ────
# Restarted first, because on a build that leaks the corpses of storm 1 are
# still counted and this row would fail for the defect it exists to exclude.
"$BIN" stop tcpr >/dev/null 2>&1 || true
"$BIN" start tcpr >/dev/null 2>&1 || true
for _ in $(seq 1 150); do ss -ltn 2>/dev/null | grep -q ":$PPORT " && break; sleep 0.1; done
timeout 120 python3 "$WORK/storm.py" "$PPORT" "$STORM" fin >/dev/null 2>&1 || true
LEFT2=$(drain "$DRAIN_SECS")
if [ "$LEFT2" = 0 ]; then pass
else fail "a polite close is reaped too" \
          "still $LEFT2 live connections after a storm that closed with FIN" \
          "-- this shape drained on the build that leaked, so a failure here is" \
          "   a different defect than the one this file is named for"; fi

# ── 5. and the proxy still works ────────────────────────────────────────────
VERDICT=$(timeout 30 python3 "$WORK/probe.py" "$PPORT" 2>/dev/null || echo DEAD)

if [ "$VERDICT" = OK ]; then pass
else fail "the proxy still serves after the storm" \
          "a plain request through it answered '$VERDICT'" \
          "-- draining must not be reached by breaking the runtime"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ] || exit 1
