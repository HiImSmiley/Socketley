#!/usr/bin/env bash
# suite: quiet
# Integration test: what --idle-timeout does to a client waiting on a backend.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# The idle sweep set `closing = true` and shutdown(SHUT_RD) and left the actual
# teardown to an armed read coming back with res == 0.  On a client whose read
# is NOT armed -- an HTTP half-close hold, or a backpressure pause on a large
# upload -- no completion is coming, and every later path is gated on !closing:
#
#   forward_to_client() drops the backend's answer, because the client is
#   marked closing.
#   detach_and_pool_backend() is skipped, so the backend leg is missing from
#   the pool for as long as the pair lives.
#   the deadline sweep skips closing connections, so no 504 fires either.
#
# The pair then lives until the BACKEND gives up, and the client is left
# holding an open socket that will never carry a byte.  close_pair(force) is
# what the sweep does now; for a client that does have a read armed it is the
# same thing, because close_pair sets the flag and shuts the read side itself.
#
# ─── WHY THIS FILE IS SLOW ─────────────────────────────────────────────────
#
# The sweep timer is a fixed 30 seconds, so the window has to be straddled
# rather than simulated: the backend holds the request for 90 s and the client
# waits 50.  Fixed, the client's socket ends at the sweep, around 31 s.  Broken,
# nothing ends it inside the wait at all.  Declared `suite: quiet` because it
# measures elapsed time.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: the idle sweep tears the pair down ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

BE=$((SL_PORT_BASE+1412))
PX=$((SL_PORT_BASE+1413))

daemon_isolate proxyidlesweep
trap 'kill ${BE_PID:-0} 2>/dev/null; daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

# A backend that accepts, reads the request, and then says nothing for a long
# time.  Not a socketley server: the point is a request that is genuinely still
# in flight when the sweep runs, and nothing in the tree holds one on purpose.
python3 -c "
import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $BE)); s.listen(8)
while True:
    try:
        c, _ = s.accept()
        c.recv(65536)
        time.sleep(90)
        c.close()
    except Exception:
        break" >/dev/null 2>&1 &
BE_PID=$!
sleep 0.7

"$BIN" create proxy is_p -p "$PX" --backend "127.0.0.1:$BE" \
    --idle-timeout 1 --backend-timeout 0 -s >/dev/null 2>&1
sleep 1.5

# How long until the client's socket ends, one way or the other.  Reported as a
# number rather than a verdict, so a failure says what actually happened.
OUT=$(python3 -c "
import socket, time
t0 = time.time()
try:
    s = socket.create_connection(('127.0.0.1', $PX), timeout=5)
    s.sendall(b'GET /is_p/x HTTP/1.1\r\nHost: b\r\n\r\n')
    # The half close is the whole point: the proxy sees the client's EOF, takes
    # the hold, and arms NO read on it -- so the sweep's mark has no completion
    # to be finished by.  A client that keeps its write side open has a read
    # armed and is torn down correctly even on the broken build.
    s.shutdown(socket.SHUT_WR)
    s.settimeout(50)
    d = s.recv(4096)
    s.close()
    print('%s %.1f' % ('ENDED' if not d else 'ANSWERED', time.time() - t0))
except socket.timeout:
    print('STILL-OPEN %.1f' % (time.time() - t0))
except Exception as e:
    print('%s %.1f' % (type(e).__name__, time.time() - t0))" 2>/dev/null)
VERDICT=${OUT%% *}
ELAPSED=${OUT##* }

case "$VERDICT" in
    ENDED|ConnectionResetError)
        ok "the swept client's socket ended after ${ELAPSED}s, at the sweep" ;;
    ANSWERED)
        ok "the client was answered after ${ELAPSED}s, which is also not a stranded pair" ;;
    *)
        bad "an idle client whose read is not armed is torn down, not just marked" \
            "the client socket was '$VERDICT' after ${ELAPSED}s with the backend still holding" \
            "the request;" \
            "STILL-OPEN is the defect: closing = true plus SHUT_RD waits for a completion" \
            "that is not coming, the answer is dropped by forward_to_client, the backend leg" \
            "never returns to the pool, and the deadline sweep skips the pair because it is" \
            "already marked" ;;
esac

"$BIN" stop is_p >/dev/null 2>&1; "$BIN" remove is_p >/dev/null 2>&1
kill "$BE_PID" 2>/dev/null; wait "$BE_PID" 2>/dev/null
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
