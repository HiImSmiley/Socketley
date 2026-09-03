#!/usr/bin/env bash
# Integration test: a restored runtime has a process when the daemon says it is up.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# restore_runtimes() creates the runtimes a state file says were running and
# puts them in `running`.  It forks nothing.  The first child came from the
# health tick, which runs every two seconds, so between "daemon started" in the
# log and that tick every restored out-of-process runtime read `Up` in `ls`
# with no process behind it and nothing on its port.
#
# Two seconds is small enough to never be noticed by hand and large enough to
# be the whole of a restart script: stop the daemon, start it, send the first
# request.  It is also exactly the window a supervisor restarting the daemon
# runs in.  The window is not a race in the usual sense -- it is deterministic,
# and it closes on a timer that has nothing to do with the runtime.
#
# So the assertion is made IMMEDIATELY after daemon_start returns, which waits
# for "daemon started" and nothing more.  A sleep here would hide the defect
# this file exists for.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: a restored runtime is up when the daemon says so ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

P=$((SL_PORT_BASE+1398))

daemon_isolate restorefork
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

WWW="$SOCKETLEY_TMPD/www"; mkdir -p "$WWW"
printf '<h1>restored</h1>\n' > "$WWW/index.html"
"$BIN" create server rs -p "$P" --http "$WWW" -s >/dev/null 2>&1
sleep 1.5

serves() {
    python3 -c "
import socket
try:
    s=socket.create_connection(('127.0.0.1',$1),timeout=2)
    s.sendall(b'GET / HTTP/1.0\r\n\r\n'); d=s.recv(400); s.close()
    print('yes' if b'restored' in d else 'wrong')
except Exception as e: print(type(e).__name__)" 2>/dev/null
}

if [ "$(serves "$P")" = "yes" ]; then ok "the runtime serves before the daemon is restarted"
else bad "the runtime serves before the restart" "it did not; nothing below would mean anything"; fi

# ── The restart, and the first question asked without a sleep ──────────────
#
# The shape test_state_was_running.sh uses, minus its closing `sleep 1.5`:
# that sleep is longer than the health tick and would hide exactly the window
# this file is about.  daemon_stop is not used because it deletes the isolate's
# directory, and the state being restored lives in it.
restart_daemon() {
    kill "$SOCKETLEY_DPID" 2>/dev/null || true
    local i
    for i in $(seq 1 60); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
    wait "$SOCKETLEY_DPID" 2>/dev/null || true
    : > "$SOCKETLEY_DLOG"
    "$BIN" daemon >>"$SOCKETLEY_DLOG" 2>&1 &
    SOCKETLEY_DPID=$!
    for i in $(seq 1 100); do
        grep -q "daemon started" "$SOCKETLEY_DLOG" 2>/dev/null && break
        sleep 0.1
    done
}
restart_daemon

# Everything from here to the first health tick is the window.
FIRST=$(serves "$P")
PIDCOL=$("$BIN" ls 2>/dev/null | awk '$2 == "rs" { print $1; exit }')
STATE=$("$BIN" ls 2>/dev/null | awk '$2 == "rs" { print $7; exit }')

if [ "$FIRST" = "yes" ]; then
    ok "the restored runtime answers on the first request after 'daemon started'"
else
    bad "a restored runtime has a process when the daemon says it is up" \
        "the first request got '$FIRST' while ls said '${STATE:-<none>}' (id ${PIDCOL:-<none>});" \
        "Up with a refused connection is restore_runtimes() setting the state and" \
        "leaving the fork to the health tick, up to two seconds later -- which is" \
        "the whole of a restart script, and of a supervisor restarting the daemon"
fi

# And it stays up, so the assertion above is about the window and not about a
# runtime that never came back at all.
sleep 3
LATER=$(serves "$P")
if [ "$LATER" = "yes" ]; then
    ok "and it is still serving three seconds later"
else
    bad "the restored runtime stays up" "it answered '$LATER' after the health tick"
fi

"$BIN" stop rs >/dev/null 2>&1; "$BIN" remove rs >/dev/null 2>&1
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
