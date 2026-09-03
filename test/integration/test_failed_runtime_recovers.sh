#!/usr/bin/env bash
# Integration test: `failed` is a state a runtime comes back from.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# A worker that cannot bind leaves its runtime `failed`, which is right.  What
# was wrong is that nothing led out of it: runtime_instance::start() took only
# `created` and `stopped`, so after the operator had removed the cause, `start`
# answered "failed to start: NAME" with rc 1 and no line in the daemon log --
# because no path knew the reason -- and `stop` answered 0 while changing
# nothing.  The only way back was remove + create, and the CLI never said so.
# The lua path already knew ("remove it and create it anew"); the operator did
# not.
#
# The half that is easy to miss is on the daemon's side.  Letting start() take
# `failed` is not enough on its own: the dead supervisors are still in
# m_proxy_workers, and reconcile_proxy_workers() counts SUPERVISORS rather than
# children, so it would find the set complete and fork nothing.  The runtime
# would come up `Up` with no process and no port -- which reads as fixed and is
# worse than the refusal it replaced.  So this file asserts the runtime SERVES,
# not that `ls` is happy.
#
# The failure is produced by occupying the port with a plain listener: socketley
# binds with SO_REUSEPORT, and a socket already on the address without it makes
# that bind fail.  A privileged port would not do -- this box has
# ip_unprivileged_port_start = 0 and binds 80 as an ordinary user.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: a failed runtime comes back ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

P=$((SL_PORT_BASE+1390))
PS=$((SL_PORT_BASE+1392))

daemon_isolate failedrecovers
trap 'kill ${HOLDER:-0} 2>/dev/null; daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

state_of() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2 == n { print $7; exit }'; }
serves()   {
    python3 -c "
import socket
try:
    s=socket.create_connection(('127.0.0.1',$1),timeout=3); s.close(); print('yes')
except Exception: print('no')" 2>/dev/null
}
occupy() {   # occupy PORT -- a plain listener, so socketley's SO_REUSEPORT bind fails
    python3 -c "
import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',$1)); s.listen(8); time.sleep(60)" &
    HOLDER=$!
    sleep 1
}
release() { kill "${HOLDER:-0}" 2>/dev/null; wait "${HOLDER:-0}" 2>/dev/null; HOLDER=0; sleep 0.5; }

# ── 1. It really is failed, and for the reason we think ────────────────────
occupy "$P"
"$BIN" create server fx -p "$P" -s >/dev/null 2>&1
CREATE_RC=$?
sleep 1.5
ST1=$(state_of fx)
if [ "$ST1" = "Failed" ] && [ "$CREATE_RC" -ne 0 ]; then
    ok "a worker that cannot bind leaves the runtime Failed, and create says so (rc $CREATE_RC)"
else
    bad "the setup produces a failed runtime" \
        "state is '${ST1:-<none>}' and create returned $CREATE_RC;" \
        "every assertion below needs a runtime that really failed to bind"
fi

# ── 2. With the cause gone, start brings it back -- and it SERVES ──────────
release
"$BIN" start fx >/dev/null 2>&1
START_RC=$?
sleep 2
ST2=$(state_of fx)
SERVED=$(serves "$P")
if [ "$START_RC" -eq 0 ] && [ "$ST2" = "Up" ] && [ "$SERVED" = "yes" ]; then
    ok "start on a failed runtime returns 0, moves it to Up, and the port answers"
else
    bad "a failed runtime starts again once its cause is gone" \
        "start returned $START_RC, state is '${ST2:-<none>}', the port answered '$SERVED';" \
        "rc 1 with 'failed to start' is the old refusal; Up with 'no' is the worse half --" \
        "start() taking \`failed\` while reconcile_proxy_workers() still counts the dead" \
        "supervisors, so nothing was forked and the state is a lie"
fi

# ── 3. stop on a failed runtime is not a silent no-op ──────────────────────
#
# Separate runtime, because the one above is running now.  stop() returned
# false for anything but `running` and cmd_stop stayed quiet about it, so the
# operator got rc 0 and a runtime still reading Failed.
occupy "$PS"
"$BIN" create server fs -p "$PS" -s >/dev/null 2>&1
sleep 1.5
ST3=$(state_of fs)
"$BIN" stop fs >/dev/null 2>&1
STOP_RC=$?
sleep 0.5
ST4=$(state_of fs)
release
if [ "$ST3" = "Failed" ] && [ "$STOP_RC" -eq 0 ] && [ "$ST4" = "Stopped" ]; then
    ok "stop on a failed runtime moves it to Stopped instead of answering 0 and doing nothing"
else
    bad "stop on a failed runtime does what it says" \
        "before stop '${ST3:-<none>}', stop returned $STOP_RC, after '${ST4:-<none>}';" \
        "Failed after a stop that returned 0 is the silent no-op this catches"
fi

# ── 4. And the way back through stop is open too ───────────────────────────
"$BIN" start fs >/dev/null 2>&1
RC4=$?
sleep 2
ST5=$(state_of fs)
SERVED2=$(serves "$PS")
if [ "$RC4" -eq 0 ] && [ "$ST5" = "Up" ] && [ "$SERVED2" = "yes" ]; then
    ok "a runtime stopped out of failed starts and serves like any other"
else
    bad "stopped-from-failed is an ordinary stopped runtime" \
        "start returned $RC4, state '${ST5:-<none>}', port answered '$SERVED2'"
fi

"$BIN" stop fx >/dev/null 2>&1; "$BIN" remove fx >/dev/null 2>&1
"$BIN" stop fs >/dev/null 2>&1; "$BIN" remove fs >/dev/null 2>&1
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
