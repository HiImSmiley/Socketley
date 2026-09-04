#!/usr/bin/env bash
# Integration test: `restart NAME -i` attaches, the way `start NAME -i` does.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# `start` routes -i to cli_interactive(), which holds the connection open and
# pumps stdin and stdout through it.  `restart` did not.  It ACCEPTS -i --- the
# argument check skips it by name, and both the man page and --help say the
# extra flags go to `start`, "which understands only -i" --- and then builds
# "start <name> -i" as an ordinary string and hands it to ipc_send(): one
# request, one answer, socket closed.
#
# It is worse than doing nothing.  The daemon honours -i on whatever connection
# it arrives on (daemon_handler.cpp: conn->interactive = true, then
# add_interactive_fd), so the session was registered and torn down in the same
# breath, and the operator got a shell prompt back with rc 0.
#
# ─── HOW IT IS ASSERTED ────────────────────────────────────────────────────
#
# By whether the command STAYS.  An interactive session polls stdin and the
# daemon socket until one of them ends, so with stdin held open by a fifo it
# must not return on its own.  `timeout` killing it is the pass.
#
# stdin comes from a fifo with a writer parked on it rather than from /dev/null,
# which would EOF immediately and end even a correct session --- that would make
# this file pass on the broken build for the wrong reason.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: restart -i attaches ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

P=$((SL_PORT_BASE+1472))

daemon_isolate restarti
trap 'kill ${HOLDER:-0} 2>/dev/null; daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

"$BIN" create server ri -p "$P" >/dev/null 2>&1
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$P" 2>/dev/null && break; sleep 0.1; done
sleep 0.4

FIFO="$SOCKETLEY_TMPD/in"; mkfifo "$FIFO"
sleep 300 > "$FIFO" &      # parks a writer, so stdin never reaches EOF
HOLDER=$!

# Returns "stayed" when timeout had to kill it, "returned" otherwise --- which
# is exactly the difference between a session and a request.
attaches() {
    timeout 4 "$BIN" "$@" < "$FIFO" >/dev/null 2>&1
    [ $? -eq 124 ] && echo stayed || echo returned
}

# The control first: if `start -i` does not attach on this build, nothing below
# distinguishes anything.
GOT_START=$(attaches start ri -i)
if [ "$GOT_START" = "stayed" ]; then
    ok "start -i holds the session open"
else
    bad "start -i attaches at all" \
        "it $GOT_START within 4 s;" \
        "the assertion below compares restart against this, so it means nothing now"
fi

"$BIN" stop ri >/dev/null 2>&1
sleep 0.5
"$BIN" start ri >/dev/null 2>&1
sleep 1.2

GOT_RESTART=$(attaches restart ri -i)
if [ "$GOT_RESTART" = "stayed" ]; then
    ok "restart -i holds the session open too"
else
    bad "restart -i attaches" \
        "it $GOT_RESTART, where start -i stayed;" \
        "that is the defect: restart accepts -i by name and then sends" \
        "\"start <name> -i\" through ipc_send --- one request, one answer, socket" \
        "closed --- while the daemon had already registered the interactive fd"
fi

# And it really restarted, so a build that attached by never doing the work
# would not pass the line above.
sleep 1.5
STATE=$("$BIN" ls 2>/dev/null | awk '$2 == "ri" { print $7; exit }')
if [ "$STATE" = "Up" ]; then
    ok "and the runtime is running afterwards ($STATE)"
else
    bad "restart -i still restarts" "ls reads '${STATE:-<none>}' after it"
fi

kill "$HOLDER" 2>/dev/null; HOLDER=""
"$BIN" stop ri >/dev/null 2>&1; "$BIN" remove ri >/dev/null 2>&1
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
