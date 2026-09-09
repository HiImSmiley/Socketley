#!/usr/bin/env bash
# Integration test: self.state on a script that defines no on_start.
#
# `self.state` is not a constant -- it is written by update_self_state() as the
# runtime moves -- and it was only ever written from inside invoke_on_start()
# and invoke_on_stop(), both of which returned early when the script had not
# defined the callback:
#
#     if (m_cb_on_start) { m_cb_on_start(); return true; }
#     if (!m_lua || !m_lua->has_on_start())
#         return true;                      <- the common case left here
#     m_lua->update_self_state("running");  <- so this never ran
#
# The initial value comes from the self table's construction, at script load,
# when the runtime is still `created`.  So a handler that defines only
# on_client_message read `self.state == "created"` for the whole life of a
# runtime that was serving traffic.  Measured, two identical servers, both `Up`
# in `ls`, both answering:
#
#     script with    on_start    state=running
#     script without on_start    state=created     <- while answering this very
#                                                     message
#
# It is a field a script can branch on, and it was wrong in the ordinary case
# and right in the rarer one, which is the worst way round for something nobody
# thinks to check.
#
# The fix is a move, not new logic: the write goes ahead of the early returns,
# because self.state is the RUNTIME's state and not the callback's.  start()
# stores runtime_running before invoke_on_start() is called, so the literal
# written there is the truth; stop() stores runtime_stopped after
# invoke_on_stop() returns, so "stopped" there says what the runtime is about
# to be -- which is what a script reading it inside on_stop was always told.
#
# Both servers below are deliberately identical apart from the presence of an
# empty on_start.  One assertion alone could not tell "the fix works" from "this
# runtime happens to report running"; the pair is what makes the difference
# attributable.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate selfstate
P_NO=$((SL_PORT_BASE+1998))
P_YES=$((SL_PORT_BASE+1999))
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    for n in ss_no ss_yes; do "$BIN" stop "$n" 2>/dev/null || true; done
    sleep 0.3
    for n in ss_no ss_yes; do "$BIN" remove "$n" 2>/dev/null || true; done
    daemon_stop
}
trap cleanup EXIT

check() {   # label expected actual
    TOTAL=$((TOTAL+1))
    if [ "$2" = "$3" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$1]: expected '$2', got '$3'"
    fi
}

L="$SOCKETLEY_TMPD"
cat > "$L/nostart.lua" <<'LUA'
-- No on_start, which is the ordinary shape of a handler and the one that read
-- `created` for its whole life.
function on_client_message(client_id, msg)
    self.send(client_id, "state=" .. tostring(self.state))
end
LUA
cat > "$L/withstart.lua" <<'LUA'
-- Identical, plus an empty on_start.  This is the control: it reported
-- `running` before the fix as well, so a difference between the two files is
-- the defect and a difference between the two RUNS is not.
function on_start() end
function on_client_message(client_id, msg)
    self.send(client_id, "state=" .. tostring(self.state))
end
LUA

echo "=== Integration: self.state without an on_start ==="

daemon_start "$BIN"

create_ok "a handler with no on_start"  \
    "$BIN" create server ss_no  -p "$P_NO"  --lua "$L/nostart.lua"   -s
create_ok "the same handler plus on_start" \
    "$BIN" create server ss_yes -p "$P_YES" --lua "$L/withstart.lua" -s

ready_tcp 127.0.0.1 "$P_NO"  || echo "  WARN: nothing listening on $P_NO"
ready_tcp 127.0.0.1 "$P_YES" || echo "  WARN: nothing listening on $P_YES"
sleep 0.5

# The runtime answers the question with the same call that proves it is
# serving: if the reply arrives at all, the runtime is running, so a `created`
# in that reply is self-contradictory on its face.
ask() {
    python3 - "$1" <<'PYEOF' 2>/dev/null || echo "PROBE-FAILED"
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); s.settimeout(2)
s.sendall(b"hi\n")
try:    print(s.recv(128).decode().strip() or "-")
except Exception: print("-")
PYEOF
}

# Both `Up`, so neither answer can be explained by the runtime not running.
for n in ss_no ss_yes; do
    TOTAL=$((TOTAL+1))
    if "$BIN" ls 2>/dev/null | grep -q "$n.*Up"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$n is up before it is asked]: $("$BIN" ls 2>/dev/null | grep "$n" || echo '<not listed>')"
    fi
done

check "no on_start: self.state is running" "state=running" "$(ask "$P_NO")"
check "with on_start: unchanged"           "state=running" "$(ask "$P_YES")"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
