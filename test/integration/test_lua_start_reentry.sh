#!/usr/bin/env bash
# Integration test: the management API called from on_start.
#
# ─── THE DEFECT THIS PINS ───────────────────────────────────────────────────
#
#     function on_start()
#         socketley.create("server", "sub", { port = ..., start = true })
#     end
#
# is the obvious way to bring a sub-server up as its parent starts, and it
# WEDGED THE DAEMON.  Not crashed — wedged, which is worse: the IPC socket went
# on accepting connections and answering none, so `ls`, `ps`, `stop` and every
# other command hung, and every runtime that daemon was serving went with it.
#
# The mechanism.  runtime_manager::start() held `mutex` in shared mode across
# runtime_instance::start(), which runs on_start; socketley.create asks the same
# std::shared_mutex for unique mode, on the same thread, and it is not
# recursive.  The daemon's only event-loop thread deadlocked against itself —
# measured, both threads parked in futex_do_wait with the listener still armed.
# The lock now covers the lookup and stops there.
#
# ─── WHY THE ASSERTIONS ARE SHAPED LIKE THIS ────────────────────────────────
#
# A wedge is not a failure any single command reports; it is a command that
# never returns.  So every step here runs under `timeout` and the assertion is
# on the exit status.  Two values mean the wedge and both are non-zero: 124 when
# this file's own timeout expires first, and 2 when the CLI's own deadline gets
# there first and it prints "the daemon socket ... accepted a connection and did
# not answer".  Asserting == 0 covers both without having to guess which race
# wins; measured against the parent, it is 2.
#
# The sub-server actually serving is asserted separately, because "create
# returned" is satisfied by a build that accepted the command and did nothing
# with it, and that is precisely the shape the old code failed in.
#
# Both spellings are covered.  They deadlocked in the same place for the same
# reason — create takes the lock in unique mode, start in shared — but they are
# two different lines a script can be written with, and only one of them was in
# any example.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luastartre

PB=$((SL_PORT_BASE+210))
P_A=$((PB + 0))   # parent using create{start=true}
S_A=$((PB + 1))
P_B=$((PB + 2))   # parent using create then socketley.start
S_B=$((PB + 3))
P_C=$((PB + 4))   # parent that stops another runtime from on_start
S_C=$((PB + 5))

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
assert_eq() {
    local label=$1 want=$2 got=$3; shift 3
    if [ "$got" = "$want" ]; then pass; else
        fail "$label" "got '$got', wanted '$want'" "$@"
    fi
}

cleanup() {
    for n in par_a sub_a par_b sub_b par_c sub_c; do
        timeout 5 "$BIN" stop   "$n" >/dev/null 2>&1 || true
    done
    sleep 0.3
    for n in par_a sub_a par_b sub_b par_c sub_c; do
        timeout 5 "$BIN" remove "$n" >/dev/null 2>&1 || true
    done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: the management API called from on_start ==="

daemon_start "$BIN"

# rc_of CMD... — the exit status, non-zero meaning "never came back".  Every
# command in this file goes through it: a deadlocked daemon does not fail a
# command, it declines to finish one, and which deadline notices first is a
# race — see the header.
rc_of() {
    local rc=0
    timeout 10 "$@" >/dev/null 2>&1 || rc=$?
    printf '%s' "$rc"
}

mk() {   # mk FILE BODY
    printf '%s\n' "$2" > "$1"
}

mk "$SOCKETLEY_TMPD/a.lua" "function on_start()
    socketley.create(\"server\", \"sub_a\", { port = $S_A, start = true })
end"
mk "$SOCKETLEY_TMPD/b.lua" "function on_start()
    socketley.create(\"server\", \"sub_b\", { port = $S_B })
    socketley.start(\"sub_b\")
end"
mk "$SOCKETLEY_TMPD/c.lua" "function on_start()
    socketley.stop(\"sub_c\")
end"

# ── 1. create with start = true ────────────────────────────────────────────
RC=$(rc_of "$BIN" create server par_a -p "$P_A" --mode in \
           --lua "$SOCKETLEY_TMPD/a.lua" --daemon-process -s)
assert_eq "create returns when on_start creates and starts a runtime" "0" "$RC" \
    "non-zero here means the command never came back — which is what a daemon" \
    "deadlocked against its own runtime map does to every command after it"

# The daemon is still answering — asked with a command of its own, under a
# timeout, because a wedged daemon accepts the connection either way.
assert_eq "the daemon still answers after that create" "0" "$(rc_of "$BIN" ls)"

ready_tcp 127.0.0.1 "$S_A" 10 || echo "  NOTE: sub_a never accepted"
assert_eq "the sub-server on_start asked for is actually serving" \
          "0" "$(rc_of nc -z 127.0.0.1 "$S_A")" \
    "'create returned' is satisfied by a build that took the command and did" \
    "nothing with it, which is the shape the deadlock left behind"

# ── 2. create, then socketley.start ────────────────────────────────────────
RC=$(rc_of "$BIN" create server par_b -p "$P_B" --mode in \
           --lua "$SOCKETLEY_TMPD/b.lua" --daemon-process -s)
assert_eq "create returns when on_start creates then starts separately" "0" "$RC" \
    "the other spelling, which deadlocks one lock acquisition later"
assert_eq "the daemon still answers after that create too" "0" "$(rc_of "$BIN" ls)"
ready_tcp 127.0.0.1 "$S_B" 10 || echo "  NOTE: sub_b never accepted"
assert_eq "that sub-server is serving as well" \
          "0" "$(rc_of nc -z 127.0.0.1 "$S_B")"

# ── 3. stopping another runtime from on_start ──────────────────────────────
#
# The same re-entry through a different call.  socketley.stop takes the lock in
# shared mode, so this one deadlocked only against a queued writer rather than
# always — the kind of intermittency that gets called a flake.
create_ok "a runtime for the third parent to stop" "$BIN" create server sub_c \
    -p "$S_C" --daemon-process -s
RC=$(rc_of "$BIN" create server par_c -p "$P_C" --mode in \
           --lua "$SOCKETLEY_TMPD/c.lua" --daemon-process -s)
assert_eq "create returns when on_start stops another runtime" "0" "$RC"
assert_eq "the daemon still answers after that one" "0" "$(rc_of "$BIN" ls)"

STATE=$(timeout 10 "$BIN" ls 2>/dev/null | awk '$2 == "sub_c" { print tolower($7) }' | head -1)
assert_eq "...and the stop it asked for actually happened" "stopped" "$STATE" \
    "the call has to have been performed, not merely survived"

# ── 4. everything the daemon was serving is still there ────────────────────
#
# The cost of the wedge was never one runtime; it was the daemon.  Three
# parents and three children were created across this file and all six have to
# be in the inventory a command can still read.
COUNT=$(timeout 10 "$BIN" ls 2>/dev/null | grep -cE ' (par_a|par_b|par_c|sub_a|sub_b|sub_c) ' || true)
assert_eq "every runtime this file created is still in the inventory" "6" "$COUNT"

TOTAL=$((TOTAL+1))
if kill -0 "$SOCKETLEY_DPID" 2>/dev/null && daemon_alive "$SOCKETLEY_SOCKET"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: the daemon did not survive"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
