#!/usr/bin/env bash
# Integration test: --log file actually records the state transitions.
#
# man socketley.1 promised "Log state transitions (created, running, stopped,
# failed) to file", and the project's own troubleshooting help offered
#
#     socketley create server api -p 9000 --log /tmp/api.log -s
#     tail -f /tmp/api.log
#
# Measured before this fix, on a private daemon: the flag is accepted, `show`
# reports "log_file", the runtime starts and stops -- and the file is never
# created, so that tail waits forever.  The whole life of the value was
# set_log_file() from four flag doors plus import and the boot restore, and
# get_log_file() twice in state_persistence.cpp to write it back into the JSON.
# Nothing opened it.  (-w had the identical shape and is fixed in the commit
# before this one.)
#
# ─── WHY A CHOKEPOINT AND NOT SIX CALL SITES ────────────────────────────────
#
# There were twelve m_state.store() calls in runtime_instance.cpp plus
# mark_failed(), and a flag that has to see ALL of them is a flag that would
# have missed one.  They go through store_state() now.  set_replicated_state()
# deliberately does not: a replica is a copy of somebody else's runtime and
# would record a transition it did not make.
#
# ─── WHO WRITES ─────────────────────────────────────────────────────────────
#
# Every runtime lives in its own process, and that process holds its own copy
# of the same state value with the same --log path in it.  Both writing would
# double every line, so the DAEMON writes: what an operator watching this file
# wants is the state `ls` reports.  in_worker_process() was already there to
# ask.
#
# The visible consequence is asserted below rather than hidden: a runtime whose
# worker refuses its configuration records created, running, failed -- because
# `running` is what the daemon asked for and reported for the moment before the
# worker answered, and `ls` said so too.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate statelog

P_SRV=$((SL_PORT_BASE+1830))
P_BAD=$((SL_PORT_BASE+1832))
P_RST=$((SL_PORT_BASE+1833))
NAMES="sl_srv sl_bad sl_rst"

L1="$SOCKETLEY_TMPD/state.log"
L2="$SOCKETLEY_TMPD/state2.log"
LB="$SOCKETLEY_TMPD/bad.log"
LR="$SOCKETLEY_TMPD/restore.log"

PASS=0; FAIL=0; TOTAL=0

cleanup() {
    for n in $NAMES; do "$BIN" stop "$n" >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

check() {   # label expected actual
    if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi
}

# Only the state names, so the assertion is about the sequence and not about
# what time the machine thought it was.
states() { sed 's/^.* //' "$1" 2>/dev/null | tr '\n' ',' | sed 's/,$//'; }

# `wc -l < missing` fails the redirect, so wc never runs and the assignment
# fails -- which under `set -e` ends the file.  A test that dies half way
# through reports fewer failures than it found, which is how a green tally on a
# broken tree gets believed.
lines() { [ -f "$1" ] && wc -l < "$1" || echo 0; }

await_lines() {   # file count
    local i
    for i in $(seq 1 60); do
        [ -f "$1" ] && [ "$(lines "$1")" -ge "$2" ] && return 0
        sleep 0.1
    done
    return 1
}

daemon_restart() {
    if [ -n "${SOCKETLEY_DPID:-}" ]; then
        for c in $(pgrep -P "$SOCKETLEY_DPID" 2>/dev/null); do
            kill -9 "$c" 2>/dev/null || true
        done
        kill -9 "$SOCKETLEY_DPID" 2>/dev/null || true
        wait "$SOCKETLEY_DPID" 2>/dev/null || true
    fi
    for _ in $(seq 1 50); do [ -S "$SOCKETLEY_SOCKET" ] || break; sleep 0.1; done
    rm -f "$SOCKETLEY_SOCKET"
    : > "$SOCKETLEY_DLOG"
    daemon_start "$BIN"
}

echo "=== Integration: --log records the state transitions ==="
daemon_start "$BIN"

# ─── 1. created, at the moment the flag is given ────────────────────────────
create_ok "a server with --log" "$BIN" create server sl_srv -p "$P_SRV" --log "$L1"
if await_lines "$L1" 1; then ok; else
    bad "the file exists after create" "$L1 is missing"; fi
check "and its first line is created" "created" "$(states "$L1")"

# The record is dated, because it outlives a day.
if grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} sl_srv created$' "$L1"; then
    ok
else
    bad "the line carries a date, a time and the name" "got '$(head -1 "$L1")'"
fi
check "mode 0600" "600" "$(stat -c %a "$L1")"

# ─── 2. running, stopped, running ───────────────────────────────────────────
"$BIN" start sl_srv >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$P_SRV" >/dev/null 2>&1 || true
if await_lines "$L1" 2; then ok; else bad "start is recorded" "$(states "$L1")"; fi

"$BIN" stop sl_srv >/dev/null 2>&1 || true
if await_lines "$L1" 3; then ok; else bad "stop is recorded" "$(states "$L1")"; fi

"$BIN" start sl_srv >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$P_SRV" >/dev/null 2>&1 || true
if await_lines "$L1" 4; then ok; else bad "the second start too" "$(states "$L1")"; fi

check "the whole sequence, in order" "created,running,stopped,running" "$(states "$L1")"

# The worker holds the same value and the same path; only the daemon writes.
check "no line is doubled" "4" "$(lines "$L1")"

# ─── 3. A restart is a stop and a start, and says so ────────────────────────
"$BIN" restart sl_srv >/dev/null 2>&1 || true
if await_lines "$L1" 6; then ok; else bad "a restart is two lines" "$(states "$L1")"; fi
check "which two" "created,running,stopped,running,stopped,running" "$(states "$L1")"

# ─── 4. A stop of a stopped runtime is not a transition ─────────────────────
"$BIN" stop sl_srv >/dev/null 2>&1 || true
sleep 0.4
BEFORE=$(lines "$L1")
"$BIN" stop sl_srv >/dev/null 2>&1 || true
sleep 0.6
check "a second stop adds nothing" "$BEFORE" "$(lines "$L1")"

# ─── 5. failed, from a worker that refuses its configuration ────────────────
# TLS naming a certificate that is not there: accepted by create, refused in
# the worker, and the daemon's record moves created -> running -> failed.
create_ok "a server with unreachable TLS files" "$BIN" create server sl_bad \
    -p "$P_BAD" --log "$LB" --tls --cert /nonexistent.pem --key /nonexistent.key
"$BIN" start sl_bad >/dev/null 2>&1 || true
if await_lines "$LB" 3; then ok; else
    bad "a refused start records failed" "$(states "$LB")"; fi
check "the daemon's own sequence" "created,running,failed" "$(states "$LB")"

STATE=$("$BIN" ps -a 2>/dev/null | awk '$2=="sl_bad" { print $7 }')
check "and ls agrees with the file" "Failed" "$STATE"

# ─── 6. The boot restore is recorded too ────────────────────────────────────
# It reads a state file and calls manager.start() directly, so a flag written
# only into a command handler would have nothing to say here.
create_ok "a server to restore" "$BIN" create server sl_rst -p "$P_RST" --log "$LR"
"$BIN" start sl_rst >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$P_RST" >/dev/null 2>&1 || true
await_lines "$LR" 2 || true
check "before the reboot" "created,running" "$(states "$LR")"

daemon_restart
if await_lines "$LR" 4; then ok; else
    bad "the restore appends" "$(states "$LR")"; fi
check "and it came back through the same two states" \
    "created,running,created,running" "$(states "$LR")"

# ─── 7. An unwritable path is one complaint ─────────────────────────────────
# `grep -c` prints 0 AND exits 1 when it matches nothing, so `|| true` and not
# `|| echo 0`, which would append a second zero.
BEFORE=$(grep -c "could not be opened" "$SOCKETLEY_DLOG" 2>/dev/null || true)
create_ok "a server whose --log cannot be opened" "$BIN" create server sl_srv2 \
    -p "$((P_SRV+4))" --log /proc/definitely-not-a-directory/state.log
NAMES="$NAMES sl_srv2"
for _ in 1 2 3; do
    "$BIN" start sl_srv2 >/dev/null 2>&1 || true
    "$BIN" stop  sl_srv2 >/dev/null 2>&1 || true
done
sleep 0.8
AFTER=$(grep -c "could not be opened" "$SOCKETLEY_DLOG" 2>/dev/null || true)
check "seven transitions, one complaint" "1" "$((AFTER - BEFORE))"

# And it kept running: a record it cannot write is not a reason to refuse work.
"$BIN" start sl_srv2 >/dev/null 2>&1 || true
sleep 0.5
STATE=$("$BIN" ps -a 2>/dev/null | awk '$2=="sl_srv2" { print $7 }')
check "the runtime still starts" "Up" "$STATE"

# ─── 7b. A relative path is refused, at every door ─────────────────────────
# Found by a test that passes `--log 'C:\'` as a JSON-escaping fixture: once
# --log opened the file it was given, that left a file called C:\ in the
# repository root.  A relative path resolves against the DAEMON's working
# directory, which is wherever it was started and "/" under systemd.
refuses_relative() {   # label -- then the command
    local label=$1; shift
    local out
    out=$("$@" 2>&1) && { bad "$label" "accepted, output '$out'"; return; }
    case "$out" in
        *"needs an absolute path"*) ok ;;
        *) bad "$label" "refused for the wrong reason: '$out'" ;;
    esac
}
refuses_relative "create --log app.log" \
    "$BIN" create server sl_rel -p "$((P_SRV+6))" --log app.log
refuses_relative "edit --log app.log"   "$BIN" edit sl_srv --log app.log
refuses_relative "edit -w rx.log"       "$BIN" edit sl_srv -w rx.log

# ─── 8. The state names are the same ones every other surface prints ────────
# state_to_string() had four copies -- lua_context, cluster_discovery,
# metrics_endpoint and ps --json -- and this file was about to be the fifth.
# They are one function now, so this asserts the two surfaces agree.
JSON_STATE=$("$BIN" ps --json 2>/dev/null \
    | sed 's/.*"name":"sl_srv2"[^}]*"status":"\([a-z]*\)".*/\1/')
check "ps --json and the log use one vocabulary" "running" "$JSON_STATE"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
