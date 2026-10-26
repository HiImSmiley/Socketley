#!/usr/bin/env bash
# Integration test: a worker the daemon could not fork.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# Two failures on one path, and the first hides the second.
#
#   The daemon DIED.  Five places build a state_persistence purely to decode a
#   config, and its constructor started a writer thread unconditionally.
#   std::thread throws std::system_error when it cannot make one, nothing on
#   these paths catches it, and the daemon aborted -- core dumped, "terminate
#   called after throwing an instance of 'std::system_error'  what():  Resource
#   temporarily unavailable" -- where it should have refused one command.  Two
#   of those five sit on the worker-restart path, so the same abort was one
#   restart away on a box that was merely busy.
#
#   The fork failure was reported as SUCCESS.  reconcile_proxy_workers() marks
#   the runtime failed and erases the name, and await_worker_startup() answered
#   0 for a name it could not find -- a return that meant "in-daemon runtime,
#   nothing in another process" and now also meant "never spawned".  `create
#   -s` and `start` returned 0 with nothing on the terminal, `ls` read Failed,
#   and the state file carried was_running:true, so the next daemon restart
#   brought back a runtime the operator was told had started.
#
# RLIMIT_NPROC is how a fork is denied without breaking anything else: the
# limit is per-process, so only the daemon is held to it, and every other
# process on the box is untouched.  The test needs prlimit and says so rather
# than skipping quietly, because a skip that reads as a pass is how this whole
# path stayed unmeasured.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: a worker the daemon could not fork ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

if ! command -v prlimit >/dev/null 2>&1; then
    echo "  FAIL [prlimit is present]: prlimit is not on this box, and it is the only"
    echo "        way this file denies a fork without disturbing anything else."
    echo "  Results: 0/1 passed (1 failed)"
    exit 1
fi

P=$((SL_PORT_BASE+1396))

daemon_isolate forkdenied
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"
DPID="$SOCKETLEY_DPID"

STATE_FILE_DIR=$("$BIN" ls >/dev/null 2>&1; grep -o 'state directory: .*' "$SOCKETLEY_DLOG" 2>/dev/null | tail -1 | sed 's/^state directory: //')

prlimit --pid "$DPID" --nproc=1:1 2>/dev/null

OUT=$("$BIN" create server fk -p "$P" -s 2>&1)
RC=$?
sleep 1

# ── 1. The daemon is still there ───────────────────────────────────────────
#
# First, because every other assertion is meaningless against a corpse -- and
# because the CLI's answer to a dead daemon is "failed to connect to daemon"
# with rc 2, which is not obviously different from a refusal if nobody looks.
if kill -0 "$DPID" 2>/dev/null; then
    ok "the daemon survived a fork it could not make"
else
    bad "the daemon survives a fork it could not make" \
        "the daemon process is gone; create said '$OUT' (rc $RC)," \
        "and the log ends with: $(tail -2 "$SOCKETLEY_DLOG" 2>/dev/null | tr '\n' ' ')" \
        "-- an uncaught std::system_error out of a std::thread constructor" \
        "takes the whole daemon down for one command it could not serve"
fi

# ── 2. It said no, and it said why ─────────────────────────────────────────
SAID=$(printf '%s' "$OUT" | head -1)
LOGGED=$(grep -c "fork failed\|could not start out-of-process" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "$RC" -ne 0 ] && [ -n "$SAID" ] && [ "${LOGGED:-0}" -ge 1 ]; then
    ok "create answered rc $RC and named it: '$SAID'"
else
    bad "a fork that failed is not reported as a start that worked" \
        "create returned $RC and said '${SAID:-<nothing>}'; the daemon log named the fork" \
        "$LOGGED time(s);" \
        "rc 0 with an empty terminal is what an operator reads as success"
fi

# ── 3. And ls agrees with what it was told ─────────────────────────────────
ST=$("$BIN" ls 2>/dev/null | awk '$2 == "fk" { print $7; exit }')
if [ "$ST" = "Failed" ]; then
    ok "ls shows the runtime Failed, which is what create just said"
else
    bad "ls agrees with the answer create gave" \
        "state is '${ST:-<none>}' after a create that returned $RC"
fi

# ── 4. It is not coming back on the next daemon start ──────────────────────
#
# was_running:true on a runtime that never ran is how a restart resurrects it,
# and this is the same clearing the `refused` verdict has always done.
WR="<no file>"
for _ in $(seq 1 50); do
    if [ -n "$STATE_FILE_DIR" ] && [ -f "$STATE_FILE_DIR/fk.json" ]; then
        WR=$(grep -o '"was_running"[[:space:]]*:[[:space:]]*[a-z]*' "$STATE_FILE_DIR/fk.json" | tail -1 || true)
        [ -n "$WR" ] && break
        WR="<no was_running>"
    fi
    sleep 0.1
done
case "$WR" in
    *true*) bad "a runtime that never started is not restored as running" \
                "the state file says '$WR';" \
                "the next daemon start would bring back a runtime that never ran" ;;
    *false) ok "was_running is not left true for a runtime that never started ($WR)" ;;
    *)      bad "a runtime that never started has a state file saying was_running is false" \
                "read '$WR' from '${STATE_FILE_DIR:-<no state directory>}/fk.json'" ;;
esac

"$BIN" remove fk >/dev/null 2>&1
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
