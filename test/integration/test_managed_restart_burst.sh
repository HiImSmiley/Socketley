#!/usr/bin/env bash
# Integration test: a managed program that dies at once stops being forked.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# check_managed_health() reaped an `add` runtime's dead child and started it
# again, with no counter anywhere.  A program that exits immediately -- a typo
# in the path, a missing interpreter, a service that refuses its own config --
# was therefore forked every two seconds for as long as the daemon lived, and
# `ls` read `Up` the whole time, because m_manager.start() puts the state back
# before the next tick finds the corpse.  Nothing in the output ever said the
# runtime was in a loop, and `stats` reported 0 restarts because this path
# never called note_restart() either.
#
# proxy_supervisor has had the answer since it was written: five restarts
# inside ten seconds and the runtime is left `failed`.  The two constants now
# live in proxy_supervisor.h so both restart paths read one definition rather
# than agreeing by coincidence.
#
# The assertion is about a runtime that STOPS being forked.  Counting forks
# would measure the health tick's period; the fact to establish is that the
# loop ends and the operator is told, so this waits past the burst window and
# asks what state it settled in.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: a managed program that dies at once ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

daemon_isolate managedburst
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

# A program that runs, records that it ran, and exits at once.  The tally is
# what says how many times it was forked, counted by the program itself rather
# than inferred from the daemon's log.
TALLY="$SOCKETLEY_TMPD/tally"
: > "$TALLY"
SVC="$SOCKETLEY_TMPD/dies.sh"
cat > "$SVC" <<EOF
#!/usr/bin/env bash
echo x >> "$TALLY"
exit 3
EOF
chmod +x "$SVC"

"$BIN" add "$SVC" --name mb1 -s </dev/null >/dev/null 2>&1
sleep 1

state_of() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2 == n { print $7; exit }'; }

# ── 1. It really is being restarted, or nothing below is about anything ────
sleep 5
FORKS_EARLY=$(wc -l < "$TALLY")
if [ "$FORKS_EARLY" -ge 2 ]; then
    ok "the program was forked $FORKS_EARLY times in the first six seconds"
else
    bad "the setup produces a restarting runtime" \
        "the program ran $FORKS_EARLY time(s); it must die and be restarted for" \
        "this file to be measuring anything"
fi

# ── 2. It stops, and the runtime is left where an operator can see it ──────
#
# Past the ten-second window with room for the tick that lands after it.
sleep 12
ST=$(state_of mb1)
FORKS_MID=$(wc -l < "$TALLY")
sleep 6
FORKS_LATE=$(wc -l < "$TALLY")
GREW=$((FORKS_LATE - FORKS_MID))

if [ "$ST" = "Failed" ] && [ "$GREW" -eq 0 ]; then
    ok "after $FORKS_LATE forks it is Failed and stopped being forked (0 more in six seconds)"
else
    bad "a program dying faster than it runs stops being forked" \
        "state is '${ST:-<none>}' and it was forked $GREW more time(s) in the six seconds after;" \
        "forks so far: $FORKS_LATE;" \
        "Up with a growing tally is the loop: every two seconds for as long as the" \
        "daemon lives, with nothing in any output saying so"
fi

# ── 3. And the log said it, once ───────────────────────────────────────────
SAID=$(grep -c "restarted too often" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "${SAID:-0}" -ge 1 ]; then
    ok "the daemon log names it ($SAID line(s))"
else
    bad "the daemon says why it gave up" \
        "no 'restarted too often' line in the daemon log;" \
        "a runtime that silently stops being restarted is the same puzzle as one" \
        "that silently keeps being restarted"
fi

"$BIN" remove mb1 >/dev/null 2>&1
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
