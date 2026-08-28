#!/usr/bin/env bash
# Integration test: what happens to a pending timer when its interpreter goes.
#
# ─── WHY THIS IS NOT COVERED BY "THE TIMER FIRED" ──────────────────────────
#
# test_lua_globals.sh holds down what the four timer calls DO: a timeout fires
# once, a cleared one never, an interval repeats, a cleared interval stops.
# None of that says anything about the dangerous case, which is a timer that is
# still in the ring when the Lua state it would call into is destroyed.
#
# There are two ways to destroy it while a runtime is up:
#
#   reload-lua   builds a replacement context and swaps.  The old one is freed
#                with the timer's sol::function still referring to it.
#   stop         tears the runtime down, and must sever the script's timers
#                with it — it severed only the on_tick timer, so a stopped
#                runtime went on executing script until it was removed.
#
# Both are ordinary operator actions and both are reachable with one line of
# script.  The failure is a use-after-free, so on a Release build it is a crash
# if you are lucky and silent corruption if you are not; the same file run
# against the Sanitize build is where it is loud.  That is the reason this is an
# integration test and not a unit test: the timer has to be genuinely pending in
# a genuinely running io_uring loop.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
# The daemon surviving is necessary and nowhere near sufficient — a freed
# context that happens not to be reused reads fine.  So the claim is also that
# the OLD script stops running: its counter must not advance after the swap,
# while the NEW one's does.  A timer that kept firing into the replaced state
# would advance both, and that is the observable half of the bug.
#
# In the daemon rather than in a worker, deliberately.  A worker that dies takes
# one runtime with it and is restarted; the daemon takes everything.  This is
# the arrangement where the defect costs the most, so it is the one pinned.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luatimer

PB=$((SL_PORT_BASE+190))
PORT=$((PB + 0))

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
    # stdout as well as stderr: this file removes tmr itself as part of the
    # last assertion, so the backstop below finds nothing — and "runtime not
    # found" goes to STDOUT in this CLI, where it reads like a failure in the
    # middle of a passing run.
    "$BIN" stop  tmr >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove tmr >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a pending timer outliving its interpreter ==="

daemon_start "$BIN"

LUA="$SOCKETLEY_TMPD/tmr.lua"
# write_script FILE TAG — an interval that keeps firing, and a timeout that is
# still pending when the interpreter is taken away.  60 ms so several are in
# flight at any moment; the timeout is 3600 s so it is certain to be pending.
write_script() {
    cat > "$1" <<LUAEOF
local n = 0
socketley.set_interval(60, function()
    n = n + 1
    socketley.log("TMR $2 tick=" .. tostring(n))
end)
socketley.set_timeout(3600000, function()
    socketley.log("TMR $2 late-timeout")
end)
function on_start()
    socketley.log("TMR $2 started")
end
LUAEOF
}

hits() { grep -ac "$1" "$2" 2>/dev/null || true; }
said() {
    local pattern=$1 deadline=$(( $(date +%s) + ${2:-8} ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        grep -qaF "$pattern" "$SOCKETLEY_DLOG" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}
alive() { kill -0 "$SOCKETLEY_DPID" 2>/dev/null && daemon_alive "$SOCKETLEY_SOCKET"; }

write_script "$LUA" V1
create_ok "runtime with a repeating timer created in the daemon" "$BIN" create server tmr \
    -p "$PORT" --mode in --lua "$LUA" -s
ready_tcp 127.0.0.1 "$PORT" 10 || echo "  NOTE: the runtime never accepted"

# ── 1. The timer is genuinely running ──────────────────────────────────────
said "TMR V1 tick=3" 10 || true
V1_AT_RELOAD=$(hits 'TMR V1 tick=' "$SOCKETLEY_DLOG")
if [ "$V1_AT_RELOAD" -ge 3 ]; then pass; else
    fail "control: the interval is running before anything is taken away" \
         "only $V1_AT_RELOAD ticks" \
         "a timer that was never pending cannot outlive anything, and every" \
         "assertion below would hold for a build with no timers at all"
fi

# ── 2. reload-lua swaps the interpreter out from under it ──────────────────
write_script "$LUA" V2
"$BIN" reload-lua tmr >/dev/null 2>&1 || true
said "TMR V2 tick=3" 12 || true

TOTAL=$((TOTAL+1))
if alive; then PASS=$((PASS+1)); else
    FAIL=$((FAIL+1))
    echo "  FAIL: the daemon did not survive a reload with timers pending"
fi

V2_TICKS=$(hits 'TMR V2 tick=' "$SOCKETLEY_DLOG")
if [ "$V2_TICKS" -ge 3 ]; then pass; else
    fail "the replacement script's own timer runs" "only $V2_TICKS ticks" \
         "without this, 'the old one stopped' is satisfied by a reload that" \
         "left the runtime with no timers at all"
fi

# The observable half of the use-after-free: the old closure must not still be
# being called.  Sampled twice a second apart, so a timer firing every 60 ms
# would add roughly sixteen ticks between the readings.
V1_A=$(hits 'TMR V1 tick=' "$SOCKETLEY_DLOG")
sleep 1
V1_B=$(hits 'TMR V1 tick=' "$SOCKETLEY_DLOG")
assert_eq "the replaced script's interval stops firing" "$V1_A" "$V1_B" \
    "a timer still calling into the context reload-lua freed is the bug this" \
    "file exists for, and it is invisible on a Release build until the memory" \
    "is reused — the Sanitize run is where it is loud"

# ── 3. stop cancels the script's timers ────────────────────────────────────
#
# This used to be a measurement with no assertion, because the build it was
# written against left the interval running: `stop` severed the on_tick timer
# and nothing at all touched the ones a script arms with set_timeout and
# set_interval, so they kept firing at full rate until `remove` destroyed the
# context.  Measured then, a 60 ms interval, counting the callback's own lines:
#
#     while running                 25
#     after stop   +0 / +2 / +4 s   25 / 58 / 92     (+33, +34)
#     after remove +0 / +2 s        92 / 92          (+0)
#
# A stopped runtime that goes on executing script is not untidy: self.send from
# such a timer delivers to clients of a runtime the operator has taken down.
# runtime_instance::stop() severs them now, after on_stop, the same way it
# already severed m_tick.
V2_A=$(hits 'TMR V2 tick=' "$SOCKETLEY_DLOG")
"$BIN" stop tmr >/dev/null 2>&1 || true
sleep 0.8
S_A=$(hits 'TMR V2 tick=' "$SOCKETLEY_DLOG")
sleep 1.5
S_B=$(hits 'TMR V2 tick=' "$SOCKETLEY_DLOG")

TOTAL=$((TOTAL+1))
if alive; then PASS=$((PASS+1)); else
    FAIL=$((FAIL+1))
    echo "  FAIL: the daemon did not survive a stop with timers pending"
fi

# The sample is taken after the stop has settled, so a tick already dispatched
# when the command arrived is not counted against the fix.  A second and a half
# of a 60 ms interval is about twenty-five, so this is not a narrow margin.
assert_eq "stop cancels the script's interval" "$S_A" "$S_B" \
    "counted a second and a half apart, both samples after the stop: an" \
    "interval still armed adds roughly twenty-five between them"

# ...and it was genuinely running right up to the stop, so the flatness above
# is the stop doing something rather than a timer that had already finished.
if [ "$(( S_A - V2_A ))" -ge 0 ] && [ "$V2_A" -ge 3 ]; then pass; else
    fail "control: the interval was running when the stop arrived" \
         "only $V2_A ticks before it" \
         "a timer that had already stopped makes every reading above flat for" \
         "a reason that has nothing to do with the fix"
fi

# ── remove, after a stop that has already severed them ─────────────────────
"$BIN" remove tmr >/dev/null 2>&1 || true
sleep 0.8
R_A=$(hits 'TMR V2 tick=' "$SOCKETLEY_DLOG")
sleep 1.2
assert_eq "remove leaves nothing further to cancel" \
          "$R_A" "$(hits 'TMR V2 tick=' "$SOCKETLEY_DLOG")" \
    "the destructor severs them too, and it must not matter that stop got" \
    "there first — a double severance is what a stopped-then-removed runtime" \
    "asks for every time"

TOTAL=$((TOTAL+1))
if alive; then PASS=$((PASS+1)); else
    FAIL=$((FAIL+1))
    echo "  FAIL: the daemon did not survive a remove with timers pending"
fi

# The 3600-second timeout was pending through the reload, the stop and the
# remove, and it must never have fired — nothing here waited an hour.  If it
# appears, an orphaned timer was dispatched rather than dropped.
assert_eq "a long-pending timeout is not fired early by the teardown" \
          "0" "$(hits 'late-timeout' "$SOCKETLEY_DLOG")" \
    "an hour had not passed; a timeout that fires because its owner went away" \
    "is a callback the script never asked for, into a state that is going"

# ── 4. and the daemon is still serving ─────────────────────────────────────
TOTAL=$((TOTAL+1))
if alive && "$BIN" ls >/dev/null 2>&1; then PASS=$((PASS+1)); else
    FAIL=$((FAIL+1))
    echo "  FAIL: the daemon is no longer answering after all of that"
fi
if grep -qa "double free\|use-after-free\|AddressSanitizer\|Segmentation" "$SOCKETLEY_DLOG" 2>/dev/null
then
    fail "the daemon log is clean across the reload and the stop" \
         "the log carries a memory diagnostic" \
         "$(grep -a 'double free\|use-after-free\|AddressSanitizer\|Segmentation' \
            "$SOCKETLEY_DLOG" | head -2 | tr '\n' '|')"
else
    pass
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
