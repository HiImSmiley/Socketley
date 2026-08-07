#!/usr/bin/env bash
# Integration test: cancelling a timer withdraws it, rather than muting it.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# socketley.clear_timeout and socketley.clear_interval were two assignments:
#
#     t->cancelled = true;
#     t->repeat    = false;
#
# That is enough to keep the callback from running, and the existing suite
# already pins exactly that — "a cleared timeout fires NEVER, a cleared interval
# STOPS" in test_lua_globals.sh.  It is not enough to end the timer.  The
# timeout stayed armed in the ring, the lua_timer kept its storage and its owner
# registration, and the sol::protected_function kept a registry reference to the
# closure and to every upvalue it had captured.  Cancelling a one-hour interval
# held every one of those for the hour.
#
# ─── HOW A SHELL SCRIPT SEES A REGISTRY REFERENCE ───────────────────────────
#
# Through the Lua heap, which the script can read itself.  A closure held by
# C++ is reachable, so collectgarbage() cannot free it or anything it captured.
# 100 timeouts of one hour each, every one capturing a distinct 32 KB string:
#
#     parent    base 60   armed 3300   cleared 3300     (the clear freed nothing)
#     fixed     base 60   armed 3300   cleared 62       (the closures are gone)
#
# The strings are made distinct on purpose.  LuaJIT interns them, so a hundred
# copies of one 32 KB string is one 32 KB allocation and the measurement would
# read zero on both builds.
#
# ─── THE CONTROLS ───────────────────────────────────────────────────────────
#
# Withdrawing a timer is easy to overdo, so this file also asserts that the
# behaviour the old two assignments bought is still there: a cleared timeout
# never fires, an UNCLEARED one still does, an interval fires repeatedly, and an
# interval that clears itself from inside its own callback stops — that last one
# being where a severance performed at the wrong moment would abort.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ready.sh"

daemon_isolate luatmrcancel

PB=${PB:-23050}
PORT=$((PB + 0))
STOP_PORT=$((PB + 1))

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop   tmr_cancel tmr_selfstop >/dev/null 2>&1 || true
    sleep 0.2
    "$BIN" remove tmr_cancel tmr_selfstop >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: clearing a timer withdraws it ==="

daemon_start "$BIN"

LUA="$SOCKETLEY_TMPD/cancel.lua"
cat > "$LUA" <<'LUAEOF'
local N = 100

function on_start()
    -- ── The measurement ────────────────────────────────────────────────────
    local ids = {}
    collectgarbage("collect")
    local base = collectgarbage("count")

    for i = 1, N do
        -- Distinct content per closure: LuaJIT interns strings, so a hundred
        -- identical ones would be a single allocation and this would measure
        -- nothing at all.
        local payload = string.rep("p", 32 * 1024) .. tostring(i)
        ids[i] = socketley.set_timeout(3600000, function()
            socketley.log("LATE " .. #payload)
        end)
    end
    collectgarbage("collect")
    local armed = collectgarbage("count")

    for i = 1, N do socketley.clear_timeout(ids[i]) end
    collectgarbage("collect")
    local cleared = collectgarbage("count")

    socketley.log(string.format("HEAP base=%d armed=%d cleared=%d",
                                base, armed, cleared))

    -- ── The behaviour those two assignments bought, still there ────────────
    local dead = socketley.set_timeout(300, function() socketley.log("DEAD fired") end)
    socketley.clear_timeout(dead)
    socketley.set_timeout(300, function() socketley.log("ALIVE fired") end)

    -- An interval that clears itself from inside its own callback: the one-shot
    -- shape, and the moment a severance done at the wrong time would land on a
    -- timer whose completion is being dispatched.
    local n = 0
    local iv
    iv = socketley.set_interval(60, function()
        n = n + 1
        socketley.log("IV n=" .. n)
        if n == 3 then
            socketley.clear_interval(iv)
            socketley.log("IV cleared")
        end
    end)

    -- ── A refusal is 0, and says so ────────────────────────────────────────
    socketley.log("REFUSE zero=" .. tostring(socketley.set_timeout(0, function() end)))
    socketley.log("REFUSE neg=" .. tostring(socketley.set_interval(-5, function() end)))
end
LUAEOF

create_ok "runtime with timers created" "$BIN" create server tmr_cancel \
    -p "$PORT" --lua "$LUA" --daemon-process -s
ready_tcp 127.0.0.1 "$PORT" 10 || echo "  NOTE: the runtime never accepted"

said() {
    local pattern=$1 deadline=$(( $(date +%s) + ${2:-8} ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        grep -qaF "$pattern" "$SOCKETLEY_DLOG" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}
hits() { grep -ac "$1" "$SOCKETLEY_DLOG" 2>/dev/null || true; }

said "HEAP base=" 15 || true
HEAP=$(grep -a "HEAP base=" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1 || true)
BASE=$(printf '%s' "$HEAP"    | sed -n 's/.*base=\([0-9-]*\).*/\1/p')
ARMED=$(printf '%s' "$HEAP"   | sed -n 's/.*armed=\([0-9-]*\).*/\1/p')
CLEARED=$(printf '%s' "$HEAP" | sed -n 's/.*cleared=\([0-9-]*\).*/\1/p')

if [ -n "$BASE" ] && [ -n "$ARMED" ] && [ -n "$CLEARED" ]; then
    HELD=$((ARMED - BASE))
    LEFT=$((CLEARED - BASE))

    # Control: the closures really were held while the timers were armed.  A
    # build where set_timeout did nothing would report HELD near zero and would
    # otherwise satisfy every assertion below.
    if [ "$HELD" -ge 2000 ]; then pass; else
        fail "control: an armed timer holds its closure's captures" \
             "the heap grew by ${HELD} KB while 100 x 32 KB were armed" \
             "line: $HEAP"
    fi

    # The finding.  A quarter of what was held is a wide margin around "none of
    # it": the parent frees nothing at all here.
    if [ "$LEFT" -le $((HELD / 4)) ]; then pass; else
        fail "clearing a timer releases its closure" \
             "after clearing 100 timers the heap was still ${LEFT} KB above" \
             "base, out of the ${HELD} KB they held" \
             "line: $HEAP" \
             "clear_timeout set two flags and returned; the sol reference to" \
             "the callback stayed, so nothing it captured could be collected" \
             "until the timeout expired on its own — an hour, here" ;
    fi
else
    fail "the script reported its heap readings" "no parsable HEAP line" \
         "got: ${HEAP:-<nothing>}"
    fail "clearing a timer releases its closure" "no HEAP line to read"
fi

# ── Control: a cleared timeout still never fires ────────────────────────────
said "ALIVE fired" 8 || true
if grep -qa "DEAD fired" "$SOCKETLEY_DLOG" 2>/dev/null; then
    fail "control: a cleared timeout does not fire" "'DEAD fired' is in the log"
else pass; fi
if grep -qa "ALIVE fired" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "control: an uncleared timeout still fires" \
         "no 'ALIVE fired' line" \
         "a withdrawal that took the working timers with it would pass every" \
         "other assertion in this file"
fi

# ── An interval that clears itself, from inside its own callback ────────────
said "IV cleared" 10 || true
IV_A=$(hits 'IV n=')
sleep 1
IV_B=$(hits 'IV n=')
if [ "$IV_A" = "3" ] && [ "$IV_B" = "3" ]; then pass; else
    fail "an interval that clears itself stops at that tick" \
         "IV fired $IV_A times, and $IV_B a second later; wanted 3 and 3" \
         "clearing from inside the callback severs a timer whose completion is" \
         "being dispatched at that moment — the one ordering that has to be right"
fi

# ── A refusal is 0, and is no longer silent ─────────────────────────────────
if grep -qa "REFUSE zero=0" "$SOCKETLEY_DLOG" 2>/dev/null &&
   grep -qa "REFUSE neg=0"  "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    GOT=$(grep -a "REFUSE " "$SOCKETLEY_DLOG" 2>/dev/null | tr '\n' ' ' || true)
    fail "an unarmable timer answers 0" "got: ${GOT:-<no line at all>}" \
         "ids come from a counter that starts at 0 and is pre-incremented, so" \
         "1 is the first real one and 0 can only ever mean 'armed nothing'"
fi
if grep -qa "set_timeout(0) armed nothing" "$SOCKETLEY_DLOG" 2>/dev/null &&
   grep -qa "set_interval(-5) armed nothing" "$SOCKETLEY_DLOG" 2>/dev/null; then
    pass
else
    fail "a refused timer says so in the log" \
         "no 'armed nothing' line for set_timeout(0) / set_interval(-5)" \
         "0 is unambiguous as a return value but tells nobody WHICH refusal it" \
         "was, and a callback that will never run is worth one line"
fi

# ── The severance's other caller, reached from inside a callback ────────────
#
# `stop` severs a runtime's timers too — runtime_instance::stop() calls
# cancel_timers() — and socketley.stop is bound in the same VM the timer runs
# in, so a script can reach that path from inside the very timer being severed.
# It is the same question as clear_interval-from-its-own-callback and it had the
# same answer, which was to replace a sol::protected_function that was mid-call.
# Measured on the parent commit, this exact script:
#
#     [lua] SI n=1 / n=2 / n=3 / SI stopping self
#     Segmentation fault (core dumped)
#
# — a daemon serving every other runtime in the process, taken down by one
# script stopping itself on a timer.
SLUA="$SOCKETLEY_TMPD/selfstop.lua"
cat > "$SLUA" <<'LUAEOF'
function on_start()
    local n = 0
    socketley.set_interval(60, function()
        n = n + 1
        socketley.log("SI n=" .. n)
        if n == 3 then
            socketley.log("SI stopping self")
            socketley.stop("tmr_selfstop")
        end
    end)
end
LUAEOF
create_ok "self-stopping runtime created" "$BIN" create server tmr_selfstop \
    -p "$STOP_PORT" --lua "$SLUA" --daemon-process -s
said "SI stopping self" 10 || true
sleep 1

TOTAL=$((TOTAL+1))
if kill -0 "$SOCKETLEY_DPID" 2>/dev/null && daemon_alive "$SOCKETLEY_SOCKET"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: a runtime stopping itself from its own timer took the daemon down"
    echo "        cancel_timers() severs the timer whose callback is on the stack;"
    echo "        the sol::protected_function it replaces is the one being called"
fi

SI_A=$(hits 'SI n=')
sleep 1
SI_B=$(hits 'SI n=')
if [ "$SI_A" = "3" ] && [ "$SI_B" = "3" ]; then pass; else
    fail "the self-stopped runtime's interval stops at that tick" \
         "SI fired $SI_A times, and $SI_B a second later; wanted 3 and 3"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
