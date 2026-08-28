#!/usr/bin/env bash
# Integration test: a script cannot schedule work for a runtime it has stopped.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# `stop` severs the timers and the subscriptions a script has armed, and that
# is what makes "a stopped runtime executes no script" true.  Both severances
# happen inside stop(), and stop() returns — to a script, if socketley.stop is
# what called it.  Whatever that handler does next runs on a runtime that is
# already down, and set_interval and socketley.subscribe were happy to arm it:
#
#     socketley.subscribe(cache, "go", function()
#         socketley.stop(self.name)          -- severs everything
#         socketley.set_interval(120, ...)   -- and this arms a new one
#     end)
#
# Measured on the parent commit, one publish and two seconds:
#
#     zombie ticks: 41   zombie subs: 1
#
# — the exact defect 23e5181 fixed, at full rate, on a runtime `ls` reports as
# Stopped, reachable again through a door the severance does not close.  Forty
# one is not a leak; it is a script running.
#
# ─── ONE LATCH, BOTH APIS ───────────────────────────────────────────────────
#
# The timers and the subscriptions are asserted together on purpose.  They are
# severed by the same call for the same sentence, and a fix applied to the one
# it was found through would leave the other half of a single rule behind — and
# leave it in the API whose bill 23e5181 already measured once.  So the test
# arms both from the same handler and reads both answers.
#
# ─── AND IT LIFTS ───────────────────────────────────────────────────────────
#
# A latch that never opened would be a way to make `stop; start` produce a
# runtime that is up and can no longer schedule anything — green on every
# assertion above and a worse defect than the one being fixed.  So the last
# section starts the runtime again and asserts that on_start's own subscribe
# and set_interval both work.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luarearm

PB=$((SL_PORT_BASE+1140))
SRV_PORT=$((PB + 0))
CACHE_PORT=$((PB + 1))

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop   rearm_srv rearm_cache >/dev/null 2>&1 || true
    sleep 0.2
    "$BIN" remove rearm_srv rearm_cache >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: re-arming after a script stops its own runtime ==="

daemon_start "$BIN"

LUA="$SOCKETLEY_TMPD/rearm.lua"
cat > "$LUA" <<'LUAEOF'
local starts = 0

-- Armed at the script's TOP LEVEL.  It is here because the top level and
-- on_start are severed by the same stop and restored by the same start: a stop
-- retires this worker and a start forks a new one, which runs the file from the
-- top.  Both come back, and the assertion at the end of this file says so.
local top_id = socketley.set_interval(150, function()
    socketley.log("TOPTICK")
end)
socketley.log("TOPLEVEL interval=" .. tostring(top_id))

function on_start()
    starts = starts + 1
    -- Both of these must work on every start, including the one after a stop.
    local sid = socketley.subscribe("rearm_cache", "go", function(ch, msg)
        socketley.log("LIVE SUB " .. msg)
        if msg ~= "selfstop" then return end

        -- The runtime goes down here, and everything below runs afterwards.
        socketley.log("STOPPED=" .. tostring(socketley.stop("rearm_srv")))

        local tid = socketley.set_interval(120, function()
            socketley.log("ZOMBIE TICK")
        end)
        local zid = socketley.subscribe("rearm_cache", "after", function(ch2, m2)
            socketley.log("ZOMBIE SUB " .. m2)
        end)
        local oid = socketley.set_timeout(150, function()
            socketley.log("ZOMBIE TIMEOUT")
        end)
        socketley.log("REARM interval=" .. tostring(tid)
                      .. " sub=" .. tostring(zid)
                      .. " timeout=" .. tostring(oid))
    end)

    local hb = socketley.set_interval(200, function()
        socketley.log("HEARTBEAT")
    end)

    socketley.log("READY starts=" .. starts
                  .. " sub=" .. tostring(sid)
                  .. " interval=" .. tostring(hb))
end

function on_stop() socketley.log("ONSTOP") end
LUAEOF

create_ok "cache created"  "$BIN" create cache  rearm_cache -p "$CACHE_PORT" -s
create_ok "server created" "$BIN" create server rearm_srv   -p "$SRV_PORT" \
    --lua "$LUA" -s
ready_tcp  127.0.0.1 "$SRV_PORT"   10 || echo "  NOTE: the server never accepted"
ready_resp 127.0.0.1 "$CACHE_PORT" 10 || echo "  NOTE: the cache never answered PING"

said() {
    local pattern=$1 deadline=$(( $(date +%s) + ${2:-6} ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        grep -qaF "$pattern" "$SOCKETLEY_DLOG" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}
publish() { printf 'PUBLISH %s %s\r\n' "$1" "$2" | nc -q 1 127.0.0.1 "$CACHE_PORT" >/dev/null 2>&1 || true; }
count()   { grep -ac "$1" "$SOCKETLEY_DLOG" 2>/dev/null || true; }

said "READY starts=1" 10 || true

# ── Controls: both APIs answer with a live id, and both work ───────────────
#
# Without these the whole file passes against a build where set_interval and
# subscribe answer 0 always and nothing is ever armed at all.
# "Not 0" rather than a particular id.  0 is the refusal this whole file is
# about and is the only value with a meaning; which number a live registration
# happens to get depends on what else the script armed first, and pinning it
# makes adding a timer to the script a red assertion somewhere unrelated.
READY1=$(grep -a "READY starts=1" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1 || true)
case "$READY1" in
    ""|*" sub=0"*|*" interval=0"*)
        fail "control: subscribe and set_interval answer with live ids while running" \
             "got: ${READY1:-<no READY line>}" \
             "0 is the refusal, so a control that starts from one measures nothing"
        ;;
    *) pass ;;
esac
said "HEARTBEAT" 6 || true
if [ "$(count HEARTBEAT)" -ge 1 ]; then pass; else
    fail "control: the interval armed while running actually fires" \
         "no HEARTBEAT line"
fi
# And the top-level one, which the last assertion in this file is about.  It has
# to be proved running here or "it did not come back" is satisfied by a timer
# that was never armed in the first place.
said "TOPTICK" 6 || true
if [ "$(count TOPTICK)" -ge 1 ]; then pass; else
    fail "control: the interval armed at the script's top level fires" \
         "no TOPTICK line" \
         "the last assertion in this file is that it does NOT return after a" \
         "restart, which says nothing unless it ran to begin with"
fi
publish go live
said "LIVE SUB live" 6 || true
if grep -qa "LIVE SUB live" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "control: the subscription armed while running actually receives" \
         "no 'LIVE SUB live' line"
fi

# ── The handler stops its own runtime and then arms three things ───────────
publish go selfstop
said "REARM " 8 || true
if grep -qa "STOPPED=true" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "control: the handler's socketley.stop took effect" \
         "no 'STOPPED=true' line" \
         "nothing below is about a stopped runtime if it never stopped"
fi
STATUS=$("$BIN" ls 2>/dev/null | awk '$2 == "rearm_srv" { print $7 }' || true)
if [ "$STATUS" = "Stopped" ]; then pass; else
    fail "control: ls reports the runtime as stopped" \
         "ls says '${STATUS:-<nothing>}', wanted 'Stopped'"
fi

# The three answers, read directly rather than inferred from what fired.  A
# refusal is 0 for all three: set_timeout and set_interval already document 0 as
# "armed nothing", and subscribe's ids start at 1 so 0 is never a registration.
# Matched on the values, not on the whole line.  The daemon's log prefix is not
# this test's to pin — it has already gained a timestamp and the runtime's name
# since this file was written — and an exact compare against it turns somebody
# else's improvement into a red assertion here.
REARM=$(grep -a "REARM " "$SOCKETLEY_DLOG" 2>/dev/null | tail -1 || true)
case "$REARM" in
    *"REARM interval=0 sub=0 timeout=0") REARM_OK=1 ;;
    *)                                   REARM_OK=0 ;;
esac
if [ "$REARM_OK" = "1" ]; then pass; else
    fail "a stopped runtime refuses to arm a timer or a subscription" \
         "got: ${REARM:-<no REARM line>}" \
         "wanted: [lua] REARM interval=0 sub=0 timeout=0" \
         "stop() severs what the script had armed and then returns to the" \
         "script, which was free to arm more; measured on the parent, that is" \
         "an interval firing at full rate on a runtime ls reports as Stopped"
fi

# ── And nothing it armed ever runs ─────────────────────────────────────────
#
# The observable half, and the one that does not depend on any return value.
# Sampled entirely after the stop, over a window a 120 ms interval would fill.
TICKS_BEFORE=$(count "ZOMBIE TICK")
sleep 2
TICKS_AFTER=$(count "ZOMBIE TICK")
if [ "$TICKS_AFTER" = "$TICKS_BEFORE" ] && [ "$TICKS_AFTER" = "0" ]; then pass; else
    fail "no interval armed after the stop ever fires" \
         "ZOMBIE TICK count $TICKS_BEFORE -> $TICKS_AFTER over 2s of a 120ms interval" \
         "measured on the parent: 41 ticks in the same window"
fi
if [ "$(count 'ZOMBIE TIMEOUT')" = "0" ]; then pass; else
    fail "no timeout armed after the stop ever fires" \
         "a ZOMBIE TIMEOUT line is in the log"
fi
# This one is already green on the parent, and it is worth saying why rather
# than letting it look like coverage it is not: delivery to a stopped runtime is
# refused by dispatch_publish's state test, so the subscription being refused
# here changes nothing observable.  What it catches is the build where BOTH go —
# a latch that covered only the timers together with a dispatch_publish that
# stopped asking about state.  The direct reading of `sub=` above is what this
# half of the latch is actually asserted by.
# Read after the two-second window above, by which time the severance has long
# settled: this is the number the restart must not move.
TOP_FROZEN=$(count TOPTICK)

publish after zombie
sleep 0.7
if [ "$(count 'ZOMBIE SUB')" = "0" ]; then pass; else
    fail "no subscription made after the stop ever receives" \
         "a ZOMBIE SUB line is in the log" \
         "both the latch and dispatch_publish's state test would have to be" \
         "gone for this to be reachable"
fi

# ── The latch lifts when the runtime starts again ──────────────────────────
"$BIN" start rearm_srv >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$SRV_PORT" 10 || echo "  NOTE: the server never re-accepted"
# Counted rather than matched on `starts=2`.  The counter is an upvalue in the
# worker's interpreter and a start forks a NEW worker, so the second on_start
# reports starts=1 -- the same number as the first, from a Lua state that has
# never seen the first.  What has to be true is that there are now TWO READY
# lines and that the second one armed live ids.
for _ in $(seq 1 80); do
    [ "$(count 'READY starts=')" -ge 2 ] && break
    sleep 0.1
done
REREADY=$(grep -a "READY starts=" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1 || true)
if [ "$(count 'READY starts=')" -lt 2 ]; then
    fail "a restarted runtime can arm timers and subscriptions again" \
         "only $(count 'READY starts=') READY line(s); the second worker's" \
         "on_start never ran" \
         "a latch that never opened would make 'stop; start' a way to get a" \
         "runtime that is up and can schedule nothing, which is worse than" \
         "the defect being fixed"
else
    case "$REREADY" in
        *" sub=0"*|*" interval=0"*)
            fail "a restarted runtime can arm timers and subscriptions again" \
                 "got: $REREADY" \
                 "0 is the refusal; the latch lowered by the stop never lifted" ;;
        *) pass ;;
    esac
fi
HB_BEFORE=$(count HEARTBEAT)
sleep 1
HB_AFTER=$(count HEARTBEAT)
if [ "$HB_AFTER" -gt "$HB_BEFORE" ]; then pass; else
    fail "the interval armed by the second on_start actually fires" \
         "HEARTBEAT count $HB_BEFORE -> $HB_AFTER over 1s of a 200ms interval"
fi
LIVE_BEFORE=$(count "LIVE SUB")
publish go again
said "LIVE SUB again" 6 || true
LIVE_AFTER=$(count "LIVE SUB")
if [ "$LIVE_AFTER" -gt "$LIVE_BEFORE" ]; then pass; else
    fail "the subscription made by the second on_start actually receives" \
         "no new 'LIVE SUB' line after the restart"
fi

# ── ...and the top-level timer DOES come back ──────────────────────────────
#
# This assertion is inverted, and the asymmetry it was written about is gone.
#
# It read: `start` re-runs on_start, so what on_start armed returns, and a timer
# armed at the script's TOP LEVEL has nothing to replay it, because the top
# level ran once, at load.  True while the script and the runtime shared a
# process and an interpreter -- which is what --daemon-process was providing.
#
# A script runs where its runtime runs.  A stop retires the worker and a start
# forks a NEW one, which loads the script from the file and runs its top level
# like any other first run.  So there is no asymmetry left to pin: on_start's
# registrations come back because on_start runs again, and the top level's come
# back because the top level runs again.
#
# `starts` says the same thing from the other direction and is why the READY
# assertion above stopped looking for `starts=2`: the counter is a Lua upvalue
# in an interpreter that no longer exists, so the second start reports 1.
TOP_AFTER=$(count TOPTICK)
if [ "$TOP_AFTER" -gt "$TOP_FROZEN" ]; then pass; else
    fail "a timer armed at the top level comes back on start" \
         "TOPTICK went $TOP_FROZEN -> $TOP_AFTER across the restart" \
         "a start forks a new worker, which runs the script from the top; a" \
         "frozen count means the second worker never loaded it"
fi

# ── The daemon survived all of that ────────────────────────────────────────
TOTAL=$((TOTAL+1))
if kill -0 "$SOCKETLEY_DPID" 2>/dev/null && daemon_alive "$SOCKETLEY_SOCKET"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: the daemon did not survive a script stopping its own runtime"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
