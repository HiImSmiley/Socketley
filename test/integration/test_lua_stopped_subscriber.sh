#!/usr/bin/env bash
# Integration test: a runtime that is not running receives no published message.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# 23e5181 fixed this for timers: `stop` severed the on_tick machinery and left
# every set_timeout and set_interval the script had armed, so a runtime the
# operator had stopped went on executing script at full rate until the daemon
# died.  socketley.subscribe was the other half of the same hole and was left
# standing.  A subscription lives in the lua_context, the context is only
# destroyed by `remove`, and nothing between `stop` and `remove` touched the
# registrations — so a PUBLISH on the linked cache was delivered to a runtime
# that `ls` reported as Stopped.  Measured on the parent commit:
#
#     publish while running    HIT n=1 msg=m1 state=running
#     stop                     ONSTOP
#     publish while stopped    HIT n=2 msg=m2 state=stopped   <- this
#
# The handler even reads self.state as "stopped" and runs anyway.  That is not
# untidy: socketley.subscribe callbacks call self.send, and self.send from a
# stopped runtime delivers to clients of a runtime the operator has taken down
# — the same sentence 23e5181 is written under, one API along.
#
# ─── WHAT COMES BACK, AND WHAT DOES NOT ─────────────────────────────────────
#
# Subscriptions differ from timers on the restart, and the difference is worth
# an assertion rather than a footnote.  Timers are armed at the script's top
# level, which runs when the script is LOADED, so a later `start` has nothing
# to replay and they stay gone.  Subscriptions are made from on_start — the
# shape the man page documents and every example uses — and `start` runs
# on_start.  So they do come back, and the last assertion here is that they do:
# a severance that also broke the restart would pass every check above this
# line while quietly making `stop; start` a way to lose your subscribers.
#
# ─── THE OTHER HALF OF "NOT RUNNING" ────────────────────────────────────────
#
# Severing at `stop` covers a runtime that stopped.  The other half is one that
# never started, and this file was written when that runtime WAS delivered to:
# a script's top level ran when the script was loaded, which was `create`, so a
# top-level socketley.subscribe was a live registration on a runtime `ls`
# reported as Created.  Measured on the parent commit:
#
#     $ socketley create server nostart -p ... --lua top.lua --daemon-process
#     $ socketley ls
#     nostart   server   ...   Created
#     $ printf 'PUBLISH news m1\r\n' | nc ... <the cache>
#     [lua] CREATED-STATE HIT msg=m1 state=created
#
# That command cannot be typed now and neither can that state be reached.  A
# script runs where its runtime runs, which is a worker, and a worker exists
# from `start` -- so a bare `create` compiles the script and runs nothing, and
# the registration this half was about is never made in the first place.
#
# The claim is kept because it is still the claim, and it is now satisfied one
# level lower down: a runtime that is not running executes no script.  What had
# to change is the CONTROL.  It used to be "the never-started runtime logged
# SUBSCRIBED", which is exactly the line that can no longer exist -- so a second
# runtime is built from the same script and started, and it is that one which
# proves the script, the subscription and the cache fan-out all work.  An
# absence for the never-started one is then a decision about delivery rather
# than a script nobody ran.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luastopsub

PB=$((SL_PORT_BASE+1060))
SRV_PORT=$((PB + 0))
CACHE_PORT=$((PB + 1))
NEW_PORT=$((PB + 2))

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop   stopsub_srv stopsub_cache stopsub_new stopsub_live >/dev/null 2>&1 || true
    sleep 0.2
    "$BIN" remove stopsub_srv stopsub_cache stopsub_new stopsub_live >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a runtime that is not running receives no publish ==="

daemon_start "$BIN"

LUA="$SOCKETLEY_TMPD/stopsub.lua"
cat > "$LUA" <<'LUAEOF'
local n = 0
function on_start()
    socketley.subscribe("stopsub_cache", "news", function(ch, msg)
        n = n + 1
        socketley.log("HIT msg=" .. msg .. " state=" .. tostring(self.state))
    end)
    socketley.log("SUBSCRIBED")
end
function on_stop()
    socketley.log("ONSTOP")
end
LUAEOF

# The never-started half.  Its subscription is made at the script's TOP LEVEL,
# which is what makes it exist at all on a runtime whose on_start has not run —
# and the top level is not an exotic place to put one: it is where tick_ms and
# callback_timeout_ms are declared and where the examples put their setup.
NEW_LUA="$SOCKETLEY_TMPD/never_started.lua"
cat > "$NEW_LUA" <<'LUAEOF'
socketley.subscribe("stopsub_cache", "news", function(ch, msg)
    socketley.log("NOSTART msg=" .. msg .. " state=" .. tostring(self.state))
end)
socketley.log("NOSTART SUBSCRIBED")
LUAEOF

create_ok "cache created"  "$BIN" create cache  stopsub_cache -p "$CACHE_PORT" -s
create_ok "server created" "$BIN" create server stopsub_srv   -p "$SRV_PORT" \
    --lua "$LUA" -s
# No -s: created, never started, and never stopped either.
create_ok "never-started created" "$BIN" create server stopsub_new -p "$NEW_PORT" \
    --lua "$NEW_LUA"
# The same script, started.  This is the control the never-started arm lost:
# it is what says the subscription in NEW_LUA is a working one, so the silence
# below is about the runtime's state and not about the script.
create_ok "the same script, started" "$BIN" create server stopsub_live \
    -p "$((NEW_PORT + 1))" --lua "$NEW_LUA" -s
ready_tcp 127.0.0.1 "$SRV_PORT"   10 || echo "  NOTE: the server never accepted"
ready_resp 127.0.0.1 "$CACHE_PORT" 10 || echo "  NOTE: the cache never answered PING"

# said PATTERN [TIMEOUT_S]
said() {
    local pattern=$1 deadline=$(( $(date +%s) + ${2:-6} ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        grep -qaF "$pattern" "$SOCKETLEY_DLOG" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}
publish() { printf 'PUBLISH news %s\r\n' "$1" | nc -q 1 127.0.0.1 "$CACHE_PORT" >/dev/null 2>&1 || true; }
hits()    { grep -ac 'HIT msg=' "$SOCKETLEY_DLOG" 2>/dev/null || true; }

said "SUBSCRIBED" 10 || true

# ── Control: the subscription is live while the runtime is running ──────────
publish m1
said "HIT msg=m1" 6 || true
said "NOSTART msg=m1" 6 || true
if grep -qa "HIT msg=m1 state=running" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "control: a publish reaches the subscriber while it is running" \
         "no 'HIT msg=m1 state=running' line" \
         "nothing below this point is measuring a severance if nothing was" \
         "ever subscribed"
fi

# ── The never-started runtime, on that same publish ────────────────────────
#
# One message, two runtimes, and the line above is this one's control: the
# publish demonstrably reached the cache and was fanned out, so an absence here
# is a decision rather than a message that never arrived.
#
# Its registration is proved live first, for the same reason — a build where the
# top level never ran would satisfy "no delivery" without deciding anything.
if grep -qa "NOSTART SUBSCRIBED" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "control: the same script, in a started runtime, subscribes" \
         "no 'NOSTART SUBSCRIBED' line from stopsub_live" \
         "the script is the same file the never-started runtime was given, so" \
         "without this the absence below is a script that does not work"
fi
if grep -qa "NOSTART msg=" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "control: and it actually receives the publish" \
         "stopsub_live logged no 'NOSTART msg=' line" \
         "subscribing is not receiving; without this the absence below could be" \
         "a fan-out that reaches nobody at all"
fi
STATUS=$("$BIN" ls 2>/dev/null | awk '$2 == "stopsub_new" { print $7 }' || true)
if [ "$STATUS" = "Created" ]; then pass; else
    fail "control: ls reports the never-started runtime as created" \
         "ls says '${STATUS:-<nothing>}', wanted 'Created'"
fi
# Counted, not merely present: stopsub_live is subscribed and receives it, so
# "a line exists" is now the control above.  What must not happen is a SECOND
# line, which is the never-started runtime having a live handler.
NOSTART_HITS=$(grep -ac "NOSTART msg=" "$SOCKETLEY_DLOG" 2>/dev/null) || NOSTART_HITS=0
if [ "$NOSTART_HITS" -eq 1 ]; then pass; else
    fail "a runtime that never started receives nothing" \
         "$NOSTART_HITS deliveries of that publish, wanted exactly 1 (the" \
         "started control's)" \
         "a second one is stopsub_new having a live handler, which would mean a" \
         "script running for a runtime the operator has not started:" \
         "$(grep -a 'NOSTART msg=' "$SOCKETLEY_DLOG" 2>/dev/null | tr '\n' '|')"
fi

# ── The stop, proved rather than assumed ───────────────────────────────────
#
# Both halves.  "The handler did not run" is an assertion that passes on a
# no-op — a build where the publish never reached the cache at all would sail
# through it — so the stop is proved to have happened and the publish is proved
# to have been served before the absence below is allowed to mean anything.
"$BIN" stop stopsub_srv >/dev/null 2>&1 || true
said "ONSTOP" 6 || true
if grep -qa "ONSTOP" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "control: the stop ran on_stop" "no 'ONSTOP' line" \
         "the runtime never stopped, so the absence below says nothing"
fi
STATUS=$("$BIN" ls 2>/dev/null | awk '$2 == "stopsub_srv" { print $7 }' || true)
if [ "$STATUS" = "Stopped" ]; then pass; else
    fail "control: ls reports the runtime as stopped" \
         "ls says '${STATUS:-<nothing>}', wanted 'Stopped'"
fi

BEFORE=$(hits)
publish m2
# The cache is still up and still serving PUBLISH — that is the point of
# publishing through it rather than through the daemon: the message was
# delivered to the cache's own subscriber machinery whether or not any Lua ran.
if said "NOSTART msg=m2" 6; then pass; else
    fail "control: the publish after the stop is delivered" \
         "stopsub_live, subscribed to the same channel, logged no 'NOSTART msg=m2' line" \
         "so m2 never left the cache and the absence below says nothing"
fi
sleep 1
AFTER=$(hits)
if [ "$AFTER" = "$BEFORE" ]; then pass; else
    GOT=$(grep -a "HIT msg=m2" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1 || true)
    fail "a stopped runtime's subscriber does not fire" \
         "the handler ran $((AFTER - BEFORE)) time(s) after the stop" \
         "got: ${GOT:-<no m2 line>}" \
         "a subscription lived as long as the lua_context, which only 'remove'" \
         "destroys, so 'stop' left every registration in place; self.send from" \
         "such a handler reaches clients of a runtime the operator took down"
fi

# ── And it comes back, because on_start comes back ─────────────────────────
"$BIN" start stopsub_srv >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$SRV_PORT" 10 || echo "  NOTE: the server never re-accepted"
BEFORE=$(hits)
publish m3
said "HIT msg=m3" 6 || true
AFTER=$(hits)
if [ "$AFTER" -gt "$BEFORE" ]; then pass; else
    fail "a restarted runtime is subscribed again" \
         "no delivery after 'start' put the runtime back up" \
         "subscriptions are registered from on_start and start() runs on_start," \
         "so unlike the timers — which are armed at the script's top level and" \
         "stay gone — these must return; a severance that also broke this would" \
         "pass every assertion above"
fi

# ── The daemon survived all of that ────────────────────────────────────────
TOTAL=$((TOTAL+1))
if kill -0 "$SOCKETLEY_DPID" 2>/dev/null && daemon_alive "$SOCKETLEY_SOCKET"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: the daemon did not survive stopping a subscribed runtime"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
