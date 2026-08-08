#!/usr/bin/env bash
# Integration test: a stopped runtime receives no published message.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# ebb6897 fixed this for timers: `stop` severed the on_tick machinery and left
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
# — the same sentence ebb6897 is written under, one API along.
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

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop   stopsub_srv stopsub_cache >/dev/null 2>&1 || true
    sleep 0.2
    "$BIN" remove stopsub_srv stopsub_cache >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a stopped runtime's subscribers do not fire ==="

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

create_ok "cache created"  "$BIN" create cache  stopsub_cache -p "$CACHE_PORT" -s
create_ok "server created" "$BIN" create server stopsub_srv   -p "$SRV_PORT" \
    --lua "$LUA" --daemon-process -s
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
if grep -qa "HIT msg=m1 state=running" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "control: a publish reaches the subscriber while it is running" \
         "no 'HIT msg=m1 state=running' line" \
         "nothing below this point is measuring a severance if nothing was" \
         "ever subscribed"
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
