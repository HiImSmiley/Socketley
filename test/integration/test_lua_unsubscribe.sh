#!/usr/bin/env bash
# Integration test: socketley.subscribe has a counterpart.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# socketley.subscribe appended to a vector and returned nothing, and nothing in
# the tree ever took an entry out again.  The whole life of a subscription was
# therefore the life of the lua_context, which is `remove` — not `stop`, not
# `reload-lua`, and certainly not "when the script is done with it".
#
# The bill is not a leak in the abstract.  A script that subscribes from a
# callback that runs more than once — on_tick is the ordinary one — registers
# the same handler again on every tick, and each publish is then delivered to
# every copy:
#
#     tick 1   subscribe   publish -> handler runs 1x
#     tick 2   subscribe   publish -> handler runs 2x
#     ...
#
# so the work per message grows without bound while the script looks correct.
#
# ─── THE IDENTITY ───────────────────────────────────────────────────────────
#
# subscribe() now returns an integer and unsubscribe() takes it, following the
# timers: set_timeout hands back an id and clear_timeout takes it, which is the
# closest precedent this API has.  unsubscribe(cache, channel) was the
# alternative and cannot express the case the counterpart exists for — two
# handlers on one channel, of which the script wants to drop one — which is the
# first thing this file asserts.
#
# ─── THE RE-ENTRANT CASE ────────────────────────────────────────────────────
#
# A handler that unsubscribes itself is how anyone writes a one-shot subscriber,
# and it lands in the middle of the loop delivering to it.  The loop used to be
# a range-for over the vector, so the mutation would have walked a freed buffer;
# insertions and removals made during a delivery are deferred to the end of it
# now.  SELFSUB below is that case, and it is asserted twice: it runs once, and
# it does not run again.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luaunsub

PB=$((SL_PORT_BASE+1030))
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
    "$BIN" stop   sub_srv subcache >/dev/null 2>&1 || true
    sleep 0.2
    "$BIN" remove sub_srv subcache >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: socketley.unsubscribe ==="

daemon_start "$BIN"

LUA="$SOCKETLEY_TMPD/sub.lua"
cat > "$LUA" <<'LUAEOF'
local ids   = {}
local n     = { a = 0, b = 0, selfsub = 0, churn = 0 }
local churn_id

function on_start()
    ids.a = socketley.subscribe("subcache", "news", function(ch, msg)
        n.a = n.a + 1
        socketley.log("SUB a=" .. n.a .. " msg=" .. msg)
    end)
    ids.b = socketley.subscribe("subcache", "news", function(ch, msg)
        n.b = n.b + 1
        socketley.log("SUB b=" .. n.b .. " msg=" .. msg)
    end)
    socketley.log("IDS a=" .. tostring(ids.a) .. " b=" .. tostring(ids.b))
    socketley.log("API unsubscribe=" .. type(socketley.unsubscribe))
end

-- Each command is one connection, so a command that raises takes only itself
-- down.  Deliberately unguarded: on a build with no socketley.unsubscribe these
-- are calls to a nil value, which is the finding rather than something to work
-- around.
function on_message(m)
    if m == "unsub_a" then
        socketley.log("UNSUB a=" .. tostring(socketley.unsubscribe(ids.a)))
    elseif m == "unsub_a_again" then
        socketley.log("UNSUB again=" .. tostring(socketley.unsubscribe(ids.a)))
    elseif m == "unsub_unknown" then
        socketley.log("UNSUB unknown=" .. tostring(socketley.unsubscribe(4242)))
    elseif m == "selfsub" then
        local id
        id = socketley.subscribe("subcache", "news", function(ch, msg)
            n.selfsub = n.selfsub + 1
            socketley.log("SELFSUB n=" .. n.selfsub)
            socketley.unsubscribe(id)
        end)
        socketley.log("SELFSUB armed=" .. tostring(id))
    elseif m == "churn" then
        -- The on_tick shape, five times over: re-register and drop the previous
        -- one.  Exactly one handler must be live afterwards.
        for _ = 1, 5 do
            if churn_id then socketley.unsubscribe(churn_id) end
            churn_id = socketley.subscribe("subcache", "news", function(ch, msg)
                n.churn = n.churn + 1
                socketley.log("CHURN n=" .. n.churn)
            end)
        end
        socketley.log("CHURN armed")
    end
end
LUAEOF

create_ok "cache created"  "$BIN" create cache  subcache -p "$CACHE_PORT" -s
create_ok "server created" "$BIN" create server sub_srv  -p "$SRV_PORT" \
    --lua "$LUA" -s
ready_tcp 127.0.0.1 "$SRV_PORT"   10 || echo "  NOTE: the server never accepted"
ready_tcp 127.0.0.1 "$CACHE_PORT" 10 || echo "  NOTE: the cache never accepted"

# said PATTERN [TIMEOUT_S]
said() {
    local pattern=$1 deadline=$(( $(date +%s) + ${2:-6} ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        grep -qaF "$pattern" "$SOCKETLEY_DLOG" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}
cmd()     { printf '%s\n' "$1" | nc -q 1 127.0.0.1 "$SRV_PORT" >/dev/null 2>&1 || true; }
publish() { printf 'PUBLISH news %s\r\n' "$1" | nc -q 1 127.0.0.1 "$CACHE_PORT" >/dev/null 2>&1 || true; }
hits()    { grep -ac "$1" "$SOCKETLEY_DLOG" 2>/dev/null || true; }

said "API unsubscribe=" 10 || true

# ── subscribe hands back an identity, and unsubscribe exists ────────────────
if grep -qa "IDS a=1 b=2" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    GOT=$(grep -a "IDS " "$SOCKETLEY_DLOG" 2>/dev/null | tail -1 || true)
    fail "subscribe returns an id, and two on one channel get different ones" \
         "got: ${GOT:-<no line at all>}, wanted 'IDS a=1 b=2'" \
         "an id is the only identity that can name one of two handlers on the" \
         "same channel; ids start at 1 so 0 is never one"
fi
if grep -qa "API unsubscribe=function" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    GOT=$(grep -a "API unsubscribe=" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1 || true)
    fail "socketley.unsubscribe is bound" "got: ${GOT:-<no line at all>}"
fi

# ── Control: both handlers receive the first message ────────────────────────
publish m1
said "SUB b=1 msg=m1" 6 || true
if grep -qa "SUB a=1 msg=m1" "$SOCKETLEY_DLOG" 2>/dev/null &&
   grep -qa "SUB b=1 msg=m1" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "control: a publish reaches both subscribers" \
         "one of 'SUB a=1 msg=m1' / 'SUB b=1 msg=m1' is missing" \
         "nothing below is measuring an unsubscribe if nothing was subscribed"
fi

# ── The removal ─────────────────────────────────────────────────────────────
cmd unsub_a
said "UNSUB a=" 6 || true
if grep -qa "UNSUB a=true" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    GOT=$(grep -a "UNSUB a=" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1 || true)
    fail "unsubscribe answers true for a live registration" \
         "got: ${GOT:-<no line at all>}"
fi

publish m2
said "SUB b=2 msg=m2" 6 || true
if grep -qa "SUB a=.* msg=m2" "$SOCKETLEY_DLOG" 2>/dev/null; then
    fail "the unsubscribed handler stops receiving" \
         "'SUB a=... msg=m2' is in the log" \
         "the vector only ever grew, so a subscription lasted as long as the" \
         "interpreter did and no script could end one"
else pass; fi
if grep -qa "SUB b=2 msg=m2" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "control: the OTHER handler on that channel keeps receiving" \
         "no 'SUB b=2 msg=m2' line" \
         "removing one entry must not empty the channel — an id names one" \
         "registration, which is the whole reason it is an id"
fi

# ── The answers for an id that names nothing ────────────────────────────────
cmd unsub_a_again
said "UNSUB again=" 6 || true
if grep -qa "UNSUB again=false" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    GOT=$(grep -a "UNSUB again=" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1 || true)
    fail "unsubscribing twice answers false the second time" \
         "got: ${GOT:-<no line at all>}" \
         "ids are never reused, so a stale one names nothing and must say so" ;
fi
cmd unsub_unknown
said "UNSUB unknown=" 6 || true
if grep -qa "UNSUB unknown=false" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    GOT=$(grep -a "UNSUB unknown=" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1 || true)
    fail "unsubscribing an id that was never issued answers false" \
         "got: ${GOT:-<no line at all>}"
fi

# ── A handler that removes itself, from inside its own delivery ─────────────
cmd selfsub
said "SELFSUB armed=" 6 || true
publish m3
said "SELFSUB n=1" 6 || true
if grep -qa "SELFSUB n=1" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "a one-shot subscriber runs once" "no 'SELFSUB n=1' line"
fi

publish m4
said "SUB b=4 msg=m4" 6 || true
if grep -qa "SELFSUB n=2" "$SOCKETLEY_DLOG" 2>/dev/null; then
    fail "a one-shot subscriber does not run again" \
         "'SELFSUB n=2' is in the log" \
         "unsubscribing from inside a delivery must take effect for the next" \
         "one; deferring the removal is not deferring it for ever"
else pass; fi

# ── The growth this whole item is about ─────────────────────────────────────
cmd churn
said "CHURN armed" 6 || true
CHURN_BEFORE=$(hits 'CHURN n=')
publish m5
said "CHURN n=" 6 || true
sleep 0.5
CHURN_AFTER=$(hits 'CHURN n=')
DELIVERED=$((CHURN_AFTER - CHURN_BEFORE))
if [ "$DELIVERED" = "1" ]; then pass; else
    fail "re-subscribing and dropping the previous one leaves exactly one" \
         "one publish reached the churn handler $DELIVERED times, wanted 1" \
         "five subscribe calls with four unsubscribes between them is the" \
         "on_tick shape; without the counterpart it is five live handlers and" \
         "every message is delivered five times"
fi

# ── The daemon survived all of that ─────────────────────────────────────────
TOTAL=$((TOTAL+1))
if kill -0 "$SOCKETLEY_DPID" 2>/dev/null && daemon_alive "$SOCKETLEY_SOCKET"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: the daemon did not survive subscribing and unsubscribing"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
