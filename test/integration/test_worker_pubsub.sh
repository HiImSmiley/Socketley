#!/usr/bin/env bash
# Integration test: a PUBLISH reaches the process that is serving the proxy.
#
# ─── WHY A RESPONSE BODY AND NOT A LOG LINE ─────────────────────────────────
#
# The obvious oracle — "the subscribe callback printed something" — cannot
# answer this question at all, and it is worth saying why before the file goes
# on to do something more awkward.
#
# A proxy created with exists twice: as the worker process that
# owns the listening socket, and as a placeholder inside the daemon that holds
# its name, port and state.  The placeholder loads the same Lua script.  So the
# script's `socketley.subscribe` call is registered in BOTH interpreters, and
# the daemon's dispatch — which walks its own runtime map — found the
# placeholder's copy and ran it.  A log line therefore appeared for every
# publish, from a copy of the script attached to an instance that serves
# nothing, while the process actually relaying the traffic never heard about it.
# Both processes write to the same stderr, and neither line says which one
# produced it.  Counting them cannot tell "delivered to the worker" from
# "delivered to the placeholder"; it cannot even tell them apart.
#
# So the oracle is what the *serving* process does with what it was told.  The
# subscriber stores the message in a Lua upvalue and a filter — which runs on
# the request path, inside whichever process owns the socket the client
# connected to — answers with it.  A response carrying the published text can
# only have come from an interpreter that received the publish AND is serving
# the port.  The placeholder is serving nothing, so it cannot produce this
# answer however many times its callback runs.
#
# ─── THE CONTROLS ───────────────────────────────────────────────────────────
#
# Three, because most of what is asserted here is a string appearing where it
# should, and a file full of those passes against a build where nothing works.
#
#   * BEFORE the publish, both proxies must answer `seen=none`.  Without it,
#     "the answer contains the message" would also pass if the filter echoed
#     something unconditional, or if a stale runtime from an earlier run were
#     answering the port.
#   * The in-process proxy must answer `seen=<message>`.  It shares the script,
#     the filter and the cache with the out-of-process one and differs only in
#     which process it runs in, so it proves the whole apparatus — cache,
#     PUBLISH, subscribe, upvalue, filter — works, and narrows a failure of the
#     out-of-process case to the boundary rather than to any of that.
#   * One PUBLISH must run the out-of-process proxy's subscriber exactly once.
#     This one is GREEN BEFORE AND AFTER and is not the finding: before, the
#     single run is the placeholder's; after, it is the worker's.  It is here
#     because the obvious way to make the assertion above pass — send the frame
#     to the worker and leave the placeholder dispatching too — delivers one
#     message to two interpreters, and every other check in this file stays
#     green when it does.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate workerpubsub

BE_PORT=$((SL_PORT_BASE+420))
CACHE_PORT=$((SL_PORT_BASE+421))
PX_IN_PORT=$((SL_PORT_BASE+422))
PX_OOP_PORT=$((SL_PORT_BASE+423))
MSG="published-at-$$"

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop px_oop px_in cachepub backend 2>/dev/null || true
    sleep 0.3
    "$BIN" remove px_oop px_in cachepub backend 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a publish reaches the worker ==="

daemon_start "$BIN"

# Two files rather than one shared between the proxies: both processes write to
# the same stderr, so the delivery count below needs a tag only one of them can
# emit.
write_script() {   # write_script PATH TAG
    cat > "$1" <<LUAEOF
-- Whatever the last publish on cachepub/news carried, or "none".  An upvalue
-- and not a global, so it is unmistakably per-interpreter: two processes
-- running this file hold two of these and neither can see the other's.
local seen = "none"

socketley.subscribe("cachepub", "news", function(chan, msg)
    seen = msg
    socketley.log("DELIVERY-$2 " .. msg)
end)

filters = {
    function(req)
        if string.find(req.path, "/probe", 1, true) then
            return { status = 200, body = "seen=" .. seen .. "\n" }
        end
    end,
}
LUAEOF
}

LUA_IN="$SOCKETLEY_TMPD/px_in.lua"
LUA_OOP="$SOCKETLEY_TMPD/px_oop.lua"
write_script "$LUA_IN"  IN
write_script "$LUA_OOP" OOP

# probe NAME PORT -> the body, or the empty string.  Never a substituted
# default: an empty answer must not compare equal to a real one.
#
# The path carries the runtime's name because that is what a socketley proxy
# routes on -- anything not under /<name>/ is answered 404 by the proxy itself,
# before any filter runs.  Getting this wrong is silent: the 404 body is the
# same one the backend would have sent.
probe() {
    curl -s --max-time 3 "http://127.0.0.1:$2/$1/probe" 2>/dev/null || printf ''
}

create_ok "backend created"  "$BIN" create server backend  -p "$BE_PORT" -s
create_ok "cache created"    "$BIN" create cache  cachepub -p "$CACHE_PORT" -s
create_ok "in-process proxy created" "$BIN" create proxy px_in -p "$PX_IN_PORT" \
    --backend "127.0.0.1:$BE_PORT" --protocol http --lua "$LUA_IN" --daemon-process -s
create_ok "out-of-process proxy created" "$BIN" create proxy px_oop -p "$PX_OOP_PORT" \
    --backend "127.0.0.1:$BE_PORT" --protocol http --lua "$LUA_OOP" -s

# The worker is forked by `create --start`; wait for it to bind rather than
# guessing at how long that takes.
for _ in $(seq 1 60); do
    [ -n "$(probe px_oop "$PX_OOP_PORT")" ] && break
    sleep 0.1
done

# ── Control 1: nothing published yet ────────────────────────────────────────
B_IN=$(probe px_in "$PX_IN_PORT")
B_OOP=$(probe px_oop "$PX_OOP_PORT")

if [ "$B_IN" = "seen=none" ]; then pass; else
    fail "control: in-process proxy starts with nothing seen" \
         "answered '$B_IN', wanted 'seen=none'" \
         "the filter did not run, so nothing below is measuring a publish"
fi
if [ "$B_OOP" = "seen=none" ]; then pass; else
    fail "control: worker starts with nothing seen" \
         "answered '$B_OOP', wanted 'seen=none'" \
         "the filter did not run in the worker, so nothing below is measuring a publish"
fi

# ── The publish ─────────────────────────────────────────────────────────────
OOP_BEFORE=$(grep -c 'DELIVERY-OOP' "$SOCKETLEY_DLOG" 2>/dev/null) || OOP_BEFORE=0

PUB_RC=0
printf 'PUBLISH news %s\r\n' "$MSG" \
    | timeout 10 nc -q 1 127.0.0.1 "$CACHE_PORT" >/dev/null 2>&1 || PUB_RC=$?

# The frame crosses a socket and is applied on the worker's next control drain,
# so poll rather than sleep a guess.
for _ in $(seq 1 60); do
    [ "$(probe px_oop "$PX_OOP_PORT")" = "seen=$MSG" ] && break
    sleep 0.1
done

A_IN=$(probe px_in "$PX_IN_PORT")
A_OOP=$(probe px_oop "$PX_OOP_PORT")

# ── Control 2: the apparatus works in process ───────────────────────────────
if [ "$A_IN" = "seen=$MSG" ]; then pass; else
    fail "control: in-process proxy saw the publish" \
         "answered '$A_IN', wanted 'seen=$MSG' (PUBLISH exited $PUB_RC)" \
         "cache, PUBLISH, subscribe, upvalue or filter is broken — the" \
         "out-of-process result below cannot be attributed to the boundary"
fi

# ── The assertion ───────────────────────────────────────────────────────────
if [ "$A_OOP" = "seen=$MSG" ]; then pass; else
    fail "a publish reaches the worker" \
         "the out-of-process proxy answered '$A_OOP', wanted 'seen=$MSG'" \
         "The daemon dispatched this publish by walking its own runtime map." \
         "The worker is not in that map; only its placeholder is, and the" \
         "placeholder serves no traffic, so the callback ran in the wrong" \
         "process and the one relaying requests never heard about it."
fi

# ── Control 3: and it ran once, not twice ───────────────────────────────────
sleep 0.5
OOP_AFTER=$(grep -c 'DELIVERY-OOP' "$SOCKETLEY_DLOG" 2>/dev/null) || OOP_AFTER=0
RUNS=$((OOP_AFTER - OOP_BEFORE))
if [ "$RUNS" -eq 1 ]; then pass; else
    fail "control: one publish runs the subscriber once" \
         "it ran $RUNS times for one PUBLISH, wanted exactly 1" \
         "Two runs means the daemon's placeholder ran the callback as well as" \
         "the worker: one message, two interpreters, and only one of them is" \
         "attached to a socket.  Every other check in this file stays green" \
         "when that happens, which is why this one is here."
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
