#!/usr/bin/env bash
# Integration test: a subscriber may remove its own runtime.
#
# ─── WHICH PATH THIS IS, EXACTLY ────────────────────────────────────────────
#
# `socketley.remove(<my own name>)` from inside a socketley.subscribe callback
# frees the runtime whose lua_context is holding the frame that made the call.
# runtime_manager::dispatch_publish re-resolves every name before it delivers,
# which protects the OTHER runtimes in its loop from a subscriber that removes
# one of them — and does nothing at all for the one that is executing.
#
# What saves the ordinary case is somewhere else entirely: runtime_manager's
# graveyard.  `remove` moves the instance out of the map and hands it to
# retire(), which does not destroy it — the ring may still hold addresses inside
# it — but parks it until the loop reports it owes nothing, and the health timer
# frees it two seconds later, long after this frame has gone.  So a RUNNING
# runtime removing itself has always worked, and the first half of this file is
# the control that says so.
#
# retire() has one shortcut, and it is the whole defect:
#
#     // An instance that never reached setup() never put an io_request of its
#     // own into the ring, so nothing can point into it and it goes now.
#     if (!inst->has_armed_io())
#         return;
#
# The ring is not the only thing that can point into an instance.  The C++ call
# stack is another, and on this path it is: `return` destroys the by-value
# unique_ptr, which destroys the runtime_instance, which destroys the
# lua_context whose dispatch_publish frame is three levels down.  Measured on
# the parent commit, with a server created and never started and its
# subscription made at the script's top level:
#
#     [lua] B: top-level handler ran, removing myself
#     Segmentation fault (core dumped)
#
# and then — because every CLI command auto-starts a daemon when the socket
# does not answer — a fresh daemon came up, restored the state file, and `ls`
# showed all three runtimes as if nothing had happened.  That is why the
# assertion below is on the pid of the daemon that was serving before the
# publish, and never on what `ls` says afterwards.
#
# The narrow reading matters and is the reason the created-state runtime is the
# one under test: a runtime that has never been started is one of the two kinds
# that never arm io (the other is an external one, which has no Lua VM to
# subscribe from).  A top-level socketley.subscribe is not exotic — the script's
# top level is where tick_ms and callback_timeout_ms are declared and where the
# examples put their configuration — and it runs at load, which is `create`.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ready.sh"

daemon_isolate luaselfrm

PB=${PB:-24070}
CACHE_PORT=$((PB + 0))
RUN_PORT=$((PB + 1))
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
    "$BIN" stop   selfrm_cache selfrm_run selfrm_new >/dev/null 2>&1 || true
    sleep 0.2
    "$BIN" remove selfrm_cache selfrm_run selfrm_new >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a subscriber that removes its own runtime ==="

daemon_start "$BIN"

# Two runtimes, one script each, differing only in which channel they listen on
# and where the subscription is made.
RUN_LUA="$SOCKETLEY_TMPD/running.lua"
cat > "$RUN_LUA" <<'LUAEOF'
function on_start()
    socketley.subscribe("selfrm_cache", "gorun", function(ch, msg)
        socketley.log("RUN: removing myself")
        socketley.log("RUN: remove=" .. tostring(socketley.remove("selfrm_run")))
    end)
    socketley.log("RUN: ready")
end
LUAEOF

NEW_LUA="$SOCKETLEY_TMPD/never_started.lua"
cat > "$NEW_LUA" <<'LUAEOF'
-- At the top level on purpose: this runs when the script is LOADED, which is
-- `create`, so the registration exists on a runtime that has never started and
-- therefore has never armed a single io_request.
socketley.subscribe("selfrm_cache", "gonew", function(ch, msg)
    socketley.log("NEW: removing myself")
    socketley.log("NEW: remove=" .. tostring(socketley.remove("selfrm_new")))
end)
socketley.log("NEW: ready")
LUAEOF

create_ok "cache created"   "$BIN" create cache  selfrm_cache -p "$CACHE_PORT" -s
create_ok "running created" "$BIN" create server selfrm_run   -p "$RUN_PORT" \
    --lua "$RUN_LUA" --daemon-process -s
# No -s: this one is created and never started.
create_ok "created created"  "$BIN" create server selfrm_new  -p "$NEW_PORT" \
    --lua "$NEW_LUA" --daemon-process
ready_resp 127.0.0.1 "$CACHE_PORT" 10 || echo "  NOTE: the cache never answered PING"

said() {
    local pattern=$1 deadline=$(( $(date +%s) + ${2:-6} ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        grep -qaF "$pattern" "$SOCKETLEY_DLOG" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}
publish() { printf 'PUBLISH %s x\r\n' "$1" | nc -q 1 127.0.0.1 "$CACHE_PORT" >/dev/null 2>&1 || true; }

# The daemon this test started, by pid and by its start time, so that a crash
# followed by the auto-start every CLI command performs cannot be mistaken for
# survival.  daemon_alive asks the socket, which a replacement would answer.
DPID=$SOCKETLEY_DPID
DSTART=$(awk '{print $22}' "/proc/$DPID/stat" 2>/dev/null || true)
survived() {
    kill -0 "$DPID" 2>/dev/null || return 1
    [ "$(awk '{print $22}' "/proc/$DPID/stat" 2>/dev/null || true)" = "$DSTART" ] || return 1
    daemon_alive "$SOCKETLEY_SOCKET"
}

said "NEW: ready" 10 || true
said "RUN: ready" 10 || true

# ── Control: the running case, which the graveyard has always covered ──────
publish gorun
said "RUN: remove=" 8 || true
if grep -qa "RUN: remove=true" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    GOT=$(grep -a "RUN: remove=" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1 || true)
    fail "a running runtime can remove itself from its own subscriber" \
         "got: ${GOT:-<no line at all>}, wanted 'RUN: remove=true'"
fi
if survived; then pass; else
    fail "the daemon survives a running runtime removing itself" \
         "the daemon that was serving before the publish is gone" \
         "this is the path retire()'s graveyard covers and it must keep working"
fi

# ── The one under test: a runtime that never armed io ──────────────────────
#
# Both halves.  "The daemon survived" passes on a build where the publish never
# reached the handler at all, so the handler is proved to have run and the
# removal is proved to have taken effect before survival is allowed to count.
publish gonew
said "NEW: remove=" 8 || true
if grep -qa "NEW: removing myself" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "control: the publish reached the never-started runtime's handler" \
         "no 'NEW: removing myself' line" \
         "nothing below is measuring a self-removal if nothing removed anything"
fi

if survived; then pass; else
    fail "the daemon survives a never-started runtime removing itself" \
         "the daemon that was serving before the publish is gone" \
         "retire() frees an instance that never armed io on the spot, and the" \
         "C++ stack is a holder its ring test does not cover: the free lands" \
         "under the live dispatch_publish frame of the very context that asked" \
         "for it.  Measured on the parent: SIGSEGV, then a fresh daemon" \
         "auto-started by the next CLI command with the runtime restored."
fi

# The removal has to have happened, not merely not crashed: deferring the free
# must not turn `remove` into a no-op.  Asked of the daemon only when it is the
# original one — a replacement would answer from a restored state file.
if survived; then
    if "$BIN" ls 2>/dev/null | grep -qa "selfrm_new"; then
        fail "the self-removal took effect" \
             "'selfrm_new' is still listed after its own handler removed it" \
             "the instance leaves the map at remove(); only the free is deferred"
    else pass; fi
else
    fail "the self-removal took effect" \
         "not asked: the daemon did not survive, so ls would be answered by a" \
         "replacement that restored the runtime from the state file"
fi

# ── And it is still a daemon afterwards ────────────────────────────────────
#
# A publish on a channel nobody listens to, served by the same cache, through
# the same fan-out the two removals went through.
TOTAL=$((TOTAL+1))
if survived && "$BIN" ls >/dev/null 2>&1; then
    publish quiet
    sleep 0.3
    if survived; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: the daemon did not survive a later publish"
    fi
else
    FAIL=$((FAIL+1))
    echo "  FAIL: the daemon was not serving by the end of this test"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
