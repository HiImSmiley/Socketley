#!/usr/bin/env bash
# suite: quiet -- waits on wall-clock deadlines for a runtime to remove
# itself; a loaded box moves the deadline, not the behaviour.
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
# ─── WHICH NEVER-ARMED RUNTIME IS STILL REACHABLE ───────────────────────────
#
# The case this file was written against was a never-started runtime reached by
# a PUBLISH.  That is gone on purpose: delivery now requires a runtime to be
# running, so a top-level socketley.subscribe on a runtime nobody started is
# never called and cannot remove anything.  Deleting the assertion would have
# been the wrong move — it would leave the guard with no test at all — so the
# question was whether any reachable path remains.
#
# One does, and it never involved delivery.  A script's TOP LEVEL runs inside
# `create`, before the runtime has started and therefore before it has armed a
# single io_request; register_bindings() runs before the chunk, so
# socketley.remove is already bound; and the top level runs inside a
# lua_deadline::scope, so a Lua frame is live for the whole of it.  A top level
# that removes its own runtime therefore asks retire() to free the instance
# whose safe_script_file frame is two levels down.  Measured on this commit's
# own code with the guard deleted:
#
#     [lua selfrm_top] TOP: about to remove myself
#     Segmentation fault (core dumped)
#
# and then — because every CLI command auto-starts a daemon when the socket does
# not answer — a fresh daemon comes up and restores the state file, so `ls`
# afterwards shows the runtime as though nothing happened.  That is why survival
# is asserted on the pid and start time of the daemon that was serving before
# the create, and never on what `ls` says.
#
# Removing your own runtime from your own top level is not something a sensible
# script does on purpose.  It does not have to be: the guard covers a class —
# "an instance may not be freed while a script frame is on this thread's stack"
# — and this is the reachable member of it, which is what a test is for.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luaselfrm

PB=$((SL_PORT_BASE+1070))
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

NEW_LUA="$SOCKETLEY_TMPD/top_level_remove.lua"
cat > "$NEW_LUA" <<'LUAEOF'
-- No callback and no delivery: this IS the top level, and it runs inside
-- `create`, before this runtime has started or armed anything.  The line after
-- the remove is what says whether the frame survived it.
socketley.log("NEW: removing myself")
local ok = socketley.remove("selfrm_new")
socketley.log("NEW: survived, remove=" .. tostring(ok))
LUAEOF

create_ok "cache created"   "$BIN" create cache  selfrm_cache -p "$CACHE_PORT" -s
create_ok "running created" "$BIN" create server selfrm_run   -p "$RUN_PORT" \
    --lua "$RUN_LUA" -s
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

# ── The one under test: a top level that removes its own runtime ───────────
#
# `create` is what runs it, so the create IS the measurement.  Its status is not
# checked: the runtime removes itself out from under the command that is
# building it, and whether that reports success is a separate question from the
# one this file asks.  What matters is that the daemon is still the same daemon
# afterwards.
# `-s`, which this create did not have and now needs.  The top level runs where
# the script runs, and that is the worker, which exists from `start`.
#
# The hazard is not the same one any more, and that is worth stating rather
# than leaving to be discovered.  In the daemon this call asked retire() to
# free the instance whose safe_script_file frame was two levels down -- the
# segfault quoted above.  From a worker, socketley.remove travels to the
# daemon, which removes a PLACEHOLDER with no Lua frame anywhere near it and
# then retires the supervisor; the worker's own object is freed later, by a
# shutdown frame, with nothing of the script on the stack.  So the free and the
# frame are in different processes and the original crash is structurally out
# of reach.
#
# The three assertions are kept because what they measure is unchanged: the
# call is answered, the frame that made it runs on, and the runtime really is
# gone.  A build that got any of those wrong would still be wrong.
NEW_T0=$(date +%s%N)
"$BIN" create server selfrm_new -p "$NEW_PORT" --lua "$NEW_LUA" -s \
    >/dev/null 2>&1 || true
NEW_MS=$(( ($(date +%s%N) - NEW_T0) / 1000000 ))

# Three assertions, and the first two exist so the third cannot pass on a build
# where nothing ran.  A script that was never loaded would satisfy "the daemon
# survived" perfectly.
said "NEW: removing myself" 8 || true
if grep -qa "NEW: removing myself" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "control: the script's top level ran and reached the remove" \
         "no 'NEW: removing myself' line" \
         "nothing below is measuring a self-removal if nothing was removed"
fi
if grep -qa "NEW: survived, remove=true" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    GOT=$(grep -a "NEW: survived" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1 || true)
    fail "the frame that asked for the removal runs on past it" \
         "got: ${GOT:-<no line after the remove>}" \
         "the line after socketley.remove executes in the lua_context the free" \
         "would have destroyed; without the guard the daemon dies between the" \
         "two log lines and this one never appears"
fi

if survived; then pass; else
    fail "the daemon survives a top level removing its own runtime" \
         "the daemon that was serving before the create is gone" \
         "retire() frees an instance that never armed io on the spot, and the" \
         "C++ stack is a holder its ring test does not cover: the free lands" \
         "under the live safe_script_file frame of the very context that asked" \
         "for it.  Measured with the guard deleted: SIGSEGV, then a fresh" \
         "daemon auto-started by the next CLI command."
fi

# And it has to come back rather than sleeping out the startup bound.  The
# worker's own socketley.remove retires the supervisor from inside the wait,
# leaving no socket, no child and no placeholder -- so nothing the wait is
# watching can change, and await_startup used to go on polling in 20ms slices
# until worker_startup_bound expired.  The two waits beside it already answer
# on that condition: "waiting out the deadline for a corpse is the difference
# between a refusal and a hang."
if [ "$NEW_MS" -lt 1500 ]; then pass; else
    fail "the create returns when the worker is gone, not at the startup bound" \
         "create -s took ${NEW_MS} ms" \
         "worker_startup_bound is 2000ms, and the answer was already decided"
fi

# The removal has to have happened, not merely not crashed: deferring the free
# must not turn `remove` into a no-op.  Asked of the daemon only when it is the
# original one — a replacement would answer from a restored state file.
if survived; then
    if "$BIN" ls 2>/dev/null | grep -qa "selfrm_new"; then
        fail "the self-removal took effect" \
             "'selfrm_new' is still listed after its own top level removed it" \
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
