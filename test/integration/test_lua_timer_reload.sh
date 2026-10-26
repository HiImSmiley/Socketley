#!/usr/bin/env bash
# Integration test: reload-lua on a script with a timer, with the timer armed.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# A Lua timer is a heap-allocated lua_timer holding a raw lua_context* and an
# io_request of its own.  ~lua_context nilled each active timer's sol::function
# and dropped them out of its vector, and that was all: the `ctx` pointer stayed,
# the timeout stayed armed, and the owner registration stayed live — so the
# completion was still DISPATCHED, and lua_timer::on_cqe opens with
#
#     if (loop) loop->deregister_owner(this);
#     if (ctx)  { ctx->unregister_timer(this); ctx->timer_pool_release(this); }
#
# — two calls on a lua_context that no longer exists, one of which pushes the
# timer into that object's vector.
#
# `reload-lua` reaches it, and so does a second load_lua_script(), on any script
# that calls set_interval — which is armed essentially always, because that is
# what an interval is.  Under ASan the process aborts on the next tick.  In a
# release build the outcome depends on what the allocator did with the freed
# storage: the reload allocates a replacement context of exactly that size
# immediately afterwards, so the stale completion is as likely to edit the NEW
# context's timer tables as to touch an unmapped page.
#
# ─── WHAT THIS FILE MEASURES, IN WHICH BUILD ────────────────────────────────
#
# Under SOCKETLEY_CONFIG=Sanitize this file is the reproducer: the daemon aborts
# with a heap-use-after-free inside lua_timer::on_cqe, and "the daemon is still
# serving" is the assertion that goes red.  That is the oracle this fix was
# written against, and it is deterministic — one tick after one reload.
#
# Under Release it is a behaviour guard rather than a crash guard, because the
# damage there depends on where the allocator puts the replacement context.  The
# assertions that still bite in both builds are the ones about the timer itself:
# the interval must be running before the reload, the RELOADED script's interval
# must be running after it, and both must survive twenty cycles.  A fix that
# stopped the crash by simply never re-arming a reloaded script's timers would
# pass the crash assertion and fail those.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luatimer

PORT_BASE=$((SL_PORT_BASE+980))
RT_PORT=$((PORT_BASE+1))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop timer_rt 2>/dev/null || true
    "$BIN" remove timer_rt 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: reload-lua with a timer armed ==="

daemon_start "$BIN"

SCRIPT="$SOCKETLEY_TMPD/ticker.lua"

# 25 ms, so a tick is owed at every moment a reload can land in, and so a run
# does not have to wait out a long interval to see the completion the defect
# needs.  The line goes through socketley.log, which is stderr, which is this
# daemon's log — the only channel a timer in another process's VM has that this
# shell can read.
cat >"$SCRIPT" <<'LUA'
socketley.set_interval(25, function()
    socketley.log("tick")
end)
LUA

# ticks — how many "tick" lines the daemon has logged so far.
#
# The prefix is "[lua <runtime>]", not "[lua]": a Lua diagnostic names the
# runtime it came from, and with several scripts writing to one stderr that is
# the only thing in the line that separates them.  Matched loosely on purpose —
# this file is about a timer surviving a reload, not about the shape of the
# prefix, and pinning the name here would put a second claim in a function
# whose whole job is to count.
ticks() { grep -cE "\[lua[^]]*\] tick${1:-}" "$SOCKETLEY_DLOG" 2>/dev/null || true; }

# grew_by BASELINE TIMEOUT_S — wait until at least one more tick than BASELINE
# has been logged.  Waiting on the count rather than sleeping a fixed span: the
# whole point of the assertion is that ticks are still arriving, and a fixed
# sleep that is generous on an idle machine is thin when the suite is running.
grew_by() {
    local base=$1 timeout=${2:-6} deadline
    deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        [ "$(ticks "${3:-}")" -gt "$base" ] && return 0
        sleep 0.1
    done
    return 1
}

# --daemon-process on purpose.  The lua_context then lives in this daemon, so
# "did the process survive the completion" is a question about the pid this test
# already has, with no worker restart in between to hide the answer.
create_ok "timer_rt created" "$BIN" create server timer_rt -p "$RT_PORT" \
    --lua "$SCRIPT" -s
ready_tcp 127.0.0.1 "$RT_PORT" 10 || true

# ─── CONTROL: the interval is actually running ──────────────────────────────
#
# Without this, every assertion below also passes on a build where set_interval
# never armed anything — which is the one way a use-after-free on a timer
# completion can be "fixed" without fixing anything.
if grew_by 0 8; then ok
else bad "the interval is running" "no '[lua <runtime>] tick' line within 8s of create" \
    "$(tail -3 "$SOCKETLEY_DLOG" 2>/dev/null | tr '\n' '|')"; fi

# ─── THE RELOAD, WITH THE TIMER ARMED ───────────────────────────────────────
#
# Twenty cycles, not one.  One is enough under ASan; twenty is what makes a
# release build likely to land the stale completion on a reallocated context
# rather than on an unmapped page, and it costs a little over a second.
CYCLES=20
for i in $(seq 1 $CYCLES); do
    if ! "$BIN" reload-lua timer_rt >/dev/null 2>&1; then
        bad "reload-lua accepted" "reload-lua timer_rt failed on cycle $i"
        break
    fi
    # Long enough that a tick is owed across the reload rather than only after
    # it: the completion that names the destroyed context is the one that was
    # already in the ring when reload-lua ran.
    sleep 0.06
done

if daemon_alive "$SOCKETLEY_SOCKET"; then ok
else
    bad "daemon survives reload-lua with a timer armed" \
        "the daemon is gone after $CYCLES reloads of a script with set_interval" \
        "$(tail -6 "$SOCKETLEY_DLOG" 2>/dev/null | tr '\n' '|')"
    daemon_bail "reload-lua with a timer armed" \
        "the daemon this test is measuring is no longer serving its socket" \
        "everything below would be measuring a dead socket, so it is not run"
fi

# No sanitizer report, whether or not the process happened to survive one.  Under
# Release this is vacuous and says so by passing; under Sanitize it is the
# finding, and it catches a report that -fno-sanitize-recover let through on a
# path that did not abort.
if grep -qE "AddressSanitizer|runtime error:|use-after-free" "$SOCKETLEY_DLOG" 2>/dev/null; then
    bad "no sanitizer report" "the daemon log carries a sanitizer diagnostic" \
        "$(grep -m3 -E "AddressSanitizer|runtime error:|use-after-free" "$SOCKETLEY_DLOG" | tr '\n' '|')"
else ok; fi

# The runtime is still there and still running — a daemon that survived by
# failing the runtime is not a daemon that survived.
PS=$("$BIN" ps 2>&1) || daemon_required "ps after reloads"
if grep -q "timer_rt" <<<"$PS"; then ok
else bad "timer_rt survives" "gone from ps after $CYCLES reloads"; fi
if grep -qE "timer_rt.*Up " <<<"$PS"; then ok
else bad "timer_rt still running" "not Up after $CYCLES reloads" "$(grep timer_rt <<<"$PS")"; fi

# ─── THE RELOADED SCRIPT'S OWN TIMER ────────────────────────────────────────
#
# The last reload built a fresh lua_context and ran set_interval in it.  Its
# ticks have to keep arriving: severing the old timer must not have severed the
# new one, and a fix that made ~lua_context withdraw the wrong timeout would
# stop exactly here.
BASE=$(ticks)
if grew_by "$BASE" 8; then ok
else bad "the reloaded interval is running" \
    "no new '[lua] tick' within 8s of the last reload (count stuck at $BASE)" \
    "$(tail -3 "$SOCKETLEY_DLOG" 2>/dev/null | tr '\n' '|')"; fi

# ─── ONLY THE NEWEST GENERATION'S TIMER ADVANCES ────────────────────────────
#
# Every generation logs the same word, so a timer left behind by a replaced
# context would keep the count above growing; this one tells the generations apart.
cat >"$SCRIPT" <<'LUA'
socketley.set_interval(25, function()
    socketley.log("tick gen2")
end)
LUA
if "$BIN" reload-lua timer_rt >/dev/null 2>&1; then ok
else bad "reload-lua accepted the second generation" "reload-lua timer_rt failed"; fi
sleep 0.3
GEN2_BASE=$(ticks " gen2")
if grew_by "$GEN2_BASE" 8 " gen2"; then ok
else bad "the newest generation's interval is running" "no 'tick gen2' within 8s of the reload"; fi
OLD_BASE=$(grep -cE "\[lua[^]]*\] tick$" "$SOCKETLEY_DLOG" 2>/dev/null || true)
sleep 0.5
OLD_NOW=$(grep -cE "\[lua[^]]*\] tick$" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "$OLD_NOW" = "$OLD_BASE" ]; then ok
else bad "the replaced generation's interval stopped" "plain 'tick' went from $OLD_BASE to $OLD_NOW after the reload"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
