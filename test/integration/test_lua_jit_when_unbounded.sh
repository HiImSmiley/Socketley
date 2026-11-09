#!/usr/bin/env bash
# Integration test: LuaJIT's trace compiler is on for a runtime's callbacks
# whatever the deadline says, and off for its top level.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# LuaJIT's trace compiler is initialised by luaopen_jit and by nothing else.
# It used to be opened only for a script with no deadline, because the deadline
# was a standing count hook and a compiled trace never calls a hook back.  The
# deadline is now watched from outside the worker -- the daemon reads a line
# the worker writes and signals a callback past its budget -- and a compiled
# runaway that never reaches the hook the signal puts on has its worker
# replaced.  Nothing is left for the compiler to defeat, so every worker opens
# it, under any limit.  This file used to assert the opposite for a bounded
# script; its premise is what changed.
#
# ─── WHY THESE ASSERTIONS AND NOT A TIMING ──────────────────────────────────
#
# The obvious test is "the compiled arm is faster", and it is the wrong one: it
# needs a hot loop, a warm-up and a threshold.  The compiler's presence is a
# fact the script can read instead.  luaopen_jit creates the global `jit`;
# nothing else in this tree does.  So the answer goes on the wire with no clock
# in it -- and jit.status() is asked as well as the table's existence, because a
# table with the engine disabled would read as "on" to a test that only checked
# for the table.
#
# ─── THE CASES, AND WHY EACH IS LOAD-BEARING ────────────────────────────────
#
#   daemon default, script silent   -> jit, engine on.  The half that fails on
#     the build before the deadline moved out of the worker: every bounded
#     script there answered `jit=false`.
#   daemon default, script says 0   -> jit, engine on.
#   daemon 0, script silent         -> jit, engine on.
#   daemon 0, script says 10000     -> jit, engine on.  The old ordering case,
#     a bound raised above an unbounded daemon, which used to close it again.
#   and the top level of each       -> no jit.  The library is opened once the
#     top level has run, so a top level that never returns is interpreted and
#     always stopped by the hook rather than by replacing a worker that is
#     still starting.
#
# Watched red before it was believed: against the build before this change,
# the two bounded cases answered `jit=false status=no-jit`.
#
# suite: quiet -- four runtimes, one message each, no timing anywhere.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luajitbound

PORT=$((SL_PORT_BASE+1160))
SILENT_PORT=$((PORT + 1))
ZERO_PORT=$((PORT + 2))
ENVZ_PORT=$((PORT + 3))
RAISE_PORT=$((PORT + 4))

NAMES="jb_silent jb_zero jb_envz jb_raise"

# The scripts outlive the daemon's tmpdir: daemon_stop deletes SOCKETLEY_TMPD,
# and the second arm needs the same files.
LUADIR=$(mktemp -d /tmp/socketley-jitbound-lua-XXXXXX)

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    # shellcheck disable=SC2086
    "$BIN" stop $NAMES 2>/dev/null || true
    sleep 0.3
    # shellcheck disable=SC2086
    "$BIN" remove $NAMES 2>/dev/null || true
    daemon_stop
    rm -rf "$LUADIR"
}
trap cleanup EXIT

echo "=== Integration: LuaJIT's compiler is on for callbacks under any deadline ==="

# ── The scripts ─────────────────────────────────────────────────────────────
#
# All four answer the same sentence, so a reply is proof the runtime is serving
# as well as proof of what it can see.

report_body='
top_jit = tostring(jit ~= nil)
function on_message(msg) end
function on_client_message(id, msg)
    local st = "no-jit"
    if jit ~= nil then st = tostring(jit.status()) end
    self.send(id, "jit=" .. tostring(jit ~= nil) .. " status=" .. st .. " top=" .. top_jit)
end
'

printf '%s' "-- takes whatever the daemon says$report_body"        > "$LUADIR/silent.lua"
printf '%s' "callback_timeout_ms = 0$report_body"                  > "$LUADIR/zero.lua"
printf '%s' "callback_timeout_ms = 10000$report_body"              > "$LUADIR/raise.lua"

# say PORT MESSAGE — one connection, one message, whatever came back.
say() {
    printf '%s\n' "$2" | timeout 8 nc -q 2 127.0.0.1 "$1" 2>/dev/null || true
}

# ── Arm 1: a daemon whose own default is a bound ────────────────────────────
daemon_start "$BIN"

create_ok "silent script created" "$BIN" create server jb_silent -p "$SILENT_PORT" --mode in --lua "$LUADIR/silent.lua" -s
create_ok "zero script created"   "$BIN" create server jb_zero   -p "$ZERO_PORT"   --mode in --lua "$LUADIR/zero.lua" -s

ready_tcp 127.0.0.1 "$SILENT_PORT" 8 || echo "  NOTE: jb_silent never accepted a connection"
ready_tcp 127.0.0.1 "$ZERO_PORT"   8 || echo "  NOTE: jb_zero never accepted a connection"

OUT=$(say "$SILENT_PORT" ask)
case "$OUT" in
    "jit=true status=true top=false") pass ;;
    "jit=true status=true top="*) fail "a script that declares nothing: the top level runs before the compiler is opened" \
            "expected top=false, got: $OUT" \
            "a top level that is compiled can only be ended by replacing its worker" ;;
    *) fail "a script that declares nothing: callbacks run with the compiler on" \
            "expected 'jit=true status=true top=false', got: ${OUT:-<nothing>}" ;;
esac

OUT=$(say "$ZERO_PORT" ask)
case "$OUT" in
    "jit=true status=true top=false") pass ;;
    "jit=true status=true top="*) fail "callback_timeout_ms = 0: the top level runs before the compiler is opened" \
            "expected top=false, got: $OUT" \
            "a top level that is compiled can only be ended by replacing its worker" ;;
    *) fail "callback_timeout_ms = 0: callbacks run with the compiler on" \
            "expected 'jit=true status=true top=false', got: ${OUT:-<nothing>}" ;;
esac

# ── Arm 2: a daemon the operator unbounded ──────────────────────────────────
#
# Fresh isolation rather than a restart in place: daemon_stop deletes the state
# directory it was given, so the second daemon gets its own.
"$BIN" stop jb_silent jb_zero 2>/dev/null || true
"$BIN" remove jb_silent jb_zero 2>/dev/null || true
daemon_stop
daemon_isolate luajitbound-env
SOCKETLEY_LUA_TIMEOUT_MS=0 daemon_start "$BIN"

create_ok "env-unbounded script created" "$BIN" create server jb_envz  -p "$ENVZ_PORT"  --mode in --lua "$LUADIR/silent.lua" -s
create_ok "script raising it created"    "$BIN" create server jb_raise -p "$RAISE_PORT" --mode in --lua "$LUADIR/raise.lua" -s

ready_tcp 127.0.0.1 "$ENVZ_PORT"  8 || echo "  NOTE: jb_envz never accepted a connection"
ready_tcp 127.0.0.1 "$RAISE_PORT" 8 || echo "  NOTE: jb_raise never accepted a connection"

OUT=$(say "$ENVZ_PORT" ask)
case "$OUT" in
    "jit=true status=true top=false") pass ;;
    "jit=true status=true top="*) fail "SOCKETLEY_LUA_TIMEOUT_MS=0: the top level runs before the compiler is opened" \
            "expected top=false, got: $OUT" \
            "a top level that is compiled can only be ended by replacing its worker" ;;
    *) fail "SOCKETLEY_LUA_TIMEOUT_MS=0: callbacks run with the compiler on" \
            "expected 'jit=true status=true top=false', got: ${OUT:-<nothing>}" ;;
esac

OUT=$(say "$RAISE_PORT" ask)
case "$OUT" in
    "jit=true status=true top=false") pass ;;
    "jit=true status=true top="*) fail "a bound raised above an unbounded daemon: the top level runs before the compiler is opened" \
            "expected top=false, got: $OUT" \
            "a top level that is compiled can only be ended by replacing its worker" ;;
    *) fail "a bound raised above an unbounded daemon: callbacks run with the compiler on" \
            "expected 'jit=true status=true top=false', got: ${OUT:-<nothing>}" ;;
esac

# ── And the daemon that did all of that is still the same process ───────────
if kill -0 "$SOCKETLEY_DPID" 2>/dev/null; then pass; else
    fail "the daemon survived every one of those" "pid $SOCKETLEY_DPID is gone"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
