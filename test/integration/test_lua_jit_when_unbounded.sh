#!/usr/bin/env bash
# Integration test: turning the callback deadline off turns LuaJIT's trace
# compiler on, and nothing else does.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# LuaJIT's trace compiler is initialised by luaopen_jit and by nothing else.
# lua_context did not call it, so every Lua callback this daemon ran was
# interpreted -- 5.2-5.5x against the same loop with the compiler on.  It is now
# opened for exactly the contexts that install no deadline hook, because those
# are one decision rather than two: a compiled trace does not call an
# instruction hook back, so with the compiler on a runaway callback cannot be
# interrupted at all.  At a limit of 0 there is no hook to defeat, so coupling
# the two gives away nothing that was not already given away.
#
# ─── WHY THESE ASSERTIONS AND NOT A TIMING ──────────────────────────────────
#
# The obvious test is "the unbounded arm is faster", and it is the wrong one:
# it needs a hot loop, a warm-up and a threshold, and a threshold separating
# 30us from 85us on an idle box separates nothing on a loaded one.  This suite
# has been wrong that way before.
#
# The compiler's presence is a fact the script can read instead.  luaopen_jit
# creates the global `jit`; nothing else in this tree does.  So the answer goes
# on the wire with no clock in it -- and jit.status() is asked as well as the
# table's existence, because a table with the engine disabled would read as
# "on" to a test that only checked for the table.
#
# ─── THE FOUR CASES, AND WHY EACH IS LOAD-BEARING ───────────────────────────
#
#   daemon default, script silent   -> no jit.  This is the half that fails if
#     the coupling is ever widened to "always on", which would quietly remove
#     the runaway bound from every script in the tree.
#   daemon default, script says 0   -> jit, engine on.  The script's knob.
#   daemon 0, script silent         -> jit, engine on.  The operator's knob.
#   daemon 0, script says 10000     -> NO jit.  This one is about ordering: the
#     decision has to be taken after the script's top level has run and its
#     declaration has been read, not when the state is built.  A build that
#     decided early would open the compiler here and then install a hook that
#     cannot stop anything -- the worst of the four outcomes, and the only one
#     no other assertion here would notice.
#
# Watched red before it was believed: against bin/Release/socketley as it stood
# on 2026-08-14, every one of these answered `jit=false`.
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

echo "=== Integration: the deadline being off is what turns LuaJIT's compiler on ==="

# ── The scripts ─────────────────────────────────────────────────────────────
#
# All four answer the same sentence, so a reply is proof the runtime is serving
# as well as proof of what it can see.

report_body='
function on_message(msg) end
function on_client_message(id, msg)
    local st = "no-jit"
    if jit ~= nil then st = tostring(jit.status()) end
    self.send(id, "jit=" .. tostring(jit ~= nil) .. " status=" .. st)
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
    "jit=false status=no-jit") pass ;;
    *) fail "a bounded script has no jit table at all" \
            "expected 'jit=false status=no-jit', got: ${OUT:-<nothing>}" \
            "a bounded script seeing jit means the compiler was opened for a" \
            "runtime whose deadline can no longer stop a runaway" ;;
esac

OUT=$(say "$ZERO_PORT" ask)
case "$OUT" in
    "jit=true status=true") pass ;;
    "jit=true status="*) fail "callback_timeout_ms = 0 leaves the engine enabled" \
            "expected status=true, got: $OUT" ;;
    *) fail "callback_timeout_ms = 0 opens the jit library" \
            "expected 'jit=true status=true', got: ${OUT:-<nothing>}" \
            "this is what fails on a build where luaopen_jit is never called:" \
            "the whole tree answered 'jit=false' before this existed" ;;
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
    "jit=true status=true") pass ;;
    *) fail "SOCKETLEY_LUA_TIMEOUT_MS=0 reaches a script that declares nothing" \
            "expected 'jit=true status=true', got: ${OUT:-<nothing>}" ;;
esac

OUT=$(say "$RAISE_PORT" ask)
case "$OUT" in
    "jit=false status=no-jit") pass ;;
    *) fail "a script that raises the bound above an unbounded daemon gets no compiler" \
            "expected 'jit=false status=no-jit', got: ${OUT:-<nothing>}" \
            "the decision has to be taken after the script's declaration is read;" \
            "taken earlier, this runtime has a compiler AND a hook that cannot" \
            "stop anything it compiles" ;;
esac

# ── And the daemon that did all of that is still the same process ───────────
if kill -0 "$SOCKETLEY_DPID" 2>/dev/null; then pass; else
    fail "the daemon survived every one of those" "pid $SOCKETLEY_DPID is gone"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
