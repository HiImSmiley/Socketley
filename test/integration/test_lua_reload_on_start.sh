#!/usr/bin/env bash
# Integration test: reload-lua re-runs on_start, so what on_start set up comes back.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# reload_lua_script() built the replacement context, swapped it in, updated
# self.state and re-armed the on_tick timer, and stopped there.  on_start was
# called from start() and from nowhere else.
#
# Everything a script establishes at run time lives in its lua_context: every
# socketley.subscribe registration, and every set_timeout/set_interval timer —
# ~lua_context severs those by name.  The ordinary place to make both is
# on_start.  So the ordinary script came back from a reload with neither, went
# on serving, and `reload-lua` reported success.  Measured on the parent commit,
# a script with one interval and one subscription in on_start:
#
#     before reload   TICKER v1 every 60 ms, SUBBED v1 on every publish
#     after  reload   nothing at all, exit 0, no output
#
# The runtime looks healthy from every angle an operator has — running in `ls`,
# counting connections in `stats`, new callbacks firing on traffic.  Only the
# periodic half is gone.
#
# ─── WHAT RELOAD DOES NOT DO ────────────────────────────────────────────────
#
# on_stop is not run for the outgoing script, and STOP below is the control for
# that.  The runtime is not stopping: it keeps its listener, its clients and its
# state right through this, and on_stop is where a script says goodbye to those.
# A reload that fired it would have every edit publish a farewell.  An
# implementation that fixed this file's first half by stopping and starting the
# script would pass everything else here and fail that one.
#
# ─── AND WHEN on_start ITSELF RAISES ────────────────────────────────────────
#
# The script is in force — this is past the swap — but with whatever its
# on_start managed before it failed, which is not what the operator asked for.
# `reload-lua` exits 1 and names the reason, the same way it does for a script
# that will not compile.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luarlstart

PB=$((SL_PORT_BASE+1040))
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
    "$BIN" stop   rl_srv rlcache >/dev/null 2>&1 || true
    sleep 0.2
    "$BIN" remove rl_srv rlcache >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: reload-lua re-runs on_start ==="

daemon_start "$BIN"

LUA="$SOCKETLEY_TMPD/rl.lua"
# write_script FILE TAG — the ordinary shape: a timer and a subscription, both
# armed from on_start, and an on_stop that says so if it ever runs.
write_script() {
    cat > "$1" <<LUAEOF
function on_start()
    socketley.log("START $2")
    socketley.set_interval(60, function() socketley.log("TICKER $2") end)
    socketley.subscribe("rlcache", "news", function(ch, msg)
        socketley.log("SUBBED $2 " .. msg)
    end)
end

function on_stop()
    socketley.log("STOP $2")
end
LUAEOF
}

said() {
    local pattern=$1 deadline=$(( $(date +%s) + ${2:-8} ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        grep -qaF "$pattern" "$SOCKETLEY_DLOG" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}
hits()    { grep -ac "$1" "$SOCKETLEY_DLOG" 2>/dev/null || true; }
# wait_hits PATTERN N [TIMEOUT_S] — `said` returns on the FIRST match, so
# counting straight after it counts one.  This waits for the Nth.
wait_hits() {
    local pattern=$1 want=$2 deadline=$(( $(date +%s) + ${3:-10} ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        [ "$(hits "$pattern")" -ge "$want" ] && return 0
        sleep 0.05
    done
    return 1
}
publish() { printf 'PUBLISH news %s\r\n' "$1" | nc -q 1 127.0.0.1 "$CACHE_PORT" >/dev/null 2>&1 || true; }

write_script "$LUA" v1
create_ok "cache created"  "$BIN" create cache  rlcache -p "$CACHE_PORT" -s
create_ok "server created" "$BIN" create server rl_srv  -p "$SRV_PORT" \
    --lua "$LUA" --daemon-process -s
ready_tcp 127.0.0.1 "$SRV_PORT" 10 || echo "  NOTE: the server never accepted"

# ── Control: v1's set-up is genuinely live ──────────────────────────────────
wait_hits 'TICKER v1' 3 10 || true
publish one
said "SUBBED v1 one" 8 || true
V1_TICKS=$(hits 'TICKER v1')
if [ "$V1_TICKS" -ge 3 ] && grep -qa "SUBBED v1 one" "$SOCKETLEY_DLOG" 2>/dev/null
then pass; else
    fail "control: the timer and the subscription are running before the reload" \
         "TICKER v1 x$V1_TICKS, SUBBED v1: $(hits 'SUBBED v1')" \
         "set-up that was never established cannot be shown to survive anything"
fi

# ── The reload ──────────────────────────────────────────────────────────────
write_script "$LUA" v2
RL_RC=0
RL_OUT=$("$BIN" reload-lua rl_srv 2>&1) || RL_RC=$?
if [ "$RL_RC" = "0" ] && [ -z "$RL_OUT" ]; then pass; else
    fail "control: a reload that works is silent and exits 0" \
         "reload-lua exited $RL_RC and said '${RL_OUT:-<nothing>}'"
fi

said "START v2" 8 || true
if grep -qa "START v2" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "on_start runs again on the reloaded script" \
         "no 'START v2' line" \
         "on_start was called from start() and from nowhere else, so a reload" \
         "swapped the callbacks in and left the script's set-up unrun"
fi

# ── What on_start established is back ───────────────────────────────────────
wait_hits 'TICKER v2' 3 10 || true
V2_TICKS=$(hits 'TICKER v2')
if [ "$V2_TICKS" -ge 3 ]; then pass; else
    fail "the reloaded script's interval is armed" \
         "TICKER v2 x$V2_TICKS, wanted at least 3" \
         "the timer lived in the context the reload destroyed, and only" \
         "on_start arms it"
fi

publish two
said "SUBBED v2 two" 8 || true
if grep -qa "SUBBED v2 two" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "the reloaded script's subscription is registered" \
         "no 'SUBBED v2 two' line" \
         "subscriptions live in the context too, and a runtime that stops" \
         "receiving publishes after a reload says nothing about it"
fi

# ── Control: the outgoing script is really gone ─────────────────────────────
V1_A=$(hits 'TICKER v1')
sleep 1
V1_B=$(hits 'TICKER v1')
if [ "$V1_A" = "$V1_B" ]; then pass; else
    fail "control: the replaced script's interval stopped" \
         "TICKER v1 went $V1_A -> $V1_B a second apart" \
         "re-running on_start must not mean the old context's timers survive"
fi
if grep -qa "SUBBED v1 two" "$SOCKETLEY_DLOG" 2>/dev/null; then
    fail "control: the replaced script's subscription stopped" \
         "'SUBBED v1 two' is in the log — the old handler is still registered"
else pass; fi

# ── Control: on_stop did NOT run for the outgoing script ────────────────────
if grep -qa "STOP v1" "$SOCKETLEY_DLOG" 2>/dev/null; then
    fail "on_stop is not run for the script being replaced" \
         "'STOP v1' is in the log" \
         "the runtime did not stop — it kept its listener, its clients and its" \
         "state through the whole reload.  An implementation that reloads by" \
         "stopping and starting the script passes everything above and fails here"
else pass; fi

# ── An on_start that raises is reported to whoever asked ────────────────────
cat > "$LUA" <<'LUAEOF'
function on_start()
    error("on_start could not reach the thing it needs")
end
function on_message(m) socketley.log("V3 saw " .. m) end
LUAEOF

BAD_RC=0
BAD_OUT=$("$BIN" reload-lua rl_srv 2>&1) || BAD_RC=$?
if [ "$BAD_RC" = "1" ]; then pass; else
    fail "reload-lua exits 1 when the new script's on_start raises" \
         "reload-lua exited $BAD_RC, wanted 1" \
         "the script is in force with half its set-up done, which is not the" \
         "thing the operator asked for — and this tree does not report success" \
         "for something that did not happen" \
         "reload-lua said: ${BAD_OUT:-<nothing>}"
fi
case "$BAD_OUT" in
    *rl_srv*on_start*"could not reach the thing it needs"*) pass ;;
    *) fail "the refusal names the runtime, the callback and the reason" \
            "wanted 'rl_srv', 'on_start' and the script's own message" \
            "reload-lua said: ${BAD_OUT:-<nothing>}" ;;
esac

# ── And the runtime is still serving the new script ─────────────────────────
printf 'ping\n' | nc -q 1 127.0.0.1 "$SRV_PORT" >/dev/null 2>&1 || true
said "V3 saw ping" 8 || true
if grep -qa "V3 saw ping" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "the new script is in force even though its on_start raised" \
         "no 'V3 saw ping' line" \
         "this is past the swap, so the refusal above must not be read as 'the" \
         "previous script is still running' — that is the OTHER failure mode"
fi

TOTAL=$((TOTAL+1))
if kill -0 "$SOCKETLEY_DPID" 2>/dev/null && daemon_alive "$SOCKETLEY_SOCKET"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: the daemon did not survive the reloads"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
