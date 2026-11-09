#!/usr/bin/env bash
# suite: quiet -- four runaways against half-second budgets, and a daemon whose own configuration file never returns.
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
# The callback deadline is watched from outside the Lua thread: a worker writes
# the running invocation into a line the daemon reads every 100 ms, and the
# daemon signals a callback that is past its budget, whose handler puts the
# instruction hook on.  With no standing hook the trace compiler is on, so a
# loop it compiled never reaches a hook at all and its worker is replaced
# instead.  Each arm is red on the count-hook mechanism this replaced or
# without the piece it covers:
#   (a) a compiled tight loop ends in a replaced worker that serves again --
#       red on the old build, which interpreted the loop and stopped it, and
#       red without the daemon's kill;
#   (b) an interpreted runaway that calls C in its loop is stopped by the hook
#       the signal put on, in the same worker -- red without the signal;
#   (c) a cache EVAL "while true do end" is stopped and the shard answers in
#       the same worker -- red without the signal, since no hook stands;
#   (d) jit.status() is true inside a callback that has a limit -- red on the
#       old build, which opened the compiler only for an unbounded script;
#   (e) a daemon whose configuration file never returns still comes up -- red
#       without the timer a process the daemon does not watch arms itself.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
. "$HERE/lib_clock.sh"

daemon_isolate luawatch

JIT_PORT=$((SL_PORT_BASE+1527))
C_PORT=$((SL_PORT_BASE+1528))
KV_PORT=$((SL_PORT_BASE+1529))

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" remove dw_jit dw_c dw_kv >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: the Lua deadline, watched from outside the Lua thread ==="

# Both answer what they can see before anything runs away, so a reply is proof
# the runtime serves as well as of what it sees.
cat > "$SOCKETLEY_TMPD/jit.lua" <<'LUA'
callback_timeout_ms = 500
function on_message(msg)
    if msg == "spin" then
        local n = 0
        while true do n = n + 1 end
    end
    if msg == "jit" then
        local st = "no-jit"
        if jit ~= nil then st = tostring(jit.status()) end
        self.broadcast("jit=" .. tostring(jit ~= nil) .. " status=" .. st)
        return
    end
    self.broadcast("echo:" .. msg)
end
LUA
# An error raised and caught on every turn leaves any trace the compiler made,
# so this loop keeps going back through the interpreter, which is where a hook
# is seen.
cat > "$SOCKETLEY_TMPD/c.lua" <<'LUA'
callback_timeout_ms = 500
function on_message(msg)
    if msg == "spin" then
        local n = 0
        while true do
            n = n + #string.format("%d", n)
            pcall(error, n)
        end
    end
    self.broadcast("echo:" .. msg)
end
LUA

# The cache's scripts take the process default, so this daemon's is short.
export SOCKETLEY_LUA_TIMEOUT_MS=800
daemon_start "$BIN"
DPID=$SOCKETLEY_DPID

"$BIN" create server dw_jit -p "$JIT_PORT" --mode inout --lua "$SOCKETLEY_TMPD/jit.lua" -s >/dev/null 2>&1
"$BIN" create server dw_c   -p "$C_PORT"   --mode inout --lua "$SOCKETLEY_TMPD/c.lua"   -s >/dev/null 2>&1
"$BIN" create cache  dw_kv  -p "$KV_PORT" -s >/dev/null 2>&1

wait_port() {
    local p=$1 i listing
    for i in $(seq 1 100); do
        listing=$(ss -ltn 2>/dev/null)
        case "$listing" in *":$p "*) return 0 ;; esac
        sleep 0.1
    done
    return 1
}
for p in "$JIT_PORT" "$C_PORT" "$KV_PORT"; do
    wait_port "$p" || echo "  NOTE: nothing listening on $p"
done

say() { printf '%s\n' "$2" | timeout 8 nc -q 1 127.0.0.1 "$1" 2>/dev/null || true; }
# The worker serving a port, by the socket it listens on, since a runtime's pid is the one thing a replacement changes.
worker_on() { ss -ltnpH "sport = :$1" 2>/dev/null | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2; }
status_of() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2==n'; }
wait_log() {
    local pattern=$1 timeout=${2:-5} i
    for i in $(seq 1 $((timeout * 20))); do
        grep -qE "$pattern" "$SOCKETLEY_DLOG" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}

# ── (d) the compiler is on under a limit ────────────────────────────────────
OUT=$(say "$JIT_PORT" jit)
case "$OUT" in
    *"jit=true status=true"*) pass ;;
    *) fail "a callback with a 500ms limit runs with the compiler on" \
            "expected 'jit=true status=true', got: ${OUT:-<nothing>}" ;;
esac

# ── (a) a compiled runaway ends in a replaced worker ────────────────────────
W0=$(worker_on "$JIT_PORT")
[ -n "$W0" ] || fail "control: dw_jit has a worker listening" "no pid on $JIT_PORT"
if ! status_of dw_jit | grep -q restart; then pass; else
    fail "control: no restart before the runaway" "$(status_of dw_jit)"
fi

T0=$(mono_s)
( printf 'spin\n' | timeout 5 nc -q 0 127.0.0.1 "$JIT_PORT" >/dev/null 2>&1 & )
W1=""
for _ in $(seq 1 100); do
    W1=$(worker_on "$JIT_PORT")
    [ -n "$W1" ] && [ "$W1" != "$W0" ] && break
    sleep 0.05
done
T1=$(mono_s)
TOOK=$(echo "$T1 - $T0" | bc)
if [ -n "$W1" ] && [ "$W1" != "$W0" ]; then pass; else
    fail "a compiled loop past its deadline ends in a new worker" \
         "dw_jit is still served by pid ${W1:-<none>} (was $W0) after ${TOOK}s"
fi
echo "  the compiled runaway's replacement listened after ${TOOK}s"
# 500ms limit, 1000ms grace, and a second for the scans and the restart.
if [ "$(echo "$TOOK < 2.5" | bc)" = "1" ]; then pass; else
    fail "and within limit + grace + 1s" "the replacement was listening after ${TOOK}s"
fi
if wait_log "runtime 'dw_jit': on_message did not stop at its 500ms deadline; its worker is replaced"; then pass; else
    fail "the daemon says which callback it ended and why" \
         "no 'did not stop at its 500ms deadline' line for dw_jit in $SOCKETLEY_DLOG"
fi
OUT=$(say "$JIT_PORT" after)
case "$OUT" in
    *echo:after*) pass ;;
    *) fail "the replaced runtime serves again" "got: ${OUT:-<nothing>}" ;;
esac
sleep 2.5   # one health tick, so ls has counted the restart
if status_of dw_jit | grep -q "(1 restart"; then pass; else
    fail "ls shows it the way a replaced worker shows" "$(status_of dw_jit)"
fi

# ── (b) an interpreted runaway is stopped in place ──────────────────────────
W0=$(worker_on "$C_PORT")
T0=$(mono_s)
( printf 'spin\n' | timeout 5 nc -q 0 127.0.0.1 "$C_PORT" >/dev/null 2>&1 & )
if wait_log '\[lua dw_c\] on_message hit its 500ms deadline and was stopped' 5; then pass; else
    fail "a runaway that calls C in its loop is stopped by the hook" \
         "no '[lua dw_c] on_message hit its 500ms deadline' line in $SOCKETLEY_DLOG"
fi
T1=$(mono_s)
TOOK=$(echo "$T1 - $T0" | bc)
echo "  the interpreted runaway was stopped after ${TOOK}s"
if [ "$(echo "$TOOK >= 0.45 && $TOOK < 1.5" | bc)" = "1" ]; then pass; else
    fail "and at its deadline, not before and not at the grace" "stopped after ${TOOK}s"
fi
OUT=$(say "$C_PORT" after)
case "$OUT" in
    *echo:after*) pass ;;
    *) fail "the stopped runtime serves on" "got: ${OUT:-<nothing>}" ;;
esac
W1=$(worker_on "$C_PORT")
if [ -n "$W0" ] && [ "$W1" = "$W0" ]; then pass; else
    fail "in the same worker, with nothing replaced" "pid $W0 before, ${W1:-<none>} after"
fi
if ! grep -q "runtime 'dw_c'.*did not stop" "$SOCKETLEY_DLOG"; then pass; else
    fail "and the daemon did not escalate" "$(grep "runtime 'dw_c'" "$SOCKETLEY_DLOG")"
fi

# ── (c) a runaway EVAL is stopped and the shard answers ─────────────────────
W0=$(worker_on "$KV_PORT")
GOT=$(printf '*3\r\n$4\r\nEVAL\r\n$17\r\nwhile true do end\r\n$1\r\n0\r\n*1\r\n$4\r\nPING\r\n' \
      | timeout 10 nc -q 3 127.0.0.1 "$KV_PORT" 2>/dev/null | tr -d '\r')
case "$GOT" in
    *"exceeded the 800ms deadline"*) pass ;;
    *) fail "a runaway EVAL is stopped with the deadline error" "got: ${GOT:-<nothing>}" ;;
esac
case "$GOT" in
    *PONG*) pass ;;
    *) fail "and the shard answers the next command" "got: ${GOT:-<nothing>}" ;;
esac
W1=$(worker_on "$KV_PORT")
if [ -n "$W0" ] && [ "$W1" = "$W0" ]; then pass; else
    fail "in the same worker, so the keyspace survives" "pid $W0 before, ${W1:-<none>} after"
fi

if kill -0 "$DPID" 2>/dev/null; then pass; else
    fail "the daemon survived every one of those" "pid $DPID is gone"
fi

# ── (e) a configuration file that never returns ─────────────────────────────
"$BIN" remove dw_jit dw_c dw_kv >/dev/null 2>&1 || true
daemon_stop
daemon_isolate luawatch-config
printf 'local n = 0\nwhile true do n = n + 1 end\n' > "$SOCKETLEY_TMPD/runaway.lua"
SOCKETLEY_CONFIG="$SOCKETLEY_TMPD/runaway.lua" daemon_start "$BIN"
if "$BIN" ls >/dev/null 2>&1; then pass; else
    fail "a daemon whose configuration file never returns comes up" "ls did not answer"
fi
if wait_log '\[lua\] the daemon configuration file hit its 800ms deadline and was stopped'; then pass; else
    fail "the configuration file was stopped at the process default" \
         "no 'the daemon configuration file hit its 800ms deadline' line in $SOCKETLEY_DLOG"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
