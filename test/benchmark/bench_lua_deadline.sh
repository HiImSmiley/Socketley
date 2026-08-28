#!/usr/bin/env bash
# What the callback deadline costs when nothing is wrong.
#
# The deadline is enforced by a LUA_MASKCOUNT hook, and a count hook is not free
# in two separate ways that have to be told apart:
#
#   * the hook body itself — one clock read and a compare, every N instructions
#   * LuaJIT dropping the state to the interpreter while any count or line hook
#     is installed, because a compiled trace does not call back out
#
# The second is the one that can be large, and it is invisible to a benchmark
# whose callback does almost nothing — which is what most socketley callbacks
# are.  So this measures two shapes against the same binary:
#
#   echo     on_client_message calls self.send and returns.  The realistic
#            shape: the C++ side dominates and the Lua is a few instructions.
#   compute  the same, with a numeric loop in front of it.  The worst case,
#            where the interpreter is the whole cost and the JIT is the reason
#            it was ever fast.
#
# Hook on versus hook off is SOCKETLEY_LUA_TIMEOUT_MS unset (10000, the default,
# hook installed) against SOCKETLEY_LUA_TIMEOUT_MS=0 (off, no hook, JIT intact)
# — the same binary either way, so nothing but the hook differs.  A/B/A/B rather
# than all of A then all of B: this machine has other work on it and a drift
# across the run would otherwise be read as the hook's cost.
#
#     bash test/benchmark/bench_lua_deadline.sh [BIN] [ROUNDS]
set -uo pipefail

BIN=${1:-$(cd "$(dirname "$0")/../.." && pwd)/bin/Release/socketley}
ROUNDS=${2:-3}
BENCH=$(dirname "$BIN")/socketley_bench
ROOT=$(cd "$(dirname "$0")/../.." && pwd)

[ -x "$BIN" ]   || { echo "no socketley at $BIN"; exit 2; }
[ -x "$BENCH" ] || { echo "no socketley_bench at $BENCH"; exit 2; }

PORT=${SOCKETLEY_PORT_BASE:-22200}
TMPD=$(mktemp -d /tmp/sl-luadl-bench-XXXXXX)
SOCK="$TMPD/d.sock"

sweep() {
    local p
    for p in $(pgrep -x socketley 2>/dev/null); do
        { tr '\0' '\n' < "/proc/$p/environ"; } 2>/dev/null \
            | grep -qx "SOCKETLEY_SOCKET=$SOCK" && kill -9 "$p" 2>/dev/null
    done
    return 0
}
trap 'sweep; rm -rf "$TMPD"' EXIT

cp "$ROOT/test/benchmark/echo.lua" "$TMPD/echo.lua"
cat > "$TMPD/compute.lua" <<'LUAEOF'
-- The worst case for a count hook: the callback IS the Lua.
function on_message(msg) end
function on_client_message(client_id, msg)
    local acc = 0
    for i = 1, 2000 do acc = acc + (i * 3) % 7 end
    self.send(client_id, msg)
end
LUAEOF

export HOME="$TMPD/home"; mkdir -p "$HOME"
export SOCKETLEY_SOCKET="$SOCK"

# one_run TIMEOUT_MS SCRIPT  ->  the median round-trip/sec on stdout
one_run() {
    local tmo=$1 script=$2
    sweep
    if [ "$tmo" = "unset" ]; then unset SOCKETLEY_LUA_TIMEOUT_MS
    else                          export SOCKETLEY_LUA_TIMEOUT_MS="$tmo"; fi

    "$BIN" daemon >"$TMPD/d.log" 2>&1 &
    local dpid=$! i
    for i in $(seq 1 100); do grep -q "daemon started" "$TMPD/d.log" 2>/dev/null && break; sleep 0.1; done

    "$BIN" create server dlb -p "$PORT" --mode inout --lua "$script" -s >/dev/null 2>&1
    for i in $(seq 1 100); do nc -z 127.0.0.1 "$PORT" 2>/dev/null && break; sleep 0.1; done

    "$BENCH" -r 7 server msg 127.0.0.1 "$PORT" 20000 64 2>/dev/null > "$TMPD/bench.out"

    "$BIN" stop dlb   >/dev/null 2>&1
    "$BIN" remove dlb >/dev/null 2>&1
    kill -9 "$dpid" 2>/dev/null
    wait "$dpid" 2>/dev/null
    sweep
    rm -f "$TMPD/d.log"

    awk '/Median:/ { print $2; exit }' "$TMPD/bench.out"
}

echo "=== callback deadline: what the hook costs when nothing is wrong ==="
echo "binary: $BIN   (server msg, 20000 round trips, 64B, median of 7 per run)"
echo
for script in echo compute; do
    off_all=""; on_all=""
    for r in $(seq 1 "$ROUNDS"); do
        off=$(one_run 0     "$TMPD/$script.lua")
        on=$(one_run  unset "$TMPD/$script.lua")
        printf '  %-8s round %d   hook off: %8s   hook on: %8s round-trip/sec\n' \
               "$script" "$r" "${off:-?}" "${on:-?}"
        off_all="$off_all $off"; on_all="$on_all $on"
    done
    best_off=$(printf '%s\n' $off_all | sort -n | tail -1)
    best_on=$(printf '%s\n'  $on_all  | sort -n | tail -1)
    if [ -n "$best_off" ] && [ -n "$best_on" ] && [ "$best_off" -gt 0 ] 2>/dev/null; then
        printf '  %-8s BEST of %d   hook off: %8s   hook on: %8s   -> %s%% of the unhooked rate\n\n' \
               "$script" "$ROUNDS" "$best_off" "$best_on" \
               "$(echo "scale=1; 100 * $best_on / $best_off" | bc)"
    else
        printf '  %-8s could not be measured\n\n' "$script"
    fi
done
