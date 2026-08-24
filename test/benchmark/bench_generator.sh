#!/usr/bin/env bash
# bench_generator.sh — the two generator questions, driven in stages.
#
#   setup                  claim the 29000 window, gate on it being empty,
#                          start one cache daemon (socketley) and one redis
#   sweep [args...]        run bench_cache_vs_redis against both arms
#   genclient DEPTH SECS   socketley client runtime as generator, one window
#   teardown               sweep OWN daemons (env-matched), release window
#
# Part (a) measures the batch path's THROUGHPUT with pipeline depth and client
# count as knobs — not per-op latency.  Part (b) measures what the shipping
# client runtime achieves as a load generator with the kernel in the path.
#
# The window claim is lib_ports.sh's protocol: flock on
# /tmp/socketley-ports-<base>.lock held for the session by a holder process,
# plus a listener scan at claim time.  The sweep in teardown matches
# SOCKETLEY_SOCKET in /proc/<pid>/environ — never a name, never pgrep -f.
set -euo pipefail

BASE=29000
STATE=/tmp/skl-genbench
BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="${BIN:-$BENCH_DIR/../../bin/Release/socketley}"

CACHE_PORT=$((BASE + 100))
REDIS_PORT=$((BASE + 101))

cpu_us_tree() {   # total utime+stime of pid and descendants, in microseconds
    local pid=$1 total=0 p t
    local clk; clk=$(getconf CLK_TCK)
    for p in $pid $(pgrep -P "$pid" 2>/dev/null || true); do
        [ -r "/proc/$p/stat" ] || continue
        t=$(awk '{print $14+$15}' "/proc/$p/stat" 2>/dev/null || echo 0)
        total=$((total + t))
    done
    echo $(( total * 1000000 / clk ))
}

# Kill every socketley belonging to one of OUR daemons: environ match on the
# socket path, and — for a pid whose environ is unreadable (seen on processes
# mid-death) — an exe match against this worktree's own binary, which nothing
# outside this harness runs.  Children first.  Never a name, never pgrep -f.
sweep_sock() {
    local sock=$1 p c
    for p in $(pgrep -x socketley 2>/dev/null || true); do
        if [ -r "/proc/$p/environ" ]; then
            tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null \
                | grep -qx "SOCKETLEY_SOCKET=$sock" || continue
        else
            [ "$(readlink "/proc/$p/exe" 2>/dev/null)" = "$BIN" ] || continue
        fi
        for c in $(pgrep -P "$p" 2>/dev/null || true); do kill -9 "$c" 2>/dev/null || true; done
        kill -9 "$p" 2>/dev/null || true
    done
}

listeners_in_window() {
    ss -ltnH 2>/dev/null | awk '{print $4}' | awk -F: '{print $NF}' \
      | awk -v lo=$BASE -v hi=$((BASE + 2000)) '$1 >= lo && $1 < hi' | sort -u
}

case "${1:-}" in

setup)
    mkdir -p "$STATE"

    # ── claim the window: flock held by a holder process for the session ──
    if [ ! -e "$STATE/lockholder.pid" ] || ! kill -0 "$(cat "$STATE/lockholder.pid")" 2>/dev/null; then
        ( flock -n 9 || { echo "FATAL: window $BASE is locked by another run" >&2; exit 2; }
          echo $BASHPID > "$STATE/lockholder.pid"
          exec sleep 100000 ) 9>"/tmp/socketley-ports-$BASE.lock" &
        sleep 0.3
        kill -0 "$(cat "$STATE/lockholder.pid" 2>/dev/null || echo 0)" 2>/dev/null \
            || { echo "FATAL: could not hold /tmp/socketley-ports-$BASE.lock" >&2; exit 2; }
    fi

    # ── gate: refuse to start into a dirty window ──
    busy=$(listeners_in_window)
    if [ -n "$busy" ]; then
        echo "FATAL: listeners already inside [$BASE,$((BASE+2000))): $busy" >&2
        exit 2
    fi

    # ── socketley cache, own daemon, own HOME and socket ──
    rm -rf "$STATE/home-cache"
    export HOME="$STATE/home-cache"
    export SOCKETLEY_SOCKET="$STATE/cache-daemon.sock"
    unset SOCKETLEY_CONFIG
    mkdir -p "$HOME"
    "$BIN" daemon >"$STATE/cache-daemon.log" 2>&1 &
    echo $! > "$STATE/cache-daemon.pid"
    for i in $(seq 1 50); do [ -S "$SOCKETLEY_SOCKET" ] && break; sleep 0.1; done
    [ -S "$SOCKETLEY_SOCKET" ] || { echo "FATAL: cache daemon never came up" >&2; exit 2; }
    "$BIN" create cache gcache -p "$CACHE_PORT" --resp -s

    # ── redis, no persistence ──
    redis-server --port "$REDIS_PORT" --save '' --appendonly no \
        --daemonize no >"$STATE/redis.log" 2>&1 &
    echo $! > "$STATE/redis.pid"

    for i in $(seq 1 50); do
        n=$(listeners_in_window | wc -l)
        [ "$n" -ge 2 ] && break
        sleep 0.1
    done
    [ "$(listeners_in_window | wc -l)" -ge 2 ] \
        || { echo "FATAL: arms never bound $CACHE_PORT/$REDIS_PORT" >&2; exit 2; }
    echo "setup OK: socketley cache :$CACHE_PORT (pid $(cat "$STATE/cache-daemon.pid")), redis :$REDIS_PORT (pid $(cat "$STATE/redis.pid"))"
    ;;

sweep)
    shift
    exec "$BENCH_DIR/bench_cache_vs_redis" "$@" "$CACHE_PORT" "$REDIS_PORT"
    ;;

genclient)
    DEPTH=${2:?usage: genclient DEPTH SECS}
    SECS=${3:?usage: genclient DEPTH SECS}

    # ── generator daemon: separate process, so its CPU is separable ──
    rm -rf "$STATE/home-gen"
    export HOME="$STATE/home-gen"
    export SOCKETLEY_SOCKET="$STATE/gen-daemon.sock"
    unset SOCKETLEY_CONFIG
    mkdir -p "$HOME"

    # Sweep any previous generator daemon FIRST — a survivor keeps pumping at
    # the cache and every later reading is a blend.
    sweep_sock "$SOCKETLEY_SOCKET"
    rm -f "$SOCKETLEY_SOCKET"
    "$BIN" daemon >"$STATE/gen-daemon.log" 2>&1 &
    GEN_DPID=$!
    echo $GEN_DPID > "$STATE/gen-daemon.pid"
    for i in $(seq 1 50); do [ -S "$SOCKETLEY_SOCKET" ] && break; sleep 0.1; done
    [ -S "$SOCKETLEY_SOCKET" ] || { echo "FATAL: generator daemon never came up" >&2; exit 2; }

    LUA="$STATE/gen_client.lua"
    cat > "$LUA" <<LUAEOF
-- RESP SET pump: one batch of $DEPTH commands in flight, refilled when the
-- last response of the batch has been seen.  Response-driven, so every op
-- counted by stats was validated by the kernel round trip that delivered it;
-- on_message checks the reply really is +OK besides.
local DEPTH = $DEPTH
local one = "*3\r\n\$3\r\nSET\r\n\$8\r\ngenkey01\r\n\$64\r\n" .. string.rep("V", 64) .. "\r\n"
local batch = string.rep(one, DEPTH)
local acked = 0
local bad = 0
local started = false

local function kick()
    if started then return end
    if self.send(batch) then started = true end
end

function on_connect(id) kick() end
function on_start() kick() end

function on_message(msg)
    if string.sub(msg, 1, 3) ~= "+OK" then bad = bad + 1 end
    acked = acked + 1
    if acked % DEPTH == 0 then self.send(batch) end
end

socketley.set_interval(2000, function()
    socketley.log("PUMP acked=" .. acked .. " bad=" .. bad)
end)
LUAEOF

    # Idempotent: the daemon restores 'gen' from a previous run's state dir.
    "$BIN" stop gen >/dev/null 2>&1 || true
    "$BIN" remove gen >/dev/null 2>&1 || true
    "$BIN" create client gen -t "127.0.0.1:$CACHE_PORT" --lua "$LUA" -s
    sleep 1   # settle: connect + first batches, outside the window

    stat_msgs() {
        local v
        v=$("$BIN" stats gen 2>/dev/null \
          | awk -F: '$1 ~ /total_messages/ { print $2; exit }' | tr -d ' ')
        echo "${v:-0}"
    }

    CACHE_DPID=$(cat "$STATE/cache-daemon.pid")
    m0=$(stat_msgs); g0=$(cpu_us_tree "$GEN_DPID"); s0=$(cpu_us_tree "$CACHE_DPID")
    t0=$(date +%s%6N)
    sleep "$SECS"
    m1=$(stat_msgs); g1=$(cpu_us_tree "$GEN_DPID"); s1=$(cpu_us_tree "$CACHE_DPID")
    t1=$(date +%s%6N)

    grep -a "PUMP" "$STATE/gen-daemon.log" | tail -2 || true

    wall=$((t1 - t0))
    ops=$((m1 - m0))
    awk -v ops=$ops -v wall=$wall -v g=$((g1 - g0)) -v s=$((s1 - s0)) -v d=$DEPTH 'BEGIN {
        rate = ops * 1000000.0 / wall
        gc = g * 1.0 / wall; sc = s * 1.0 / wall
        printf "GENCLIENT depth=%d ops=%d wall_s=%.2f rate=%.0f ops/s  gen_cores=%.2f  cache_cores=%.2f  ops_per_gen_core=%.0f%s\n",
            d, ops, wall/1000000.0, rate, gc, sc, (gc > 0 ? rate/gc : 0),
            (gc >= 0.95 ? "  ** GENERATOR-SATURATED **" : "")
    }'

    "$BIN" stop gen >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove gen >/dev/null 2>&1 || true
    kill "$GEN_DPID" 2>/dev/null || true
    ;;

teardown)
    for sock in "$STATE/cache-daemon.sock" "$STATE/gen-daemon.sock"; do
        sweep_sock "$sock"
    done
    [ -e "$STATE/redis.pid" ] && kill "$(cat "$STATE/redis.pid")" 2>/dev/null || true
    [ -e "$STATE/lockholder.pid" ] && kill "$(cat "$STATE/lockholder.pid")" 2>/dev/null || true
    sleep 0.5
    left=$(listeners_in_window)
    [ -z "$left" ] && echo "teardown OK: window empty" \
                   || { echo "teardown INCOMPLETE, still bound: $left" >&2; exit 1; }
    ;;

*)
    echo "usage: $0 setup | sweep [bench args] | genclient DEPTH SECS | teardown" >&2
    exit 1
    ;;
esac
