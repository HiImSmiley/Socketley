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
          exec sleep 100000 >/dev/null 2>&1 </dev/null ) 9>"/tmp/socketley-ports-$BASE.lock" &
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
    # Built on demand rather than committed.  A prebuilt ELF used to be tracked
    # here beside its own source, so the repository shipped a binary compiled on
    # somebody's machine against that machine's libc, and running a sweep on any
    # other one executed it.  The compile line was already written down in the
    # first thirty lines of the .c file; it just was not being used.
    #
    # Rebuilt when the source is newer than the binary, so editing the generator
    # cannot leave a sweep measuring the previous version -- which is the failure
    # this is really guarding against, not the missing file.
    BENCH_SRC="$BENCH_DIR/bench_cache_vs_redis.c"
    BENCH_BIN="$BENCH_DIR/bench_cache_vs_redis"
    if [ ! -x "$BENCH_BIN" ] || [ "$BENCH_SRC" -nt "$BENCH_BIN" ]; then
        echo "building $(basename "$BENCH_BIN")" >&2
        cc -O3 -Wall -Wextra -o "$BENCH_BIN" "$BENCH_SRC" -lpthread \
            || { echo "FATAL: could not build $BENCH_SRC" >&2; exit 2; }
    fi
    exec "$BENCH_BIN" "$@" "$CACHE_PORT" "$REDIS_PORT"
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

# ─── Measured 2026-08-24, quiet box (suite finished, 0 socketley, window empty)
# Raw logs: results/results-{depth,clients,rb,genclient}.txt.  All rounds
# validated in full; not one refusal.  16 cores; unsharded cache, redis 7.0.15.
#
# (a) bench_cache_vs_redis, SET 64B, rates in ops/s, per-round [r1 r2 r3],
#     cores/client = max thread over the timed window:
#   P=1   c=1  skl [47832 49935 46945] 0.48-0.51c | redis [41445 43947 43859] 0.44-0.47c
#   P=8   c=1  skl [360071 345935 365320] ~0.49c  | redis [276290 286812 284528] 0.39c
#   P=32  c=1  skl [1226490 1144286 1290227] ~0.44c | redis [706418 686474 687467] ~0.27c
#   P=128 c=1  skl [3236508 2915558 2787097] ~0.38c | redis [1184020 1213497 1223580] ~0.15c
#   P=32  c=2  skl [2207707 2499891 2699757] ~0.42c | redis [1079462 1120924 1040780] ~0.18c
#   P=32  c=4  skl [2506323 2645071 2540048] ~0.21c | redis [1142521 1136936 1146931] ~0.10c
#   GET P=32 c=1 skl [1221829 1212298 1224534] ~0.48c | redis [807632 864852 781985] ~0.32c
#   Nothing tripped GENERATOR-SATURATED.  One generator core ≈ 95k ops/s at
#   P=1 (the known redis-benchmark ceiling) and ≈ 2.8M ops/s at P=32.
#
# (a) cross-check, redis-benchmark -t set -d 64 -P 32 -c 1 -n 500000:
#   → redis     667557 / 670241 rps at 0.39 cores   (agrees with our tool within 3%)
#   → socketley 927644 / 1006036 rps at 0.60-0.61 cores (reads 20% under our tool
#     while spending 40% more CPU — instrument overhead, not a server difference)
#
# (b) client runtime as generator (one instance, prebuilt RESP batch through
#     lua_send, response-driven refill, on_message validates +OK; fwd/rev order):
#   depth 1    44067 /  44362 ops/s  gen 0.59c  cache 0.51c   ~75k ops/gen-core
#   depth 8   310307 / 313337 ops/s  gen 0.61c  cache 0.49c  ~513k ops/gen-core
#   depth 32  916602 / 926163 ops/s  gen 0.65c  cache 0.43c  ~1.42M ops/gen-core
#   depth 128 1797090 / 1846977 ops/s gen 0.70c cache 0.45c  ~2.62M ops/gen-core
#   SQPOLL=1 depth 32: 922037 ops/s at gen 1.54c — same rate, 2.4x the CPU;
#   the poll thread spins and GENERATOR-SATURATED trips.  bad=0 throughout.
