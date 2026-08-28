#!/usr/bin/env bash
# Two daemons with a shared cluster directory running scripts that exercise
# socketley.cluster.* and the on_cluster_* callbacks -- a simulation, since
# members find each other through the directory and the addresses they
# advertise rather than through socket paths, and both sockets and the state
# directory are per-run.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
PASS=0; FAIL=0; TOTAL=0

TMPD=$(mktemp -d /tmp/socketley-clua-XXXXXX)
export HOME="$TMPD/home"
mkdir -p "$HOME"
CLUSTER_DIR="$TMPD/cluster"
mkdir -p "$CLUSTER_DIR"
SOCK_A="$TMPD/nodeA.sock"
SOCK_B="$TMPD/nodeB.sock"
# One base, so this file can be driven on a private port block while it is
# being changed.
PB=$((SL_PORT_BASE+401))
PORT_A=$((PB + 0))
PORT_B=$((PB + 1))
PORT_N=$((PB + 2))
DAEMON_PIDS=()

# Unique runtime names
RT_A="clua_srvA"
RT_B="clua_srvB"
# Created on nodeA and never started, because a cluster callback is a callback
# and a runtime that has never run must not execute one.
RT_N="clua_srvN"

# Temp files for Lua output
LUA_OUT=$(mktemp)
LUA_SCRIPT=$(mktemp --suffix=.lua)
# Its own file, because the assertion is about WHOSE callback fired and both
# runtimes would otherwise append to one.
NEVER_OUT=$(mktemp)
NEVER_SCRIPT=$(mktemp --suffix=.lua)

nodeA() { SOCKETLEY_SOCKET="$SOCK_A" "$BIN" "$@"; }
nodeB() { SOCKETLEY_SOCKET="$SOCK_B" "$BIN" "$@"; }

cleanup() {
    set +e
    # Only talk to a daemon that is answering, because test 6 kills nodeB's on
    # purpose and a CLI command against its dead socket auto-starts a detached
    # daemon nothing below could find again.
    for sock in "$SOCK_A" "$SOCK_B"; do
        daemon_alive "$sock" || continue
        for rt in "$RT_A" "$RT_B" "$RT_N"; do
            SOCKETLEY_SOCKET="$sock" "$BIN" stop "$rt" &>/dev/null
        done
    done
    sleep 0.5
    for sock in "$SOCK_A" "$SOCK_B"; do
        daemon_alive "$sock" || continue
        for rt in "$RT_A" "$RT_B" "$RT_N"; do
            SOCKETLEY_SOCKET="$sock" "$BIN" remove "$rt" &>/dev/null
        done
    done
    for pid in "${DAEMON_PIDS[@]}"; do
        [ "$pid" = "0" ] && continue
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    done
    daemon_sweep "$SOCK_A"
    daemon_sweep "$SOCK_B"
    rm -f "$LUA_OUT" "$LUA_SCRIPT" "$NEVER_OUT" "$NEVER_SCRIPT"
    rm -rf "$TMPD"
}
trap cleanup EXIT

assert_contains() {
    TOTAL=$((TOTAL+1))
    if grep -q "$2" <<<"$1"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: expected '$2' in output"
        echo "  GOT: $1"
    fi
}

# Every numeric thing the script reported used to be checked with
# assert_contains, which asks whether the key is present and never looks at the
# value, so the two assertions meant to prove this daemon sees across the
# cluster passed on a view containing only itself -- with `2>/dev/null` because
# an absent line yields the empty string and `[ "" -ge 2 ]` is an error that
# would end the run at the assertion.
assert_ge() {
    TOTAL=$((TOTAL+1))
    if [ "${1:-}" -ge "$2" ] 2>/dev/null; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: ${3:-value} is '${1:-<absent>}', wanted at least $2"
    fi
}

# The largest value rather than the last, because on_tick reports repeatedly
# while the cluster view is still filling in.
num_max() {
    { grep -aoE "^$1=[0-9]+$" "$LUA_OUT" 2>/dev/null || true; } \
        | cut -d= -f2 | sort -n | tail -1
}

echo "=== Integration: cluster Lua API ==="

# ─── Write Lua script that exercises cluster introspection ────────────────────
cat > "$LUA_SCRIPT" << 'LUAEOF'
local out_file = os.getenv("CLUA_OUT_FILE") or "/tmp/clua_out.txt"

local function append(line)
    local f = io.open(out_file, "a")
    if f then
        f:write(line .. "\n")
        f:close()
    end
end

function on_start()
    -- Query cluster daemons
    local daemons = socketley.cluster.daemons()
    append("daemons_count=" .. #daemons)
    for _, d in ipairs(daemons) do
        append("daemon=" .. d.name .. " host=" .. d.host)
    end

    -- Query cluster stats
    local stats = socketley.cluster.stats()
    append("stats_daemons=" .. stats.daemons)
    append("stats_runtimes=" .. stats.runtimes)
    -- The other two fields the call returns.  `running` and `groups` were
    -- never read by anything: a script choosing where to place work reads
    -- exactly these, and a build that returned an empty groups table or a
    -- zero running count satisfied every assertion this file used to make.
    append("stats_running=" .. stats.running)
    local gn, gsum = 0, 0
    for name, count in pairs(stats.groups) do
        gn = gn + 1
        gsum = gsum + count
        append("stats_group_" .. name .. "=" .. count)
    end
    append("stats_groupcount=" .. gn)
end

function on_cluster_join(daemon)
    append("JOIN=" .. daemon.name)
end

function on_cluster_leave(daemon)
    append("LEAVE=" .. daemon.name)
end

function on_group_change(group, members)
    append("GROUP_CHANGE=" .. group .. " members=" .. #members)
end

tick_ms = 500
function on_tick(dt)
    -- The argument, which nothing has ever looked at.  tick_ms is 500, so a dt
    -- expressed in seconds is about 0.5 and one expressed in milliseconds is
    -- about 500 -- two readings a factor of a thousand apart, and a script
    -- doing rate arithmetic gets it wrong silently either way.  Recorded in
    -- thousandths so the shell can compare integers.
    append("TICKDT_MILLI=" .. math.floor((tonumber(dt) or -1) * 1000))
    -- Periodically check runtimes
    local rts = socketley.cluster.runtimes()
    if #rts > 1 then
        append("runtimes_count=" .. #rts)
        -- Check group query
        local api_members = socketley.cluster.group("api")
        if #api_members > 0 then
            append("api_group_count=" .. #api_members)
        end
    end
end
LUAEOF

# ─── Start daemon A ──────────────────────────────────────────────────────────
# Wait for the daemon to say it is up, because the configuration call below is
# a CLI command that would otherwise auto-start a detached daemon nobody has
# the pid of.
start_node() {   # start_node SOCKET NAME [env assignments...]
    local sock=$1 name=$2 i; shift 2
    env "$@" SOCKETLEY_SOCKET="$sock" "$BIN" daemon >>"$TMPD/$name.log" 2>&1 &
    DAEMON_PIDS+=($!)
    for i in $(seq 1 100); do
        grep -q "daemon started" "$TMPD/$name.log" 2>/dev/null && break
        sleep 0.1
    done
    if [ ! -S "$sock" ]; then
        echo "ERROR: daemon $name socket not created"
        tail -5 "$TMPD/$name.log" 2>/dev/null | sed 's/^/    /'
        exit 1
    fi
    SOCKETLEY_SOCKET="$sock" "$BIN" daemon --name "$name" --cluster "$CLUSTER_DIR"
}

start_node "$SOCK_A" nodeA "CLUA_OUT_FILE=$LUA_OUT"
sleep 0.2

# ─── Create server on A with Lua script ─────────────────────────────────────
# create_ok takes the whole command because these go through the per-node
# wrappers, and a script the daemon refuses to load used to be reported as "the
# callback never fired" -- the defect this file exists to catch.
create_ok "server on nodeA created with the cluster script" \
    nodeA create server "$RT_A" -p "$PORT_A" -g api --lua "$LUA_SCRIPT" \
 -s
sleep 1

# ─── Test 1: on_start sees at least the local daemon ────────────────────────
echo "  Test 1: on_start cluster.daemons() sees local daemon"
OUT=$(cat "$LUA_OUT" 2>/dev/null || echo "")
assert_contains "$OUT" "daemon=nodeA"
assert_contains "$OUT" "stats_daemons=1"
assert_ge "$(num_max daemons_count)" 1 "cluster.daemons() count at on_start"
assert_ge "$(num_max stats_runtimes)" 1 "cluster.stats().runtimes at on_start"
assert_ge "$(num_max stats_running)" 1 "cluster.stats().running at on_start"
assert_ge "$(num_max stats_groupcount)" 1 "cluster.stats().groups is not empty"
assert_ge "$(num_max stats_group_api)" 1 "cluster.stats().groups counts the api group"

# Its own script and its own output file, because two runtimes appending to one
# file could not say whose callback wrote a line, and registered before nodeB
# exists so the join it must not hear has not happened yet.
cat > "$NEVER_SCRIPT" <<LUAEOF
local out_file = "$NEVER_OUT"
local function append(line)
    local f = io.open(out_file, "a")
    if f then f:write(line .. "\n"); f:close() end
end
append("LOADED")
function on_cluster_join(daemon)  append("NEVER_JOIN=" .. daemon.name) end
function on_cluster_leave(daemon) append("NEVER_LEAVE=" .. daemon.name) end
function on_group_change(group, members)
    append("NEVER_GROUP=" .. group)
end
LUAEOF
# ─── Started, proved loaded, then stopped ───────────────────────────────────
# Started and then stopped rather than never started, because a worker exists
# only from `start` and a bare `create` now only compiles -- and the claim is
# stronger for it, since a runtime that has demonstrably registered its
# callbacks and then been stopped makes any later line delivery to a stopped
# runtime.
create_ok "server on nodeA that will be stopped created" \
    nodeA create server "$RT_N" -p "$PORT_N" -g api --lua "$NEVER_SCRIPT" -s

for _ in $(seq 1 40); do
    grep -q 'LOADED' "$NEVER_OUT" 2>/dev/null && break
    sleep 0.1
done
nodeA stop "$RT_N" >/dev/null 2>&1 || true
sleep 0.3


# ─── Start daemon B ──────────────────────────────────────────────────────────
start_node "$SOCK_B" nodeB
sleep 0.2

# Create server on B in same group
create_ok "server on nodeB created" nodeB create server "$RT_B" -p "$PORT_B" -g api -s

# Wait for cluster heartbeat cycle (publish every 2s) + scan
sleep 5

# ─── Test 2: on_cluster_join fired for nodeB ────────────────────────────────
echo "  Test 2: on_cluster_join fires for new daemon"
OUT=$(cat "$LUA_OUT" 2>/dev/null || echo "")
assert_contains "$OUT" "JOIN=nodeB"

# The assertion above is this one's control and both are about the same join,
# so a build that delivered to neither would fail test 2 first -- with LOADED
# proving the script ran and registered, which an absence cannot.
echo "  Test 2b: a stopped runtime hears no cluster event"
NEVER=$(cat "$NEVER_OUT" 2>/dev/null || echo "")
assert_contains "$NEVER" "LOADED"
TOTAL=$((TOTAL+1))
case "$NEVER" in
    *NEVER_JOIN=*|*NEVER_LEAVE=*|*NEVER_GROUP=*)
        FAIL=$((FAIL+1))
        echo "  FAIL: a stopped runtime ran a cluster callback"
        echo "        got: $(printf '%s' "$NEVER" | grep -a NEVER_ | tr '\n' ' ')"
        echo "        dispatch_cluster_events collected every runtime with a Lua"
        echo "        VM and never asked what state it was in"
        ;;
    *) PASS=$((PASS+1)) ;;
esac

# ─── Test 3: on_group_change fired for "api" group ─────────────────────────
echo "  Test 3: on_group_change fires for group membership change"
assert_contains "$OUT" "GROUP_CHANGE=api"

# ─── Test 4: cluster.runtimes() sees both runtimes via on_tick ──────────────
echo "  Test 4: cluster.runtimes() sees cross-daemon runtimes"
# Give tick a few cycles
sleep 3
OUT=$(cat "$LUA_OUT" 2>/dev/null || echo "")
# Two, not "a number": one is what this daemon sees without leaving home, and
# the whole claim is that cluster.runtimes() reaches the other daemon's.
assert_ge "$(num_max runtimes_count)" 2 "cluster.runtimes() across both daemons"

# ─── Test 5: cluster.group() returns api members ───────────────────────────
echo "  Test 5: cluster.group() returns group members"
# Two again: nodeA's own server is in group api, so a count of one proves only
# that the local runtime is in the table it was put in.
assert_ge "$(num_max api_group_count)" 2 "cluster.group(\"api\") members"

# The argument on_group_change was handed rather than only that it fired,
# because the substring check in test 3 is satisfied by members=0.
assert_ge "$({ grep -aoE '^GROUP_CHANGE=api members=[0-9]+$' "$LUA_OUT" 2>/dev/null || true; } \
           | cut -d= -f3 | sort -n | tail -1)" 2 "on_group_change member count"

# ─── Test 6: on_cluster_leave fires when daemon B is killed ─────────────────
echo "  Test 6: on_cluster_leave fires when daemon leaves"
# Stop runtime on B first
nodeB stop "$RT_B" 2>/dev/null || true
sleep 0.5
nodeB remove "$RT_B" 2>/dev/null || true
kill "${DAEMON_PIDS[1]}" 2>/dev/null || true
wait "${DAEMON_PIDS[1]}" 2>/dev/null || true
DAEMON_PIDS[1]=0

# Wait for stale detection (10s threshold + scan cycles)
sleep 13

OUT=$(cat "$LUA_OUT" 2>/dev/null || echo "")
assert_contains "$OUT" "LEAVE=nodeB"

# ─── on_tick's argument ─────────────────────────────────────────────────────
# Nothing had ever read dt, so neither its unit nor its magnitude was held down
# -- and the bound is wide on purpose, excluding only the readings that matter,
# since seconds would land three orders of magnitude below the floor and
# microseconds three above the ceiling.
DT_MILLI=$(num_max TICKDT_MILLI)
assert_ge "$DT_MILLI" 300000 "on_tick dt is milliseconds and near tick_ms (lower bound)"
TOTAL=$((TOTAL+1))
if [ "${DT_MILLI:-0}" -le 5000000 ] 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: on_tick dt is '$DT_MILLI' thousandths of a ms, wanted at most 5000000"
    echo "        (dt should be about 500 for tick_ms=500; this is the upper bound"
    echo "         that a microsecond or nanosecond reading would break)"
fi

# ─── Summary ──────────────────────────────────────────────────────────────────
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
