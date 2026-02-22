#!/usr/bin/env bash
# Integration test: Lua cluster introspection API + event callbacks
#
# Starts 2 daemons with a shared cluster directory, creates servers with
# Lua scripts that exercise socketley.cluster.* and on_cluster_* callbacks,
# then verifies the output.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
PASS=0; FAIL=0; TOTAL=0

CLUSTER_DIR=$(mktemp -d)
SOCK_A="/tmp/socketley-clua-a.sock"
SOCK_B="/tmp/socketley-clua-b.sock"
PORT_A=19401
PORT_B=19402
DAEMON_PIDS=()

# Unique runtime names
RT_A="clua_srvA"
RT_B="clua_srvB"

# Temp files for Lua output
LUA_OUT=$(mktemp)
LUA_SCRIPT=$(mktemp --suffix=.lua)

nodeA() { SOCKETLEY_SOCKET="$SOCK_A" "$BIN" "$@"; }
nodeB() { SOCKETLEY_SOCKET="$SOCK_B" "$BIN" "$@"; }

cleanup() {
    set +e
    for cmd in nodeA nodeB; do
        for rt in "$RT_A" "$RT_B"; do
            $cmd stop "$rt" &>/dev/null
        done
    done
    sleep 0.5
    for cmd in nodeA nodeB; do
        for rt in "$RT_A" "$RT_B"; do
            $cmd remove "$rt" &>/dev/null
        done
    done
    for pid in "${DAEMON_PIDS[@]}"; do
        [ "$pid" = "0" ] && continue
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    done
    rm -f "$SOCK_A" "$SOCK_B" "$LUA_OUT" "$LUA_SCRIPT"
    rm -rf "$CLUSTER_DIR"
}
trap cleanup EXIT

assert_contains() {
    TOTAL=$((TOTAL+1))
    if echo "$1" | grep -q "$2"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: expected '$2' in output"
        echo "  GOT: $1"
    fi
}

assert_ge() {
    TOTAL=$((TOTAL+1))
    if [ "$1" -ge "$2" ] 2>/dev/null; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: expected $1 >= $2"
    fi
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
CLUA_OUT_FILE="$LUA_OUT" SOCKETLEY_SOCKET="$SOCK_A" "$BIN" daemon \
    --name nodeA --cluster "$CLUSTER_DIR" 2>/dev/null &
DAEMON_PIDS+=($!)
sleep 0.5

# Verify socket created
if [ ! -S "$SOCK_A" ]; then
    echo "ERROR: daemon A socket not created"
    exit 1
fi

# ─── Create server on A with Lua script ─────────────────────────────────────
nodeA create server "$RT_A" -p "$PORT_A" -g api \
    --lua "$LUA_SCRIPT" -s 2>&1 || true
sleep 1

# ─── Test 1: on_start sees at least the local daemon ────────────────────────
echo "  Test 1: on_start cluster.daemons() sees local daemon"
OUT=$(cat "$LUA_OUT" 2>/dev/null || echo "")
assert_contains "$OUT" "daemons_count="
assert_contains "$OUT" "daemon=nodeA"
assert_contains "$OUT" "stats_daemons=1"

# ─── Start daemon B ──────────────────────────────────────────────────────────
SOCKETLEY_SOCKET="$SOCK_B" "$BIN" daemon \
    --name nodeB --cluster "$CLUSTER_DIR" 2>/dev/null &
DAEMON_PIDS+=($!)
sleep 0.5

# Create server on B in same group
nodeB create server "$RT_B" -p "$PORT_B" -g api -s 2>&1 || true

# Wait for cluster heartbeat cycle (publish every 2s) + scan
sleep 5

# ─── Test 2: on_cluster_join fired for nodeB ────────────────────────────────
echo "  Test 2: on_cluster_join fires for new daemon"
OUT=$(cat "$LUA_OUT" 2>/dev/null || echo "")
assert_contains "$OUT" "JOIN=nodeB"

# ─── Test 3: on_group_change fired for "api" group ─────────────────────────
echo "  Test 3: on_group_change fires for group membership change"
assert_contains "$OUT" "GROUP_CHANGE=api"

# ─── Test 4: cluster.runtimes() sees both runtimes via on_tick ──────────────
echo "  Test 4: cluster.runtimes() sees cross-daemon runtimes"
# Give tick a few cycles
sleep 3
OUT=$(cat "$LUA_OUT" 2>/dev/null || echo "")
assert_contains "$OUT" "runtimes_count="

# ─── Test 5: cluster.group() returns api members ───────────────────────────
echo "  Test 5: cluster.group() returns group members"
assert_contains "$OUT" "api_group_count="

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

# ─── Summary ──────────────────────────────────────────────────────────────────
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
