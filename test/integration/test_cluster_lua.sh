#!/usr/bin/env bash
# Integration test: Lua cluster introspection API + event callbacks
#
# Starts 2 daemons with a shared cluster directory, creates servers with
# Lua scripts that exercise socketley.cluster.* and on_cluster_* callbacks,
# then verifies the output.
#
# Two daemons in one filesystem namespace is a simulation of a cluster, not how
# one is deployed: members find each other through the shared cluster directory
# and the network addresses they advertise there, never through socket paths.
# Both sockets and the state directory are per-run — they used to be two fixed
# names in /tmp and the caller's real state directory.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
PASS=0; FAIL=0; TOTAL=0

TMPD=$(mktemp -d /tmp/socketley-clua-XXXXXX)
export HOME="$TMPD/home"
mkdir -p "$HOME"
CLUSTER_DIR="$TMPD/cluster"
mkdir -p "$CLUSTER_DIR"
SOCK_A="$TMPD/nodeA.sock"
SOCK_B="$TMPD/nodeB.sock"
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
    # Only talk to a daemon that is answering.  Test 6 kills nodeB's daemon on
    # purpose, and these loops then ran `nodeB stop` and `nodeB remove` against
    # its dead socket — which auto-starts a detached daemon rather than failing,
    # because that is what every CLI command except `daemon`, `version` and
    # `help` does when the socket is silent.  Nothing below could kill it: its
    # pid slot is 0 by then, and the `rm -f` unlinked the socket so it could not
    # even be found again.  That is one of the two daemons a full suite run left
    # behind; test_cluster.sh left the other.
    for sock in "$SOCK_A" "$SOCK_B"; do
        daemon_alive "$sock" || continue
        for rt in "$RT_A" "$RT_B"; do
            SOCKETLEY_SOCKET="$sock" "$BIN" stop "$rt" &>/dev/null
        done
    done
    sleep 0.5
    for sock in "$SOCK_A" "$SOCK_B"; do
        daemon_alive "$sock" || continue
        for rt in "$RT_A" "$RT_B"; do
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
    rm -f "$LUA_OUT" "$LUA_SCRIPT"
    rm -rf "$TMPD"
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
#
# The configuration call below is a CLI command, so it auto-starts a detached
# daemon of its own if the socket is not answering yet.  The `sleep 0.3` it used
# to wait was a guess; losing that guess did not fail loudly, it silently left a
# daemon nobody had the pid of.  Wait for the daemon to say it is up instead.
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
# wrapper functions rather than through $BIN directly.  A script the daemon
# refuses to load makes `create` fail, and every assertion below reads the file
# that script writes — so a refusal used to be reported as "the callback never
# fired", which is the defect this file exists to catch.
create_ok "server on nodeA created with the cluster script" \
    nodeA create server "$RT_A" -p "$PORT_A" -g api --lua "$LUA_SCRIPT" -s
sleep 1

# ─── Test 1: on_start sees at least the local daemon ────────────────────────
echo "  Test 1: on_start cluster.daemons() sees local daemon"
OUT=$(cat "$LUA_OUT" 2>/dev/null || echo "")
assert_contains "$OUT" "daemons_count="
assert_contains "$OUT" "daemon=nodeA"
assert_contains "$OUT" "stats_daemons=1"

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
