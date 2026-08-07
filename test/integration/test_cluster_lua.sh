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
# One base, so this file can be driven on a private port block while it is being
# changed.  The default is the pair it has always used.
PB=${SOCKETLEY_PORT_BASE:-19401}
PORT_A=$((PB + 0))
PORT_B=$((PB + 1))
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
    if grep -q "$2" <<<"$1"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: expected '$2' in output"
        echo "  GOT: $1"
    fi
}

# assert_ge GOT WANT LABEL
#
# Defined since this file was written and called by none of it: every numeric
# thing the script reported was checked with assert_contains, which asks whether
# the KEY is present and never looks at the value.  "runtimes_count=" is
# satisfied by runtimes_count=0, "api_group_count=" by a group of one — so the
# two assertions that are supposed to prove this daemon can see across the
# cluster passed on a view that contained only itself.  The counts below are the
# ones a second daemon changes.
#
# `2>/dev/null` on the comparison because GOT is extracted from a file the Lua
# script writes: an absent line yields the empty string, `[ "" -ge 2 ]` is an
# error rather than a false, and under `set -e` that would end the run at the
# assertion instead of reporting it.
assert_ge() {
    TOTAL=$((TOTAL+1))
    if [ "${1:-}" -ge "$2" ] 2>/dev/null; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: ${3:-value} is '${1:-<absent>}', wanted at least $2"
    fi
}

# num_max KEY — the largest value the script wrote for KEY, or empty if it never
# wrote one.  The largest and not the last: on_tick reports repeatedly while the
# cluster view is still filling in, so the last line can be a snapshot taken
# before the remote daemon was visible.
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
    nodeA create server "$RT_A" -p "$PORT_A" -g api --lua "$LUA_SCRIPT" \
        --daemon-process -s
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
# Two, not "a number": one is what this daemon sees without leaving home, and
# the whole claim is that cluster.runtimes() reaches the other daemon's.
assert_ge "$(num_max runtimes_count)" 2 "cluster.runtimes() across both daemons"

# ─── Test 5: cluster.group() returns api members ───────────────────────────
echo "  Test 5: cluster.group() returns group members"
# Two again: nodeA's own server is in group api, so a count of one proves only
# that the local runtime is in the table it was put in.
assert_ge "$(num_max api_group_count)" 2 "cluster.group(\"api\") members"

# The argument on_group_change was handed, rather than only that it fired.  The
# substring check in Test 3 is satisfied by members=0.
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
#
# tick_ms is 500 and the man page says dt is "the actual elapsed time in
# milliseconds since the last tick (double)".  Measured: 500.128.  Nothing had
# ever read the argument, so neither the unit nor the magnitude was held down —
# and the two plausible readings are a factor of a thousand apart, which a
# script doing rate arithmetic gets wrong in silence.
#
# The bound is wide on purpose: this runs beside two daemons and a suite, so the
# actual gap drifts.  What it excludes is the reading that matters — dt in
# SECONDS would land at 500 thousandths, three orders of magnitude below the
# floor, and dt in microseconds three above the ceiling.
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
