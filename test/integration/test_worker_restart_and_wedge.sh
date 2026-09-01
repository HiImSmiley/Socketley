#!/usr/bin/env bash
# Integration test: a worker that was replaced, and a worker that is running
# without serving, are both visible in `ls`.
#
# waitpid tells the daemon a child died -- measured, within one 2s tick -- and
# the default death policy forks a replacement.  Neither fact reached the
# operator.  On the parent commit:
#
#   kill -9 the worker of a cache holding a key, wait for the replacement, and
#   `ls` reads "Up 38 seconds" with the uptime still counting from the original
#   start.  The key is gone.  Nothing in the row says so.
#
# And the case waitpid cannot see at all: the worker sets stats_dirty on every
# completion, so one doing any work speaks within stats_interval_ms.  A silent
# worker is either idle, which costs no cpu, or stuck inside a handler, which
# costs a core -- and only the second is a fault.  The idle arm is here because
# a detector that flags silence alone would condemn every quiet runtime.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate wedge

PORT_CACHE=$((SL_PORT_BASE+1420))
PORT_SPIN=$((SL_PORT_BASE+1421))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

SPIN_LUA="$SOCKETLEY_TMPD/spin.lua"
cleanup() {
    "$BIN" remove kv  >/dev/null 2>&1
    "$BIN" remove spn >/dev/null 2>&1
    daemon_stop
}
trap cleanup EXIT

# A callback that never returns.  The deadline is switched off for this daemon
# because otherwise lua_deadline ends the loop first -- which is the runtime
# resolving it, and the detector deliberately sits above that.
cat > "$SPIN_LUA" <<'LUA'
function on_message(msg)
    if msg:find("spin") then
        local x = 0
        while true do x = (x + 1) % 1000000 end
    end
    return msg
end
LUA

export SOCKETLEY_LUA_TIMEOUT_MS=0
daemon_start "$BIN"

DPID=$(daemon_starting_pids "$SOCKETLEY_SOCKET")

# Bound waits on the thing itself, never a fixed sleep.
wait_port() {
    local p=$1 i
    for i in $(seq 1 200); do ss -ltn | grep -q ":$p " && return 0; sleep 0.1; done
    return 1
}
worker_of() { pgrep -P "$1" 2>/dev/null | head -1; }
status_of() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2==n'; }

echo "=== Integration: a replaced worker and a stuck worker are visible ==="

echo "--- 1. a restart shows up, and the uptime is the new child's ---"
"$BIN" create cache kv -p "$PORT_CACHE" -s >/dev/null 2>&1
wait_port "$PORT_CACHE" || { echo "  FATAL: cache never bound $PORT_CACHE"; exit 2; }
printf 'set survivor 1\n' | timeout 3 nc -q0 127.0.0.1 "$PORT_CACHE" >/dev/null

# The control: before any kill there is no restart note, so the assertions
# below are not passing on a string that is always there.
if ! status_of kv | grep -q "restart"; then ok; else
    bad "no restart note before a kill" "$(status_of kv)"
fi

sleep 4   # so the original uptime is visibly larger than the replacement's
for round in 1 2; do
    W=$(worker_of "$DPID")
    [ -n "$W" ] || { echo "  FATAL: no worker to kill"; exit 2; }
    kill -9 "$W"

    # The replacement, waited for by pid change rather than by sleeping.
    NEW=""
    for i in $(seq 1 200); do
        NEW=$(worker_of "$DPID")
        [ -n "$NEW" ] && [ "$NEW" != "$W" ] && break
        sleep 0.1
    done
    [ -n "$NEW" ] && [ "$NEW" != "$W" ] || { echo "  FATAL: no replacement worker"; exit 2; }
    sleep 3   # one health tick, so the daemon has counted it

    want="($round restart"
    if status_of kv | grep -q "$want"; then ok; else
        bad "kill #$round is counted" "expected '$want', got '$(status_of kv)'"
    fi
done

# The uptime restarted with the child: the runtime was created well before this.
up=$(status_of kv | grep -oE "Up [0-9]+ second" | grep -oE "[0-9]+" | head -1)
if [ -n "$up" ] && [ "$up" -lt 8 ]; then ok; else
    bad "uptime is the replacement's" "got '${up:-<none>}' seconds on a runtime created long before"
fi

# What the count is for: the store did not survive, and without the note the
# row is indistinguishable from a cache that has held the key all along.
val=$(printf 'get survivor\n' | timeout 3 nc -q0 127.0.0.1 "$PORT_CACHE")
if [ "$val" = "nil" ]; then ok; else
    bad "the restart lost the store" "expected nil, got '$val'"
fi

if "$BIN" ls --json 2>/dev/null | grep -q '"restarts":2'; then ok; else
    bad "json carries the count" "$("$BIN" ls --json 2>/dev/null | head -c 200)"
fi

echo "--- 2. a stuck worker is named, an idle one is not ---"
"$BIN" create server spn -p "$PORT_SPIN" --lua "$SPIN_LUA" -s >/dev/null 2>&1
wait_port "$PORT_SPIN" || { echo "  FATAL: server never bound $PORT_SPIN"; exit 2; }

# The control again: neither runtime is accused before anything is stuck.
if ! "$BIN" ls | grep -q "NOT RESPONDING"; then ok; else
    bad "nothing is accused before the spin" "$("$BIN" ls)"
fi

( printf 'spin now\n' | timeout 3 nc -q0 127.0.0.1 "$PORT_SPIN" >/dev/null 2>&1 & )

# wedge_silence is 15s, plus one 2s tick to notice it.
found=0
for i in $(seq 1 30); do
    sleep 1
    status_of spn | grep -q "NOT RESPONDING" && { found=1; break; }
done
if [ "$found" = 1 ]; then ok; else
    bad "the stuck worker is named" "still nothing after ${i}s: $(status_of spn)"
fi

# The whole point of measuring cpu and not just silence: this cache has said
# nothing for the entire arm above and is perfectly healthy.
if ! status_of kv | grep -q "NOT RESPONDING"; then ok; else
    bad "an idle runtime is not accused" "$(status_of kv)"
fi

# It is a warning beside the uptime, not instead of it: the process is up.
if status_of spn | grep -q "Up "; then ok; else
    bad "the uptime is still shown" "$(status_of spn)"
fi

echo
echo "=============================="
echo " Summary: $PASS passed, $FAIL failed (of $TOTAL)"
echo "=============================="
[ "$FAIL" -eq 0 ]
