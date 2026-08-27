#!/usr/bin/env bash
# Integration test: Lua on_start / on_connect / on_message / on_disconnect / on_stop
#
# ─── WHAT THIS FILE USED TO DO ──────────────────────────────────────────────
#
# It had one assertion, and the assertion was that execution reached it:
#
#     # Verify no crash — if we get here, the runtime handled Lua callbacks
#     TOTAL=$((TOTAL+1))
#     PASS=$((PASS+1))
#
# The four assertions that measured anything sat behind
#
#     if [ -s "$LOG_FILE" ]; then
#
# and LOG_FILE was `2>` on the CLI, which captures the CLI's stderr.
# socketley.log() writes to the DAEMON's stderr — a different process — so that
# file was zero bytes on every run and the block never executed.  Measured on
# the current build: CLI stderr 0 bytes, daemon log five [lua] lines.
#
# The result was "Lua callbacks 1/1 OK", for years, for a file that would have
# reported exactly the same against a build with the Lua callback machinery
# deleted.  A green suite is worth what its weakest file measures.
#
# 3ffde3c gave every test in this directory a daemon of its own, and with it
# $SOCKETLEY_DLOG — that daemon's stdout and stderr, the [lua] lines included.
# The assertions read it now, and the gate is gone: a missing log is a failure,
# not a reason to skip.
#
# The patterns name the runtime — `[lua luasvr]`, not `[lua]` — because the
# prefix carries it now, and matching on it is worth more than tolerating it: a
# daemon serving several scripts writes all of their lines to this one file, so
# `CB:on_start` alone is satisfied by any of them.
#
# ─── WHAT THE ASSERTIONS ASSERT ─────────────────────────────────────────────
#
# Each one names a callback and a claim about its argument, because "the
# callback ran" is the weaker half of what matters and the half a typo in the
# handler still satisfies:
#
#   on_start       fired
#   on_connect     fired with a connection id, not with nil
#   on_message     fired with the exact payload the client sent
#   on_disconnect  fired with a connection id
#   the two ids    are the same id — the disconnect names the connection that
#                  connected, which no "did it fire" check can see
#   on_stop        fired
#
# Every one has been watched to fail on its own; the commit message has the
# runs.  An assertion nobody has seen go red is not evidence, and this file is
# the proof of that.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate luacb
# One base, so this file can be driven on a private port block while a change to
# it is being verified.  The default is the port it has always used.
PORT=$((SL_PORT_BASE+400))
PASS=0; FAIL=0; TOTAL=0
LUA_SCRIPT="/tmp/test-callbacks-$$.lua"

# SOCKETLEY_LUA_SCRIPT lets the breakage proofs swap in a script with one
# callback removed, mistyped or lying about its argument, and watch a single
# assertion go red.  Unset in a normal run, which is every run but those.
LUA_SCRIPT="${SOCKETLEY_LUA_SCRIPT:-$LUA_SCRIPT}"
SERVER_MODE="${SOCKETLEY_SERVER_MODE:-inout}"

cleanup() {
    "$BIN" stop luasvr 2>/dev/null || true
    sleep 0.5
    "$BIN" remove luasvr 2>/dev/null || true
    [ -n "${SOCKETLEY_LUA_SCRIPT:-}" ] || rm -f "$LUA_SCRIPT"
    daemon_stop
}
trap cleanup EXIT

# assert_log LABEL EGREP_PATTERN [TIMEOUT_S]
#
# The daemon writes its [lua] lines whenever the event loop gets to them, so
# this waits for the line rather than sleeping a guess and then looking.  It
# returns the moment the line appears, and only a callback that genuinely never
# fires costs the full timeout.
assert_log() {
    local label=$1 pattern=$2 timeout=${3:-8}
    TOTAL=$((TOTAL+1))
    local deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        if grep -qE "$pattern" "$SOCKETLEY_DLOG" 2>/dev/null; then
            PASS=$((PASS+1))
            return 0
        fi
        sleep 0.05
    done
    FAIL=$((FAIL+1))
    echo "  FAIL: $label"
    echo "        no daemon log line matching /$pattern/"
    return 0
}

assert_eq() {
    local label=$1 want=$2 got=$3
    TOTAL=$((TOTAL+1))
    if [ "$got" = "$want" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: $label (got '$got', expected '$want')"
    fi
}

echo "=== Integration: Lua callbacks ==="

if [ -z "${SOCKETLEY_LUA_SCRIPT:-}" ]; then
cat > "$LUA_SCRIPT" << 'LUAEOF'
function on_start()
    socketley.log("CB:on_start")
end

function on_message(msg)
    socketley.log("CB:on_message:" .. msg)
end

function on_connect(id)
    socketley.log("CB:on_connect:" .. tostring(id))
end

function on_disconnect(id)
    socketley.log("CB:on_disconnect:" .. tostring(id))
end

function on_stop()
    socketley.log("CB:on_stop")
end
LUAEOF
fi

daemon_start "$BIN"

create_ok "server with the callback script created" "$BIN" create server luasvr \
    -p "$PORT" --mode "$SERVER_MODE" --lua "$LUA_SCRIPT" -s
ready_tcp 127.0.0.1 "$PORT" 8 || echo "  NOTE: listener never accepted a connection"

# on_start runs as the runtime comes up, before anything connects.
assert_log "on_start fired when the runtime started" '\[lua luasvr\] CB:on_start$'

# One connection, one message, then a clean close — the three remaining
# callbacks in the order the runtime must produce them.
echo "hello-from-test" | nc -q 1 127.0.0.1 "$PORT" 2>/dev/null || true

assert_log "on_connect fired with a connection id" '\[lua luasvr\] CB:on_connect:[0-9]+$'
assert_log "on_message fired with the payload the client sent" \
           '\[lua luasvr\] CB:on_message:hello-from-test$'
assert_log "on_disconnect fired with a connection id" '\[lua luasvr\] CB:on_disconnect:[0-9]+$'

# The argument, not just the arrival.  A handler invoked with the wrong id — or
# with a fresh one — satisfies both patterns above and fails here.
#
# The `|| true` is load-bearing under `set -euo pipefail`: grep exits 1 when it
# matches nothing, which is precisely the case where the assertion below has
# something to say, and without it the run dies here and never prints a result
# line.  Found by deleting on_connect from the script and watching this file
# stop mid-run instead of reporting 5/7.
CONN_ID=$(grep -oE 'CB:on_connect:[0-9]+' "$SOCKETLEY_DLOG" 2>/dev/null | head -1 | cut -d: -f3 || true)
DISC_ID=$(grep -oE 'CB:on_disconnect:[0-9]+' "$SOCKETLEY_DLOG" 2>/dev/null | head -1 | cut -d: -f3 || true)
# ...and NOT with assert_eq alone.  The `|| true` above that keeps the run
# alive is exactly what makes both variables empty when neither callback fired,
# and `assert_eq "" ""` is green — so the one assertion in this file that
# compares two ids passed hardest against the build that produced no ids at all.
# The emptiness has to be its own failure, named, before the comparison means
# anything: an identity assertion is satisfied by a no-op unless something says
# the operands exist.
TOTAL=$((TOTAL+1))
if [ -n "$CONN_ID" ] && [ -n "$DISC_ID" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: there are two ids to compare"
    echo "        on_connect gave '${CONN_ID:-<none>}', on_disconnect '${DISC_ID:-<none>}'"
    echo "        — with neither, the identity check below compares '' with ''"
fi
assert_eq "on_disconnect names the connection that connected" "$CONN_ID" "$DISC_ID"

"$BIN" stop luasvr 2>&1 || true
assert_log "on_stop fired when the runtime stopped" '\[lua luasvr\] CB:on_stop$'

# The claim the old single assertion was reaching for, made into one that can
# fail: the daemon that ran all of that is still alive.  A Lua callback that
# takes the daemon down with it fails here instead of being reported as a pass
# by a script that merely got to the next line.
TOTAL=$((TOTAL+1))
if kill -0 "$SOCKETLEY_DPID" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: the daemon did not survive the callbacks"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
