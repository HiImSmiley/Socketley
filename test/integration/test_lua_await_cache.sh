#!/usr/bin/env bash
# A handler that cannot answer from what it holds.
#
# Before this, every Lua callback ran to the end in one go, so a script could
# only answer out of its own arguments: a server had no way to read the cache it
# was linked to at all, and the one call that reaches outside -- socketley.http
# -- does it by blocking the event loop for every runtime in the daemon.
#
# What is checked here is the whole of that in three parts: that the answer
# arrives, that the connection waiting for it is still there when it does, and
# that a handler whose answer never comes is given up on rather than left
# stopped for ever.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate luaawait
CACHE_PORT=$((SL_PORT_BASE+310))
SRV_PORT=$((SL_PORT_BASE+311))
BARE_PORT=$((SL_PORT_BASE+312))
PASS=0; FAIL=0; TOTAL=0

FROZEN=""
cleanup() {
    # Before the stops: a stopped worker cannot be resumed, and a run that left
    # one SIGSTOPped would leave a process nothing reaps.
    [ -n "$FROZEN" ] && kill -CONT "$FROZEN" 2>/dev/null; true
    for r in awsrv awbare awcache; do
        "$BIN" stop "$r"   >/dev/null 2>&1 || true
    done
    sleep 0.3
    for r in awsrv awbare awcache; do
        "$BIN" remove "$r" >/dev/null 2>&1 || true
    done
    daemon_stop
}
trap cleanup EXIT

assert_eq() {
    TOTAL=$((TOTAL+1))
    local got="$1" expected="$2" label="$3"
    if [ "$got" = "$expected" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: got '$got', expected '$expected'"
    fi
}

assert_contains() {
    TOTAL=$((TOTAL+1))
    local got="$1" needle="$2" label="$3"
    case "$got" in
        *"$needle"*) PASS=$((PASS+1)) ;;
        *) FAIL=$((FAIL+1)); echo "  FAIL [$label]: '$got' does not contain '$needle'" ;;
    esac
}

echo "=== Integration: a Lua handler that waits for the linked cache ==="

SCRIPT="$SOCKETLEY_TMPD/await.lua"
cat > "$SCRIPT" <<'LUA'
function on_client_message(id, msg)
    local v, err = self.cache("get " .. msg)
    if v then
        self.send(id, "v=" .. v)
    else
        self.send(id, "err=" .. tostring(err))
    end
end
LUA

daemon_start "$BIN"

create_ok "cache created" "$BIN" create cache awcache -p "$CACHE_PORT" -s
sleep 0.5

# Noted before the server exists, so the set that follows cannot be confused
# with one the server made.
echo "set k1 hello" | nc -q1 127.0.0.1 "$CACHE_PORT" >/dev/null 2>&1

create_ok "server created" "$BIN" create server awsrv -p "$SRV_PORT" \
    --cache awcache --lua "$SCRIPT" -s
sleep 1

# ─── The capability ─────────────────────────────────────────────────────────
# The peer sends one line and half-closes at once, which is what every
# `echo | nc` does and the case that fails if nothing holds the connection open
# while the handler is stopped: by the time the answer exists, the FIN has
# already been read and the connection marked closing.
got=$(echo "k1" | nc -q3 127.0.0.1 "$SRV_PORT" 2>/dev/null | tr -d '\r')
assert_eq "$got" "v=hello" "a handler answered with what the linked cache said"

# Three on one connection, because one invocation per connection would pass
# with an id space that only ever holds one entry.
echo "set k2 second" | nc -q1 127.0.0.1 "$CACHE_PORT" >/dev/null 2>&1
echo "set k3 third"  | nc -q1 127.0.0.1 "$CACHE_PORT" >/dev/null 2>&1
got=$(printf 'k1\nk2\nk3\n' | nc -q3 127.0.0.1 "$SRV_PORT" 2>/dev/null | tr -d '\r' | tr '\n' ' ')
assert_eq "$got" "v=hello v=second v=third " "three awaits on one connection, answered in order"

# ─── A runtime with nothing to ask ──────────────────────────────────────────
# Refused inline and named, rather than raised or silently nil: a script that
# calls this on a server with no --cache has made a mistake worth reading.
create_ok "bare server created" "$BIN" create server awbare -p "$BARE_PORT" \
    --lua "$SCRIPT" -s
sleep 1
got=$(echo "k1" | nc -q3 127.0.0.1 "$BARE_PORT" 2>/dev/null | tr -d '\r')
assert_contains "$got" "no cache is linked" "a server with no cache says so instead of waiting"

# ─── The bound ──────────────────────────────────────────────────────────────
# A cache that ACCEPTS and never answers, which is the shape a deadline exists
# for -- a clean crash answers by itself.  The request is written into the
# worker's socket and parked against a ticket nothing will ever complete, so
# without a deadline the handler is stopped for the life of the runtime and the
# connection it is answering is held open with it.
FROZEN=""
for p in $(pgrep -x socketley); do
    grep -qz "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" /proc/"$p"/environ 2>/dev/null || continue
    case "$(tr '\0' ' ' < /proc/"$p"/cmdline)" in
        *proxy-worker*) FROZEN=$p ;;
    esac
done
if [ -z "$FROZEN" ]; then
    echo "  FAIL [setup]: no worker of this run was found to freeze"
    FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1))
else
    # The cache is the first worker this run forked and the loop above keeps the
    # last, so the order is not the answer: `stats` names the process a runtime
    # is, which is the only thing that cannot pick the wrong worker.
    CACHE_PID=$("$BIN" stats awcache 2>/dev/null | grep -oP '^pid:\K[0-9]+' | head -1)
    [ -n "$CACHE_PID" ] && FROZEN=$CACHE_PID
    kill -STOP "$FROZEN" 2>/dev/null || true

    # Timed on when the ANSWER lands and not on when the reader gives up.  The
    # obvious form, `nc -q20`, reports its own linger: the first draft of this
    # block read 30 seconds for an answer that had arrived at ten, because -q
    # keeps reading for twenty after stdin ends whatever the peer does.
    outf="$SOCKETLEY_TMPD/deadline.out"
    : > "$outf"
    # Not wrapped in a subshell: $! would then name the subshell, and killing
    # that leaves nc running -- measured, a counter-proof run read a `v=hello`
    # the abandoned reader collected after the cache was let go again.
    { echo "k1"; sleep 30; } | timeout 35 nc 127.0.0.1 "$SRV_PORT" > "$outf" 2>/dev/null &
    ncpid=$!
    start=$(date +%s)
    waited=99
    for _ in $(seq 1 150); do
        if [ -s "$outf" ]; then waited=$(( $(date +%s) - start )); break; fi
        sleep 0.2
    done
    kill "$ncpid" 2>/dev/null || true
    wait "$ncpid" 2>/dev/null || true
    kill -CONT "$FROZEN" 2>/dev/null || true
    FROZEN=""
    got=$(tr -d '\r' < "$outf")

    assert_contains "$got" "err=" "a handler whose answer never came is told so"
    # The window, not the exact number: the sweep ticks at a second and the
    # budget is ten, so anything inside twenty is the deadline firing and
    # anything past it is the handler still stopped.
    TOTAL=$((TOTAL+1))
    if [ "$waited" -lt 20 ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [deadline]: the answer had not arrived after ${waited}s"
    fi
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
