#!/usr/bin/env bash
# A request that reached its target and got no answer.
#
# request_channel promises exactly one reply per request, and kept that promise
# for everything still in its queue: detach() drained the queue and answered it
# `dropped`.  A request that had already been handed to a target parked against
# a ticket instead, and the parked table was bounded and swept only when the
# ORIGIN went -- which is the side still waiting.  So the two ways a target
# stops answering were both unbounded:
#
#   * it goes away         -- drop_sink removed the sink and left the tickets
#   * it takes and wedges  -- nothing ever looked at them again
#
# Measured before the fix, against a cache worker under SIGSTOP: a client's
# `cache get` was never answered at all, and the server held the connection open
# for good because close_conn defers while an answer is owed.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate parked
CACHE_PORT=$((SL_PORT_BASE+315))
SRV_PORT=$((SL_PORT_BASE+316))
QCACHE_PORT=$((SL_PORT_BASE+317))
QSRV_PORT=$((SL_PORT_BASE+318))
PASS=0; FAIL=0; TOTAL=0

FROZEN=""
cleanup() {
    [ -n "$FROZEN" ] && kill -CONT "$FROZEN" 2>/dev/null; true
    for r in psrv pcache qsrv qcache; do "$BIN" stop   "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in psrv pcache qsrv qcache; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

assert_contains() {
    local got="$1" needle="$2" label="$3"
    case "$got" in
        *"$needle"*) pass ;;
        *) fail "$label" "'$got' does not contain '$needle'" ;;
    esac
}

# Send one line and hold the socket open, answering with when the reply landed
# rather than with when the reader gave up -- `nc -q N` reports its own linger,
# which read 30 seconds for an answer that had arrived at ten.
#   ask <port> <line> <max-seconds>  ->  sets ANSWER and WAITED
ask() {
    local port=$1 line=$2 limit=$3
    local outf="$SOCKETLEY_TMPD/ask.$$"
    : > "$outf"
    setsid sh -c '{ echo "$1"; sleep "$2"; } | timeout "$3" nc 127.0.0.1 "$4"' _ "$line" "$limit" $((limit+5)) "$port" > "$outf" 2>/dev/null &
    local pid=$! start now
    start=$(date +%s)
    WAITED=999
    for _ in $(seq 1 $((limit*5))); do
        if [ -s "$outf" ]; then WAITED=$(( $(date +%s) - start )); break; fi
        sleep 0.2
    done
    kill -- "-$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    ANSWER=$(tr -d '\r' < "$outf")
    rm -f "$outf"
}

# The pid of the worker a runtime is.  `stats` names it; the fork order does
# not, and a run with two runtimes has two workers to tell apart.
worker_pid() { "$BIN" stats "$1" 2>/dev/null | grep -oP '^pid:\K[0-9]+' | head -1; }

echo "=== Integration: a request its target never answers ==="

daemon_start "$BIN"

# A pair per case, because the two cases cannot share one.  Measured sharing
# them: the first case leaves its cache frozen for half a minute, the daemon
# gives up on it in the meantime, and the second case's request is then answered
# `no such runtime` without ever parking -- a pass that tested nothing.
create_ok "cache created"  "$BIN" create cache pcache -p "$CACHE_PORT" -s
sleep 1
create_ok "server created" "$BIN" create server psrv -p "$SRV_PORT" --cache pcache -s
create_ok "second cache created"  "$BIN" create cache qcache -p "$QCACHE_PORT" -s
sleep 1
create_ok "second server created" "$BIN" create server qsrv -p "$QSRV_PORT" --cache qcache -s
sleep 1
echo "set foo bar" | nc -q1 127.0.0.1 "$CACHE_PORT"  >/dev/null 2>&1
echo "set foo bar" | nc -q1 127.0.0.1 "$QCACHE_PORT" >/dev/null 2>&1

# The healthy answer first, or everything below could pass on a link that was
# never carrying anything.
ask "$SRV_PORT" "cache get foo" 5
assert_contains "$ANSWER" "bar" "a linked cache answers at all"

# ─── The target goes away while the answer is owed ──────────────────────────
# Known at the moment it happens, so it is answered then rather than thirty
# seconds later.  The runtime is stopped while STILL wedged: letting it run
# first lets it answer normally, which is what the first draft of this block
# measured and reported as a pass.
FROZEN=$(worker_pid qcache || true)
if [ -z "$FROZEN" ]; then
    fail "setup" "the second cache reports no pid"
else
    kill -STOP "$FROZEN" 2>/dev/null || true
    outf="$SOCKETLEY_TMPD/dropped.out"
    : > "$outf"
    setsid sh -c '{ echo "cache get foo"; sleep 40; } | timeout 45 nc 127.0.0.1 "$1"' _ "$QSRV_PORT" > "$outf" 2>/dev/null &
    ncpid=$!
    sleep 2
    start=$(date +%s)
    "$BIN" stop qcache >/dev/null 2>&1 || true
    waited=999
    for _ in $(seq 1 100); do
        if [ -s "$outf" ]; then waited=$(( $(date +%s) - start )); break; fi
        sleep 0.2
    done
    kill -- "-$ncpid" 2>/dev/null || true
    wait "$ncpid" 2>/dev/null || true
    kill -CONT "$FROZEN" 2>/dev/null || true; FROZEN=""
    got=$(tr -d '\r' < "$outf")

    assert_contains "$got" "dropped" "stopping the target answers what was owed"
    # Well inside the deadline, which is what says this came from the stop and
    # not from the sweep that would have caught it anyway.  Not zero: stopping a
    # worker that is wedged costs the stop's own patience before the SIGKILL,
    # measured at seven seconds, and the answer follows the sink being dropped.
    if [ "$waited" -lt 20 ]; then pass
    else fail "immediate" "the answer took ${waited}s, which is the deadline and not the stop"; fi
fi

# ─── The target takes the request and wedges ────────────────────────────────
# SIGSTOP and not SIGKILL: a killed worker is noticed and its sink dropped,
# which is the OTHER case below.  A stopped one stays registered, so the request
# is written into its socket, parked, and nothing is coming.
FROZEN=$(worker_pid pcache || true)
if [ -z "$FROZEN" ]; then
    fail "setup" "the cache reports no pid to freeze"
else
    kill -STOP "$FROZEN" 2>/dev/null || true
    ask "$SRV_PORT" "cache get foo" 50
    kill -CONT "$FROZEN" 2>/dev/null || true; FROZEN=""

    assert_contains "$ANSWER" "dropped" "a wedged target's request is given up on rather than waited out"
    # 30s deadline swept at 5s, so the answer is due by 35 and anything past 45
    # is the old behaviour -- no answer at all.
    if [ "$WAITED" -lt 45 ]; then pass
    else fail "deadline" "the answer had not arrived after ${WAITED}s"; fi

    # The connection slot this frees is deliberately NOT asserted here.  It was,
    # and it passed with the deadline taken out: by the time this read happens
    # the daemon has also given up on the wedged worker, so the count comes back
    # either way and the assertion discriminated nothing.  The leak is real --
    # measured 15s after the client went, with no deadline: connections 1, two
    # descriptors above baseline, one socket in CLOSE-WAIT -- and it belongs in
    # the record rather than in a check that cannot fail.
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
