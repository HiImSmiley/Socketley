#!/usr/bin/env bash
# Integration test: a runtime in a worker asking a runtime it cannot see.
#
# The cross-process channel was built in one direction first — a server in the
# daemon reaching a cache in a worker — and the other direction was not merely
# missing, it was silent.  A runtime asks through its manager, and a worker had
# none, so server_instance::post_cache_request() returned at
# `if (!mgr) return;` before anything was posted.  Nothing was refused and
# nothing was logged: the client sent `cache get k` and waited until its socket
# timed out.
#
# What runs here is the arrangement the daemon becomes once is
# the default, where *every* runtime is on the far side of a socket from every
# other one and the daemon is the only process holding the map.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate wrkask

# The seven runtimes below, WA+0 through WA+6, in creation order.
WA=$((SL_PORT_BASE+1901))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    for r in sin swrk snone sbadin sbadout cdaemon cwrk; do
        "$BIN" stop   "$r" >/dev/null 2>&1
        "$BIN" remove "$r" >/dev/null 2>&1
    done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a worker asks the daemon ==="

if ! command -v nc >/dev/null 2>&1; then
    echo "  SKIP: nc is required to speak to a server"
    exit 0
fi

daemon_start "$BIN"

ask() {            # port, command -> the first line of the answer
    printf '%s\n' "$2" | timeout 5 nc -q1 127.0.0.1 "$1" 2>/dev/null | head -1
}

# ── the control ─────────────────────────────────────────────────────────────
#
# Both in the daemon.  If this stops working the rest of the file is measuring
# something other than the process boundary.
"$BIN" create cache  cdaemon -p $((WA+0)) --resp -s          >/dev/null 2>&1
"$BIN" create server sin     -p $((WA+1)) --cache cdaemon -s >/dev/null 2>&1
sleep 1.5

if [ "$(ask $((WA+1)) 'cache set ctl 1')" = "ok" ] && [ "$(ask $((WA+1)) 'cache get ctl')" = "1" ]; then
    ok
else
    bad "control: a server and a cache both in the daemon" \
        "the in-process path is broken, so nothing below means anything"
fi

# ── out of the daemon, asking into it ───────────────────────────────────────
"$BIN" create server swrk -p $((WA+2)) --cache cdaemon -s >/dev/null 2>&1
sleep 2.5

SPID=$(ss -ltnp 2>/dev/null | awk -v p=":$((WA+2))" '$4 ~ p' | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
if [ -n "$SPID" ] && [ "$SPID" != "${SOCKETLEY_DPID:-}" ]; then ok; else
    bad "the server really is in a process of its own" \
        "port pid='${SPID:-none}' daemon pid='${SOCKETLEY_DPID:-none}'"
fi

SET=$(ask $((WA+2)) 'cache set wd 2')
GOT=$(ask $((WA+2)) 'cache get wd')
if [ "$GOT" = "2" ]; then ok; else
    bad "a server in a worker reaches a cache in the daemon" \
        "set said '$SET', get said '$GOT'" \
        "an empty answer is the old behaviour: the request never left the worker"
fi

# Read on the cache's own port as an inline command, so the check needs no client that may not be installed; a --resp
# cache answers a bulk string, whose value is the second line.
DIRECT=$(python3 -c "
import socket, sys
s = socket.create_connection(('127.0.0.1', int(sys.argv[1])), 5)
s.sendall(b'GET wd\r\n')
f = s.makefile('rb')
head = f.readline().strip()
print(f.readline().strip().decode() if head.startswith(b'\$') and head != b'\$-1' else head.decode())" $((WA+0)) 2>/dev/null)
if [ "$DIRECT" = "2" ]; then
    ok
else
    bad "the write landed in the daemon's cache, not somewhere in the worker" \
        "the cache's own port read '$DIRECT'"
fi

# ── two workers, with the daemon only routing ───────────────────────────────
#
# Neither runtime is in the daemon now.  The request crosses the boundary twice
# in each direction: worker -> daemon -> worker for the question, and back for
# the answer, paired by two ticket namespaces that never meet.
"$BIN" create cache  cwrk -p $((WA+3)) --resp      -s >/dev/null 2>&1
sleep 1.5
"$BIN" create server snone -p $((WA+4)) --cache cwrk -s >/dev/null 2>&1
sleep 2.5

CPID=$(ss -ltnp 2>/dev/null | awk -v p=":$((WA+3))" '$4 ~ p' | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
NPID=$(ss -ltnp 2>/dev/null | awk -v p=":$((WA+4))" '$4 ~ p' | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
if [ -n "$CPID" ] && [ -n "$NPID" ] && [ "$CPID" != "$NPID" ] \
   && [ "$CPID" != "${SOCKETLEY_DPID:-}" ] && [ "$NPID" != "${SOCKETLEY_DPID:-}" ]; then
    ok
else
    bad "three processes: the daemon and one per runtime" \
        "cache='$CPID' server='$NPID' daemon='${SOCKETLEY_DPID:-none}'"
fi

SET2=$(ask $((WA+4)) 'cache set ww 3')
GOT2=$(ask $((WA+4)) 'cache get ww')
if [ "$GOT2" = "3" ]; then ok; else
    bad "a server in one worker reaches a cache in another" \
        "set said '$SET2', get said '$GOT2'"
fi

# ── a name nobody answers to ────────────────────────────────────────────────
#
# The fallback sends every unknown name to the daemon, so a typo now travels a
# socket before it is refused.  What must not happen is that it travels and
# never comes back: the worker's runtime is owed exactly one reply per request
# whatever the answer is.
#
# Timing is not the oracle here and an earlier version of this test wrongly used
# it — `nc -q1` quits a second after its stdin ends whether or not an answer
# arrived, so a hung request and a refused one take the same wall time.  The
# content is what tells them apart: silence was the old behaviour.
"$BIN" create server sbadin  -p $((WA+5)) --cache nosuchcache      -s >/dev/null 2>&1
"$BIN" create server sbadout -p $((WA+6)) --cache nosuchcache -s >/dev/null 2>&1
sleep 2.5

MISS_IN=$(ask $((WA+5)) 'cache get k')
MISS_OUT=$(ask $((WA+6)) 'cache get k')

case "$MISS_IN" in
    error:*) ok ;;
    *)  bad "control: the daemon refuses an unknown cache name out loud" \
            "got '$MISS_IN'" ;;
esac

if [ -n "$MISS_OUT" ] && [ "$MISS_OUT" = "$MISS_IN" ]; then ok; else
    bad "a worker gets the same refusal, not silence" \
        "in-daemon said '$MISS_IN', in-worker said '$MISS_OUT'" \
        "an empty answer means the request was dropped inside the worker"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
