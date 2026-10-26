#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Integration test: a proxy with more backends than the old fixed-size buffer held.
#
# Random selection over healthy backends collected the available indices into a
# 256-entry array on the stack, filled by a loop bounded only by the number of
# configured backends.  Nothing capped that number, so backend 257 wrote past
# the end of the frame; the stack protector catches it and aborts the process.
#
# This test runs its own daemon on its own socket and state directory.  That is
# not tidiness: against a build with the defect the daemon dies, and if that
# were the shared one it would take every later test in the suite with it.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# shellcheck source=lib_create.sh
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

PROXY_PORT=$((SL_PORT_BASE+286))
SINK_PORT=$((SL_PORT_BASE+287))
BACKENDS=300
PASS=0; FAIL=0; TOTAL=0

TMPDIR_T=$(mktemp -d /tmp/socketley-manybe-XXXXXX)
export HOME="$TMPDIR_T/home"
export SOCKETLEY_SOCKET="$TMPDIR_T/daemon.sock"
. "$(dirname "$0")/lib_daemon.sh"
daemon_watch "$TMPDIR_T"   # its processes go with it if it is killed
mkdir -p "$HOME"
DPID=""
NC_PID=""

cleanup() {
    [ -n "$NC_PID" ] && kill "$NC_PID" 2>/dev/null || true
    [ -n "$DPID" ] && kill "$DPID" 2>/dev/null || true
    rm -rf "$TMPDIR_T"
}
trap cleanup EXIT

echo "=== Integration: proxy with $BACKENDS backends ==="

SOCKETLEY_DLOG="$TMPDIR_T/daemon.log"
"$BIN" daemon >"$TMPDIR_T/daemon.log" 2>&1 &
DPID=$!
sleep 2

# One reachable sink so a backend is usable; the rest are dead ends.
timeout 25 nc -lk 127.0.0.1 "$SINK_PORT" >/dev/null 2>&1 &
NC_PID=$!
sleep 0.3

BE="127.0.0.1:$SINK_PORT"
for i in $(seq 1 $((BACKENDS-1))); do
    BE="$BE,127.0.0.1:$((SL_PORT_BASE+1000+i))"
done

create_ok "proxy with $BACKENDS backends created" \
    "$BIN" create proxy manybe -p "$PROXY_PORT" --backend "$BE" \
    --protocol tcp --strategy random --health-check tcp --health-interval 1 -s
sleep 2

TOTAL=$((TOTAL+1))
if grep -q "^backends:$BACKENDS$" < <("$BIN" stats manybe 2>/dev/null); then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: proxy does not report $BACKENDS backends"
fi

# The proxy runs in a worker of its own, which is what a smashed stack kills -- and the daemon starts it again under
# a new pid -- so the worker is the one watched, and it has to be the same process after the probes.
PXPID=$("$BIN" stats manybe 2>/dev/null | sed -n 's/^pid://p')

# Every connection runs backend selection, which is where the overflow happened.
for i in 1 2 3 4 5; do
    printf 'probe\n' | timeout 2 nc -q 1 127.0.0.1 "$PROXY_PORT" >/dev/null 2>&1 || true
done
sleep 0.5

TOTAL=$((TOTAL+1))
NOWPID=$("$BIN" stats manybe 2>/dev/null | sed -n 's/^pid://p')
if [ -n "$PXPID" ] && kill -0 "$PXPID" 2>/dev/null && [ "$NOWPID" = "$PXPID" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [the proxy's worker survived backend selection]: pid ${PXPID:-<none>} before, ${NOWPID:-<none>} after"
    grep -E "stack smashing|AddressSanitizer|Segmentation|signal" "$TMPDIR_T/daemon.log" 2>/dev/null | head -3
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
