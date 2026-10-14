#!/usr/bin/env bash
# suite: quiet -- counts a worker's wakeups over ten seconds, which a loaded box adds to.
# A cache whose only blocked clients wait for ever does not wake to look at them.
#
# The blocked-pop tick ran ten times a second for as long as anyone was parked, though it can only end a
# deadline or a group reader whose stream went, so a job queue's idle workers, BLPOP key 0 each, kept their
# cache awake for nothing.  Asserted: a waiter with no deadline leaves the worker asleep, one with a deadline
# still has it ended, and the forever waiter is still served by a push.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate blockidle
PORT=$((SL_PORT_BASE + 1650))

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  ok: $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

cleanup() { [ -n "${WAITER:-}" ] && kill "$WAITER" 2>/dev/null; daemon_stop; }
trap cleanup EXIT

echo "=== a cache with only forever-blocked clients stays asleep ==="
daemon_start "$BIN"
"$BIN" create cache bq -p "$PORT" -s >/dev/null 2>&1
for _ in $(seq 50); do redis-cli -p "$PORT" ping >/dev/null 2>&1 && break; sleep 0.1; done

W=$(pgrep -P "$SOCKETLEY_DPID" | head -1)
vctx() { awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }

OUT="$SOCKETLEY_TMPD/waiter.out"
redis-cli -p "$PORT" blpop jobs 0 >"$OUT" 2>&1 &
WAITER=$!
sleep 1

WINDOW=10
C0=$(vctx "$W")
sleep "$WINDOW"
C1=$(vctx "$W")
WAKES=$((C1 - C0))
echo "  worker $W with one BLPOP jobs 0 parked: $WAKES voluntary wakeups in ${WINDOW}s"
# The tick alone was a hundred in this window.
if [ "$WAKES" -le 20 ]; then
    ok "a waiter with no deadline leaves the worker asleep ($WAKES wakeups, bound 20; the 100 ms tick reads 100)"
else
    bad "a waiter with no deadline woke the worker $WAKES times in ${WINDOW}s (bound 20)"
fi

T0=$(date +%s%3N)
TIMED=$(redis-cli -p "$PORT" blpop other 0.5 2>&1)
MS=$(( $(date +%s%3N) - T0 ))
if [ -z "$(echo "$TIMED" | tr -d '[:space:]')" ] || [ "$TIMED" = "(nil)" ]; then
    if [ "$MS" -lt 2000 ]; then ok "a waiter with a deadline is still ended at it (${MS} ms for 500)"
    else bad "a 500 ms BLPOP took ${MS} ms to end"; fi
else
    bad "a BLPOP on an empty list with a deadline answered '$TIMED'"
fi

redis-cli -p "$PORT" rpush jobs one >/dev/null
for _ in $(seq 40); do kill -0 "$WAITER" 2>/dev/null || break; sleep 0.05; done
if grep -q one "$OUT"; then ok "the forever waiter is served by a push"
else bad "the forever waiter got '$(cat "$OUT")' after a push"; fi

echo ""
echo " Summary: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
