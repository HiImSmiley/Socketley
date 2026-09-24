#!/usr/bin/env bash
# Integration test: a dump that does not fit on the disk fails as an error, and
# does not end the worker with SIGBUS.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# save_v2() sized its temp file with ftruncate -- a sparse file -- and wrote
# the dump into a shared mapping of it.  A store into a page the filesystem has
# no block for raises SIGBUS, not ENOSPC, so a full disk killed the worker in
# the middle of a stop instead of producing "could not write the dump", and
# left a sparse .tmp behind.  The blocks are now reserved with fallocate
# first, which answers ENOSPC like any other write.
#
# ─── HOW ────────────────────────────────────────────────────────────────────
#
# A full disk is a 1 MiB tmpfs in a private mount namespace, entered with
# `unshare -rm` so no privilege is needed; the daemon runs inside it and the
# cache holds 2 MiB, so the dump cannot fit.  The control is the same cache
# with a dump path on the ordinary /tmp, which must be written.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)

if [ -z "${SL_IN_NS:-}" ]; then
    unshare -rm true 2>/dev/null || { echo "  FAIL: unshare -rm is not permitted here"; exit 1; }
    exec env SL_IN_NS=1 BIN="$BIN" unshare -rm bash "$0" "$@"
fi

. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate dumpfull

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
         local l; for l in "${@:3}"; do echo "        $l"; done; }
FULL="$SOCKETLEY_TMPD/full"
cleanup() { daemon_stop; umount "$FULL" 2>/dev/null; }
trap cleanup EXIT

echo "=== Integration: a dump that does not fit fails, it does not crash ==="
command -v redis-cli >/dev/null 2>&1 || { echo "  FAIL: redis-cli required"; exit 1; }
mkdir -p "$FULL" && mount -t tmpfs -o size=1m tmpfs "$FULL" || { echo "  FAIL: could not mount a small tmpfs"; exit 1; }

daemon_start "$BIN"
P=$((SL_PORT_BASE + 1880))
fill() {
    local port=$1
    for _ in $(seq 1 100); do redis-cli -p "$port" ping 2>/dev/null | grep -q PONG && break; sleep 0.1; done
    head -c 65536 /dev/zero | tr '\0' v > "$SOCKETLEY_TMPD/v"
    for i in $(seq 1 32); do redis-cli -p "$port" -x set "k$i" < "$SOCKETLEY_TMPD/v" >/dev/null 2>&1; done
}

"$BIN" create cache dfull -p "$P" --persistent "$FULL/d.rdb" -s >/dev/null 2>&1
"$BIN" create cache dok -p $((P + 1)) --persistent "$SOCKETLEY_TMPD/ok.rdb" -s >/dev/null 2>&1
fill "$P"; fill $((P + 1))

"$BIN" stop dfull >/dev/null 2>&1
"$BIN" stop dok >/dev/null 2>&1
for _ in $(seq 1 50); do [ -s "$SOCKETLEY_TMPD/ok.rdb" ] && break; sleep 0.1; done
sleep 1

if grep -q 'signal 7' "$SOCKETLEY_DLOG"; then
    fail "the worker was not killed by SIGBUS" "$(grep 'signal 7' "$SOCKETLEY_DLOG" | head -1)"
else pass "the worker was not killed by SIGBUS"; fi

if grep -q 'could not write the dump' "$SOCKETLEY_DLOG"; then pass "the failed dump is reported"
else fail "the failed dump is reported" "no 'could not write the dump' in the daemon log"; fi

LEFT=$(ls "$FULL" 2>/dev/null | grep -c tmp)
if [ "$LEFT" = 0 ]; then pass "no half-written temp file is left behind"
else fail "no temp file left" "$(ls -la "$FULL")"; fi

if [ -s "$SOCKETLEY_TMPD/ok.rdb" ]; then pass "the same dump where there is room is written"
else fail "the control dump" "nothing at $SOCKETLEY_TMPD/ok.rdb"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
