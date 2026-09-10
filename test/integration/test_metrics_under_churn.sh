#!/usr/bin/env bash
# Integration test: the metrics endpoint keeps answering while runtimes churn,
# and the daemon does not stall doing it.
#
# ─── WHAT THIS IS FOR, SAID HONESTLY ────────────────────────────────────────
#
# It is NOT a reproduction of the defect that prompted it.
#
# The defect is a lock discipline: reconcile_proxy_workers() calls
# shard_stats_table().close() -- a munmap -- holding no lock at all, while the
# metrics thread reads that same region in worker_figures() -> sum() holding a
# SHARED lock on runtime_manager::mutex. Two shared holders exclude nothing,
# and sum() null-checks the mapping once and then loads from it N times, so an
# unmap landing in between is a SIGSEGV in the daemon on a thread that was only
# being asked for a number.
#
# That is plain on the page. It is also, measured, extremely hard to hit: with
# the fix removed and this file's churn cranked up -- two runtimes at 16 shards,
# six concurrent scrapers, forty stop/start rounds -- the daemon survived every
# attempt. sum() over a handful of shards is a few dozen atomic loads and the
# window is that wide. So there is no red-with-the-defect measurement here, and
# claiming one would be a lie.
#
# What this file DOES guard is the risk the fix introduces. The fix takes the
# manager's mutex EXCLUSIVELY on the event-loop thread, which is the thread
# that must never block: if that lock could be held against it, or if it
# deadlocked with the metrics thread, the symptom would be a daemon that stops
# answering under exactly this load. So the assertions are:
#
#   - the endpoint answers before, during and after heavy churn
#   - every runtime comes back up
#   - the daemon is still there, and still prompt
#
# A test for the danger you added is worth more than a test for the danger you
# removed, when only one of the two can be measured.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

# SOCKETLEY_CONFIG is the daemon's CONFIG PATH as well as run_all.sh's choice
# of build, so a `SOCKETLEY_CONFIG=Sanitize` run leaves every daemon looking for
# a config file called "Sanitize", finding none, and never reading metrics_port
# -- and this whole file then measures an endpoint that was never opened.
# test_metrics_endpoint.sh carries the full account of it and the same unset;
# measured here, 8/8 without the variable and 5/8 with it.  run_all.sh has
# already resolved it into BIN by now, so nothing downstream needs it.
unset SOCKETLEY_CONFIG

MPORT=$((SL_PORT_BASE+1860))
P=$((SL_PORT_BASE+1862))
RUNTIMES="mc_a mc_b"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

SCRAPERS=""
cleanup() {
    for p in $SCRAPERS; do { kill -9 "$p"; wait "$p"; } 2>/dev/null; done
    for r in $RUNTIMES; do
        "$BIN" stop "$r"   >/dev/null 2>&1 || true
        "$BIN" remove "$r" >/dev/null 2>&1 || true
    done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: metrics keep answering while runtimes churn ==="

daemon_isolate metricschurn
# Written before the daemon starts: the port is read once, at startup.
mkdir -p "$HOME/.config/socketley"
cat > "$HOME/.config/socketley/config.lua" <<LUA
config = {
    metrics_port = $MPORT
}
LUA
daemon_start "$BIN"

scrape() {   # -> the status line, or empty
    printf 'GET /api/runtimes HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' \
        | timeout 8 nc 127.0.0.1 "$MPORT" 2>/dev/null | head -1
}

# Sharded, because a shard-stats region is what the daemon maps as a reader and
# unmaps when the runtime goes -- an unsharded runtime has nothing to race over.
for r in $RUNTIMES; do
    "$BIN" create server "$r" -p $((P += 1)) --shards 4 -s >/dev/null 2>&1
done
sleep 2

BEFORE=$(scrape)
if [[ "$BEFORE" == *"200 OK"* ]]; then ok; else
    bad "the endpoint answers before the churn" "got '${BEFORE:-<nothing>}'"; fi

# Four readers in their own processes, so the metrics thread is genuinely busy
# rather than being asked once between rounds.
for _ in 1 2 3 4; do
    ( while :; do
        printf 'GET /api/runtimes HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' \
            | timeout 3 nc 127.0.0.1 "$MPORT" >/dev/null 2>&1
      done ) & SCRAPERS="$SCRAPERS $!"
done

# The writer: stop and start is what retires the regions and unmaps them.
CHURN_FAIL=0
for _ in $(seq 1 15); do
    for r in $RUNTIMES; do "$BIN" stop  "$r" >/dev/null 2>&1 || CHURN_FAIL=$((CHURN_FAIL+1)); done
    for r in $RUNTIMES; do "$BIN" start "$r" >/dev/null 2>&1 || CHURN_FAIL=$((CHURN_FAIL+1)); done
done
check_mid=$(scrape)
if [[ "$check_mid" == *"200 OK"* ]]; then ok; else
    bad "the endpoint answers during the churn" "got '${check_mid:-<nothing>}'"; fi

for p in $SCRAPERS; do { kill -9 "$p"; wait "$p"; } 2>/dev/null; done
SCRAPERS=""

if [ "$CHURN_FAIL" -eq 0 ]; then ok; else
    bad "every stop and start was accepted" "$CHURN_FAIL of 60 were refused"; fi

# The event-loop thread now takes the manager's mutex exclusively while it
# unmaps a retired region.  A daemon that had deadlocked or was being starved
# by four readers would fail here and nowhere else.
if kill -0 "$SOCKETLEY_DPID" 2>/dev/null; then ok; else
    bad "the daemon is still running" "it is gone after the churn"; fi

AFTER=$(scrape)
if [[ "$AFTER" == *"200 OK"* ]]; then ok; else
    bad "the endpoint answers after the churn" "got '${AFTER:-<nothing>}'"; fi

# And promptly: a command over the control socket is answered by the same
# thread that takes that lock, so a stall shows up here as a timeout.
if timeout 5 "$BIN" ping >/dev/null 2>&1; then ok; else
    bad "the daemon still answers its own socket promptly" \
        "ping did not come back within 5s"; fi

UP=$("$BIN" ps -a 2>/dev/null | awk -v n="$(echo $RUNTIMES | wc -w)" \
     '$7=="Up" {c++} END {print c+0}')
if [ "$UP" -eq 2 ]; then ok; else
    bad "both runtimes came back up" "ps reports $UP of 2 Up"; fi

# Nothing in the log from a sanitizer or a fault, which is where a
# use-after-munmap would land if this ever did reproduce one.
if ! grep -qiE "AddressSanitizer|SEGV|SUMMARY: .*Sanitizer" "$SOCKETLEY_DLOG" 2>/dev/null; then
    ok
else
    bad "no fault in the daemon log" \
        "$(grep -iE 'AddressSanitizer|SEGV' "$SOCKETLEY_DLOG" | head -1)"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
