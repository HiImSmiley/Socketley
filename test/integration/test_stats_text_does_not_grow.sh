#!/usr/bin/env bash
# Integration test: a runtime's `stats` text does not grow on its own.
#
# runtime_instance::publish_offthread_stats() stored get_stats() into
# m_stat_detail on every health tick, and get_stats() for a worker-backed
# runtime is
#
#     stats_prefix() + stat_detail_snapshot()
#
# where stat_detail_snapshot() is m_stat_detail. So each tick prepended a whole
# prefix block to the text it had last time.
#
# While a worker is pushing, set_worker_stats() overwrites the string and
# nothing shows. Once it stops -- the runtime is stopped, or its supervisors
# have gone -- nothing does. Measured, with the metrics endpoint on and the
# runtime stopped:
#
#     t=0    235 bytes
#     t=12   865 bytes
#     t=24  1495 bytes,  thirteen "name:" blocks stacked on each other
#
# Unbounded memory, and `socketley stats NAME` printing the same runtime over
# and over. It only happens once something has asked for metrics, because
# publishing is off until then and one-way once on.
#
# The fix is that publish_offthread_stats() does nothing for a worker-backed
# runtime: both the figures it refreshes belong to the worker, and neither is
# true of the placeholder -- get_connection_count() walks containers that are
# empty there.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate statsgrow

# SOCKETLEY_CONFIG is the daemon's config path as well as run_all.sh's choice
# of build; see test_metrics_endpoint.sh for the full account. Without this
# unset the endpoint never opens, publishing is never enabled, and the growth
# this file is about cannot happen -- the test would pass on a broken tree.
unset SOCKETLEY_CONFIG

MPORT=$((SL_PORT_BASE+1950))
P=$((SL_PORT_BASE+1952))
NAMES="sg_one"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

cleanup() {
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: the stats text does not grow on its own ==="

mkdir -p "$HOME/.config/socketley"
cat > "$HOME/.config/socketley/config.lua" <<LUA
config = {
    metrics_port = $MPORT
}
LUA
daemon_start "$BIN"

size()   { "$BIN" stats "$1" 2>/dev/null | wc -c; }
blocks() { "$BIN" stats "$1" 2>/dev/null | grep -c '^name:' || true; }

create_ok "a runtime" "$BIN" create server sg_one -p "$P" -s
ready_tcp 127.0.0.1 "$P" >/dev/null 2>&1 || true

# Publishing is off until something asks, and one-way once on, so a single
# scrape is what arms the loop this file is about. Without it nothing ticks and
# the assertions below are vacuous.
SCRAPE=$(printf 'GET /api/runtimes HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' \
         | timeout 8 nc 127.0.0.1 "$MPORT" 2>/dev/null | head -1)
case "$SCRAPE" in *"200 OK"*) ok ;;
    *) bad "the metrics endpoint is up, so publishing is on" \
           "the scrape said '${SCRAPE:-<nothing>}' -- without it this file measures nothing" ;;
esac

# ─── 1. While it is running ─────────────────────────────────────────────────
# The worker's own push overwrites the string here, so this was already stable
# and is the control.
#
# Waited for, not slept at: until the worker's first stats frame lands the text
# is the placeholder's short "worker_report:none" form, and measuring there
# reads the report ARRIVING as growth -- 141 bytes then 251, on a tree with and
# without the fix alike.
for _ in $(seq 1 60); do
    "$BIN" stats sg_one 2>/dev/null | grep -q "worker_report:none" || break
    sleep 0.25
done
if "$BIN" stats sg_one 2>/dev/null | grep -q "worker_report:none"; then
    bad "the worker reported its stats" \
        "still worker_report:none after 15s -- nothing below measures growth"
else
    ok
fi

RUN_A=$(size sg_one)
sleep 12
RUN_B=$(size sg_one)
check "a running runtime's stats text is the same size 12s later" "$RUN_A" "$RUN_B"

# ─── 2. And when it is stopped ──────────────────────────────────────────────
# Nothing pushes any more, so nothing overwrites what the tick wrote.
"$BIN" stop sg_one >/dev/null 2>&1 || true
sleep 1
STOP_A=$(size sg_one)
sleep 12
STOP_B=$(size sg_one)
sleep 12
STOP_C=$(size sg_one)

check "a stopped runtime's text is the same size after 12s" "$STOP_A" "$STOP_B"
check "and after 24s"                                       "$STOP_A" "$STOP_C"

# The size is the symptom; this is the thing itself. One runtime, one block.
check "and it is still one runtime's worth of text" "1" "$(blocks sg_one)"

# ─── 3. It is still a real report ───────────────────────────────────────────
# Not growing is easy to get by publishing nothing at all, so the text has to
# still say what it is.
OUT=$("$BIN" stats sg_one 2>/dev/null)
case "$OUT" in *"name:sg_one"*) ok ;;
    *) bad "the text still names the runtime" "got '$(printf '%s' "$OUT" | head -1)'" ;; esac
case "$OUT" in *"port:$P"*) ok ;;
    *) bad "and still carries its port" "got '$(printf '%s' "$OUT" | grep '^port:')'" ;; esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
