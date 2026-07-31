#!/usr/bin/env bash
# Create, serve and remove a runtime, sixty times over, watching for what stays.
#
# Was scratchpad/gy_fix.sh ("gy" for graveyard).  Each cycle creates a proxy,
# drives real traffic through it, and removes it.  A runtime that is removed
# while io_uring still owes it completions cannot be freed immediately — the
# daemon parks it — and a parked runtime that is never collected is a leak of a
# whole instance, descriptors and buffers included.  Sixty cycles is enough for
# a per-cycle leak to be unmistakable and short enough to run nightly.
#
# COVERS:      create -> serve -> remove of proxy runtimes, descriptor and RSS
#              accounting across cycles, the daemon's own warning about retired
#              instances that were never reclaimed.
# DOES NOT:    stop/start (restart_under_load.sh does that), cache or server
#              runtimes (churn_repro.sh covers all three), state persistence.
#
# FAILS WHEN:  the daemon dies, descriptors or RSS grow past the allowance, or
#              the daemon logged a retired-instance warning.  The original
#              printed all three and exited 0 regardless.
#
#   CYCLES=n           create/remove cycles (default 60)
#   FD_GROWTH_MAX=n    tolerated descriptor growth (default 8)
#   RSS_GROWTH_PCT=n   tolerated RSS growth in percent (default 40)

HARNESS_NAME="runtime_churn_leak"
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

require_bin
require_lib httpharness.py

CYCLES="${CYCLES:-60}"
FD_MAX="${FD_GROWTH_MAX:-8}"
RSS_PCT="${RSS_GROWTH_PCT:-40}"
BE="${BE_PORT:-26000}"
PORT_BASE="${PORT_BASE:-26010}"
PORT_SPAN="${PORT_SPAN:-20}"

RUNDIR="$(make_run_dir)"
BPID=""
cleanup() {
    [ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null
    [ -n "$BPID" ] && kill "$BPID" 2>/dev/null
    rm -rf "$RUNDIR"
}
trap cleanup EXIT

echo "=== Runtime create/remove churn — $CYCLES cycles ==="
announce_environment

pin_load python3 "$LIB/httpharness.py" --mode backend --port "$BE" >"$RUNDIR/backend.log" 2>&1 &
BPID=$!
sleep 1
kill -0 "$BPID" 2>/dev/null || nothing_measured "the echo backend did not start on port $BE"

start_daemon "$RUNDIR" || nothing_measured "daemon did not start"

base_rss="$(daemon_rss_kb)"
base_fd="$(daemon_fds)"
[ "$base_fd" -gt 0 ] 2>/dev/null || nothing_measured "could not read the daemon's descriptor count"
echo "  baseline: ${base_rss} kB RSS, $base_fd descriptors"

served=0
completed=0
for r in $(seq 1 "$CYCLES"); do
    P=$((PORT_BASE + r % PORT_SPAN))
    "$BIN" create proxy "gy$r" -p "$P" --backend "127.0.0.1:$BE" --protocol http -s >/dev/null 2>&1
    if pin_load python3 "$LIB/httpharness.py" --mode drive --port "$P" --prefix "/gy$r" \
            --clients 4 --count 8 >/dev/null 2>&1; then
        served=$((served + 1))
    fi
    "$BIN" remove "gy$r" >/dev/null 2>&1
    completed=$((completed + 1))

    if ! daemon_alive; then
        fail "the daemon died in cycle $r of $CYCLES (create/serve/remove churn)"
    fi

    if [ $((r % 20)) -eq 0 ]; then
        echo "  after $r cycles: $(daemon_rss_kb) kB RSS, $(daemon_fds) descriptors, $served served"
    fi
done

sleep 2
end_rss="$(daemon_rss_kb)"
end_fd="$(daemon_fds)"
echo "  end: ${end_rss} kB RSS, $end_fd descriptors"

[ "$completed" -eq "$CYCLES" ] || nothing_measured "only $completed of $CYCLES cycles ran"

# A run where nothing was ever served proves nothing about leaks: creating and
# removing a runtime that never accepted a connection does not exercise the
# path this harness is about.
if [ "$served" -eq 0 ]; then
    nothing_measured "not one cycle served traffic — the churn ran but nothing was exercised"
fi
if [ "$served" -lt $((CYCLES / 2)) ]; then
    fail "only $served of $completed cycles served traffic — the proxy is failing to come up, not leaking"
fi

# The daemon says so itself when a retired instance was never reclaimed.
retired=$(tr -d '\0' < "$RUNDIR/daemon.log" 2>/dev/null | grep -ac 'retired runtime instances' || true)
[ -z "$retired" ] && retired=0

fd_growth=$((end_fd - base_fd))
if [ "$fd_growth" -gt "$FD_MAX" ]; then
    fail "descriptors grew by $fd_growth over $completed cycles (allowance $FD_MAX): $base_fd -> $end_fd"
fi

if [ "$base_rss" -gt 0 ]; then
    rss_growth=$(( (end_rss - base_rss) * 100 / base_rss ))
    if [ "$rss_growth" -gt "$RSS_PCT" ]; then
        fail "RSS grew by ${rss_growth}% over $completed cycles (allowance ${RSS_PCT}%): ${base_rss} -> ${end_rss} kB"
    fi
else
    rss_growth="?"
fi

if [ "$retired" -gt 0 ]; then
    fail "the daemon logged $retired warning(s) about retired runtime instances it could not reclaim"
fi

daemon_alive || fail "the daemon died after the cycles completed"
pass "$completed cycles ($served served), descriptors +$fd_growth, RSS +${rss_growth}%, no retired-instance warnings"
