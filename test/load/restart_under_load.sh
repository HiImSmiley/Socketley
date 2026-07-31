#!/usr/bin/env bash
# Stop and start a runtime while traffic is in flight, repeatedly.
#
# Was scratchpad/restartload.sh.  Twelve stop/start cycles with an HTTP load
# generator running across each one, then a check that the proxy still serves
# and that the daemon has not accumulated descriptors or memory.
#
# This is the lifecycle stress: a stop that lands between a client read and the
# backend write it was about to become is the moment when io_uring still owes
# completions for structures the stop is tearing down.  Every defect of that
# family shows up here as a dead daemon, a descriptor that is never closed, or a
# proxy that survives but no longer answers.
#
# COVERS:      stop/start of a proxy runtime under concurrent HTTP load,
#              descriptor and RSS accounting across cycles, post-restart service.
# DOES NOT:    create/remove (runtime_churn_leak.sh does that), other runtime
#              kinds, the CLI path itself, restart of the daemon.
#
# FAILS WHEN:  the daemon dies, the proxy stops serving, or descriptors grow past
#              the allowance.  The original printed its numbers and exited 0 —
#              including on the line that said "DAEMON DEAD".
#
#   CYCLES=n           stop/start cycles (default 12)
#   FD_GROWTH_MAX=n    tolerated descriptor growth (default 8)
#   RSS_GROWTH_PCT=n   tolerated RSS growth in percent (default 50)

HARNESS_NAME="restart_under_load"
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

require_bin
require_lib httpharness.py

CYCLES="${CYCLES:-12}"
FD_MAX="${FD_GROWTH_MAX:-8}"
RSS_PCT="${RSS_GROWTH_PCT:-50}"
BE="${BE_PORT:-25200}"
PX="${PX_PORT:-25201}"

RUNDIR="$(make_run_dir)"
BPID=""
cleanup() {
    [ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null
    [ -n "$BPID" ] && kill "$BPID" 2>/dev/null
    rm -rf "$RUNDIR"
}
trap cleanup EXIT

echo "=== Runtime stop/start under load — $CYCLES cycles ==="
announce_environment

pin_load python3 "$LIB/httpharness.py" --mode backend --port "$BE" >"$RUNDIR/backend.log" 2>&1 &
BPID=$!
sleep 1
kill -0 "$BPID" 2>/dev/null || nothing_measured "the echo backend did not start on port $BE"

start_daemon "$RUNDIR" || nothing_measured "daemon did not start"

"$BIN" create proxy rl -p "$PX" --backend "127.0.0.1:$BE" --protocol http -s >/dev/null 2>&1
sleep 1

# Serve once before measuring anything, so the baseline is taken on a daemon
# that has already allocated its per-connection structures.  A baseline taken
# before the first request makes every later reading look like growth.
if ! pin_load python3 "$LIB/httpharness.py" --mode drive --port "$PX" --prefix /rl \
        --clients 4 --count 5 >/dev/null 2>&1; then
    nothing_measured "the proxy did not serve before the first cycle — nothing was measured"
fi
sleep 1

base_fd="$(daemon_fds)"
base_rss="$(daemon_rss_kb)"
[ "$base_fd" -gt 0 ] 2>/dev/null || nothing_measured "could not read the daemon's descriptor count"
echo "  baseline: $base_fd descriptors, ${base_rss} kB RSS"

completed=0
for r in $(seq 1 "$CYCLES"); do
    pin_load python3 "$LIB/httpharness.py" --mode drive --port "$PX" --prefix /rl \
        --clients 10 --count 20 >/dev/null 2>&1 &
    LP=$!
    sleep 0.4
    "$BIN" stop rl >/dev/null 2>&1
    wait "$LP" 2>/dev/null
    "$BIN" start rl >/dev/null 2>&1
    sleep 0.4
    if ! daemon_alive; then
        fail "the daemon died in cycle $r of $CYCLES (stop/start under load)"
    fi
    completed=$((completed + 1))
done

sleep 3
end_fd="$(daemon_fds)"
end_rss="$(daemon_rss_kb)"
echo "  after $completed stop/start cycles: $end_fd descriptors, ${end_rss} kB RSS"

[ "$completed" -eq "$CYCLES" ] || nothing_measured "only $completed of $CYCLES cycles ran"

# Does it still serve?
if ! out="$(pin_load python3 "$LIB/httpharness.py" --mode drive --port "$PX" --prefix /rl \
              --clients 10 --count 20 2>&1)"; then
    fail "the proxy no longer serves after $completed stop/start cycles: ${out:-<no output>}"
fi
[ "$out" = "OK" ] || fail "the proxy serves incorrectly after $completed cycles: $out"

daemon_alive || fail "the daemon died after the cycles completed"

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

pass "$completed cycles, still serving, descriptors +$fd_growth, RSS +${rss_growth}%"
