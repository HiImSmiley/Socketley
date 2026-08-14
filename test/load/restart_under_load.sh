#!/usr/bin/env bash
# Stop and start a runtime while traffic is in flight, repeatedly.
#
# Was scratchpad/restartload.sh.  Stop/start cycles with an HTTP load generator
# running across each one, then a check that the proxy still serves and that the
# daemon has not accumulated descriptors or memory.
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
#   CYCLES=n           counted stop/start cycles (default 30)
#   WARMUPS=n          cycles run and discarded before the baseline (default 3)
#   FD_GROWTH_MAX=n    tolerated descriptor growth (default 8)
#   RSS_GROWTH_PCT=n   tolerated RSS growth in percent (default 50)

HARNESS_NAME="restart_under_load"
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

require_bin
require_lib httpharness.py

CYCLES="${CYCLES:-30}"
WARMUPS="${WARMUPS:-3}"
FD_MAX="${FD_GROWTH_MAX:-8}"
RSS_PCT="${RSS_GROWTH_PCT:-50}"
BE="${BE_PORT:-$((SL_PORT_BASE + 1300))}"
PX="${PX_PORT:-$((SL_PORT_BASE + 1301))}"

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

start_load_bg python3 "$LIB/httpharness.py" --mode backend --port "$BE" >"$RUNDIR/backend.log" 2>&1
BPID=$!
sleep 1
kill -0 "$BPID" 2>/dev/null || nothing_measured "the echo backend did not start on port $BE"

start_daemon "$RUNDIR" || nothing_measured "daemon did not start"

"$BIN" create proxy rl -p "$PX" --backend "127.0.0.1:$BE" --protocol http -s >/dev/null 2>&1
sleep 1

# Serve once before anything else.  This is the gate, not the warm-up: a proxy
# that never answers has to end the run here rather than produce numbers.
if ! pin_load python3 "$LIB/httpharness.py" --mode drive --port "$PX" --prefix /rl \
        --clients 4 --count 5 >/dev/null 2>&1; then
    nothing_measured "the proxy did not serve before the first cycle — nothing was measured"
fi
sleep 1

# One stop/start cycle under load — the thing this harness counts, written once
# so the warm-ups and the counted cycles cannot drift apart.
cycle() {
    pin_load python3 "$LIB/httpharness.py" --mode drive --port "$PX" --prefix /rl \
        --clients 10 --count 20 >/dev/null 2>&1 &
    local lp=$!
    sleep 0.4
    "$BIN" stop rl >/dev/null 2>&1
    wait "$lp" 2>/dev/null
    "$BIN" start rl >/dev/null 2>&1
    sleep 0.4
}

# ─── WARM-UPS, AND WHY THEY ARE CYCLES AND NOT A SERVE ──────────────────────
#
# Discipline 4 in common.sh: the first rounds pay for page faults and allocator
# growth, they are run and thrown away.  This harness had no WARMUPS knob; what
# it had instead was the serve above, and the serve is not the same operation as
# the thing being measured.  It drives 4 clients for 5 requests; a counted cycle
# drives 10 for 20 and stops and starts the runtime underneath them.  So the
# baseline was taken on a daemon that had never held ten connections at once,
# and the first counted cycle was charged for the six it had not paid for yet —
# with the priming serve's own descriptors still open at the moment it was read.
#
# It made no difference while DAEMON_PID named a bash subshell (9b6e865): the
# baseline and every later sample read the same 2136 kB whatever the daemon did.
# Against the daemon it now reads, sampled every cycle on a Release build,
# 4 cores, quiet machine, 2026-08-02:
#
#     no proxy yet   7092 kB   6 fd     cycle  3   15892 kB  7 fd  (+0)
#     proxy started 13712 kB   7 fd     cycle  4   15892 kB  7 fd  (+0)
#     after 1 serve 13952 kB  11 fd  <- the old baseline, 11 descriptors
#     cycle 1       15604 kB   7 fd  (+1652)
#     cycle 2       15892 kB   7 fd  (+288)     ... and +0 for cycles 3-40
#
# Every kilobyte of the 1.94 MB this run grew by is in the first two cycles.
# Thirty-eight consecutive samples after that are identical to the byte, and
# descriptors are 7 at every one of them.  That is a daemon finishing its
# allocation for ten concurrent connections, once, and it was being charged to
# the churn.
#
# THREE, because that is the first cycle at which the per-cycle delta is zero
# here, and because three is what every measure_* harness in this directory
# uses.  It is deliberately not taken from a run that had to pass: the run above
# passes at +13.9% against a 50% allowance either way.  A machine that settles
# more slowly than this one is the case three might not cover, which is what the
# per-cycle line below is for — the next run to fail carries its own curve in
# the log instead of leaving the next reader to guess at it, which is what the
# nightly's 163% over 12 cycles left behind.
warm=0
while [ "$warm" -lt "$WARMUPS" ]; do
    warm=$((warm + 1))
    cycle
    daemon_alive || fail "the daemon died in warm-up cycle $warm of $WARMUPS"
done
sleep 1

base_fd="$(daemon_fds)"
base_rss="$(daemon_rss_kb)"
[ "$base_fd" -gt 0 ] 2>/dev/null || nothing_measured "could not read the daemon's descriptor count"
echo "  baseline: $base_fd descriptors, ${base_rss} kB RSS (after $WARMUPS discarded warm-up cycles)"

# THIRTY, up from twelve.  Not to make anything pass — the allowance is
# untouched — but because twelve cycles cannot tell a fixed cost from a
# per-cycle one.  That discriminator is division: a start-up cost spread over
# more cycles shrinks as a percentage and a leak does not, which is how 8e18cbd
# read runtime_churn_leak (60 cycles 227%, 180 cycles 230% — fixed).  With a
# single before/after pair over twelve cycles there is nothing to divide.  A
# cycle here costs about two seconds, so this buys eighteen more samples for
# well under a minute.
completed=0
prev_rss="$base_rss"
for r in $(seq 1 "$CYCLES"); do
    cycle
    if ! daemon_alive; then
        fail "the daemon died in cycle $r of $CYCLES (stop/start under load)"
    fi
    completed=$((completed + 1))
    cur_rss="$(daemon_rss_kb)"
    printf '    cycle %3d: %8s kB  %3s fd  (%+d)\n' \
        "$r" "$cur_rss" "$(daemon_fds)" "$((cur_rss - prev_rss))"
    prev_rss="$cur_rss"
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
