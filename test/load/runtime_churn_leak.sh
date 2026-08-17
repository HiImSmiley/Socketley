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
#   CYCLES=n           counted create/remove cycles (default 60)
#   WARMUPS=n          cycles run and discarded before the baseline (default 10)
#   FD_GROWTH_MAX=n    tolerated descriptor growth (default 8)
#   RSS_GROWTH_PCT=n   tolerated RSS growth in percent (default 40)

HARNESS_NAME="runtime_churn_leak"
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

require_bin
require_lib httpharness.py

CYCLES="${CYCLES:-60}"
WARMUPS="${WARMUPS:-10}"
FD_MAX="${FD_GROWTH_MAX:-8}"
RSS_PCT="${RSS_GROWTH_PCT:-40}"
BE="${BE_PORT:-$((SL_PORT_BASE + 1400))}"
PORT_BASE="${PORT_BASE:-$((SL_PORT_BASE + 1410))}"
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

start_load_bg python3 "$LIB/httpharness.py" --mode backend --port "$BE" >"$RUNDIR/backend.log" 2>&1
BPID=$!
sleep 1
kill -0 "$BPID" 2>/dev/null || nothing_measured "the echo backend did not start on port $BE"

start_daemon "$RUNDIR" || nothing_measured "daemon did not start"

# ─── WARM-UPS, AND WHY THERE ARE TEN OF THEM ────────────────────────────────
#
# Discipline 4 in common.sh: the first rounds pay for page faults and allocator
# growth, they are run and thrown away, never counted.  Every measure_* harness
# has done that from the start.  This one did not, and it did not matter while
# DAEMON_PID named a bash subshell — the baseline and every later sample read
# the same 2160 kB whatever the daemon did.
#
# Against the daemon it now reads, the omission is the whole verdict.  Sampled
# every cycle on a Release build, quiet machine, 2026-08-02:
#
#     cycle  0    7116 kB          cycle  9   22784 kB   (+28)
#     cycle  1   14016 kB (+6900)  cycle 15   23052 kB   (+4)
#     cycle  2   18516 kB (+4500)  cycle 24   23180 kB   (+128)
#     cycle  4   21428 kB (+2624)  cycle 45   23192 kB   (+4)
#
# 16 MB of the growth is the first nine cycles and 140 kB is the thirty after
# cycle 15.  Descriptors are 6 at every single sample.  That is a daemon
# allocating what it needs to hold one proxy runtime, once, and it was being
# reported as a 228% leak.
#
# TEN is where the per-cycle delta has decayed into the noise (+28 kB at cycle
# 9, and zero for most cycles after it), taken from the profile above rather
# than chosen to make this line pass.  It is not three, as elsewhere in the
# suite, because a cycle here creates and destroys a whole runtime rather than
# opening a connection.
#
# THE ALLOWANCE IS NOT TOUCHED.  It stays at the 40% it has always been.  What
# changes is that it is now compared against a warm daemon, which is the only
# comparison in which "did the churn leak" is the question being asked.  With
# that baseline the observed growth is about 1%, so 40% is now very loose and is
# the next thing worth calibrating — from a few dozen runs, not from these.
warm=0
while [ "$warm" -lt "$WARMUPS" ]; do
    warm=$((warm + 1))
    P=$((PORT_BASE + warm % PORT_SPAN))
    "$BIN" create proxy "wu$warm" -p "$P" --backend "127.0.0.1:$BE" --protocol http -s >/dev/null 2>&1
    pin_load python3 "$LIB/httpharness.py" --mode drive --port "$P" --prefix "/wu$warm" \
        --clients 4 --count 8 >/dev/null 2>&1
    "$BIN" remove "wu$warm" >/dev/null 2>&1
done
daemon_alive || fail "the daemon died during the $WARMUPS warm-up cycles"
sleep 1

base_rss="$(daemon_rss_kb)"
base_fd="$(daemon_fds)"
[ "$base_fd" -gt 0 ] 2>/dev/null || nothing_measured "could not read the daemon's descriptor count"
echo "  baseline: ${base_rss} kB RSS, $base_fd descriptors (after $WARMUPS discarded warm-up cycles)"

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
