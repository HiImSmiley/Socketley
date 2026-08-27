#!/usr/bin/env bash
# Shared plumbing and measurement discipline for the load harnesses.
#
# ─── WHERE THESE CAME FROM ──────────────────────────────────────────────────
#
# These scripts were written one at a time while chasing defects by hand, and
# they lived in a scratch directory with absolute paths baked into them.  CI
# cannot depend on a temp directory, so they were moved here.  What survived the
# move is not just the commands — it is the measurement discipline they encode,
# which is the only reason their numbers meant anything:
#
#   1. A DEFINED STARTING STATE.  Nothing is measured until TIME_WAIT sockets
#      and load average are back under a threshold.  A run started on top of the
#      previous run's debris measures the debris.
#
#   2. 60 SECONDS OF IDLE BEFORE EACH BATCH.  Not a guess: it is how long this
#      class of machine takes to settle after a batch of short-lived TCP
#      connections.  Batches compared against each other must have started from
#      the same place or the comparison is noise.
#
#   3. CPU PINNING.  Daemon on one pair of cores, load generator on another.
#      Without it the generator and the daemon fight for the same core and the
#      result measures the scheduler.
#
#   4. WARM-UPS DISCARDED.  The first few rounds pay for page faults, socket
#      buffer growth and branch predictor training.  They are run and thrown
#      away, never counted.
#
# Any of these can be turned off with an environment variable.  Doing so makes
# the run faster and the numbers incomparable with every other run, so each one
# prints a loud line when it is off.
#
# ─── WHAT THESE HARNESSES DO AND DO NOT PROVE ───────────────────────────────
#
# They are correctness-under-load harnesses, not benchmarks.  They report how
# many rounds came back wrong (a missing response, a response delivered on the
# wrong connection, a daemon that died), and whether descriptors and RSS grow
# across cycles.  They do not measure throughput or latency; test/benchmark/ is
# for that.  A clean run says the defect classes these were written for did not
# reproduce in this many rounds on this machine.  It does not say they are gone.

set -uo pipefail

LOAD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$LOAD_DIR/../.." && pwd)"
LIB="$LOAD_DIR/lib"

# ─── binaries ────────────────────────────────────────────────────────────────

# Which build to exercise.  Defaults to Release because that is what these
# harnesses were calibrated against; the nightly sanitizer job overrides it.
SOCKETLEY_CONFIG="${SOCKETLEY_CONFIG:-Release}"
BIN="${SOCKETLEY_BIN:-$ROOT/bin/$SOCKETLEY_CONFIG/socketley}"
BENCH="${SOCKETLEY_BENCH:-$ROOT/bin/$SOCKETLEY_CONFIG/socketley_bench}"

require_bin() {
    if [ ! -x "$BIN" ]; then
        echo "ERROR: socketley binary not found or not executable: $BIN"
        echo "       build it, or set SOCKETLEY_BIN / SOCKETLEY_CONFIG."
        exit 2
    fi
}

require_bench() {
    if [ ! -x "$BENCH" ]; then
        echo "ERROR: socketley_bench not found or not executable: $BENCH"
        echo "       build it, or set SOCKETLEY_BENCH / SOCKETLEY_CONFIG."
        exit 2
    fi
}

require_lib() {
    local f
    for f in "$@"; do
        if [ ! -f "$LIB/$f" ]; then
            echo "ERROR: harness helper missing: $LIB/$f"
            exit 2
        fi
    done
}

# ─── CPU pinning ─────────────────────────────────────────────────────────────
#
# Two disjoint core sets: the daemon must not share a core with the thing
# driving it.  On a machine with fewer than four cores that separation is not
# possible, and a run without it is not comparable to one with it — so say so,
# once, loudly, rather than quietly producing numbers that look like the others.

NPROC="$(nproc 2>/dev/null || echo 1)"
PIN_AVAILABLE=0
DAEMON_CPUS=""
LOAD_CPUS=""

if command -v taskset >/dev/null 2>&1 && [ "$NPROC" -ge 4 ]; then
    PIN_AVAILABLE=1
    DAEMON_CPUS="${SOCKETLEY_DAEMON_CPUS:-0,1}"
    LOAD_CPUS="${SOCKETLEY_LOAD_CPUS:-2,3}"
fi

pin_daemon() {
    if [ "$PIN_AVAILABLE" = 1 ]; then taskset -c "$DAEMON_CPUS" "$@"; else "$@"; fi
}

pin_load() {
    if [ "$PIN_AVAILABLE" = 1 ]; then taskset -c "$LOAD_CPUS" "$@"; else "$@"; fi
}

# ─── backgrounding, and why it is not `pin_load cmd &` ───────────────────────
#
# `&` applied to a shell function runs the function in a subshell.  $! is then
# the subshell's pid and the command is its child, so:
#
#   kill "$!"            kills bash and leaves the command running
#   /proc/$!/fd          lists bash's descriptors
#   /proc/$!/status      reports bash's RSS
#
# Every harness here backgrounded through pin_load or pin_daemon and kept $!, so
# every one of those was true.  The two below background the command themselves,
# in the current shell, so $! is the command's own pid — and taskset execs its
# argument rather than forking, so the pinned branch keeps that pid too.
#
# Call them without a trailing `&`; they add it:
#
#   start_daemon_bg "$BIN" daemon >"$log" 2>&1   ; DAEMON_PID=$!
#   start_load_bg   python3 "$LIB/x.py" >"$log" 2>&1 ; BPID=$!
start_daemon_bg() {
    if [ "$PIN_AVAILABLE" = 1 ]; then
        taskset -c "$DAEMON_CPUS" "$@" &
    else
        "$@" &
    fi
}

start_load_bg() {
    if [ "$PIN_AVAILABLE" = 1 ]; then
        taskset -c "$LOAD_CPUS" "$@" &
    else
        "$@" &
    fi
}

announce_environment() {
    echo "  binary:   $BIN"
    if [ "$PIN_AVAILABLE" = 1 ]; then
        echo "  pinning:  daemon on CPU $DAEMON_CPUS, load on CPU $LOAD_CPUS (${NPROC} cores)"
    else
        echo "  pinning:  NONE — ${NPROC} core(s), or taskset unavailable."
        echo "            !! Results are NOT comparable with a pinned run: the daemon and"
        echo "            !! the load generator share cores, so this measures the scheduler"
        echo "            !! as much as it measures socketley."
    fi
    if [ "${LOAD_SETTLE_SECS:-60}" != "60" ]; then
        echo "  settle:   ${LOAD_SETTLE_SECS}s — !! not the calibrated 60s, results are"
        echo "            !! not comparable with runs that used it."
    else
        echo "  settle:   60s before each batch"
    fi
}

# ─── settling and preflight ──────────────────────────────────────────────────

# The idle period between batches.  Overridable so a smoke run can be quick;
# every override is announced, because a 5-second settle and a 60-second settle
# produce different numbers from identical code.
settle() {
    local secs="${LOAD_SETTLE_SECS:-60}"
    [ "$secs" -eq 0 ] 2>/dev/null && return 0
    echo "  (${secs}s idle for the same starting state)"
    sleep "$secs"
}

time_wait_count() {
    ss -tan state time-wait 2>/dev/null | wc -l
}

load_x100() {
    awk '{print int($1*100)}' /proc/loadavg 2>/dev/null || echo 0
}

# Wait for a defined starting state.  Returns 0 when reached, 1 when it gave up
# — callers report that alongside their numbers so a batch measured on a dirty
# machine is visible as such rather than silently mixed in with the clean ones.
#
# This waits.  It does not kill anything, and it must not: it used to open with
#
#     pkill -f "$BIN daemon"
#
# which matches every daemon started from this binary — including the one the
# caller started moments earlier.  measure_tcp.sh calls preflight *before*
# start_daemon and survived it; measure_http.sh and measure_ws.sh call it at the
# top of each pass, after start_daemon, and killed their own daemon on the first
# line of the first pass.  Everything after that measured an absent daemon:
# every round reported connect-failed=20, and the harness closed with "the
# daemon died during the run" — a true statement about a death it had caused
# itself.  Nothing replaces the kill because nothing needs to: start_daemon
# gives every run its own HOME and its own control socket, so a daemon left over
# from another run is invisible to this one, each harness uses its own ports, and
# each harness already kills the daemon it started.
preflight() {
    local tw_limit="${LOAD_TW_LIMIT:-200}"
    local load_limit="${LOAD_LOADAVG_LIMIT:-60}"     # x100, so 60 == 0.60
    local tries="${LOAD_PREFLIGHT_TRIES:-60}"

    local i tw la
    for i in $(seq 1 "$tries"); do
        tw="$(time_wait_count)"
        la="$(load_x100)"
        if [ "$tw" -lt "$tw_limit" ] && [ "$la" -lt "$load_limit" ]; then
            return 0
        fi
        sleep 5
    done
    echo "  WARNING: starting state not reached (TIME_WAIT=$tw load=$la) — this batch is suspect"
    return 1
}

# ─── per-run isolation ───────────────────────────────────────────────────────
#
# Every harness gets its own HOME and its own control socket so it cannot see,
# or be seen by, a daemon belonging to another run or to the developer's shell.

make_run_dir() {
    local t
    t="$(mktemp -d /tmp/socketley-load-XXXXXX)" || { echo "ERROR: mktemp failed"; exit 2; }
    mkdir -p "$t/home"
    echo "$t"
}

# Start a daemon in the given run dir; sets DAEMON_PID to the daemon's own pid.
# Fails loudly rather than letting the rest of the harness measure an absent
# daemon.
#
# DAEMON_PID is the instrument the leak harnesses read: restart_under_load.sh and
# runtime_churn_leak.sh both sample /proc/$DAEMON_PID for descriptors and RSS and
# report the difference across their cycles.  It used to be set from
# `pin_daemon "$BIN" daemon &`, which named the subshell — so both harnesses were
# reporting bash's five descriptors and bash's two megabytes, unchanged across
# every cycle because bash was doing nothing.  Nightly run 30719890629 printed
# "baseline: 5 descriptors, 2136 kB RSS" and then, after twelve stop/start
# cycles, "5 descriptors, 2136 kB RSS" — identical to the byte, as it always
# would be.  Neither harness could fail its leak check.  See the note above
# start_daemon_bg for the mechanism.
start_daemon() {
    local rundir="$1"
    export HOME="$rundir/home"
    export SOCKETLEY_SOCKET="$rundir/d.sock"
    start_daemon_bg "$BIN" daemon >"$rundir/daemon.log" 2>&1
    DAEMON_PID=$!
    local i
    for i in $(seq 1 100); do
        if [ -S "$SOCKETLEY_SOCKET" ] && "$BIN" ps >/dev/null 2>&1; then
            return 0
        fi
        kill -0 "$DAEMON_PID" 2>/dev/null || break
        sleep 0.1
    done
    echo "ERROR: daemon did not come up within 10s (socket $SOCKETLEY_SOCKET)"
    echo "--- daemon log ---"
    tail -30 "$rundir/daemon.log" 2>/dev/null
    return 1
}

daemon_alive() {
    kill -0 "${DAEMON_PID:-0}" 2>/dev/null
}

daemon_fds() {
    ls "/proc/${DAEMON_PID}/fd" 2>/dev/null | wc -l
}

daemon_rss_kb() {
    awk '/VmRSS/{print $2}' "/proc/${DAEMON_PID}/status" 2>/dev/null || echo 0
}

# ─── result reporting ────────────────────────────────────────────────────────
#
# A harness that prints numbers and exits 0 is a harness CI cannot use: the
# original versions of these scripts all did exactly that, which is how a run
# that reported "12 of 40 rounds bad" still showed up as a green step.  Every
# harness now ends in one of these.

HARNESS_NAME="${HARNESS_NAME:-load}"

pass() {
    echo "RESULT $HARNESS_NAME: PASS — $*"
    exit 0
}

fail() {
    echo "RESULT $HARNESS_NAME: FAIL — $*"
    exit 1
}

# "The measurement did not happen" is its own outcome, distinct from pass and
# from fail, and it must never be reported as pass.
nothing_measured() {
    echo "RESULT $HARNESS_NAME: NO DATA — $*"
    echo "  A harness that measured nothing is not a passing harness."
    exit 2
}

# ─── a port window, claimed like everybody else's ───────────────────────────
#
# Every harness in this directory used to bind literals, and every one of those
# literals sat inside a window integration/lib_ports.sh hands out: 19599, 19600
# and 19700 in the FIRST window, the one a quiet run always takes; 23100, 23101,
# 23200 and 23201 in the third; 25200, 25201, 26000 and 26010-26029 in the
# fourth.  Nothing coordinated the two.
#
# It cost a nightly job on 2026-08-15:
#
#     OSError: [Errno 98] error while attempting to bind on address
#              ('127.0.0.1', 23200): address already in use
#     RESULT measure_ws: NO DATA — the WebSocket echo backend did not start
#
# The load phase runs alone, so the collision was not with another harness --
# it was with something still holding a port out of a window a suite had
# claimed.  Concurrent runs on this box are also handed blocks at 21000-23999 by
# hand, which is the same range arriving from a third direction.
#
# Sited here because all seven harnesses source this file and none of them has
# to know about it.  lib_ports.sh is idempotent -- it returns immediately when
# SL_PORT_BASE is already set -- so a harness run from test/load/run_all.sh, or
# under a suite that has already claimed a window, uses that one rather than
# taking a second.
#
# The offsets each harness derives from SL_PORT_BASE are distinct across the
# directory, so two of them running at once cannot collide either.
. "$(dirname "${BASH_SOURCE[0]}")/../integration/lib_ports.sh"
