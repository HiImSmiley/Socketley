#!/usr/bin/env bash
# Shared plumbing and measurement discipline for the load harnesses.
#
# ─── WHERE THESE CAME FROM ──────────────────────────────────────────────────
# What survived the move out of a scratch directory is the measurement
# discipline: a defined starting state, because a run on the previous run's
# debris measures the debris; sixty seconds of idle before each batch, because
# batches compared against each other must start from the same place; CPU
# pinning, without which the result measures the scheduler; and warm-ups
# discarded, because the first rounds pay for page faults and buffer growth --
# each disableable, and each printing a loud line when it is off, since the run
# is then incomparable with every other; these are correctness-under-load
# harnesses rather than benchmarks, so a clean run says the defect classes did
# not reproduce in this many rounds on this machine and not that they are gone.

set -uo pipefail

LOAD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$LOAD_DIR/../.." && pwd)"
LIB="$LOAD_DIR/lib"

# ─── binaries ────────────────────────────────────────────────────────────────

# Defaults to Release because that is what these harnesses were calibrated
# against; the nightly sanitizer job overrides it.
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
# Two disjoint core sets, because the daemon must not share a core with the
# thing driving it -- and on a machine with fewer than four cores that is
# impossible, so say so once rather than quietly producing numbers that look
# like the others.

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

# `&` on a shell function runs it in a subshell, so $! named bash and every
# harness here was killing, sampling descriptors from and reporting the RSS of
# the wrong process -- these background the command in the current shell, and
# taskset execs rather than forks, so the pinned branch keeps that pid too.
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

# The idle period between batches, overridable for a smoke run and announced
# when overridden, because a 5-second settle and a 60-second settle produce
# different numbers from identical code.
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

# This waits and must not kill anything, because the `pkill -f` it opened with
# matched every daemon started from this binary -- including the caller's own,
# which two harnesses then measured the absence of and reported as a death they
# had caused; nothing replaces it, since every run has its own HOME, socket and
# ports and already kills the daemon it started.
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

# Sets DAEMON_PID to the daemon's own pid and fails loudly rather than letting
# the harness measure an absent daemon -- it used to name the subshell, so both
# leak harnesses reported bash's five descriptors and two megabytes, identical
# to the byte across every cycle and unable to fail their leak check.
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
# A harness that prints numbers and exits 0 is one CI cannot use, which is how
# a run reporting "12 of 40 rounds bad" still showed up as a green step.

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

# Every harness used to bind literals sitting inside windows lib_ports.sh hands
# out, which cost a nightly job to a port still held from a claimed window --
# sited here because all seven source this file, and lib_ports.sh returns
# immediately when SL_PORT_BASE is already set, so a harness under a suite uses
# that window rather than taking a second, with each harness's offsets distinct
# across the directory.
. "$(dirname "${BASH_SOURCE[0]}")/../integration/lib_ports.sh"
