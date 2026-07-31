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
preflight() {
    local tw_limit="${LOAD_TW_LIMIT:-200}"
    local load_limit="${LOAD_LOADAVG_LIMIT:-60}"     # x100, so 60 == 0.60
    local tries="${LOAD_PREFLIGHT_TRIES:-60}"

    pkill -f "$BIN daemon" 2>/dev/null
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

# Start a daemon in the given run dir; sets DAEMON_PID.  Fails loudly rather
# than letting the rest of the harness measure an absent daemon.
start_daemon() {
    local rundir="$1"
    export HOME="$rundir/home"
    export SOCKETLEY_SOCKET="$rundir/d.sock"
    pin_daemon "$BIN" daemon >"$rundir/daemon.log" 2>&1 &
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
