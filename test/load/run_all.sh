#!/usr/bin/env bash
# Run every load harness and summarise.
#
#   ./test/load/run_all.sh [harness ...]
#
# With no arguments, runs all of them in the order below.
#
# ─── TIME ───────────────────────────────────────────────────────────────────
#
# The measuring harnesses idle for 60 s before each of three passes and then run
# 40 counted rounds, so the full set takes roughly 25-40 minutes on a four-core
# machine.  That is a nightly job, not a per-push one, and the idle time is not
# padding — see the note at the top of common.sh.
#
# For a smoke run: LOAD_SETTLE_SECS=5 ROUNDS=5 PASSES=1 CYCLES=3 ./run_all.sh
# Those numbers are not comparable with a calibrated run and every harness says
# so in its own output when they are set.
#
# ─── WHAT A GREEN RUN MEANS ─────────────────────────────────────────────────
#
# That the defect classes these harnesses were written for did not reproduce, on
# this machine, in this many rounds.  These are stochastic reproducers: several
# of the defects they were built to catch reproduced in 1 run out of 40.  A
# single green run is weak evidence; a green run every night for a week is
# strong evidence.  Neither is a proof of absence.

set -uo pipefail

LOAD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ALL=(
    measure_tcp
    measure_http
    measure_ws
    restart_under_load
    runtime_churn_leak
    churn_repro
)

if [ "$#" -gt 0 ]; then
    HARNESSES=("$@")
else
    HARNESSES=("${ALL[@]}")
fi

PASS=0; FAIL=0; NODATA=0
declare -a FAILED=()
declare -a NO_DATA=()

echo "=================================================="
echo " Socketley load harnesses"
echo "=================================================="

start_all=$SECONDS

for h in "${HARNESSES[@]}"; do
    script="$LOAD_DIR/$h.sh"
    if [ ! -f "$script" ]; then
        echo "ERROR: no such harness: $script"
        FAIL=$((FAIL + 1))
        FAILED+=("$h (missing)")
        continue
    fi

    echo
    echo "──────────────────────────────────────────────────"
    t0=$SECONDS
    bash "$script"
    rc=$?
    dt=$((SECONDS - t0))

    case "$rc" in
        0) PASS=$((PASS + 1));   echo "  [${dt}s] $h: pass" ;;
        2) NODATA=$((NODATA + 1)); NO_DATA+=("$h"); echo "  [${dt}s] $h: NO DATA" ;;
        *) FAIL=$((FAIL + 1));   FAILED+=("$h"); echo "  [${dt}s] $h: FAIL (exit $rc)" ;;
    esac
done

echo
echo "=================================================="
echo " Summary: $PASS passed, $FAIL failed, $NODATA produced no data  ($((SECONDS - start_all))s)"
[ "${#FAILED[@]}" -gt 0 ] && echo " Failed:  ${FAILED[*]}"
[ "${#NO_DATA[@]}" -gt 0 ] && echo " No data: ${NO_DATA[*]}"
echo "=================================================="

# "No data" is not "pass".  A harness that could not measure anything is
# reported as a failure of the run, because a job that goes green on a set of
# harnesses that all did nothing is the worst outcome available here.
if [ "$FAIL" -gt 0 ] || [ "$NODATA" -gt 0 ]; then
    exit 1
fi
if [ "$PASS" -eq 0 ]; then
    echo " ERROR: no harness ran."
    exit 2
fi
exit 0
