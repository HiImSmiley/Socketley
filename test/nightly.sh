#!/usr/bin/env bash
# The nightly, locally.
#
# The six jobs of .github/workflows/nightly.yml, run on this machine instead of
# on GitHub's runners.  Same scripts, same configurations; what changes is who
# pays for the cores and how many there are.
#
# WHY THIS EXISTS.  The workflow bills a private repository by the minute, and
# it bills the sum of its jobs rather than the wall clock they finish in: one
# measured run came to 184 minutes across six jobs, of which the fuzz job alone
# was 116.  A nightly schedule at that rate exhausts a month's free allowance in
# eleven nights.  Since 2026-08-08 the jobs have not started at all -- every one
# fails in about two seconds with no steps executed, on "recent account payments
# have failed or your spending limit needs to be increased" -- so the coverage
# has simply been absent, and absent quietly: a run that fails in two seconds
# looks exactly like a run that fails in 116 minutes if all anybody reads is the
# colour.
#
# WHAT PARALLELISM IS SAFE HERE, AND WHY.  The suite became concurrency-safe
# without anyone setting out to make it so:
#
#   * Each run claims its own port window under an flock, so two suites cannot
#     take the same one -- see integration/lib_ports.sh.
#   * Each run gets its own socket and HOME out of mktemp, so no two share a
#     daemon or a state directory.
#   * run_all.sh's cleanup sweeps daemons by /proc/<pid>/exe against
#     $BIN_DIR/socketley, which is per-configuration.  A Release run and a
#     Sanitize run therefore cannot sweep each other -- but two runs of the SAME
#     configuration still would, which is why nothing below starts one twice.
#
# WHAT IS NOT PARALLELISED, AND WHY THAT IS NOT AN OVERSIGHT.  The load and
# invariant harnesses measure: CPU burned at idle, RSS growth across churn,
# throughput under a fixed offered load.  Every one of those reads differently
# when nine other things are competing for the same cores, and a measurement
# taken under unknown contention is not a cheaper measurement, it is a different
# question answered by accident.  They run alone, after the rest is finished.
#
# Usage:  bash test/nightly.sh [job ...]
#         FUZZ_SECONDS=120 bash test/nightly.sh fuzz
#
# Jobs:   release sanitize tsan fuzz load invariants
#         (default: all six)
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

RUNDIR="${NIGHTLY_RUNDIR:-$(mktemp -d "${TMPDIR:-/tmp}/socketley-nightly.XXXXXX")}"
mkdir -p "$RUNDIR"

# The CI value is 600 per target, spent twice (libFuzzer then replay), across
# nine targets: about 92 minutes.  That is a budget for an unattended run, not
# for one somebody is waiting on, so the local default is shorter and the knob
# is here rather than buried.
FUZZ_SECONDS="${FUZZ_SECONDS:-120}"

JOBS=("$@")
[ ${#JOBS[@]} -eq 0 ] && JOBS=(release sanitize tsan fuzz load invariants)

want() { local j; for j in "${JOBS[@]}"; do [ "$j" = "$1" ] && return 0; done; return 1; }

# ─── the machine has to be quiet before any of this ─────────────────────────
#
# Not `pgrep -f`: -f matches the whole command line, so it also matches the
# shell that merely carries the string in its arguments -- including this one.
# That has killed the killer here before.
stray=$(pgrep -x socketley 2>/dev/null | wc -l)
if [ "$stray" -ne 0 ]; then
    echo "REFUSING: $stray socketley process(es) already running."
    echo "  A suite's cleanup sweeps by executable, so an existing daemon of the"
    echo "  same build will be killed under whoever owns it -- and whoever owns"
    echo "  it will kill these.  Clear them first."
    exit 2
fi

echo "nightly (local)   run dir: $RUNDIR"
echo "jobs: ${JOBS[*]}"
echo "cores: $(nproc)   fuzz budget: ${FUZZ_SECONDS}s/target"
echo

STARTED=$(date +%s)
declare -A RESULT

# ─── builds, one at a time ──────────────────────────────────────────────────
#
# Serially and deliberately.  A parallel link of two sanitized configurations is
# where this machine has run out of memory before, and a build that dies halfway
# costs more than the minutes it saved.
build() {
    # Two statements, not one.  bash expands every word of a `local` command
    # before it assigns any of them, so `local cfg=$1 log=...$cfg...` reads cfg
    # while it is still unset — which under `set -u` is a fatal error, not an
    # empty string.  This function had therefore never run to completion: the
    # only invocation anybody had tried was `nightly.sh fuzz`, which requested no
    # build and so never called it.  Every job this runner has reported on was
    # measured against whatever binaries were already under bin/, which is how
    # the fuzz job came to run a libFuzzer build twelve days old.
    local cfg=$1
    local log="$RUNDIR/build-$cfg.log"
    printf '  build %-9s ' "$cfg"
    if make -C make "config=${cfg}_x64" -j"$(nproc)" >"$log" 2>&1; then
        local w
        w=$(grep -cE 'warning:|error:' "$log")
        if [ "$w" -ne 0 ]; then
            echo "FAIL ($w warnings/errors, see $log)"
            return 1
        fi
        echo "ok"
        return 0
    fi
    echo "FAIL (see $log)"
    return 1
}

./bin/premake5 gmake2 >/dev/null 2>&1 || { echo "premake failed"; exit 2; }

echo "── builds ──"
want release    && { build release  || RESULT[release]=BUILD_FAIL; }

# Sanitize is two jobs' build, not one.  The fuzz job runs the replay half of
# every target out of bin/Sanitize, so `nightly.sh fuzz` needs this
# configuration even when the sanitize suite itself is not among the jobs.
SANITIZE_BUILT=1
if want sanitize || want fuzz; then
    build sanitize || SANITIZE_BUILT=0
fi
if [ "$SANITIZE_BUILT" -eq 0 ]; then
    want sanitize && RESULT[sanitize]=BUILD_FAIL
    want fuzz     && RESULT[fuzz]=BUILD_FAIL
fi

want tsan       && { build tsan     || RESULT[tsan]=BUILD_FAIL; }
want invariants && { build debug    || RESULT[invariants]=BUILD_FAIL; }

# The coverage-guided half, which nothing else here builds.
#
# This job used to run whatever binaries happened to be under bin/ — on
# 2026-08-13 that was a libFuzzer build twelve days old, against a Sanitize
# build of three.  A stale fuzz binary does not merely test old code: its own
# translation unit is recompiled at link time while its cached SDK objects are
# not, so the two disagree about the layout of the runtime they share, and what
# the job reports is a defect that exists in neither build.  That is what the
# 2026-08-13 client finding was, and the seed 75afc3a filed as
# stale_binary_artifact-f57f22fc before it.  So the fuzz job builds what it is
# about to run, like every other job here.
#
# Exit 1 is "no clang, or no libFuzzer runtime" — build_libfuzzer.sh's own
# contract, and the replay driver still covers the targets — so it is reported
# and not fatal.  Exit 2 is a build that was attempted and failed, which is.
if want fuzz && [ -z "${RESULT[fuzz]:-}" ]; then
    printf '  build %-9s ' libfuzzer
    bash test/fuzz/build_libfuzzer.sh >"$RUNDIR/build-libfuzzer.log" 2>&1
    case $? in
        0) echo "ok" ;;
        1) echo "unavailable — replay driver only (see $RUNDIR/build-libfuzzer.log)" ;;
        *) echo "FAIL (see $RUNDIR/build-libfuzzer.log)"; RESULT[fuzz]=BUILD_FAIL ;;
    esac
fi
echo

# ─── phase 1: everything that only decides pass or fail ─────────────────────
#
# Concurrent, because none of these reports a number that contention could
# change -- they answer whether something is broken, and that answer is the same
# under load.
echo "── phase 1 (concurrent) ──"
declare -A PID
run_bg() { # name, command...
    local name=$1; shift
    "$@" >"$RUNDIR/$name.log" 2>&1 &
    PID[$name]=$!
    echo "  started $name (pid ${PID[$name]})"
}

want release  && [ -z "${RESULT[release]:-}"  ] && \
    run_bg release  env SOCKETLEY_CONFIG=Release  bash test/run_all.sh
want sanitize && [ -z "${RESULT[sanitize]:-}" ] && \
    run_bg sanitize env SOCKETLEY_CONFIG=Sanitize bash test/run_all.sh
want tsan     && [ -z "${RESULT[tsan]:-}"     ] && \
    run_bg tsan     env SOCKETLEY_CONFIG=TSan     bash test/run_all.sh
# Positional, not an environment variable: run_fuzz.sh reads its budget from
# $1 and defaults to 10 seconds, so passing FUZZ_SECONDS= would have run a
# tenth-of-a-minute fuzz and reported it as a nightly.
want fuzz && [ -z "${RESULT[fuzz]:-}" ] && \
    run_bg fuzz     bash test/fuzz/run_fuzz.sh "$FUZZ_SECONDS"

for name in "${!PID[@]}"; do
    if wait "${PID[$name]}"; then RESULT[$name]=PASS; else RESULT[$name]=FAIL; fi
done
echo

# ─── phase 2: the ones that measure, alone ──────────────────────────────────
echo "── phase 2 (serial — these measure) ──"
if want load; then
    printf '  load harnesses    '
    if bash test/load/run_all.sh >"$RUNDIR/load.log" 2>&1; then
        RESULT[load]=PASS; echo "pass"
    else
        RESULT[load]=FAIL; echo "FAIL"
    fi
fi
if want invariants && [ -z "${RESULT[invariants]:-}" ]; then
    printf '  invariants        '
    if SOCKETLEY_CONFIG=Debug bash test/load/run_all.sh \
           restart_under_load runtime_churn_leak churn_repro \
           >"$RUNDIR/invariants.log" 2>&1; then
        RESULT[invariants]=PASS; echo "pass"
    else
        RESULT[invariants]=FAIL; echo "FAIL"
    fi
fi
echo

# ─── the verdict ────────────────────────────────────────────────────────────
ELAPSED=$(( $(date +%s) - STARTED ))
echo "══ nightly (local) — $((ELAPSED / 60))m $((ELAPSED % 60))s ══"
fail=0
for name in release sanitize tsan fuzz load invariants; do
    r="${RESULT[$name]:-skipped}"
    [ "$r" = "skipped" ] && continue
    # The count alongside the verdict: a suite that passes 141 and one that
    # passes 3 both say PASS, and only one of them ran.
    summary=$(grep -hE "^ Summary:" "$RUNDIR/$name.log" 2>/dev/null | tail -1)
    printf '  %-11s %-10s %s\n' "$name" "$r" "$summary"
    [ "$r" = "PASS" ] || fail=1
done
echo
echo "logs: $RUNDIR"
exit $fail
