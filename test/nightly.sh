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
# THE INVARIANTS SUITE STAYS IN PHASE 2, AND IT WAS TRIED IN PHASE 1.  It looks
# like it belongs there: it decides pass or fail, which is this file's entry
# condition for concurrency, and running it serially costs a full integration
# suite of wall clock.  Measured on this ten-core machine:
#
#     four concurrent (Release, Sanitize, TSan, fuzz)          1453 s
#     five concurrent (the same, plus Debug)                   1463 s
#     the Debug suite on its own, which is what phase 2 pays   1204 s
#
# So the fifth suite costs no time that can be told from noise and would take
# twenty minutes off the night.  All five came back 142/0.  It was moved -- and
# the first real nightly on the new arrangement failed two jobs:
#
#     tsan         FAIL   connections reaped: still 1464 live 8 s after the
#                         last client went away
#     invariants   FAIL   enough healthy cache traffic to mean something:
#                         cache_ok=9, wanted at least 60
#
# Both are test_abrupt_client_abort.sh, and both are that test measuring.  Its
# floors are calibrated on Release and it demotes them for a build carrying
# __tsan_ or __asan_ symbols -- a Debug build has neither, so a -O0 binary with
# -DSOCKETLEY_INVARIANTS is held to Release numbers.  It clears them alone
# (142/0 in two runs) and got 9 with four other suites on the cores.  The
# reaping deadline is the same story without the calibration: eight seconds is
# eight seconds however many suites are running.
#
# So this file's premise -- "none of these reports a number that contention
# could change" -- is false for one test that is already in phase 1, and adding
# a fifth suite is what made it say so.  One green run of the five-way
# arrangement was not evidence; the nightly was.  Whoever tries this again:
# the twenty minutes are real, and they cost a job that fails on a test which
# passes alone, which is the fastest way to teach everyone to ignore red.
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
    local extra_cppflags=${2:-}
    local log="$RUNDIR/build-$cfg.log"
    printf '  build %-9s ' "$cfg"
    if make -C make "config=${cfg}_x64" -j"$(nproc)" \
            ${extra_cppflags:+CPPFLAGS="$extra_cppflags"} >"$log" 2>&1; then
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
# The invariants are a compile-time option, and the whole job is worthless
# without them: a CPPFLAGS that never reached the compiler produces a binary with
# every check compiled out, runs the harnesses, and reports green -- which is
# indistinguishable from a run where the invariants held.  This ran that way from
# 52c55fa until now, reporting "3 passed, 0 failed" from a build with no checks
# in it.  invariants.h documents CPPFLAGS as the way to turn itself on; the
# verification below is what makes the flag's arrival a fact rather than a hope.
#
# NOT `nm | grep skl_inv`, which is what this check said first and which was
# measured passing on a binary with the checks compiled out.  Building
# fuzz_proxy_ops with the flag while the socketley_sdk.a it links was built
# without it produced exactly that: two skl_inv symbols in the binary, from the
# fuzz target's own translation unit, and not one check body anywhere.  A symbol
# from any single TU satisfies that grep, so it answers "did anything include the
# header", not "did the flag reach the compiler".
#
# The markers below come from two different translation units on purpose -- one
# from a check body in invariants.h, one from the SKL_INV_FAIL site in
# proxy_instance.cpp.  Both present means the flag reached more than the file
# that happened to be looked at.
INV_MARKERS=(
    'nothing in flight on either half'   # invariants.h, check_pair
    'answer-owed-close'                  # proxy_instance.cpp, close_pair
)
if want invariants; then
    if build debug "-DSOCKETLEY_INVARIANTS -DSOCKETLEY_INVARIANTS_WARN_ONLY"; then
        for m in "${INV_MARKERS[@]}"; do
            # Not `grep -q`: it exits at the first match, and `strings` on this
            # binary is long enough that the SIGPIPE is reliable rather than
            # theoretical.  The workflow carries the same note.
            if ! strings bin/Debug/socketley 2>/dev/null | grep -F "$m" >/dev/null; then
                echo "  invariants NOT compiled in — no '$m' in bin/Debug/socketley"
                echo "  This job would have reported success while checking nothing."
                RESULT[invariants]=BUILD_FAIL
            fi
        done
    else
        RESULT[invariants]=BUILD_FAIL
    fi
fi

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
#
# One thing did have to be arranged rather than merely observed.  The suites
# claim 2000-wide port windows under an flock (integration/lib_ports.sh) at
# 19000, 21000, 23000 and upwards; the fuzz targets bound ports from
# 20000 + getpid() % 4096 and took that lock never.  Running the two together
# therefore had a fuzz target squatting in a window a suite had been promised --
# measured, a Sanitize run in window 21000 came back 139/2 with fuzz live, and
# 141/0 on a quiet machine.  The fuzz job is now pointed at 31000-32767, still
# below the ephemeral range and the one stretch no window reaches.
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
# Under setarch -R, which the workflow does not need and this machine does.
#
# ThreadSanitizer maps its shadow at fixed addresses and refuses to start when
# the loader has put something where it wants to be: "FATAL: ThreadSanitizer:
# unexpected memory mapping", before main().  With randomize_va_space=2 here
# that happens every time -- 140 of 141 tests failed for it, which reads as a
# catastrophic regression and is a binary that never ran.  GitHub's runners lay
# memory out differently and the job passes there, which is exactly why this had
# to be found by running it somewhere else.
#
# -R disables randomisation for the child only, so nothing outside this suite is
# affected, and the sanitizer's own findings are unchanged by it.
want tsan     && [ -z "${RESULT[tsan]:-}"     ] && \
    run_bg tsan     setarch "$(uname -m)" -R env SOCKETLEY_CONFIG=TSan bash test/run_all.sh
# Positional, not an environment variable: run_fuzz.sh reads its budget from
# $1 and defaults to 10 seconds, so passing FUZZ_SECONDS= would have run a
# tenth-of-a-minute fuzz and reported it as a nightly.
want fuzz && [ -z "${RESULT[fuzz]:-}" ] && \
    run_bg fuzz     env SOCKETLEY_FUZZ_PORT_BASE=31000 SOCKETLEY_FUZZ_PORT_TOP=32768 \
                        bash test/fuzz/run_fuzz.sh "$FUZZ_SECONDS"

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
    ok=1
    # The integration suite as well as the load harnesses, which is what the
    # workflow does and this runner did not: three churn harnesses exercise far
    # less of the tree than 128 integration tests, and the invariants are
    # statements about connection handling, which is most of what those tests
    # are.  Running only the harnesses is why this job reported on three files
    # for as long as it has existed.
    SOCKETLEY_CONFIG=Debug bash test/run_all.sh \
        >"$RUNDIR/invariants-suite.log" 2>&1 || ok=0
    SOCKETLEY_CONFIG=Debug bash test/load/run_all.sh \
        restart_under_load runtime_churn_leak churn_repro \
        >"$RUNDIR/invariants-load.log" 2>&1 || ok=0

    # Exit codes are not the whole verdict here.  Under
    # -DSOCKETLEY_INVARIANTS_WARN_ONLY a violation prints and does not abort, so
    # a run can hold every assertion, exit 0, and still have reported that a
    # property this project states about itself does not hold.  The grep is the
    # enforcement; lib_daemon.sh's daemon_stop is what puts the line in reach of
    # it, by echoing the daemon's own log before deleting it.
    hits=$(grep -hF '[invariant]' "$RUNDIR/invariants-suite.log" \
                                  "$RUNDIR/invariants-load.log" 2>/dev/null | wc -l)
    if [ "$hits" -ne 0 ]; then
        ok=0
        echo "FAIL ($hits invariant violation(s))"
        grep -hF '[invariant]' "$RUNDIR/invariants-suite.log" \
                               "$RUNDIR/invariants-load.log" 2>/dev/null \
            | sed 's/^ *//' | sort | uniq -c | sort -rn | head -10 | sed 's/^/      /'
    elif [ "$ok" -eq 1 ]; then
        echo "pass"
    else
        echo "FAIL"
    fi
    [ "$ok" -eq 1 ] && RESULT[invariants]=PASS || RESULT[invariants]=FAIL
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
    # The glob is for invariants, which writes two logs rather than one.  A
    # missing file here costs the count and nothing else, which is precisely why
    # it would go unnoticed -- the line still prints, just without the number
    # that makes it mean anything.
    summary=$(grep -hE "^ Summary:" "$RUNDIR/$name.log" "$RUNDIR/$name"-*.log \
                   2>/dev/null | tail -1)
    printf '  %-11s %-10s %s\n' "$name" "$r" "$summary"
    [ "$r" = "PASS" ] || fail=1
done
echo
echo "logs: $RUNDIR"
exit $fail
