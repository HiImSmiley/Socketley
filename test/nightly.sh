#!/usr/bin/env bash
# The six jobs of the nightly workflow run on this machine instead of GitHub's
# runners, because the workflow bills a private repository by the summed minute
# -- 184 across six jobs -- and has not started at all since payment failed,
# which looks exactly like a passing run to anyone reading only the colour;
# phase 1 runs concurrently because each suite claims its own port window,
# socket and HOME and sweeps only its own configuration, while the load and
# invariant harnesses run alone since a measurement taken under unknown
# contention is a different question answered by accident -- and the invariants
# suite belongs in phase 2 despite fitting phase 1's entry condition, because
# test_abrupt_client_abort.sh calibrates its floors on Release and reads 9
# instead of 60 with four other suites on the cores.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

RUNDIR="${NIGHTLY_RUNDIR:-$(mktemp -d "${TMPDIR:-/tmp}/socketley-nightly.XXXXXX")}"
mkdir -p "$RUNDIR"

# The CI value is a budget for an unattended run rather than one somebody is
# waiting on, so the local default is shorter and the knob is here rather than
# buried.
FUZZ_SECONDS="${FUZZ_SECONDS:-120}"

JOBS=("$@")
[ ${#JOBS[@]} -eq 0 ] && JOBS=(release sanitize tsan fuzz load invariants)

want() { local j; for j in "${JOBS[@]}"; do [ "$j" = "$1" ] && return 0; done; return 1; }

# Not `pgrep -f`: it matches the whole command line, including the shell that
# merely carries the string in its arguments, which has killed the killer here
# before.
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

# The makefiles carry this machine's architecture in their configuration names, so it is read from the ones premake wrote.
platform() {
    local p
    p=$(sed -n 's/^  config=debug_//p' make/Makefile 2>/dev/null)
    [ -n "$p" ] || { [ "$(uname -m)" = aarch64 ] && p=arm64 || p=x64; }
    printf '%s' "$p"
}

# ─── builds, one at a time ──────────────────────────────────────────────────
# Serially and deliberately, because a parallel link of two sanitized
# configurations is where this machine has run out of memory and a build that
# dies halfway costs more than the minutes it saved.
build() {
    # Two statements rather than one, because bash expands every word of a
    # `local` command before assigning any of them, so reading cfg in the same
    # statement that sets it is fatal under `set -u`.
    local cfg=$1
    local extra_cppflags=${2:-}
    local log="$RUNDIR/build-$cfg.log"
    printf '  build %-9s ' "$cfg"
    if make -C make "config=${cfg}_$(platform)" -j"$(nproc)" \
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

# Sanitize is two jobs' build, because the fuzz job runs the replay half of
# every target out of bin/Sanitize even when the sanitize suite is not among
# the jobs.
SANITIZE_BUILT=1
if want sanitize || want fuzz; then
    build sanitize || SANITIZE_BUILT=0
fi
if [ "$SANITIZE_BUILT" -eq 0 ]; then
    want sanitize && RESULT[sanitize]=BUILD_FAIL
    want fuzz     && RESULT[fuzz]=BUILD_FAIL
fi

want tsan       && { build tsan     || RESULT[tsan]=BUILD_FAIL; }
# The invariants are a compile-time option and the whole job is worthless
# without them, so the flag's arrival is verified from two markers in two
# different translation units -- not `nm | grep skl_inv`, which a symbol from
# any single TU satisfies and which was measured passing on a binary with every
# check compiled out.
INV_MARKERS=(
    'nothing in flight on either half'   # invariants.h, check_pair
    'answer-owed-close'                  # proxy_instance.cpp, close_pair
)
if want invariants; then
    if build debug "-DSOCKETLEY_INVARIANTS -DSOCKETLEY_INVARIANTS_WARN_ONLY"; then
        for m in "${INV_MARKERS[@]}"; do
            # Not `grep -q`: it exits at the first match, and `strings` on this
            # binary is long enough that the SIGPIPE is reliable rather than
            # theoretical.
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

# The fuzz job builds what it is about to run, because a stale fuzz binary's
# own translation unit is recompiled at link time while its cached SDK objects
# are not, so the two disagree about the layout of the runtime they share and
# the job reports a defect that exists in neither build.
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

# Concurrent, because none of these reports a number contention could change --
# with the fuzz targets pointed at 31000-32767, since they bound ports from
# 20000 + getpid() % 4096 without taking the port-window lock and squatted in a
# window a suite had been promised.
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
# Under setarch -R, because ThreadSanitizer maps its shadow at fixed addresses
# and refuses to start under this machine's address randomisation -- 140 of 141
# tests failing for a binary that never reached main.
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
    # The integration suite as well as the load harnesses, because the
    # invariants are statements about connection handling and three churn
    # harnesses exercise far less of the tree than 128 integration tests.
    SOCKETLEY_CONFIG=Debug bash test/run_all.sh \
        >"$RUNDIR/invariants-suite.log" 2>&1 || ok=0
    SOCKETLEY_CONFIG=Debug bash test/load/run_all.sh \
        restart_under_load runtime_churn_leak churn_repro \
        >"$RUNDIR/invariants-load.log" 2>&1 || ok=0

    # Exit codes are not the whole verdict, because under warn-only a violation
    # prints without aborting, so the grep is the enforcement and daemon_stop
    # is what puts the line in reach of it.
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
    # The count alongside the verdict, because a suite that passes 141 and one
    # that passes 3 both say PASS and only one of them ran.
    summary=$(grep -hE "^ Summary:" "$RUNDIR/$name.log" "$RUNDIR/$name"-*.log \
                   2>/dev/null | tail -1)
    printf '  %-11s %-10s %s\n' "$name" "$r" "$summary"
    [ "$r" = "PASS" ] || fail=1
done
echo
echo "logs: $RUNDIR"
exit $fail
