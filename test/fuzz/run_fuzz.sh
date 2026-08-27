#!/usr/bin/env bash
# Run every fuzz target that exists, for a fixed budget, and fail loudly.
#
#   ./test/fuzz/run_fuzz.sh <seconds-per-target> [config]
#
#   config   premake config directory under bin/ (default: Sanitize)
#
# Environment:
#   FUZZ_CORPUS_ROOT   seed corpus root, READ ONLY (default test/fuzz/corpus)
#   FUZZ_WORK_ROOT     where libFuzzer writes what it discovers
#                      (default bin/fuzz-corpus, gitignored).  See the note
#                      below on why these are two directories and not one.
#   FUZZ_ARTIFACTS     where a crashing input is written (default bin/fuzz-artifacts)
#   FUZZ_SEED          PRNG seed for the replay driver (default 1)
#   FUZZ_SMUGGLING=0   downgrade the HTTP smuggling oracle to a warning (triage only)
#   FUZZ_CACHE_SKIP    comma-separated finding ids that fuzz_cache_ops demotes
#                      from a failure to a printed observation.  Triage only:
#                      it exists so a run can get past a known defect and look
#                      for the next one.  See the header of fuzz_cache_ops.cpp.
#   FUZZ_HTTPRESP_SKIP the same thing for fuzz_http_response; the ids are the
#                      first argument of each RESP_FINDING in that file.
#   FUZZ_SERVER_SKIP   the same for fuzz_server_ops,
#   FUZZ_CLIENT_SKIP   for fuzz_client_ops, and
#   FUZZ_PROXY_SKIP    for fuzz_proxy_ops; the ids are the first argument of
#                      each RT_FINDING in those files and in fuzz_runtime_ops.h.
#   FUZZ_LOOP_SKIP     the same thing for fuzz_event_loop; the ids are the first
#                      argument of each LOOP_FINDING in that file.
#   REQUIRE_LIBFUZZER=1  a target with no libFuzzer binary is a failure rather
#                      than a target that quietly ran the replay driver only.
#                      Set this anywhere the runner is known to have clang —
#                      otherwise a broken build_libfuzzer.sh downgrades the job
#                      to the GCC floor and still reports green.
#   FUZZ_TARGETS       which targets to run (default: all nine).  Every target
#                      named here must exist or the run fails — narrowing the
#                      set is a decision the caller states, never something that
#                      happens because a binary quietly was not built.
#   FUZZ_PROXY_MATRIX  the pinned proxy configurations the seed corpus is
#                      replayed over, ';'-separated (default: the three below).
#                      Empty skips the sweep entirely — for a triage run only;
#                      CI must not, because the sweep is the only thing holding
#                      1ab3141's predicate down.  See THE CONFIGURATION MATRIX.
#   FUZZ_MATRIX_SECONDS  mutation budget per matrix entry (default 0 = replay
#                      the seeds and stop).  Raise it for a manual dig into one
#                      configuration; leaving it at 0 is what makes the sweep
#                      cost seconds rather than minutes.
#
# WHAT THIS COVERS.  The four parsers an unauthenticated peer can reach — RESP,
# WebSocket frames, the proxy's HTTP request line and header block, and the
# proxy's response framing, which is the one that decides whether a backend
# socket may be pooled — plus five targets of a different kind, which check
# accounting and lifetime invariants after every step rather than looking for a
# crash on one buffer: cache_store driven as a sequence of operations, the event
# loop's completion handling driven as a scripted order of CQEs, and the server,
# client and proxy runtimes driven as sequences of lifecycle and connection
# operations against a real ring.
#
# WHAT IT DOES NOT.  No kernel behind the event loop — fuzz_event_loop scripts
# the arrivals and checks the books, it does not prove a submission was really
# consumed — no command dispatch between the RESP parser and the store, no
# load() over a file that save() did not write, and no Lua anywhere except the
# one filter chain fuzz_proxy_ops loads.  A green run here says these nine
# survived the inputs tried; it says nothing about the code that calls them.
#
# ─── TWO CORPUS DIRECTORIES, ON PURPOSE ─────────────────────────────────────
#
# libFuzzer writes every input it finds interesting back into the *first*
# corpus directory on its command line.  This script used to pass the tracked
# seed directory there, so a nightly run added several thousand files to a
# directory under version control: test/fuzz/corpus/cache went from 37 seeds to
# 6783 files, none of them readable, none of them reviewed, and all of them in
# the repository.  The seeds stopped being seeds.
#
# So the seed directory is now passed second — libFuzzer reads additional corpus
# directories and never writes to them — and a working directory under bin/ is
# passed first.  The working set is what grows during a run and what CI carries
# between runs through actions/cache; the repository holds only what
# make_corpus.py generates plus a handful of hand-added reproducers.  A future
# run cannot swell the tracked set because it is not writable from libFuzzer's
# point of view at all.
#
# ─── THE CONFIGURATION MATRIX ───────────────────────────────────────────────
#
# Every seed in test/fuzz/corpus/proxy starts from the default proxy
# configuration.  Only the operation stream differs between them, so 64 seeds
# are 64 programs against one proxy — and a defect that exists only in another
# configuration is invisible to all 64 however long they are mutated.
#
# That is not hypothetical.  1ab3141 is a half-closed client losing its answer
# on a proxy running --backend-timeout 0: the predicate deciding whether an
# answer was still owed rested on a flag that arm_response_deadline() never sets
# when the deadline is switched off, and with no deadline there is no sweep to
# answer 502/504 in its place either.  The seed for exactly that loss —
# proxy/client_fin_after_a_whole_request — replays clean on a broken build,
# because it does not pin the value.  It was found by hand-editing
# fuzz_proxy_ops.cpp to hard-code the timeout, and a defect found that way stays
# fixed only for as long as somebody remembers to do it again.
#
# So the corpus is replayed once more per pinned configuration.  FUZZ_PROXY_CONFIG
# builds every instance with those values and refuses OP_CONFIG for them, so the
# configuration is a property of the run and the input cannot leave it.  Which
# configurations, and why these:
#
#   backend-timeout=0        The response deadline off.  No 502/504 sweep, and
#                            an unbounded wait — the one setting that has
#                            already hidden a defect here.
#   circuit-threshold=0      The breaker off.  A backend that fails is dialled
#                            again for ever instead of being taken out, so
#                            every failure path is walked rather than
#                            short-circuited after the fifth.
#   both at once             Where the two removals meet: no deadline to end a
#                            wait and no breaker to stop the retrying.
#
# Those two are chosen and the other knobs are not, on one rule: a setting whose
# *disabling* value removes a guarantee, and which is on by default so the
# corpus has never run without it.  retries, max-connections and idle-timeout
# all default to 0 already — the corpus runs with them off on every seed, and
# pinning them off would be a second copy of the default run.
#
# WHAT IT COSTS.  Replay only, seeds only, zero mutation budget: about a second
# per entry for all 64 seeds on a developer box, three entries, so a few seconds
# on a job that already spends 2 x 9 x 600.  It is deliberately not given a
# libFuzzer pass — that would be a full budget per configuration and would put
# this job past its timeout.
#
# WHAT IT THEREFORE CANNOT SEE.  A defect that needs both a non-default
# configuration *and* a program no seed contains.  The sweep is a guarantee that
# the curated cases still hold in each configuration, not a search inside it.
# FUZZ_MATRIX_SECONDS turns each entry into a mutation run for a manual dig.
#
# WHY THE WORK CORPUS IS NOT IN IT.  The matrix replays the tracked seeds and
# nothing else: it has to cost the same every night, and $work grows without
# bound through actions/cache.  The work corpus is already replayed once, under
# the default configuration, in the step above.
#
# WHY IT FAILS LOUDLY.  Three separate ways a fuzz step can pass while doing
# nothing — missing binaries, an empty corpus, a target that exits 0 without
# executing anything — have to be errors, or the job becomes decoration.  Every
# one of them is checked below and by the replay driver itself.

set -uo pipefail

SECS="${1:-10}"
CONFIG="${2:-Sanitize}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

BIN_DIR="$ROOT/bin/$CONFIG"
CORPUS_ROOT="${FUZZ_CORPUS_ROOT:-$ROOT/test/fuzz/corpus}"
WORK_ROOT="${FUZZ_WORK_ROOT:-$ROOT/bin/fuzz-corpus}"
ARTIFACTS="${FUZZ_ARTIFACTS:-$ROOT/bin/fuzz-artifacts}"
LIBFUZZ_DIR="$ROOT/bin/fuzz-libfuzzer"

mkdir -p "$ARTIFACTS" "$WORK_ROOT"

# UBSan must abort rather than print-and-continue: a diagnostic on stderr in a
# job nobody reads is the same as no check at all.
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1:abort_on_error=1${UBSAN_OPTIONS:+:$UBSAN_OPTIONS}"
export ASAN_OPTIONS="abort_on_error=1:detect_leaks=1:allocator_may_return_null=0${ASAN_OPTIONS:+:$ASAN_OPTIONS}"

declare -A CORPUS=(
    [fuzz_resp]=resp
    [fuzz_ws_frame]=ws
    [fuzz_cache_ops]=cache
    [fuzz_http_request]=http
    [fuzz_http_response]=httpresp
    [fuzz_event_loop]=eventloop
    [fuzz_server_ops]=server
    [fuzz_client_ops]=client
    [fuzz_proxy_ops]=proxy
)

read -r -a TARGETS <<< "${FUZZ_TARGETS:-fuzz_resp fuzz_ws_frame fuzz_cache_ops fuzz_http_response fuzz_event_loop fuzz_http_request fuzz_server_ops fuzz_client_ops fuzz_proxy_ops}"

# The pinned configurations the proxy seed corpus is replayed over, on top of
# the default run.  ';' separated because the values themselves are comma
# separated.  See THE CONFIGURATION MATRIX above for why these three.
PROXY_MATRIX_DEFAULT='backend-timeout=0;circuit-threshold=0;backend-timeout=0,circuit-threshold=0'
PROXY_MATRIX="${FUZZ_PROXY_MATRIX-$PROXY_MATRIX_DEFAULT}"
MATRIX_SECONDS="${FUZZ_MATRIX_SECONDS:-0}"

# ─── the targets, side by side ──────────────────────────────────────────────
#
# Nine targets run one after another is where this job's 92 minutes come from,
# and none of that time is spent waiting on anything shared: each target has its
# own corpus and work directory (CORPUS[$target] above), writes artifacts under
# its own prefix, and binds ports from a base of 20000 + getpid() % 4096 — which
# is chosen exactly so that two of these can run at once.  Nothing had to be
# made concurrency-safe here; it already was, and only the loop was serial.
#
# Re-invoking this script once per target rather than backgrounding the loop
# body: the body is long, it counts failures in variables a subshell would not
# give back, and FUZZ_TARGETS already selects a subset. A wrapper that calls the
# thing that works is worth more than a rewrite of ninety-seven lines that must
# keep behaving identically.
#
# HOW MANY AT ONCE.  Cores are the obvious bound and the wrong one: libFuzzer is
# given -rss_limit_mb=2048, so nine at once could ask for 18 GB on a machine
# with ten. Measured peak RSS runs 44 MB (client_ops) to 457 MB (resp), so 600 MB
# per job is a realistic budget with headroom, and the limit stays where it is —
# lowering it would change what the fuzzer tolerates, and a target that hits it
# is a finding rather than a tuning problem. The smaller of the two bounds wins,
# and FUZZ_JOBS=1 restores the old serial behaviour exactly.
FUZZ_JOBS="${FUZZ_JOBS:-0}"
if [ "$FUZZ_JOBS" -eq 0 ]; then
    fz_avail=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 2048)
    fz_by_mem=$(( (fz_avail * 70 / 100) / 600 ))
    [ "$fz_by_mem" -lt 1 ] && fz_by_mem=1
    fz_by_cpu=$(nproc 2>/dev/null || echo 1)
    FUZZ_JOBS=$fz_by_mem
    [ "$fz_by_cpu" -lt "$FUZZ_JOBS" ] && FUZZ_JOBS=$fz_by_cpu
fi
[ "$FUZZ_JOBS" -gt "${#TARGETS[@]}" ] && FUZZ_JOBS=${#TARGETS[@]}

if [ -z "${FUZZ_CHILD:-}" ] && [ "$FUZZ_JOBS" -gt 1 ] && [ "${#TARGETS[@]}" -gt 1 ]; then
    fz_dir=$(mktemp -d "${TMPDIR:-/tmp}/socketley-fuzz-par.XXXXXX")
    echo "=============================================="
    echo " Fuzz run — ${SECS}s per target, config $CONFIG"
    echo " targets: ${TARGETS[*]}"
    echo " $FUZZ_JOBS at a time (cores $(nproc 2>/dev/null || echo ?), 600 MB budgeted each)"
    echo "=============================================="

    fz_started=$(date +%s)
    for fz_t in "${TARGETS[@]}"; do
        # Block until a slot frees. `wait -n` returns on the first child to
        # finish rather than the oldest, so a quick target does not hold a slot
        # behind a slow one.
        while [ "$(jobs -pr | wc -l)" -ge "$FUZZ_JOBS" ]; do wait -n 2>/dev/null || break; done
        FUZZ_CHILD=1 FUZZ_TARGETS="$fz_t" bash "$0" "$SECS" "$CONFIG" \
            >"$fz_dir/$fz_t.log" 2>&1 &
        echo "  started $fz_t"
    done
    wait

    # In the order they were asked for, not the order they finished: a log that
    # reorders itself run to run cannot be diffed against yesterday's.
    fz_fail=0 fz_ran=0
    for fz_t in "${TARGETS[@]}"; do
        echo
        cat "$fz_dir/$fz_t.log"
        # Counts come out of each child's own summary line so that the total
        # means the same thing it does serially — a target contributes several
        # runs (libFuzzer, replay, matrix), not one.
        fz_line=$(grep -oE '[0-9]+ of [0-9]+ fuzz runs failed' "$fz_dir/$fz_t.log" | tail -1)
        if [ -n "$fz_line" ]; then
            fz_fail=$(( fz_fail + $(echo "$fz_line" | awk '{print $1}') ))
            fz_ran=$((  fz_ran  + $(echo "$fz_line" | awk '{print $3}') ))
        else
            fz_clean=$(grep -oE '[0-9]+ fuzz runs, all clean' "$fz_dir/$fz_t.log" | tail -1)
            [ -n "$fz_clean" ] && fz_ran=$(( fz_ran + $(echo "$fz_clean" | awk '{print $1}') ))
        fi
    done

    fz_elapsed=$(( $(date +%s) - fz_started ))
    echo
    echo "=============================================="
    echo " $((fz_elapsed / 60))m $((fz_elapsed % 60))s wall, $FUZZ_JOBS at a time"
    rm -rf "$fz_dir"
    if [ "$fz_ran" -eq 0 ]; then
        echo " ERROR: no fuzz target ran at all."
        exit 2
    fi
    if [ "$fz_fail" -ne 0 ]; then
        echo " $fz_fail of $fz_ran fuzz runs failed."
        echo " Reproducers, if any, are in $ARTIFACTS"
        ls -la "$ARTIFACTS" 2>/dev/null
        exit 1
    fi
    echo " $fz_ran fuzz runs, all clean."
    echo "=============================================="
    exit 0
fi

fail=0
ran=0

echo "=============================================="
echo " Fuzz run — ${SECS}s per target, config $CONFIG"
echo " targets: ${TARGETS[*]}"
echo "=============================================="

for target in "${TARGETS[@]}"; do
    if [ -z "${CORPUS[$target]:-}" ]; then
        echo "FAIL: unknown fuzz target '$target'"
        fail=$((fail + 1))
        continue
    fi
    corpus="$CORPUS_ROOT/${CORPUS[$target]}"
    work="$WORK_ROOT/${CORPUS[$target]}"
    mkdir -p "$work"

    if [ ! -d "$corpus" ] || [ -z "$(ls -A "$corpus" 2>/dev/null)" ]; then
        echo "FAIL $target: corpus $corpus is missing or empty"
        echo "     run: python3 test/fuzz/make_corpus.py"
        fail=$((fail + 1))
        continue
    fi

    # ── libFuzzer: the primary path ──
    # Coverage-guided, so this is the run that actually explores.  The replay
    # driver below is a floor, not a substitute: it has no coverage feedback and
    # will not find what this finds.  When REQUIRE_LIBFUZZER=1 the absence of a
    # binary here is an error — a job that meant to fuzz with coverage and
    # silently ran a fixed corpus instead is the failure mode this guards.
    if [ ! -x "$LIBFUZZ_DIR/$target" ] && [ "${REQUIRE_LIBFUZZER:-0}" = "1" ]; then
        echo "FAIL $target: REQUIRE_LIBFUZZER=1 but $LIBFUZZ_DIR/$target does not exist"
        echo "     build it: ./test/fuzz/build_libfuzzer.sh"
        fail=$((fail + 1))
        continue
    fi

    if [ -x "$LIBFUZZ_DIR/$target" ]; then
        echo "--- $target (libFuzzer) ---"
        # -print_funcs=0 turns off the "NEW_FUNC: 0x... in <name>" lines.
        # They are cosmetic, and each one costs a round trip to llvm-symbolizer
        # against a binary built with full debug info.  On fuzz_cache_ops, which
        # covers thousands of new template instantiations in the first seconds
        # of a run, that was the entire budget: 141 executions in 90 seconds
        # with the lines on, 187,000 in 26 seconds with them off.  Every target
        # pays some of this; none of them needs the output.
        # $work first, $corpus second.  libFuzzer writes new inputs only into
        # the first directory; every further one is read-only additional
        # corpus.  That is the whole of the mechanism keeping discoveries out of
        # the tracked seed set — see the note at the top of this file.
        if ! FUZZ_ARTIFACTS="$ARTIFACTS" "$LIBFUZZ_DIR/$target" \
                "$work" "$corpus" \
                -max_total_time="$SECS" \
                -print_final_stats=1 \
                -print_funcs=0 \
                -artifact_prefix="$ARTIFACTS/${target}-" \
                -rss_limit_mb=2048; then
            echo "FAIL $target (libFuzzer)"
            fail=$((fail + 1))
        fi
        ran=$((ran + 1))
    fi

    # ── GCC replay driver: always, even when libFuzzer ran ──
    if [ ! -x "$BIN_DIR/$target" ]; then
        echo "FAIL $target: $BIN_DIR/$target does not exist"
        echo "     build it: ./bin/premake5 gmake2 && cd make && make config=$(echo "$CONFIG" | tr 'A-Z' 'a-z')_x64 $target"
        fail=$((fail + 1))
        continue
    fi

    echo "--- $target (replay) ---"
    # The replay driver reads every path it is given and writes to none of them,
    # so it gets both: the seeds, and whatever the libFuzzer half just found.
    if ! FUZZ_SECONDS="$SECS" FUZZ_ARTIFACTS="$ARTIFACTS" "$BIN_DIR/$target" "$corpus" "$work"; then
        echo "FAIL $target (replay)"
        fail=$((fail + 1))
    fi
    ran=$((ran + 1))

    # ── the configuration matrix ──
    # Seeds only, and each entry replayed with the configuration pinned for the
    # whole run.  This is what makes "the corpus is clean" a claim about more
    # than one proxy: see THE CONFIGURATION MATRIX at the top of this file for
    # which values and why, and for what it costs.
    if [ "$target" = "fuzz_proxy_ops" ] && [ -n "$PROXY_MATRIX" ]; then
        old_ifs="$IFS"
        IFS=';'
        read -r -a matrix <<< "$PROXY_MATRIX"
        IFS="$old_ifs"
        for pin in "${matrix[@]}"; do
            [ -z "$pin" ] && continue
            echo "--- $target (replay, pinned: $pin) ---"
            if ! FUZZ_SECONDS="$MATRIX_SECONDS" FUZZ_ITERS="${FUZZ_MATRIX_ITERS:-0}" \
                 FUZZ_PROXY_CONFIG="$pin" FUZZ_ARTIFACTS="$ARTIFACTS" \
                 "$BIN_DIR/$target" "$corpus"; then
                echo "FAIL $target (replay, pinned: $pin)"
                echo "     reproduce: FUZZ_PROXY_CONFIG=$pin $BIN_DIR/$target <input>"
                fail=$((fail + 1))
            fi
            ran=$((ran + 1))
        done
    fi
done

echo "=============================================="
if [ "$ran" -eq 0 ]; then
    echo " ERROR: no fuzz target ran at all."
    exit 2
fi
if [ "$fail" -ne 0 ]; then
    echo " $fail of $ran fuzz runs failed."
    echo " Reproducers, if any, are in $ARTIFACTS"
    ls -la "$ARTIFACTS" 2>/dev/null
    exit 1
fi
echo " $ran fuzz runs, all clean."
echo "=============================================="
exit 0
