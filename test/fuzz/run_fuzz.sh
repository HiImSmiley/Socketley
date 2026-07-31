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
#   FUZZ_SERVER_SKIP   the same for fuzz_server_ops, and
#   FUZZ_CLIENT_SKIP   for fuzz_client_ops; the ids are the first argument of
#                      each RT_FINDING in those files and in fuzz_runtime_ops.h.
#   FUZZ_LOOP_SKIP     the same thing for fuzz_event_loop; the ids are the first
#                      argument of each LOOP_FINDING in that file.
#   REQUIRE_LIBFUZZER=1  a target with no libFuzzer binary is a failure rather
#                      than a target that quietly ran the replay driver only.
#                      Set this anywhere the runner is known to have clang —
#                      otherwise a broken build_libfuzzer.sh downgrades the job
#                      to the GCC floor and still reports green.
#   FUZZ_TARGETS       which targets to run (default: all seven).  Every target
#                      named here must exist or the run fails — narrowing the
#                      set is a decision the caller states, never something that
#                      happens because a binary quietly was not built.
#
# WHAT THIS COVERS.  The four parsers an unauthenticated peer can reach — RESP,
# WebSocket frames, the proxy's HTTP request line and header block, and the
# proxy's response framing, which is the one that decides whether a backend
# socket may be pooled — plus two targets of a different kind, which check
# accounting and lifetime invariants after every step rather than looking for a
# crash on one buffer: cache_store driven as a sequence of operations, and the
# event loop's completion handling driven as a scripted order of CQEs.
#
# WHAT IT DOES NOT.  No kernel behind the event loop — fuzz_event_loop scripts
# the arrivals and checks the books, it does not prove a submission was really
# consumed — no connection lifecycle, no Lua, no command dispatch between the
# RESP parser and the store, and no load() over a file that save() did not
# write.  A green run here says these six survived the inputs tried; it says
# nothing about the code that calls them.
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
)

read -r -a TARGETS <<< "${FUZZ_TARGETS:-fuzz_resp fuzz_ws_frame fuzz_cache_ops fuzz_http_response fuzz_event_loop fuzz_http_request fuzz_server_ops fuzz_client_ops}"

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
