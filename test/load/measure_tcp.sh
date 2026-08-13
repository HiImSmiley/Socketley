#!/usr/bin/env bash
# Repeatability of the proxy's TCP path under concurrent load.
#
# Was scratchpad/measure.sh.  Three independent passes of the same binary, each
# from the same defined starting state, each preceded by discarded warm-up
# rounds.  The question it answers is "does this binary lose responses under
# concurrency, and does the answer stay the same across passes" — three passes
# because a single pass cannot distinguish a defect from a bad neighbour on the
# machine.
#
# COVERS:      proxy in tcp mode, 20 concurrent connections x 100 operations,
#              via test/benchmark/bench.c (socketley_bench proxy concurrent).
# DOES NOT:    HTTP framing, WebSocket, runtime lifecycle, any protocol parsing.
#
# FAILS WHEN:  any round reports an incomplete run, or the bench binary cannot
#              be run, or no round produced output at all.  The original version
#              of this script only printed its counts and always exited 0, which
#              is how a run with 12 bad rounds out of 40 became a green step.
#
#   ROUNDS=n            counted rounds per pass (default 40)
#   PASSES=n            passes (default 3)
#   LOAD_MAX_BAD=n      tolerated bad rounds in total (default 0)
#   LOAD_SETTLE_SECS=n  idle before each pass (default 60 — see common.sh)

HARNESS_NAME="measure_tcp"
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

require_bin
require_bench

ROUNDS="${ROUNDS:-40}"
PASSES="${PASSES:-3}"
PORTBASE="${PORTBASE:-21100}"
WARMUPS="${WARMUPS:-3}"
MAX_BAD="${LOAD_MAX_BAD:-0}"

echo "=== Proxy TCP path — $PASSES passes of $ROUNDS rounds ==="
announce_environment

total_bad=0
total_unstable=0
total_rounds=0
dirty_passes=0

one_pass() {
    local tag="$1" port="$2"
    local dirty=0
    preflight || dirty=1
    local tw0 rundir
    tw0="$(time_wait_count)"
    rundir="$(make_run_dir)"

    if ! start_daemon "$rundir"; then
        rm -rf "$rundir"
        return 2
    fi

    # An echoing backend, because `proxy concurrent` measures round trips.
    #
    # This was `--mode in`, which answers nothing — no --mode does, they say
    # which directions the runtime accepts, not that it replies.  That was fine
    # while the harness timed sends; since bench.c was changed to read a reply
    # per request, every client here waited for something that could not come
    # and every round reported 0 of 2000 completed.  120 of 120, which is what
    # a missing fixture looks like next to a race.
    #
    # The benchmark scripts were moved to this file when bench.c changed; this
    # harness reaches the same target through a different path and was missed.
    "$BIN" create server sink -p "$port" \
        --lua "$(cd "$(dirname "${BASH_SOURCE[0]}")/../benchmark" && pwd)/echo.lua" \
        -s >/dev/null 2>&1
    "$BIN" create proxy px -p "$((port + 1))" --backend "127.0.0.1:$port" --protocol tcp -s >/dev/null 2>&1
    sleep 1.5

    # Warm-ups: run and discard.  These pay for page faults, socket buffer
    # growth and predictor training; counting them measures the first round.
    local w
    for w in $(seq 1 "$WARMUPS"); do
        pin_load "$BENCH" proxy concurrent 127.0.0.1 "$((port + 1))" 20 100 >/dev/null 2>&1
    done

    local bad=0 ran=0 out rc first="" first_out="" unstable=0 first_unstable=""
    local r
    for r in $(seq 1 "$ROUNDS"); do
        out="$(pin_load "$BENCH" proxy concurrent 127.0.0.1 "$((port + 1))" 20 100 2>&1)"
        rc=$?
        # A round that produced nothing did not happen.  Counting it as good is
        # how a harness reports success for a proxy that was never contacted.
        if [ -z "$out" ]; then
            echo "  $tag: the bench produced no output at all — treating as no data"
            kill "$DAEMON_PID" 2>/dev/null
            rm -rf "$rundir"
            return 2
        fi
        ran=$((ran + 1))

        # The bench exits 2 for two different reasons and they are not the same
        # claim.  bench.c raises g_incomplete_runs from
        #
        #   INCOMPLETE — a run completed fewer operations than it asked for.
        #                That is a statement about the proxy: something was sent
        #                and did not come back.
        #   UNSTABLE   — the repetitions of one test span more than 100x in
        #                throughput.  That is a statement about the machine:
        #                "at least one run measured something other than
        #                throughput", in bench.c's own words.
        #
        # This harness counted both as "rounds incomplete", which is how the
        # nightly of 2026-08-02 reported `1 of 120 rounds incomplete` for a
        # round whose bench had printed `Success: 2000  Failed: 0` — every
        # operation had completed, and the exit code was the stability check
        # firing on a 2-core shared runner the harness itself declares unfit for
        # comparison ("this measures the scheduler as much as it measures
        # socketley").  A machine reading, counted as a product defect.
        #
        # Not `echo "$out" | grep -q`: this file runs under `set -o pipefail`
        # and `grep -q` exits at its first match, handing echo a SIGPIPE, so the
        # pipeline reports 141 and the test takes the "no match" branch
        # precisely when it matched.  A here-string has no pipeline.
        local marker=""
        marker="$(grep -m1 -E 'socketley-bench: (INCOMPLETE|UNSTABLE)' <<<"$out" || true)"

        case "$marker" in
            *INCOMPLETE*)
                bad=$((bad + 1))
                [ -z "$first" ] && first="$marker"
                ;;
            *UNSTABLE*)
                unstable=$((unstable + 1))
                [ -z "$first_unstable" ] && first_unstable="$marker"
                ;;
            *)
                # Exited non-zero and said neither.  Unclassified, so it counts
                # against the proxy: the alternative is a silent exit code, and
                # this harness has already been red once for a round it could
                # not describe.
                if [ "$rc" -ne 0 ]; then
                    bad=$((bad + 1))
                    [ -z "$first" ] && {
                        first="bench exited $rc and printed neither marker"
                        first_out="$(tail -3 <<<"$out")"
                    }
                fi
                ;;
        esac
    done

    kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
    rm -rf "$rundir"

    printf "  %-10s %2d of %d rounds incomplete, %d unstable   (TIME_WAIT before %s, load %s)%s\n" \
        "$tag" "$bad" "$ran" "$unstable" "$tw0" "$(awk '{print $1}' /proc/loadavg)" \
        "$([ "$dirty" = 1 ] && echo '   [dirty start]')"
    [ -n "$first" ] && echo "      first: $first"
    [ -n "$first_out" ] && { echo "      the bench said, last 3 lines:"; \
        while IFS= read -r l; do echo "        $l"; done <<<"$first_out"; }
    [ -n "$first_unstable" ] && echo "      unstable: $first_unstable"

    total_bad=$((total_bad + bad))
    total_unstable=$((total_unstable + unstable))
    total_rounds=$((total_rounds + ran))
    dirty_passes=$((dirty_passes + dirty))
    return 0
}

for k in $(seq 1 "$PASSES"); do
    settle
    if ! one_pass "pass$k" "$((PORTBASE + k * 10))"; then
        nothing_measured "pass$k could not be measured"
    fi
done

[ "$total_rounds" -eq 0 ] && nothing_measured "no rounds ran"

note=""
[ "$dirty_passes" -gt 0 ] && note=" ($dirty_passes pass(es) started from a dirty machine)"

if [ "$total_bad" -gt "$MAX_BAD" ]; then
    fail "$total_bad of $total_rounds rounds incomplete, tolerated $MAX_BAD$note"
fi

# An UNSTABLE round is bench.c saying "at least one repetition measured
# something other than throughput".  Whether that is about socketley depends
# entirely on whether this machine could be measured at all:
#
#   pinned   — the daemon and the load generator have cores of their own, a
#              100x spread between repetitions of one test is not the scheduler,
#              and it fails here like any other bad round.
#   unpinned — announce_environment has already printed that results are NOT
#              comparable because the two share cores.  A harness that says that
#              and then fails the build on a spread is asserting the thing it
#              just disclaimed.  Reported, counted, and not a verdict.
#
# This is the whole of the 2026-08-02 nightly failure: one unstable round in 120
# on a 2-core runner, reported as "1 of 120 rounds incomplete" over a bench that
# had printed Success: 2000  Failed: 0.
if [ "$total_unstable" -gt 0 ]; then
    if [ "${PIN_AVAILABLE:-0}" = 1 ]; then
        fail "$total_unstable of $total_rounds rounds unstable on a pinned machine$note"
    fi
    note="$note ($total_unstable unstable round(s); this machine is unpinned, so that is not a verdict about socketley)"
fi

pass "$total_rounds rounds, $total_bad incomplete$note"
