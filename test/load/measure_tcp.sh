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

    "$BIN" create server sink -p "$port" --mode in -s >/dev/null 2>&1
    "$BIN" create proxy px -p "$((port + 1))" --backend "127.0.0.1:$port" --protocol tcp -s >/dev/null 2>&1
    sleep 1.5

    # Warm-ups: run and discard.  These pay for page faults, socket buffer
    # growth and predictor training; counting them measures the first round.
    local w
    for w in $(seq 1 "$WARMUPS"); do
        pin_load "$BENCH" proxy concurrent 127.0.0.1 "$((port + 1))" 20 100 >/dev/null 2>&1
    done

    local bad=0 ran=0 out rc first="" first_out=""
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
        # Not `echo "$out" | grep -qi`.  This file runs under `set -o pipefail`
        # (common.sh) and `grep -q` exits at its first match, which hands echo a
        # SIGPIPE; the pipeline then reports 141 and this test takes the "no
        # match" branch precisely when it matched.  It is latent only while the
        # output is small enough that echo finishes writing first — which stops
        # being true exactly when a round goes wrong enough to print many
        # INCOMPLETE lines, so the check would go blind in the case it exists
        # for.  A here-string has no pipeline and cannot do that.
        if [ "$rc" -ne 0 ] || grep -qi INCOMPLETE <<<"$out"; then
            bad=$((bad + 1))
            if [ -z "$first" ]; then
                # A round is bad for one of two reasons and only one of them
                # leaves a line worth quoting.  On 2026-08-02 the nightly failed
                # this harness with "1 of 120 rounds incomplete" and printed
                # nothing further: the bench had exited non-zero without an
                # INCOMPLETE line anywhere, and its output was discarded, so the
                # log recorded a failure and no way to read it.  Whatever the
                # reason, the exit code and the tail are kept now.
                first="$(grep -i INCOMPLETE <<<"$out" | head -1)"
                [ -z "$first" ] && first="bench exited $rc with no INCOMPLETE line"
                first_out="$(tail -3 <<<"$out")"
            fi
        fi
    done

    kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
    rm -rf "$rundir"

    printf "  %-10s %2d of %d rounds incomplete   (TIME_WAIT before %s, load %s)%s\n" \
        "$tag" "$bad" "$ran" "$tw0" "$(awk '{print $1}' /proc/loadavg)" \
        "$([ "$dirty" = 1 ] && echo '   [dirty start]')"
    [ -n "$first" ] && echo "      first: $first"
    [ -n "$first_out" ] && { echo "      the bench said, last 3 lines:"; \
        while IFS= read -r l; do echo "        $l"; done <<<"$first_out"; }

    total_bad=$((total_bad + bad))
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
pass "$total_rounds rounds, $total_bad incomplete$note"
