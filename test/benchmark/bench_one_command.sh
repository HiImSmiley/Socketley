#!/usr/bin/env bash
# One command, four arms, in the two minutes between edits.
#
#   bench_one_command.sh EVAL 1000 'EVAL return(1) 0'
#   bench_one_command.sh TTL  1000 'TTL KEYTAGvolatile:__rand_int__'
#
# The full matrix is seventy-three commands against two topologies and it takes
# most of an hour.  Optimising one command against it means an hour per idea,
# so ideas stop being tried.  This runs the SAME harness -- same cells, same
# pairing, same refusals -- on one row, and prints the four numbers that decide
# whether a change was worth making:
#
#   socketley alone   vs  redis-server alone
#   socketley sharded vs  a four-master Redis Cluster
#
# It is a wrapper and not a second implementation on purpose.  A private copy
# of the measuring code is a copy that drifts, and the drift is invisible
# because both halves keep producing plausible numbers.
#
# ─── WHAT IT INHERITS, WHICH IS THE POINT ───────────────────────────────────
#
#   * paired per-pass ratios, not a ratio of two medians
#   * the 500,000-operations-per-process floor, under which a cell reports the
#     clock instead of the server
#   * per-cell `timeout`, so one bad cell cannot hang the run
#   * the client-core check, so a cell measuring the load generator says so
#   * a cluster that did not form, or a node that died mid-run, is an error and
#     not a fast-looking number
#
# ─── AND WHAT IT DOES NOT TELL YOU ──────────────────────────────────────────
#
# Absolute rates here are worth nothing across runs.  This box is a guest: the
# host's governor can change under it with no sign from in here, and the laptop
# it runs on switches to powersave on battery.  Both arms move together, so the
# RATIO survives that and the rate does not.  Quote the ratio.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

if [ $# -lt 3 ]; then
    echo "usage: $0 NAME KEYSPACE 'COMMAND TEMPLATE'" >&2
    echo "   e.g. $0 EVAL 1000 'EVAL return(1) 0'" >&2
    exit 1
fi
NAME=$1; RANGE=$2; shift 2
TMPL=$*

PASSES=${ONE_PASSES:-3}
OPS=${ONE_OPS:-1000000}
MODES=${ONE_MODES:-"unsharded sharded"}
OUTD=$(mktemp -d /tmp/one.XXXXXX)
trap 'rm -rf "$OUTD"' EXIT

# A run that starts on a busy box is not salvageable, so it does not start.
LEFT=$(pgrep -x socketley 2>/dev/null | wc -l)
BENCHERS=$(pgrep -x redis-benchmark 2>/dev/null | wc -l)
if [ "$LEFT" -ne 0 ] || [ "$BENCHERS" -ne 0 ]; then
    echo "refusing: socketley=$LEFT redis-benchmark=$BENCHERS still running" >&2
    exit 2
fi

printf '%s | %s | %s\n' "$NAME" "$RANGE" "$TMPL" > "$OUTD/row"
ROW=$(printf '%s|%s|%s' "$NAME" "$RANGE" "$TMPL")

echo "── $NAME ─ $TMPL ─ keyspace $RANGE ─ $PASSES passes ──"
for mode in $MODES; do
    BENCH_MATRIX_MODE=$mode \
    BENCH_MATRIX_PASSES=$PASSES \
    BENCH_MATRIX_OPS=$OPS \
    BENCH_MATRIX_CMDS="$ROW" \
        timeout 1200 bash "$HERE/bench_resp_matrix.sh" > "$OUTD/$mode.log" 2>&1
    rc=$?
    if [ $rc -ne 0 ]; then
        echo "  $mode: harness exited $rc" >&2
        tail -3 "$OUTD/$mode.log" | sed 's/\x1b\[[0-9;]*m//g;s/^/    /' >&2
    fi
    pkill -9 -x redis-benchmark 2>/dev/null
    sleep 3
done

# One line per mode, and the verdict the matrix itself would print.
printf '\n  %-10s %14s %14s %8s %8s  %s\n' arm socketley redis ratio spread verdict
printf '  %s\n' "──────────────────────────────────────────────────────────────────────────"
for mode in $MODES; do
    line=$(sed 's/\x1b\[[0-9;]*m//g' "$OUTD/$mode.log" 2>/dev/null \
           | grep -E "^\s+$NAME\s+[0-9]" | head -1)
    if [ -z "$line" ]; then
        printf '  %-10s %14s %14s %8s %8s  %s\n' "$mode" — — — — "NO ROW — the cell produced nothing"
        continue
    fi
    # Two zeroes together are always the instrument: redis-server cannot be
    # slowed by our code, so a cell where both arms measured nothing measured
    # nothing at all and must not be printed as 0.00x.
    set -- $line
    if [ "$2" = "0" ] && [ "$3" = "0" ]; then
        printf '  %-10s %14s %14s %8s %8s  %s\n' "$mode" — — — — "not measured (both arms zero)"
    else
        printf '  %-10s %14s %14s %8s %7s%%  %s\n' "$mode" "$2" "$3" "$4" \
            "$(awk -v s="$5" 'BEGIN{printf "%.0f", s*100}')" "$(echo "$line" | sed 's/.*[0-9]  *//')"
    fi
done
echo ""
