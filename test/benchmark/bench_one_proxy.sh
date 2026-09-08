#!/usr/bin/env bash
# One proxy shape, both arms, in the two minutes between edits.
#
#   bench_one_proxy.sh UNIX-64                       # a row the matrix defines
#   bench_one_proxy.sh MINE 'tcp|serial|1|16384'     # one you invent
#   ONE_MODES='single sharded' bench_one_proxy.sh TCP-c8
#
# The full matrix is twenty-one shapes against two topologies and it takes most
# of an hour.  Optimising one shape against it means an hour per idea, so ideas
# stop being tried.  This runs the SAME harness -- same pairing, same quiet gate,
# same refusals, same client-cap check -- on one row.
#
# It is a wrapper and not a second implementation on purpose.  A private copy of
# the measuring code is a copy that drifts, and the drift is invisible because
# both halves keep producing plausible numbers.  The cache's equivalent,
# bench_one_command.sh, is the same shape for the same reason.
#
# ─── WHAT IT INHERITS, WHICH IS THE POINT ───────────────────────────────────
#
#   * paired per-pass ratios, not a ratio of two medians
#   * a pair measured while the box was busy is discarded whole
#   * the client's own CPU beside every rate, against what that shape's load
#     generator could hold -- a capped client reads as the two proxies being
#     level, and that has been mistaken for a result here before
#   * throughput per proxy core as well as per second, because a saturated
#     HAProxy makes the raw ratio a statement about the client
#   * the TIME-WAIT wait, so a connection-per-request row does not measure the
#     ephemeral port pool
#
# ─── AND WHAT IT DOES NOT TELL YOU ──────────────────────────────────────────
#
# Absolute rates here are worth nothing across runs.  This box is a guest: the
# host's governor can change under it with no sign from in here, and the laptop
# it runs on switches to powersave on battery.  Both arms move together, so the
# RATIO survives that and the rate does not.  Quote the ratio.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)

if [ $# -lt 1 ]; then
    echo "usage: $0 NAME [ 'fixture|shape|conns|payload' ]" >&2
    echo "   NAME alone looks the row up in bench_proxy_matrix.sh" >&2
    echo "   e.g. $0 UNIX-64" >&2
    echo "        $0 BIG 'tcp|serial|1|65536'" >&2
    exit 1
fi
NAME=$1; SPEC=${2:-}

# The row comes from the matrix's own table when it is not given, so a shape
# tuned here and a shape measured there cannot be different shapes.
if [ -z "$SPEC" ]; then
    SPEC=$(PROXY_MATRIX_TABLE_ONLY=1 bash -c "source '$HERE/bench_proxy_matrix.sh'; printf '%s\n' \"\$ROWS_DEFAULT\"" 2>/dev/null \
           | awk -F'|' -v n="$NAME" '$1 == n { print $2 "|" $3 "|" $4 "|" $5 }' | head -1)
    if [ -z "$SPEC" ]; then
        echo "no row named '$NAME' in bench_proxy_matrix.sh, and no spec given" >&2
        echo "known rows:" >&2
        PROXY_MATRIX_TABLE_ONLY=1 bash -c "source '$HERE/bench_proxy_matrix.sh'; printf '%s\n' \"\$ROWS_DEFAULT\"" 2>/dev/null \
            | awk -F'|' 'NF==5 {printf "  %s\n", $1}' >&2
        exit 1
    fi
fi

MODES=${ONE_MODES:-single}
PAIRS=${ONE_PAIRS:-7}
RUN_MS=${ONE_RUN_MS:-1500}

echo "── $NAME ─ $SPEC ─ $PAIRS pairs ─ ${RUN_MS} ms ──"
for mode in $MODES; do
    PROXY_MATRIX_MODE=$mode \
    PROXY_MATRIX_PAIRS=$PAIRS \
    PROXY_MATRIX_RUN_MS=$RUN_MS \
    PROXY_MATRIX_ROWS="$NAME|$SPEC" \
        bash "$HERE/bench_proxy_matrix.sh" 2>&1 \
        | sed 's/\x1b\[[0-9;]*m//g' \
        | grep -E "^  (shape|─|$NAME) |cannot resolve|no pair survived|refusing|ERROR" \
        | sed "s/^/  [$mode] /"
done
