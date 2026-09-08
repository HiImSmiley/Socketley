#!/usr/bin/env bash
# One server shape against the C floor, in the two minutes between edits.
#
#   bench_one_server.sh LUA-64                     # a row the matrix defines
#   bench_one_server.sh MINE 'lua|msg|1|4096'      # one you invent
#   ONE_PASSES=15 bench_one_server.sh WS-64
#
# The full matrix is twenty rows and takes most of an hour.  Optimising one
# shape against it means an hour per idea, so ideas stop being tried.  This runs
# the SAME harness -- same fixtures, same floor pairing, same quiet gate, same
# interleaving -- on one row.
#
# A wrapper and not a second implementation: a private copy of the measuring
# code drifts, and the drift is invisible because both halves keep producing
# plausible numbers.  bench_one_proxy.sh and bench_one_command.sh are the same
# shape for the same reason.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)

if [ $# -lt 1 ]; then
    echo "usage: $0 NAME [ 'fixture|shape|conns|size' ]" >&2
    echo "   NAME alone looks the row up in bench_server_matrix.sh" >&2
    exit 1
fi
NAME=$1; SPEC=${2:-}

rows() {
    SRV_MATRIX_TABLE_ONLY=1 bash -c "source '$HERE/bench_server_matrix.sh'; printf '%s\n' \"\$ROWS_DEFAULT\"" 2>/dev/null
}
if [ -z "$SPEC" ]; then
    SPEC=$(rows | awk -F'|' -v n="$NAME" '$1 == n { print $2 "|" $3 "|" $4 "|" $5 }' | head -1)
    if [ -z "$SPEC" ]; then
        echo "no row named '$NAME', and no spec given.  known rows:" >&2
        rows | awk -F'|' 'NF==5 {printf "  %s\n", $1}' >&2
        exit 1
    fi
fi

PASSES=${ONE_PASSES:-9}
RUN_MS=${ONE_RUN_MS:-1500}
echo "── $NAME ─ $SPEC ─ $PASSES passes ─ ${RUN_MS} ms ──"
SRV_MATRIX_PASSES=$PASSES SRV_MATRIX_RUN_MS=$RUN_MS SRV_MATRIX_ROWS="$NAME|$SPEC" \
    bash "$HERE/bench_server_matrix.sh" 2>&1 \
    | sed 's/\x1b\[[0-9;]*m//g' \
    | grep -E "^  (row|─|$NAME) |refusing|ERROR|measured nothing"
