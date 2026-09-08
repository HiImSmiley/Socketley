#!/usr/bin/env bash
# Every proxy shape under the profiler, BESIDE HAProxy doing the same work.
#
# ─── WHY BOTH ARMS, WHEN THE CACHE PROFILER ONLY PROFILED OURS ──────────────
#
# For the cache, ours was the only profile worth taking: Redis's internals are
# not ours to change, and the finding was always "this command spends 60% of the
# worker in our own code and its neighbours spend 3%".
#
# A proxy is different, because a proxy does almost nothing of its own.  Measured
# here before: the worker is 94.8% kernel and 5.5% userspace, and inside that
# userspace liburing is 0.42%, malloc 0.25% and socketley's own symbols 0.14%.
# A ranking of our own share would therefore rank noise, and every row would say
# "the network path dominates" -- which is true, and which no amount of our code
# can be blamed for or credited with.
#
# What CAN be read off a proxy profile is the SPLIT, against a second program
# doing the identical forwarding.  Both arms move the same bytes between the same
# two sockets.  So if we spend materially more of the CPU in the kernel than
# HAProxy does for the same shape, we are making more syscalls -- or heavier ones
# -- per unit of forwarded traffic, and that is a fixable thing that a profile of
# ours alone cannot show.  That is the axis this file adds.
#
# ─── AND THE SECOND AXIS: COST PER OPERATION ────────────────────────────────
#
# A share is a proportion and says nothing about the size of the pie.  A proxy
# at 0.51 cores serving 25,000 round trips a second and one at 0.56 serving
# 22,000 have nearly identical profiles and different efficiencies.  So every
# row also carries microseconds of CPU per operation, for both arms, taken from
# the same window as the samples.  That number is what a change has to move.
#
# ─── WHAT MAKES THE OUTPUT MEAN ANYTHING ────────────────────────────────────
#
# lib_profile.sh carries the four refusals -- the perf wrapper, paranoid, the
# stripped binary, the root-owned data file -- each of which has produced a
# complete and entirely blind table here before.  On top of them:
#
#   THE FIXTURES ARE THE MATRIX'S OWN, from lib_proxy_fixtures.sh, so a profile
#   explains a row somebody actually measured.
#
#   THE CLIENT IS CHECKED.  A load generator at its ceiling profiles an idle
#   proxy, and the profile of an idle proxy is a profile of epoll_wait.  The
#   client's own CPU is read for every cell and reported beside the row.
#
#   SINGLE MODE ONLY.  A sharded proxy is four processes and `perf record -p`
#   takes one, so a sharded profile would be a quarter of the work under a name
#   that claims all of it.  What is learned in single mode transfers; what is
#   not is which shard got the connection, and that is not a code question.
#
# Usage:
#   bash test/benchmark/profile_proxy_scenarios.sh
#   PROF_SECS=5 PROF_ONLY='UNIX-64 TCP-64' bash .../profile_proxy_scenarios.sh
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
cd "$ROOT" || exit 2

PROF_SECS=${PROF_SECS:-4}          # sampling window per cell
PROF_FREQ=${PROF_FREQ:-997}        # Hz, prime so it does not beat with a timer
PROF_ONLY=${PROF_ONLY:-}           # space separated row names, empty = all
# A row is listed when the two arms' kernel shares differ by this much, or when
# our own userspace share reaches PROF_MIN_OURS.  Everything else is counted.
PROF_MIN_SPLIT=${PROF_MIN_SPLIT:-6}
PROF_MIN_OURS=${PROF_MIN_OURS:-6}

# The port block and the row table, from the matrix rather than from a copy.  A
# private table drifts and the drift shows up as a profile of a shape nobody
# measured.
PROXY_MATRIX_TABLE_ONLY=1
export PROXY_MATRIX_TABLE_ONLY
# shellcheck disable=SC1090
source "$HERE/bench_proxy_matrix.sh"
unset PROXY_MATRIX_TABLE_ONLY

source "$HERE/lib_profile.sh"

MODE=single                        # see the header: -p takes one pid
SHARDS=1
# One second of setup, the sampling window, and a second past it, so the
# client finishes on its own and prints the summary the rate is read from.
RUN_MS=$(( (PROF_SECS + 2) * 1000 ))

TS=$(date +%Y%m%d_%H%M%S)
OUT=${PROF_OUT:-$ROOT/test/benchmark/results/proxy_profile_$TS.md}
WORK=$(mktemp -d /tmp/pprof.XXXXXX)
PM_HOME=$WORK/home
PM_SOCK=$WORK/d.sock
mkdir -p "$PM_HOME" "$(dirname "$OUT")"
DAEMON_PID=""; BENCH_PID=""
# Counted in a file and not a variable: a loop behind a pipe is a subshell and
# every increment made there is discarded at its end.  A counter that silently
# reads zero is how a blind run passes for a clean one.
BLIND_F=$WORK/blind.count
CELLS_F=$WORK/cells.count

say() { printf '%s\n' "$*"; }
die() { printf 'profile: %s\n' "$*" >&2; exit 2; }

# Only this run's processes: they carry its private socket in their environment,
# and matching on that leaves other agents' daemons alone.  Never `pgrep -f`,
# which matches the shell doing the matching.
sweep() {
    local p c
    for p in $(pgrep -x socketley 2>/dev/null); do
        grep -qz "SOCKETLEY_SOCKET=$PM_SOCK" "/proc/$p/environ" 2>/dev/null || continue
        for c in $(pgrep -P "$p" 2>/dev/null); do kill -9 "$c" 2>/dev/null; done
        kill -9 "$p" 2>/dev/null
    done
    return 0
}
cleanup() {
    [ -n "$BENCH_PID" ] && kill -9 "$BENCH_PID" 2>/dev/null
    [ -n "${HA_PID:-}" ] && kill -9 "$HA_PID" 2>/dev/null
    sweep; sleep 0.3; sweep
    [ -n "$DAEMON_PID" ] && kill -9 "$DAEMON_PID" 2>/dev/null
    rm -rf "$WORK"
    return 0
}
trap cleanup EXIT INT TERM

# ─── Refusals ───────────────────────────────────────────────────────────────

command -v haproxy >/dev/null 2>&1 || die "haproxy is not installed; there is no second arm to profile"
[ -x "$SOCKETLEY_BENCH" ] || die "socketley_bench is not built"
PERF=$(profile_find_perf) || die "no perf binary found"
profile_require_perf || die "perf_event_paranoid denies profiling; sudo sysctl -w kernel.perf_event_paranoid=1 kernel.kptr_restrict=0"

busy=$(
    ps=$(pgrep -x socketley 2>/dev/null | tr '\n' ' '); t0=0; t1=0
    for p in $ps; do t0=$((t0 + $(awk '{print $14+$15}' /proc/$p/stat 2>/dev/null || echo 0))); done
    sleep 0.3
    for p in $ps; do t1=$((t1 + $(awk '{print $14+$15}' /proc/$p/stat 2>/dev/null || echo 0))); done
    awk -v d=$((t1 - t0)) -v hz="$(getconf CLK_TCK)" 'BEGIN{printf "%.2f", d / hz / 0.3}')
awk -v b="$busy" 'BEGIN{exit !(b > 0.05)}' \
    && die "socketley processes on this box are burning $busy cores; a profile taken beside them is not attributable"

say "linking a symbol-bearing build if the Release is newer (Release strips)"
BIN=$(profile_symbol_build "$ROOT" "$WORK/build.log") \
    || die "the symbol-bearing build failed, see $WORK/build.log"
SOCKETLEY_BIN=$BIN

# ─── The fixtures, which are the matrix's own ───────────────────────────────

export HOME=$PM_HOME
export SOCKETLEY_SOCKET=$PM_SOCK
unset SOCKETLEY_CONFIG            # a config PATH, not a build selector

"$SOCKETLEY_BIN" daemon >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 100); do [ -S "$PM_SOCK" ] && break; sleep 0.1; done
[ -S "$PM_SOCK" ] || die "the private daemon did not come up"

source "$HERE/lib_proxy_fixtures.sh"
proxy_fixtures_ports_free || exit 2
proxy_fixtures_up   || die "the fixtures did not come up"
proxy_fixtures_check || die "the two arms are not serving the same thing"

# The binary the fixtures actually started, so a stripped one cannot be profiled
# under a name that promises symbols.
w=${SKPIDS[tcp]%% *}
readlink -f "/proc/$w/exe" 2>/dev/null | grep -q '/bin/Profile/socketley$' \
    || die "the worker is running $(readlink -f "/proc/$w/exe" 2>/dev/null), not the symbol-bearing build"

# ─── One cell ───────────────────────────────────────────────────────────────

ticks_sum() {
    local t=0 p
    for p in $1; do t=$((t + $(awk '{print $14+$15}' "/proc/$p/stat" 2>/dev/null || echo 0))); done
    echo "$t"
}

start_load() {   # port shape conns payload -> sets BENCH_PID
    local port=$1 shape=$2 conns=$3 payload=$4
    case "$shape" in
        serial)
            "$SOCKETLEY_BENCH" -r 1 -d "$RUN_MS" proxy tcp 127.0.0.1 "$port" \
                100000000 "$payload" >"$WORK/cell.txt" 2>&1 & ;;
        concurrent)
            "$SOCKETLEY_BENCH" -r 1 -d "$RUN_MS" proxy concurrent 127.0.0.1 "$port" \
                "$conns" 100000000 >"$WORK/cell.txt" 2>&1 & ;;
        http-keepalive|http-close)
            "$SOCKETLEY_BENCH" -r 1 -d "$RUN_MS" -u "$payload" proxy "$shape" \
                127.0.0.1 "$port" "$conns" 100000000 >"$WORK/cell.txt" 2>&1 & ;;
    esac
    BENCH_PID=$!
}

# Echoes: kernel ours libs top1 pct1 top2 pct2 px_cores cli_cores
profile_cell() {   # name arm port pids shape conns payload own_dso
    local name=$1 arm=$2 port=$3 pids=$4 shape=$5 conns=$6 payload=$7 own=$8
    local p0 p1 c0 c1 w0 w1

    start_load "$port" "$shape" "$conns" "$payload"
    sleep 1.0                                  # past connection setup
    if ! kill -0 "$BENCH_PID" 2>/dev/null; then
        BENCH_PID=""
        # Counted and named.  A client that died on an error is not a cheap
        # shape, and leaving it out of both counters is how a row reads "-"
        # under a summary that said nothing was wrong.
        echo "$name/$arm" >> "$WORK/refused.txt"
        printf -- "- - - refused - - - 0 0"; return
    fi
    p0=$(ticks_sum "$pids"); c0=$(ticks_sum "$BENCH_PID"); w0=$(date +%s%N)
    rm -f "$WORK/p.data"
    sudo -n "$PERF" record -e cpu-clock -F "$PROF_FREQ" -g -p "${pids%% *}" \
        -o "$WORK/p.data" -- sleep "$PROF_SECS" >/dev/null 2>&1
    w1=$(date +%s%N); p1=$(ticks_sum "$pids"); c1=$(ticks_sum "$BENCH_PID")
    # Waited for, not killed.  A client killed with -9 writes no summary line,
    # so the rate reads zero and every microsecond-per-operation figure built on
    # it comes out in the millions -- which is what the first run of this file
    # printed, in a table that otherwise looked complete.
    wait "$BENCH_PID" 2>/dev/null; BENCH_PID=""

    local rep sum
    rep=$(profile_parse_report "$PERF" "$WORK/p.data" "$own")
    # A cell whose three shares sum to nothing profiled nothing, and it has to
    # say so rather than print zeroes: a blind run otherwise writes a complete,
    # plausible table that sorts every shape to the bottom as if it were cheap.
    sum=$(awk '{print ($1 + $2 + $3 > 0.5) ? 1 : 0}' <<<"$rep")
    if [ "$sum" != "1" ]; then
        echo x >> "$BLIND_F"
        printf -- "- - - no-samples - - - 0 0"; return
    fi
    echo x >> "$CELLS_F"
    printf '%s %s' "$rep" "$(awk -v px=$((p1 - p0)) -v cl=$((c1 - c0)) -v hz="$(getconf CLK_TCK)" \
        -v ns=$((w1 - w0)) 'BEGIN { s = ns / 1e9; printf "%.3f %.3f", px / hz / s, cl / hz / s }')"
}

# The rate the load generator achieved, from the summary it prints on its way
# out.  Zero when the client never finished, which the caller reports as such
# rather than dividing by it.
cell_rate() {
    grep -oE '^[[:space:]]*Median:[[:space:]]+[0-9]+' "$WORK/cell.txt" 2>/dev/null \
        | grep -oE '[0-9]+' | head -1
}

# ─── Run ────────────────────────────────────────────────────────────────────

say ""
say "profiling $PROF_SECS s per arm per shape at ${PROF_FREQ}Hz, single mode"
: > "$WORK/rows.txt"
while IFS='|' read -r name fix shape conns payload; do
    case "$name" in ''|'#'*) continue ;; esac
    if [ -n "$PROF_ONLY" ] && ! grep -qw "$name" <<<"$PROF_ONLY"; then continue; fi
    spath=$payload; hpath=$payload
    case "$shape" in http-*) spath="/$SK_HTTP_NAME/$payload"; hpath="/$payload" ;; esac

    s=$(profile_cell "$name" sk  "${SKPORT[$fix]}" "${SKPIDS[$fix]}" "$shape" "$conns" "$spath" socketley)
    srate=$(cell_rate)
    h=$(profile_cell "$name" hap "${HAPORT[$fix]}" "$HA_PIDS"        "$shape" "$conns" "$hpath" haproxy)
    hrate=$(cell_rate)

    printf '%s|%s|%s %s|%s %s\n' "$name" "$fix" "$s" "${srate:-0}" "$h" "${hrate:-0}" >> "$WORK/rows.txt"
    printf '  %-12s sk kernel %5s%% ours %5s%%   hap kernel %5s%% own %5s%%\n' \
        "$name" "$(awk '{print $1}' <<<"$s")" "$(awk '{print $2}' <<<"$s")" \
        "$(awk '{print $1}' <<<"$h")" "$(awk '{print $2}' <<<"$h")"
done < <(printf '%s\n' "$ROWS_DEFAULT" | grep -vE '^[[:space:]]*(#|$)')

# ─── The file ───────────────────────────────────────────────────────────────
#
# Fields per row:
#   1 name  2 fixture
#   3..11  sk: kernel ours libs top1 p1 top2 p2 px_cores cli_cores rate
#   12..20 hap: the same
{
say "# Proxy scenario profile — $TS"
say ""
say "\`cpu-clock\` at ${PROF_FREQ}Hz, ${PROF_SECS}s per arm per shape, single-process"
say "mode on both sides.  Hardware counters are not exposed to this guest, so"
say "these are shares of time, not cycles or cache misses.  A share survives the"
say "host's governor moving under us; an absolute rate does not."
say ""
say "## Where the two arms disagree about the kernel"
say ""
say "Both arms move the same bytes between the same two sockets.  A shape where"
say "our kernel share is materially higher is one where we make more syscalls, or"
say "heavier ones, for the same forwarded traffic — and that is a fixable thing"
say "that a profile of ours alone cannot show.  \`us/op\` is CPU microseconds per"
say "operation, from the same window: the share says where the time goes, this"
say "says how much there is."
say ""
say '| shape | sk kernel | hap kernel | split | sk us/op | hap us/op | us/op ratio |'
say '|---|---|---|---|---|---|---|'
awk -F'|' -v min="$PROF_MIN_SPLIT" '
    {
        split($3, s, " "); split($4, h, " ")
        if (s[1] == "-" || h[1] == "-") { skipped++; next }
        d = s[1] - h[1]
        su = (s[10] > 0 && s[8] > 0) ? s[8] * 1e6 / s[10] : 0
        hu = (h[10] > 0 && h[8] > 0) ? h[8] * 1e6 / h[10] : 0
        r  = (hu > 0) ? su / hu : 0
        if (d >= min || d <= -min || (r > 0 && (r > 1.2 || r < 0.8)))
            printf "| %s | %s%% | %s%% | %+.1f | %.2f | %.2f | %.2fx |\n",
                   $1, s[1], h[1], d, su, hu, r
        else hidden++
    }
    END { print ""
          printf "%d shapes were within %s points on the split and 20%% on the cost,",
                 hidden, min
          printf " and are not listed"
          if (skipped) printf "; %d produced no samples", skipped
          print "." }' "$WORK/rows.txt"
say ""
say "## Our own userspace, ranked"
say ""
say "A proxy does almost nothing of its own — measured before on this box, the"
say "worker is 94.8% kernel and 5.5% userspace — so most rows here are small by"
say "construction.  A shape that stands out from its neighbours is the one worth"
say "reading, because whatever it is doing, the others are not."
say ""
say '| shape | ours | top symbol | % | second | % | sk cores | client cores | rate |'
say '|---|---|---|---|---|---|---|---|---|'
awk -F'|' '
    { split($3, s, " "); if (s[1] == "-") next
      printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", s[2], $1, s[4], s[5], s[6], s[7], s[8], s[9], s[10] }' \
    "$WORK/rows.txt" | sort -gr | awk -F'\t' -v min="$PROF_MIN_OURS" '
    $1 >= min { printf "| %s | %s%% | `%s` | %s | `%s` | %s | %s | %s | %s |\n",
                       $2, $1, $3, $4, $5, $6, $7, $8, $9; shown++ }
    $1 <  min { hidden++ }
    END { print ""; printf "%d rows above %s%%, %d below and not listed.\n", shown, min, hidden }'
say ""
say "## Raw"
say ""
say '```'
say "name|fixture|sk: kernel ours libs top1 p1 top2 p2 cores cli rate|hap: same"
cat "$WORK/rows.txt"
say '```'
} > "$OUT"

say ""
say "wrote $OUT"
BLIND=$( [ -f "$BLIND_F" ] && wc -l < "$BLIND_F" || echo 0)
CELLS=$( [ -f "$CELLS_F" ] && wc -l < "$CELLS_F" || echo 0)
[ "${BLIND:-0}" -gt 0 ] && say "WARNING: $BLIND cells produced no samples"
[ -s "$WORK/refused.txt" ] && say "WARNING: the client died inside these cells: $(tr '\n' ' ' < "$WORK/refused.txt")"
# The whole point of the counter: a run where nothing was sampled writes a file
# full of zeroes that reads like a finding.  It is an error, not a result.
[ "${CELLS:-0}" -eq 0 ] \
    && die "every cell was blind; the profile is worthless (check sudo, perf_event_paranoid, and the pids)"
say "$CELLS cells sampled, $BLIND blind"
