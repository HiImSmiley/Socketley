#!/bin/bash
# Every shape the proxy forwards in, against HAProxy, in one table.
#
# ─── WHY, WHEN TWO FILES ALREADY COMPARE THESE TWO ──────────────────────────
#
# bench_proxy_vs_haproxy.sh measures six cases and bench_proxy_http_vs_haproxy.sh
# seven, both on one fixture: a TCP proxy in front of one loopback backend, or an
# HTTP proxy in front of one static file.  That is the narrowest slice of what
# this proxy does, and it is the slice both implementations are best at.  The
# cache had the same gap until bench_resp_matrix.sh went wide, and going wide is
# what found pub/sub at 3x and EVAL at 0.20x -- neither of which any of the six
# hand-picked cache commands touched.
#
# So this is the same instrument for the proxy: not a contest and not a ranking,
# an OUTLIER DETECTOR.  Drive every fixture the proxy supports through every
# shape it can be driven in, print the ratio against HAProxy doing the same
# thing, and draw the band around our OWN median rather than around 1.00x.  A
# row level with the others is uninteresting whatever it says about HAProxy.  A
# row at half our own norm is a morning's work with a known payoff.
#
# ─── THE FIXTURES, AND WHY EACH IS A SEPARATE ONE ───────────────────────────
#
#   tcp    raw byte forwarding to a loopback TCP backend.  The floor: nothing is
#          parsed, nothing is routed, and what is left is the wake-up path.
#   unix   the same, with an AF_UNIX backend leg.  --backend unix: exists to
#          take TCP out of one of the two hops and the man page claims 2.2-2.4x
#          for a cache on one; nothing has ever checked what a PROXY gets, and
#          HAProxy can address a unix server too, so the comparison is fair.
#   rr4    four backends, round-robin.  Choosing a backend per connection is
#          work neither the tcp nor the unix fixture does at all, and it is the
#          first thing a real deployment turns on.
#   http   request parsing, path routing and a rewritten request line.  This is
#          the mode HAProxy was written for.
#
# Every fixture is fronted by BOTH proxies over the SAME backend object, started
# once and left alone, so a difference between the arms cannot be a difference
# between two fixtures.
#
# ─── THE TRAP THIS FILE INHERITED, AND CHECKS FOR ───────────────────────────
#
# socketley's HTTP proxy routes on a leading `/<runtime-name>/` and strips it;
# HAProxy is given the bare path.  Point both arms at one URL and socketley
# answers 404 -- faster than HAProxy serves the file, and with a close that
# turns the keep-alive case into something else.  Measured that way it "did"
# 6656 req/s and every worker ended in an error no throughput number mentions.
# So each arm gets its own path and both are fetched and required to return 200
# with the same body length before anything is timed.
#
# ─── AND THE ONE THIS FILE ADDS ─────────────────────────────────────────────
#
# TIME-WAIT.  A connection-per-request row opens tens of thousands of sockets a
# second and this box has 28,231 ephemeral ports held for 60 seconds each.  Run
# enough of those rows back to back and the pool, not the proxy, is what the
# table is measuring -- the same build measured 18,370 / 71,546 / 41,459 on
# three consecutive connection benchmarks when that happened in this directory
# before.  Every pair waits for the pool to come back, and the count is printed
# beside the row so a reader can see when it was close.
#
# ─── THE TWO ARMS ───────────────────────────────────────────────────────────
#
# single:  one socketley proxy process against `nbthread 1`.  One event loop
#          each, which is the comparison of the two forwarding paths.
# sharded: `--shards 4` against `nbthread 4`.  Four processes behind one
#          SO_REUSEPORT listener against four threads behind one, which compares
#          two architectures rather than two forwarding paths and says so.  The
#          backend is sharded four ways in this mode as well, because a
#          single-process backend becomes the ceiling long before four shards do
#          and then both arms are measuring it.
#
# Usage:
#   bash test/benchmark/bench_proxy_matrix.sh                    # single
#   PROXY_MATRIX_MODE=sharded bash test/benchmark/bench_proxy_matrix.sh
#   PROXY_MATRIX_ROWS='TCP-64|tcp|serial|1|64' bash ...          # one row
set -uo pipefail

source "$(dirname "$0")/utils.sh"
source "$(dirname "$0")/lib_paired.sh"

MODE=${PROXY_MATRIX_MODE:-single}          # single | sharded
PAIRS=${PROXY_MATRIX_PAIRS:-5}
RUN_MS=${PROXY_MATRIX_RUN_MS:-1500}
OPS_CAP=100000000
TARGET_PCT=${BENCH_RESOLUTION_TARGET:-15}
QUIET_CORES=${BENCH_QUIET_CORES:-1.0}
SHARDS=${PROXY_MATRIX_SHARDS:-4}
# The pool has to be back before a pair starts.  12000 is a little under half of
# this box's 28,231 ephemeral ports: above that a connection-per-request row is
# within a factor of two of the pool and its number is the pool's.
TW_LIMIT=${PROXY_MATRIX_TW:-12000}
TW_WAIT=${PROXY_MATRIX_TW_WAIT:-90}
# Printing only, no measurement: how profile_proxy_scenarios.sh borrows the row
# table without starting anything.
TABLE_ONLY=${PROXY_MATRIX_TABLE_ONLY:-0}

if (( PAIRS < 3 )); then
    log_warn "raising pairs from $PAIRS to 3: fewer cannot produce an interval"
    PAIRS=3
fi

B=${PROXY_MATRIX_PORT_BASE:-24000}
P_BE_TCP=$((B+0))          # the shared TCP backend
P_BE_HTTP=$((B+1))         # the shared HTTP backend
P_BE_RR=$((B+2))           # ..+5, the four round-robin backends
P_SK_TCP=$((B+10)); P_SK_UNIX=$((B+11)); P_SK_RR=$((B+12)); P_SK_HTTP=$((B+13))
P_HA_TCP=$((B+20)); P_HA_UNIX=$((B+21)); P_HA_RR=$((B+22)); P_HA_HTTP=$((B+23))

SK_HTTP_NAME=pm_http       # the path prefix the HTTP arm must be given

# name|fixture|shape|conns|payload
#
# ─── WHAT IS IN HERE AND WHY EACH AXIS EARNS ITS ROWS ───────────────────────
#
# SIZE, on the serial shape.  One connection with one request in flight is the
# latency regime: nothing batches, so every wake-up lands in the number.  The
# sizes step by sixteen because that is where a forwarding path stops being
# wake-up bound and starts being copy bound, and the two proxies need not cross
# over at the same place.
#
# CONNECTIONS, at a fixed 64 bytes.  This is where the wake-ups amortise and
# where an io_uring proxy should be at its best -- one submit can carry work for
# many connections, which a thread-per-loop design cannot do.  If our advantage
# does not grow with the connection count, the batching is not happening.
#
# THE HTTP CLOSE SHAPE, which is not a setting of the keep-alive one.  With
# keep-alive the connection exists already and only the per-request cost is
# left; without it every request pays an accept, a backend connect and two
# teardowns, and whether the proxy pools its backend side is exactly the
# difference being looked for.  On this box the two shapes have disagreed about
# who is faster, which is the whole argument for measuring both.
#
# What is deliberately absent: TLS on either leg, because socketley_bench has no
# TLS client for the proxy tests and a benchmark change would be a build change
# first; health checking and circuit breaking, which change behaviour under
# failure and not throughput under load; and anything with a real NIC.
ROWS_DEFAULT='
TCP-64|tcp|serial|1|64
TCP-1K|tcp|serial|1|1024
TCP-16K|tcp|serial|1|16384
TCP-64K|tcp|serial|1|65536
TCP-c8|tcp|concurrent|8|64
TCP-c32|tcp|concurrent|32|64
TCP-c64|tcp|concurrent|64|64
UNIX-64|unix|serial|1|64
UNIX-16K|unix|serial|1|16384
UNIX-c8|unix|concurrent|8|64
UNIX-c32|unix|concurrent|32|64
RR4-64|rr4|serial|1|64
RR4-c8|rr4|concurrent|8|64
RR4-c32|rr4|concurrent|32|64
HTTPKA-c1|http|http-keepalive|1|small.txt
HTTPKA-c8|http|http-keepalive|8|small.txt
HTTPKA-c32|http|http-keepalive|32|small.txt
HTTPKA-16K|http|http-keepalive|8|large.txt
HTTPCL-c1|http|http-close|1|small.txt
HTTPCL-c8|http|http-close|8|small.txt
HTTPCL-c32|http|http-close|32|small.txt
'
ROWS=${PROXY_MATRIX_ROWS:-$ROWS_DEFAULT}

if [ "$TABLE_ONLY" = "1" ]; then
    return 0 2>/dev/null || exit 0
fi

# ─── Private daemon ─────────────────────────────────────────────────────────
#
# Its own HOME and its own IPC socket, so this cannot disturb -- or be disturbed
# by -- the daemon a developer has running, and so the sweep below can tell its
# own processes from everybody else's by an environment variable rather than by
# a process name.
WORK=$(mktemp -d /tmp/pmatrix.XXXXXX)
PM_HOME=$WORK/home
PM_SOCK=$WORK/d.sock
mkdir -p "$PM_HOME"
HA_PID=""
DAEMON_PID=""

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
    # The backends are floor_server processes and not socketley ones, so the
    # environment-matched sweep below cannot see them.
    command -v proxy_fixtures_down >/dev/null 2>&1 && proxy_fixtures_down
    [ -n "$HA_PID" ] && kill -9 "$HA_PID" 2>/dev/null
    sweep; sleep 0.3; sweep
    [ -n "$DAEMON_PID" ] && kill -9 "$DAEMON_PID" 2>/dev/null
    rm -rf "$WORK"
    return 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM   # see setup_cleanup_trap in utils.sh

if ! command -v haproxy >/dev/null 2>&1; then
    log_error "haproxy is not installed — there is nothing to compare against"
    exit 0
fi
HA_VERSION=$(haproxy -v 2>&1 | head -1 | sed 's/[",]/ /g')

# A run that starts on a busy box is not salvageable, so it does not start.
#
# Refused on CPU and not on existence, which is the difference between a gate
# that fires when it should and one that fires all night.  An idle daemon
# holding no runtimes costs nothing and is the normal state of a developer's
# machine; a socketley actually burning a core is a neighbour whose work lands
# in every number below.  Measured over a third of a second, which is long
# enough to see a busy event loop and short enough not to be a wait.
busy_socketley_cores() {
    local p t0=0 t1=0
    local ps; ps=$(pgrep -x socketley 2>/dev/null | tr '\n' ' ')
    [ -n "$ps" ] || { echo 0; return; }
    for p in $ps; do t0=$((t0 + $(awk '{print $14+$15}' "/proc/$p/stat" 2>/dev/null || echo 0))); done
    sleep 0.3
    for p in $ps; do t1=$((t1 + $(awk '{print $14+$15}' "/proc/$p/stat" 2>/dev/null || echo 0))); done
    awk -v d=$((t1 - t0)) -v hz="$(getconf CLK_TCK)" 'BEGIN{printf "%.2f", d / hz / 0.3}'
}
BUSY=$(busy_socketley_cores)
if awk -v b="$BUSY" 'BEGIN{exit !(b > 0.05)}'; then
    log_error "refusing: socketley processes on this box are burning ${BUSY} cores"
    log_error "a proxy measured beside somebody else's load is not attributable"
    exit 2
fi
check_binary || exit 1
[ -x "$SOCKETLEY_BENCH" ] || { log_error "socketley_bench not built"; exit 1; }

export HOME=$PM_HOME
export SOCKETLEY_SOCKET=$PM_SOCK
unset SOCKETLEY_CONFIG            # a config PATH, not a build selector

"$SOCKETLEY_BIN" daemon >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 100); do [ -S "$PM_SOCK" ] && break; sleep 0.1; done
[ -S "$PM_SOCK" ] || { log_error "the private daemon did not come up"; exit 1; }

# ─── Fixtures ───────────────────────────────────────────────────────────────
#
# Four backends, four socketley proxies, one haproxy with a frontend for each,
# and the checks that say both arms serve the same thing.  In
# lib_proxy_fixtures.sh because profile_proxy_scenarios.sh profiles exactly
# these: a profiler with its own copy of the setup profiles a different program
# than the one this table measured, and nothing in either output would say so.

source "$(dirname "$0")/lib_proxy_fixtures.sh"

proxy_fixtures_ports_free || exit 2
proxy_fixtures_up  || { log_error "the fixtures did not come up"; exit 1; }
proxy_fixtures_check || exit 1

# ─── One measured run ───────────────────────────────────────────────────────

# Ticks over a LIST of pids; see lib_proxy_fixtures.sh for why it is a list.
ticks_sum() {
    local t=0 p
    for p in $1; do t=$((t + $(awk '{print $14+$15}' "/proc/$p/stat" 2>/dev/null || echo 0))); done
    echo "$t"
}
tw_now() {
    ss -s 2>/dev/null | awk -F'timewait ' '/^TCP:/{split($2,a,")"); print a[1]+0}'
}
tw_wait() {
    local i
    for ((i = 0; i < TW_WAIT; i++)); do
        [ "$(tw_now)" -lt "$TW_LIMIT" ] && return 0
        sleep 1
    done
    return 1
}

# What the load generator itself could hold at most, in cores: one thread per
# connection it drives, and never more than the machine has.  A cell whose
# client reaches this is reporting socketley_bench and not either proxy, and
# without the ceiling there is no way to tell that from the two being level.
CORES=$(nproc)
client_ceiling() {   # shape conns -> cores
    local shape=$1 conns=$2 n=1
    case "$shape" in serial) n=1 ;; *) n=$conns ;; esac
    [ "$n" -gt "$CORES" ] && n=$CORES
    echo "$n"
}
# And what the backend behind this fixture could hold: one core per process it
# runs in.  rr4 is four backends whatever the mode; the tcp one is `-n SHARDS`
# when sharded; AF_UNIX has no SO_REUSEPORT so the unix backend is always one.
backend_ceiling() {   # fixture -> cores
    local n; n=$(wc -w <<<"${BEPIDS[$1]}")
    [ "${n:-0}" -lt 1 ] && n=1
    [ "$n" -gt "$CORES" ] && n=$CORES
    echo "$n"
}

measure() {   # port shape conns payload pids bepids -> "rate px_cores be_cores client_cores"
    local port=$1 shape=$2 conns=$3 payload=$4 pids=$5 bepids=$6
    local p0 p1 e0 e1 w0 w1 out rate failed

    p0=$(ticks_sum "$pids"); e0=$(ticks_sum "$bepids"); w0=$(date +%s%N)
    # /usr/bin/time and not a /proc sampler: a run is a second and a half and a
    # sampler on any interval misses most of it.  This is the whole process,
    # threads included, which is what the ceiling above is about.
    case "$shape" in
        serial)
            out=$(/usr/bin/time -f '%U %S' -o "$WORK/cli.t" \
                  timeout "$BENCH_TIMEOUT_CMD" "$SOCKETLEY_BENCH" -r 1 -d "$RUN_MS" \
                  proxy tcp 127.0.0.1 "$port" "$OPS_CAP" "$payload" 2>/dev/null) ;;
        concurrent)
            out=$(/usr/bin/time -f '%U %S' -o "$WORK/cli.t" \
                  timeout "$BENCH_TIMEOUT_CMD" "$SOCKETLEY_BENCH" -r 1 -d "$RUN_MS" \
                  proxy concurrent 127.0.0.1 "$port" "$conns" "$OPS_CAP" 2>/dev/null) ;;
        http-keepalive|http-close)
            out=$(/usr/bin/time -f '%U %S' -o "$WORK/cli.t" \
                  timeout "$BENCH_TIMEOUT_CMD" "$SOCKETLEY_BENCH" -r 1 -d "$RUN_MS" \
                  -u "$payload" proxy "$shape" 127.0.0.1 "$port" "$conns" "$OPS_CAP" 2>/dev/null) ;;
    esac
    w1=$(date +%s%N); p1=$(ticks_sum "$pids"); e1=$(ticks_sum "$bepids")
    local clicpu; clicpu=$(awk '{print $1 + $2}' "$WORK/cli.t" 2>/dev/null || echo 0)

    rate=$(grep -oE '^\s*Median:\s+[0-9]+' <<<"$out" | grep -oE '[0-9]+' | head -1)
    # A run with a failed request is not a slower run, it is a different one: a
    # thread that gave up stopped contributing load and the rate that comes out
    # is for however many were still going.  Zero, which the pairing discards.
    failed=$(grep -oE 'Failed: [0-9]+' <<<"$out" | grep -oE '[0-9]+' | head -1)
    [ "${failed:-0}" -gt 0 ] && rate=0

    awk -v r="${rate:-0}" -v px=$((p1 - p0)) -v be=$((e1 - e0)) -v cl="${clicpu:-0}" \
        -v hz="$HZ" -v ns=$((w1 - w0)) \
        'BEGIN { s = ns / 1e9
                 printf "%s %.3f %.3f %.3f", r, px / hz / s, be / hz / s, cl / s }'
}

# lib_paired.sh calls this with (arm, mode, a, b); the fixture is carried in
# CUR_FIX because the shared signature has no room for it and widening it would
# touch both existing callers for the benefit of this one.
arm_measure() {
    local arm=$1 shape=$2 conns=$3 payload=$4
    local path=$payload
    if [ "$arm" = a ]; then
        case "$shape" in http-*) path="/$SK_HTTP_NAME/$payload" ;; esac
        measure "${SKPORT[$CUR_FIX]}" "$shape" "$conns" "$path" "${SKPIDS[$CUR_FIX]}" "${BEPIDS[$CUR_FIX]}"
    else
        case "$shape" in http-*) path="/$payload" ;; esac
        measure "${HAPORT[$CUR_FIX]}" "$shape" "$conns" "$path" "$HA_PIDS" "${BEPIDS[$CUR_FIX]}"
    fi
}

# ─── Run ────────────────────────────────────────────────────────────────────

log_info "$PAIRS pairs per row, ${RUN_MS} ms per run, order alternating"
log_info "box load with nothing of ours running: $(box_load_cores) cores (pairs above $QUIET_CORES are discarded)"
echo ""

: > "$WORK/rows.txt"
ROW_N=0
NROWS=$(printf '%s\n' "$ROWS" | grep -cE '^[A-Z]' || true)
while IFS='|' read -r name fix shape conns payload; do
    case "$name" in ''|'#'*) continue ;; esac
    CUR_FIX=$fix
    # Waited for before the row, not after it: a row that starts with the pool
    # exhausted measures the pool for its whole first pair, and the pairing has
    # no way to tell that from a slow proxy.
    if ! tw_wait; then
        log_warn "$name: TIME-WAIT stayed above $TW_LIMIT for ${TW_WAIT}s — the row below may be the port pool"
    fi
    TW_AT=$(tw_now)
    paired_run_case "$shape" "$conns" "$payload"
    v=$(paired_verdict "$C_CI" "$C_KEPT" "$C_BE" "$C_CLI" \
                       "$(client_ceiling "$shape" "$conns")" "$(backend_ceiling "$fix")")
    ROW_N=$((ROW_N + 1))
    # Said out loud as it happens.  The table is sorted and therefore printed
    # only at the end, so for twenty minutes a healthy run looks exactly like a
    # hung one — which had to be settled with ps twice while the cache matrix
    # was being written.  To stderr, so it cannot land in a log somebody later
    # parses as a result row.
    printf '  [%2d/%2d] %-12s %8sx  ±%-6s tw=%s  %s\n' \
        "$ROW_N" "$NROWS" "$name" "$(printf '%.2f' "$C_RATIO")" "${C_CI}%" "$TW_AT" "$v" >&2
    printf '%s|%s|%s|%.0f|%.0f|%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "$name" "$fix" "$shape" "$C_A" "$C_B" "$C_RATIO" "$C_CI" \
        "$C_APX" "$C_BPX" "$C_BE" "$C_CLI" "$C_KEPT" "$v" >> "$WORK/rows.txt"
done < <(printf '%s\n' "$ROWS" | grep -vE '^[[:space:]]*(#|$)')

# ─── The band, and why it is relative ───────────────────────────────────────
#
# Judging each row against 1.00x answers "are we faster than HAProxy", which is
# the question this file says it is not asking.  If we are typically 1.4x and
# one shape is 1.05x, that shape is carrying something the others are not — and
# against 1.00x it reads as a pass.  So the band is drawn around our OWN median,
# and a row whose interval could not resolve the target is never given one.
MED=$(awk -F'|' '$13 ~ /^resolves/ {print $6}' "$WORK/rows.txt" | sort -g | \
      awk '{v[n++]=$1} END{if(n) printf "%.3f", (n%2)?v[int(n/2)]:(v[n/2-1]+v[n/2])/2}')

# Two zeroes together cannot be the proxies: our code does not reach haproxy, so
# a row where BOTH arms measured nothing measured nothing at all — a shape the
# client does not implement, a port nobody was listening on, a path that 404s.
DEAD=$(awk -F'|' '$4 == 0 && $5 == 0 {printf "%s ", $1}' "$WORK/rows.txt")
if [ -n "$DEAD" ]; then
    log_error "measured NOTHING on either arm: $DEAD"
    log_error "  both arms zero is always the harness, never the proxies"
fi

# Throughput per core of proxy, ours over theirs.
#
# The raw ratio is the answer to "how many more requests a second", and it stops
# meaning that the moment either arm saturates: HAProxy at `nbthread 1` reaches
# one core on the HTTP shapes while we are at half of one, and from there the
# raw ratio is a statement about whatever else was in the way -- the client,
# usually.  Measured in the smoke run: HTTPCL-c8 read 1.15x with haproxy at 0.99
# cores and socketley at 0.54, which is 2.1x the work per core and 1.15x on the
# clock.  Both numbers are true and they answer different questions, so both are
# printed.  Where neither arm is near a core they agree, which is the check that
# the column is not inventing anything.
per_core() {   # a b apx bpx -> ratio of (rate/cores)
    awk -v a="$1" -v b="$2" -v x="$3" -v y="$4" \
        'BEGIN { if (x <= 0 || y <= 0 || b <= 0) { print "-"; exit }
                 printf "%.2f", (a / x) / (b / y) }'
}

S_LABEL="socketley"; H_LABEL="haproxy"
[ "$MODE" = "sharded" ] && { S_LABEL="skl x$SHARDS"; H_LABEL="hap x$SHARDS"; }
printf '\n  %-11s %10s %10s %8s %8s %7s %8s %8s %7s %7s  %s\n' \
    shape "$S_LABEL" "$H_LABEL" ratio /core '±95%' sk_cores hap_cores be_cores cli_cores verdict
printf '  %s\n' "$(printf '%.0s─' {1..127})"
sort -t'|' -k6 -g "$WORK/rows.txt" | while IFS='|' read -r name fix shape a b ratio ci apx bpx be cli kept v; do
    note=$(awk -v x="$ratio" -v m="$MED" -v v="$v" \
        'BEGIN{ if (v !~ /^resolves/) { print v; exit }
                if (m <= 0)          { print "-"; exit }
                rel = x / m
                if      (rel < 0.55) printf "WELL BELOW our %.2fx norm — look here", m
                else if (rel < 0.75) printf "below our %.2fx norm", m
                else if (rel > 1.4)  print "above the norm"
                else                 print "as usual" }')
    printf '  %-11s %10s %10s %7sx %7sx %6s%% %8s %8s %7s %7s  %s\n' \
        "$name" "$a" "$b" "$ratio" "$(per_core "$a" "$b" "$apx" "$bpx")" \
        "$ci" "$apx" "$bpx" "$be" "$cli" "$note"
done

echo ""
log_info "our own median ratio in this run: ${MED:-?}x — the band above is drawn around it"
log_info "rates are round trips (tcp) or requests (http) a second, and are worth"
log_info "nothing across runs: this box's clock moves under it invisibly.  The ratio survives that."
