#!/bin/bash
# Every shape the client runtime dials in, against the C client that does the
# same round trips.
#
# ─── WHY THE FLOOR IS socketley_bench AND NOT A floor_* PROGRAM ─────────────
#
# A client dials OUT, so nothing can point a load generator at it -- bench.c has
# no client category at all, and floor_pingpong forks its own pair rather than
# dialling anything.  What a client runtime does is: open a connection, run Lua,
# send and receive.  The C program in this tree that already does exactly that
# is socketley_bench's own `server msg`: one connection, one message out, its
# reply read before the next goes out, against an echoing target.
#
# So both arms dial the SAME floor_server and do the same round trips, one of
# them in C and one as a runtime with a Lua handler.  The distance is what the
# runtime costs over a C client -- the same question the server matrix asks of
# the server, asked from the other end.
#
# ─── AND WHY THIS ONE REACHES SHAPES THE SERVER MATRIX COULD NOT ────────────
#
# The server table has no AF_UNIX and no UDP rows because socketley_bench speaks
# neither, and it is the client there.  Here OUR runtime is the client, so
# `-t unix:/path` and `--udp` are simply configurations of the thing under test.
# Only the floor arm is limited, and where it cannot follow the row says so
# rather than inventing a comparison.
#
# ─── HOW THE RATE IS READ ───────────────────────────────────────────────────
#
# From the runtime's own message counter through `stats`, sampled either side of
# a window.  A Lua handler that printed per message would measure the print, and
# a client has no throughput line of its own to parse.
set -uo pipefail

source "$(dirname "$0")/utils.sh"
source "$(dirname "$0")/lib_paired.sh"

PASSES=${CLI_MATRIX_PASSES:-7}
RUN_S=${CLI_MATRIX_RUN_S:-3}
QUIET_CORES=${BENCH_QUIET_CORES:-1.0}
TABLE_ONLY=${CLI_MATRIX_TABLE_ONLY:-0}

B=${CLI_MATRIX_PORT_BASE:-29900}
P_ECHO=$((B+0))       # the shared echo target, floor_server -m epoll
P_ECHO2=$((B+1))      # a second one, so the two arms never share a socket

# name|transport|size
#
# The sizes step by sixteen for the same reason as everywhere else: that is
# where a path stops being wake-up bound and starts being copy bound.
#
# `unix` has no floor arm -- socketley_bench dials no unix socket -- so it is
# reported for its own rate and against the tcp row of the same size, which is
# the comparison that is actually available.
#
# UDP is absent and that is a decision: floor_server is TCP only, so the only
# echo targets available are a socketley server or a script, and either would
# put a second thing under test inside the row.  A C UDP echo is a build change
# before it is a benchmark change, the same answer TLS got in the server table.
ROWS_DEFAULT='
TCP-64|tcp|64
TCP-1K|tcp|1024
TCP-16K|tcp|16384
UNIX-64|unix|64
UNIX-1K|unix|1024
'
ROWS=${CLI_MATRIX_ROWS:-$ROWS_DEFAULT}
if [ "$TABLE_ONLY" = "1" ]; then return 0 2>/dev/null || exit 0; fi

WORK=$(mktemp -d /tmp/cmatrix.XXXXXX)
CM_HOME=$WORK/home
CM_SOCK=$WORK/d.sock
ECHO_SOCK=$WORK/echo.sock
mkdir -p "$CM_HOME"
DAEMON_PID=""; FLOOR_PIDS=""

sweep() {
    local p c
    for p in $(pgrep -x socketley 2>/dev/null); do
        grep -qz "SOCKETLEY_SOCKET=$CM_SOCK" "/proc/$p/environ" 2>/dev/null || continue
        for c in $(pgrep -P "$p" 2>/dev/null); do kill -9 "$c" 2>/dev/null; done
        kill -9 "$p" 2>/dev/null
    done
    return 0
}
cleanup() {
    local p c
    for p in $FLOOR_PIDS; do
        for c in $(pgrep -P "$p" 2>/dev/null); do kill -9 "$c" 2>/dev/null; done
        kill -9 "$p" 2>/dev/null
    done
    sweep; sleep 0.3; sweep
    [ -n "$DAEMON_PID" ] && kill -9 "$DAEMON_PID" 2>/dev/null
    rm -rf "$WORK"
    return 0
}
trap cleanup EXIT INT TERM

BUSY=$(
  ps=$(pgrep -x socketley 2>/dev/null | tr '\n' ' '); t0=0; t1=0
  for p in $ps; do t0=$((t0 + $(awk '{print $14+$15}' /proc/$p/stat 2>/dev/null || echo 0))); done
  sleep 0.3
  for p in $ps; do t1=$((t1 + $(awk '{print $14+$15}' /proc/$p/stat 2>/dev/null || echo 0))); done
  awk -v d=$((t1-t0)) -v hz="$(getconf CLK_TCK)" 'BEGIN{printf "%.2f", d/hz/0.3}')
awk -v b="$BUSY" 'BEGIN{exit !(b > 0.05)}' && {
    log_error "refusing: socketley processes are burning $BUSY cores"; exit 2; }
for p in "$P_ECHO" "$P_ECHO2"; do
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$p\$" && {
        log_error "refusing: port $p is already listening"; exit 2; }
done
check_binary || exit 1
FLOOR_BIN=$PROJECT_ROOT/bin/Release/floor_server
[ -x "$FLOOR_BIN" ] || { log_error "floor_server is not built"; exit 1; }
[ -x "$SOCKETLEY_BENCH" ] || { log_error "socketley_bench is not built"; exit 1; }

log_section "Client matrix: what the runtime costs over a C client doing the same round trips"

# Three echo targets, because the three transports are three sockets.  The two
# TCP ones are separate so the floor arm and the runtime never share a listener
# and cannot queue behind each other.
"$FLOOR_BIN" "$P_ECHO"  -m epoll & FLOOR_PIDS="$FLOOR_PIDS $!"
"$FLOOR_BIN" "$P_ECHO2" -m epoll & FLOOR_PIDS="$FLOOR_PIDS $!"
"$FLOOR_BIN" -u "$ECHO_SOCK" -m epoll & FLOOR_PIDS="$FLOOR_PIDS $!"
sleep 0.6
for p in "$P_ECHO" "$P_ECHO2"; do
    wait_for_port "$p" || { log_error "no echo target on $p"; exit 1; }
done
for _ in $(seq 1 100); do [ -S "$ECHO_SOCK" ] && break; sleep 0.1; done
[ -S "$ECHO_SOCK" ] || { log_error "the unix echo target never appeared"; exit 1; }

export HOME=$CM_HOME
export SOCKETLEY_SOCKET=$CM_SOCK
unset SOCKETLEY_CONFIG
"$SOCKETLEY_BIN" daemon >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 100); do [ -S "$CM_SOCK" ] && break; sleep 0.1; done
[ -S "$CM_SOCK" ] || { log_error "the private daemon did not come up"; exit 1; }
log_info "echo targets up: tcp $P_ECHO/$P_ECHO2, unix $ECHO_SOCK"

# The runtime's own message counter, which is the only rate a client publishes.
msgs_of() {   # name -> count, or empty
    socketley_cmd stats "$1" 2>/dev/null | sed -n 's/^total_messages:\([0-9]*\).*/\1/p' | head -1
}

# ─── One measured window ────────────────────────────────────────────────────
HZ=$(getconf CLK_TCK)
ticks_of() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0; }

# The runtime arm: create, let it settle, then count messages across a window.
runtime_arm() {   # transport size -> "rate cores"
    local transport=$1 size=$2 target extra=""
    case "$transport" in
        tcp)  target="127.0.0.1:$P_ECHO2" ;;
        unix) target="unix:$ECHO_SOCK" ;;
    esac
    socketley_cmd stop cm_c   >/dev/null 2>&1
    socketley_cmd remove cm_c >/dev/null 2>&1
    # The size is written INTO the script and not passed in the environment.
    # `VAR=x socketley_cmd create ...` sets it for the CLI invocation, and the
    # worker inherits the DAEMON's environment instead -- so every row measured
    # the script's 64-byte default and the rate did not move with the size at
    # all.  A negative distance at 16 KB was the only thing that said so.
    sed "s/@BYTES@/$size/" "$SCRIPT_DIR/pingpong.lua" > "$WORK/pp_$size.lua"
    socketley_cmd create client cm_c -t "$target" \
        --lua "$WORK/pp_$size.lua" $extra -s >/dev/null 2>&1
    # Settle: the first messages pay for the dial and the script's first trace.
    sleep 1.2
    local wp; wp=$(pgrep -x socketley 2>/dev/null | while read -r q; do
        grep -qz "SOCKETLEY_SOCKET=$CM_SOCK" "/proc/$q/environ" 2>/dev/null && echo "$q"; done | tail -1)
    local m0 m1 t0 t1 w0 w1
    m0=$(msgs_of cm_c); t0=$(ticks_of "${wp:-0}"); w0=$(date +%s%N)
    sleep "$RUN_S"
    m1=$(msgs_of cm_c); t1=$(ticks_of "${wp:-0}"); w1=$(date +%s%N)
    socketley_cmd stop cm_c >/dev/null 2>&1
    [ -n "$m0" ] && [ -n "$m1" ] || { echo "0 0"; return; }
    awk -v a="$m0" -v b="$m1" -v d=$((t1-t0)) -v hz="$HZ" -v ns=$((w1-w0)) \
        'BEGIN{ s=ns/1e9; printf "%.0f %.3f", (b-a)/s, d/hz/s }'
}

# The floor arm: the same round trips, in C, against the other echo target.
floor_arm() {   # size -> "rate cores"
    local size=$1 out rate
    out=$(timeout "$BENCH_TIMEOUT_CMD" "$SOCKETLEY_BENCH" -r 1 -W 0 -d $((RUN_S * 1000)) \
          server msg 127.0.0.1 "$P_ECHO" 100000000 "$size" 2>/dev/null)
    rate=$(grep -oE '^\s*Median:\s+[0-9]+' <<<"$out" | grep -oE '[0-9]+' | head -1)
    echo "${rate:-0} 0"
}

log_info "$PASSES passes per row, ${RUN_S}s per window, arms interleaved"
echo ""
: > "$WORK/rows.txt"
ROW_N=0
NROWS=$(printf '%s\n' "$ROWS" | grep -cE '^[A-Z]' || true)
while IFS='|' read -r name transport size; do
    case "$name" in ''|'#'*) continue ;; esac
    rv=""; rc=""; fv=""
    for ((pass = 1; pass <= PASSES; pass++)); do
        before=$(box_load_cores)
        if (( pass % 2 )); then
            read -r r c <<<"$(runtime_arm "$transport" "$size")"
            [ "$transport" = tcp ] && read -r f _ <<<"$(floor_arm "$size")" || f=0
        else
            [ "$transport" = tcp ] && read -r f _ <<<"$(floor_arm "$size")" || f=0
            read -r r c <<<"$(runtime_arm "$transport" "$size")"
        fi
        after=$(box_load_cores)
        awk -v x="$before" -v y="$after" -v l="$QUIET_CORES" 'BEGIN{exit !(x>l||y>l)}' && continue
        [ "${r:-0}" -gt 0 ] || continue
        rv="$rv $r"; rc="$rc $c"
        [ "${f:-0}" -gt 0 ] && fv="$fv $f"
    done
    s=$(median_of "$rv"); ci=$(ci_pct_of "$rv"); cm=$(median_of "$rc"); f=$(median_of "$fv")
    ROW_N=$((ROW_N+1))
    printf '  [%2d/%2d] %-9s %10s msg/s  floor %10s  ±%s%%\n' \
        "$ROW_N" "$NROWS" "$name" "$s" "${f:-—}" "$ci" >&2
    printf '%s|%s|%s|%s|%s|%s\n' "$name" "$transport" "$s" "$f" "$ci" "$cm" >> "$WORK/rows.txt"
done < <(printf '%s\n' "$ROWS" | grep -vE '^[[:space:]]*(#|$)')

printf '\n  %-9s %11s %11s %9s %9s %9s %7s %7s  %s\n' \
    row 'msg/sec' 'C client' 'us/msg' 'C us' 'over' '±95%' 'cores' verdict
printf '  %s\n' "$(printf '%.0s─' {1..100})"
sort -t'|' -k3 -gr "$WORK/rows.txt" | while IFS='|' read -r name tr s f ci cm; do
    awk -v n="$name" -v s="$s" -v f="$f" -v ci="$ci" -v c="$cm" \
      'function verdict(us, fus,   d) {
         # An if-chain and not a nested ternary across lines: awk will not
         # continue a ?: past a newline, and the first version of this printed
         # a parse error where the table should have been.
         if (ci + 0 > 15)   return "interval too wide to read"
         if (fus <= 0)      return "no C arm - socketley_bench dials no unix socket"
         d = us - fus
         if (d < 0)         return "faster than the C client - check the pairing"
         if (d < fus * 0.25) return "close to the C client"
         if (d < fus)       return "under the C client own cost"
         return "MORE than the C client itself - look here"
       }
       BEGIN{
         if (s <= 0) { printf "  %-9s %11s %11s %9s %9s %9s %6s%% %7s  %s\n",
                       n,"-","-","-","-","-",ci,"-","measured nothing"; exit }
         us = 1e6/s
         if (f > 0) printf "  %-9s %11d %11d %9.2f %9.2f %+9.2f %6s%% %7.3f  %s\n",
                           n, s, f, us, 1e6/f, us-1e6/f, ci, c, verdict(us, 1e6/f)
         else       printf "  %-9s %11d %11s %9.2f %9s %9s %6s%% %7.3f  %s\n",
                           n, s, "-", us, "-", "-", ci, c, verdict(us, 0)
       }'
done
echo ""
log_info "the distance is what the runtime costs over a C client doing the same"
log_info "round trips; quote it and not the rate, which this box does not hold still"
