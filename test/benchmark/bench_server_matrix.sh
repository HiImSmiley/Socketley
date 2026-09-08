#!/bin/bash
# Every shape the server runtime answers in, against the C floor, in one table.
#
# bench_server_floor.sh measures three cases -- 64 B and 1 KB on one connection,
# and one concurrent row -- against floor_server.c.  That is the same narrowness
# the proxy had before bench_proxy_matrix.sh went wide, and going wide is what
# found the things worth finding there.
#
# ─── WHY THE FLOOR AND NOT ANOTHER SERVER ───────────────────────────────────
#
# A ratio against a competitor says which of two programs is ahead and nothing
# about whether either has anything left to give.  floor_server.c is accept,
# read, write and nothing else -- no io_uring, no framing, no Lua, no runtime
# state -- so the distance above it is exactly the part of each number that is
# ours to remove.  Measured for the proxy the same way: four handoffs cost
# 22.51 us before anyone's code runs, which turned "1.05x haproxy" into "there
# is one microsecond left on this path".
#
# ─── THE THING THAT MAKES THE SERVER DIFFERENT FROM THE PROXY ───────────────
#
# A plain server answers nothing.  `--mode in` and `--mode inout` describe which
# directions the runtime accepts, not a reply, so every round trip a server
# serves runs SOMETHING on top of the I/O path: a Lua handler, a file out of the
# HTTP cache, or a relay to an upstream.  The floor answers with a memcpy.
#
# So the distance above the floor is not "our I/O overhead" here, it is "our
# I/O overhead PLUS whatever answered".  That is why the table carries the
# fixtures separately rather than averaging them: the difference between the
# lua row and the http row at the same size is what the Lua interpreter costs
# per message, and neither row alone can say it.
#
# ─── AND WHAT THE FLOOR CANNOT ANSWER ───────────────────────────────────────
#
# floor_server is single-threaded on purpose: a floor spread over ten cores
# would be a different architecture and the distance would measure core count.
# So in `sharded` mode the CONCURRENT rows have no fair floor -- four shards
# beat a one-thread floor by construction, and the table shows that as a
# negative distance, which the verdict names as a mispairing rather than a win.
# Measured: LUA-c32 reached 306,491 ops/s sharded against 139,479 single, which
# is 2.20x on four shards; that ratio, against the single-mode row, is what the
# sharded concurrent rows are for.  The serial rows are unaffected, because one
# connection lands on one shard.
#
# ─── READING IT ─────────────────────────────────────────────────────────────
#
# Microseconds per operation and the distance over the floor at the same size
# and concurrency.  Quote the distance, never the rate: this box is a guest, the
# host's governor moves under it with no sign from in here, and the floor moves
# with it while an absolute number does not.
#
# CPU per operation sits beside it because the two come apart, and which one
# moves decides what a change is worth -- a serial round trip waits on wake-ups,
# so freed CPU has nowhere to go and stays off the clock.
set -uo pipefail

source "$(dirname "$0")/utils.sh"
source "$(dirname "$0")/lib_paired.sh"      # median_of, ci_pct_of, box_load_cores, HZ

PASSES=${SRV_MATRIX_PASSES:-7}
RUN_MS=${SRV_MATRIX_RUN_MS:-1500}
QUIET_CORES=${BENCH_QUIET_CORES:-1.0}
MODE=${SRV_MATRIX_MODE:-single}             # single | sharded
SHARDS=${SRV_MATRIX_SHARDS:-4}
TABLE_ONLY=${SRV_MATRIX_TABLE_ONLY:-0}

B=${SRV_MATRIX_PORT_BASE:-29500}
P_FLOOR_B=$((B+0))    # floor, -m block   : the serial rows
P_FLOOR_E=$((B+1))    # floor, -m epoll   : the concurrent rows
# The upstream fixture relays, so its floor is four handoffs and not two:
# measured against floor_server it read +28.67 us over an 18.78 us floor, and
# most of that was the two hops the floor does not make.
P_FLOOR_R=$((B+2))    # floor_relay -m block : the serial upstream row
P_FLOOR_RE=$((B+3))   # floor_relay -m epoll : the concurrent upstream row
P_LUA=$((B+10)); P_HTTP=$((B+11)); P_WS=$((B+12)); P_UP=$((B+13)); P_UPBE=$((B+14))
P_SINK=$((B+15))
SK_HTTP_NAME=sm_http

# name|fixture|shape|conns|size
#
# Sizes step by sixteen because that is where a path stops being wake-up bound
# and starts being copy bound, and the fixtures need not cross over together.
# The concurrency rows are at a fixed 64 bytes, which is where the wake-ups
# amortise and a single-threaded loop is at its best.
#
# `ingest` is write-only and has no floor arm: floor_server echoes, so a
# write-only client against it would fill the socket and measure the buffer.
# It is here without a distance, for the rate alone -- and against a fixture
# that does NOT answer, because echo.lua does: with a replying server the
# client's receive buffer fills, the server blocks in send, the client blocks in
# write, and the row hangs rather than measuring.  `--mode in` with no Lua is
# exactly a server that accepts and answers nothing.
#
# `--listen unix:` is absent, and not by oversight: socketley_bench has no
# AF_UNIX client at all, so there is nothing here that could drive that socket.
# Adding one is a build change before it is a benchmark change.
#
# The upstream row is SERIAL only.  upstream_relay.lua answers one client at a
# time because an upstream's reply carries no client identity; at 32 clients
# `waiting` is overwritten constantly and replies reach whoever asked last --
# which `server concurrent` still counts as round trips, so the row read 223,014
# ops/s against a 78,691 floor.  A negative distance was the only thing that
# gave it away.
#
# CONN takes a COUNT and not the clock.  bench_server_conn has no
# deadline_passed() check, so `-d` does nothing there and an operation cap of a
# hundred million is a run that never ends -- which is how the first draft of
# this table hung.  A connection rate is also the one shape bounded by the
# ephemeral port pool, so the count is small and the pool is waited for.
ROWS_DEFAULT='
LUA-64|lua|msg|1|64
LUA-1K|lua|msg|1|1024
LUA-16K|lua|msg|1|16384
LUA-c8|lua|concurrent|8|64
LUA-c32|lua|concurrent|32|64
LUA-c100|lua|concurrent|100|64
WS-64|ws|ws-echo|1|64
WS-1K|ws|ws-echo|1|1024
WS-c32|ws|ws-concurrent|32|64
HTTP-c1|http|http-keepalive|1|small.txt
HTTP-c8|http|http-keepalive|8|small.txt
HTTP-c32|http|http-keepalive|32|small.txt
HTTP-16K|http|http-keepalive|8|large.txt
UP-64|upstream|msg|1|64
CONN|lua|conn|1|0
INGEST-64|sink|ingest|1|64
INGEST-16K|sink|ingest|1|16384
'
ROWS=${SRV_MATRIX_ROWS:-$ROWS_DEFAULT}

if [ "$TABLE_ONLY" = "1" ]; then return 0 2>/dev/null || exit 0; fi

# ─── Fixtures ───────────────────────────────────────────────────────────────
#
# Two floors, because one connection and many are different questions: with a
# single connection there is nothing to multiplex, so an epoll_wait would be a
# syscall the floor never has to pay and every number measured against it would
# be flattered.
WORK=$(mktemp -d /tmp/smatrix.XXXXXX)
SM_HOME=$WORK/home
SM_SOCK=$WORK/d.sock
mkdir -p "$SM_HOME"
DAEMON_PID=""; FLOOR_PIDS=""

sweep() {
    local p c
    for p in $(pgrep -x socketley 2>/dev/null); do
        grep -qz "SOCKETLEY_SOCKET=$SM_SOCK" "/proc/$p/environ" 2>/dev/null || continue
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

# Refused on CPU and not on existence: an idle daemon holding no runtimes costs
# nothing and is the normal state of a developer's box; one burning a core lands
# in every number below.
BUSY=$(
  ps=$(pgrep -x socketley 2>/dev/null | tr '\n' ' '); t0=0; t1=0
  for p in $ps; do t0=$((t0 + $(awk '{print $14+$15}' /proc/$p/stat 2>/dev/null || echo 0))); done
  sleep 0.3
  for p in $ps; do t1=$((t1 + $(awk '{print $14+$15}' /proc/$p/stat 2>/dev/null || echo 0))); done
  awk -v d=$((t1-t0)) -v hz="$(getconf CLK_TCK)" 'BEGIN{printf "%.2f", d/hz/0.3}')
awk -v b="$BUSY" 'BEGIN{exit !(b > 0.05)}' && {
    log_error "refusing: socketley processes are burning $BUSY cores"; exit 2; }
for p in "$P_FLOOR_B" "$P_FLOOR_E" "$P_FLOOR_R" "$P_FLOOR_RE" "$P_LUA" "$P_HTTP" "$P_WS" "$P_UP" "$P_UPBE"; do
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$p\$" && {
        log_error "refusing: port $p is already listening"; exit 2; }
done
check_binary || exit 1
FLOOR_BIN=$PROJECT_ROOT/bin/Release/floor_server
[ -x "$FLOOR_BIN" ] || { log_error "floor_server is not built"; exit 1; }
[ -x "$SOCKETLEY_BENCH" ] || { log_error "socketley_bench is not built"; exit 1; }

log_section "Server matrix: every shape it answers in, against the C floor ($MODE)"

mkdir -p "$SM_HOME/www"
printf 'ok' > "$SM_HOME/www/small.txt"
# Not an .html file: --http injects a WebSocket script into every .html it
# serves, so an HTML fixture would time a rewrite as well as a send.
head -c 16384 /dev/zero | tr '\0' 'x' > "$SM_HOME/www/large.txt"
chmod -R a+rX "$SM_HOME"

"$FLOOR_BIN" "$P_FLOOR_B" -m block  & FLOOR_PIDS="$FLOOR_PIDS $!"
"$FLOOR_BIN" "$P_FLOOR_E" -m epoll  & FLOOR_PIDS="$FLOOR_PIDS $!"
"$FLOOR_BIN" "$P_UPBE"    -m epoll  & FLOOR_PIDS="$FLOOR_PIDS $!"
sleep 0.3
"$PROJECT_ROOT/bin/Release/floor_relay" "$P_FLOOR_R"  127.0.0.1 "$P_UPBE" -m block & FLOOR_PIDS="$FLOOR_PIDS $!"
"$PROJECT_ROOT/bin/Release/floor_relay" "$P_FLOOR_RE" 127.0.0.1 "$P_UPBE" -m epoll & FLOOR_PIDS="$FLOOR_PIDS $!"
sleep 0.5

export HOME=$SM_HOME
export SOCKETLEY_SOCKET=$SM_SOCK
unset SOCKETLEY_CONFIG            # a config PATH, not a build selector
"$SOCKETLEY_BIN" daemon >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 100); do [ -S "$SM_SOCK" ] && break; sleep 0.1; done
[ -S "$SM_SOCK" ] || { log_error "the private daemon did not come up"; exit 1; }

SH=""; [ "$MODE" = "sharded" ] && SH="--shards $SHARDS"
up() { local n=$1; shift; socketley_cmd create "$@" -s >/dev/null 2>&1; return 0; }
up sm_lua  server sm_lua  -p "$P_LUA"  --mode in --lua "$BENCH_ECHO_LUA" $SH
# Answers nothing, which is what ingest needs; see the row table.
up sm_sink server sm_sink -p "$P_SINK" --mode in $SH
up sm_ws   server sm_ws   -p "$P_WS"   --mode in --lua "$BENCH_ECHO_LUA" $SH
up "$SK_HTTP_NAME" server "$SK_HTTP_NAME" -p "$P_HTTP" --http "$SM_HOME/www" --http-cache $SH
# --upstream is an outbound connection with Lua callbacks and not a
# transparent relay, so the relay has to be written down; see
# upstream_relay.lua for why it serves one client at a time.
up sm_up   server sm_up   -p "$P_UP"   --mode in --upstream "127.0.0.1:$P_UPBE" \
                          --lua "$SCRIPT_DIR/upstream_relay.lua" $SH
for p in "$P_LUA" "$P_WS" "$P_HTTP" "$P_UP" "$P_SINK"; do
    wait_for_port "$p" || { log_error "no server on $p"; exit 1; }
done

pids_on_port() {
    ss -ltnp 2>/dev/null | awk -v p=":$1\$" '$4 ~ p' \
        | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u | tr '\n' ' '
}
declare -A FPORT FPIDS
FPORT[lua]=$P_LUA;   FPIDS[lua]=$(pids_on_port "$P_LUA")
FPORT[ws]=$P_WS;     FPIDS[ws]=$(pids_on_port "$P_WS")
FPORT[http]=$P_HTTP; FPIDS[http]=$(pids_on_port "$P_HTTP")
FPORT[upstream]=$P_UP; FPIDS[upstream]=$(pids_on_port "$P_UP")
FPORT[sink]=$P_SINK; FPIDS[sink]=$(pids_on_port "$P_SINK")
for f in lua ws http upstream sink; do
    [ -n "${FPIDS[$f]## }" ] || { log_error "no pid for the $f fixture"; exit 1; }
done
FLOOR_R_PID=$(pids_on_port "$P_FLOOR_R")
FLOOR_RE_PID=$(pids_on_port "$P_FLOOR_RE")
FLOOR_B_PID=$(pids_on_port "$P_FLOOR_B")
FLOOR_E_PID=$(pids_on_port "$P_FLOOR_E")
[ -n "$FLOOR_B_PID" ] && [ -n "$FLOOR_E_PID" ] || { log_error "no pid for a floor"; exit 1; }
log_info "fixtures up: lua ${FPIDS[lua]} ws ${FPIDS[ws]} http ${FPIDS[http]} upstream ${FPIDS[upstream]} sink ${FPIDS[sink]}"

# Every fixture must actually answer before anything is timed.  A runtime that
# refuses is faster than one that serves, and the difference does not appear in
# a throughput number -- the proxy table once reported 6656 req/s of 404s.
probe_tcp() {
    python3 - "$1" <<'PY' 2>/dev/null
import socket, sys
try:
    s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); s.settimeout(3)
    s.sendall(b"ping\n"); sys.stdout.write(s.recv(64).decode("latin1").strip())
except Exception: pass
PY
}
for p in "$P_FLOOR_B" "$P_FLOOR_E" "$P_FLOOR_R" "$P_FLOOR_RE" "$P_LUA" "$P_WS" "$P_UP"; do
    [ -n "$(probe_tcp "$p")" ] || { log_error "port $p answered nothing"; exit 1; }
done
HTTP_OK=$(python3 - "$P_HTTP" <<'PY' 2>/dev/null
import socket, sys
try:
    s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); s.settimeout(5)
    s.sendall(b"GET /small.txt HTTP/1.1\r\nHost: x\r\n\r\n")
    print(s.recv(256).split(b"\r\n")[0].split(b" ")[1].decode())
except Exception: print("ERR")
PY
)
[ "$HTTP_OK" = "200" ] || { log_error "the http fixture answered $HTTP_OK, not 200"; exit 1; }
log_info "every fixture answers"

# ─── One measured run ───────────────────────────────────────────────────────
HZ=$(getconf CLK_TCK)
ticks_sum() { local t=0 p; for p in $1; do t=$((t + $(awk '{print $14+$15}' "/proc/$p/stat" 2>/dev/null || echo 0))); done; echo "$t"; }
CORES=$(nproc)
CONN_OPS=${SRV_MATRIX_CONN_OPS:-2000}
tw_now() { ss -s 2>/dev/null | awk -F'timewait ' '/^TCP:/{split($2,a,")"); print a[1]+0}'; }
# A connection row measured on an exhausted pool reports the pool: the same
# build once gave 18,370 / 71,546 / 41,459 on three consecutive runs that way.
tw_wait() { local i; for ((i=0;i<90;i++)); do [ "$(tw_now)" -lt 8000 ] && return 0; sleep 1; done; return 1; }

run_one() {   # host_or_port shape conns size pids -> "rate cores cli_cores"
    local target=$1 shape=$2 conns=$3 size=$4 pids=$5
    local a b w0 w1 out rate
    a=$(ticks_sum "$pids"); w0=$(date +%s%N)
    case "$shape" in
      msg)            out=$(/usr/bin/time -f '%U %S' -o "$WORK/c.t" timeout "$BENCH_TIMEOUT_CMD" \
                            "$SOCKETLEY_BENCH" -r 1 -W 0 -d "$RUN_MS" server msg 127.0.0.1 "$target" 100000000 "$size" 2>/dev/null) ;;
      concurrent)     out=$(/usr/bin/time -f '%U %S' -o "$WORK/c.t" timeout "$BENCH_TIMEOUT_CMD" \
                            "$SOCKETLEY_BENCH" -r 1 -W 0 -d "$RUN_MS" server concurrent 127.0.0.1 "$target" "$conns" 100000000 2>/dev/null) ;;
      ingest)         out=$(/usr/bin/time -f '%U %S' -o "$WORK/c.t" timeout "$BENCH_TIMEOUT_CMD" \
                            "$SOCKETLEY_BENCH" -r 1 -W 0 -d "$RUN_MS" server ingest 127.0.0.1 "$target" 100000000 "$size" 2>/dev/null) ;;
      conn)           # A COUNT and not the clock: bench_server_conn has no deadline check,
                      # so -d does nothing and an operation cap is a run with no end.  2000
                      # is the benchmarking notes' bound for a connection test on this box,
                      # whose ephemeral pool is 28,232 ports held 60 seconds each.
                      tw_wait
                      out=$(/usr/bin/time -f '%U %S' -o "$WORK/c.t" timeout "$BENCH_TIMEOUT_CMD" \
                            "$SOCKETLEY_BENCH" -r 1 -W 0 server conn 127.0.0.1 "$target" "$CONN_OPS" 2>/dev/null) ;;
      ws-echo)        out=$(/usr/bin/time -f '%U %S' -o "$WORK/c.t" timeout "$BENCH_TIMEOUT_CMD" \
                            "$SOCKETLEY_BENCH" -r 1 -W 0 -d "$RUN_MS" ws echo 127.0.0.1 "$target" 100000000 "$size" 2>/dev/null) ;;
      ws-concurrent)  out=$(/usr/bin/time -f '%U %S' -o "$WORK/c.t" timeout "$BENCH_TIMEOUT_CMD" \
                            "$SOCKETLEY_BENCH" -r 1 -W 0 -d "$RUN_MS" ws concurrent 127.0.0.1 "$target" "$conns" 100000000 2>/dev/null) ;;
      http-keepalive) out=$(/usr/bin/time -f '%U %S' -o "$WORK/c.t" timeout "$BENCH_TIMEOUT_CMD" \
                            "$SOCKETLEY_BENCH" -r 1 -W 0 -d "$RUN_MS" -u "/$size" proxy http-keepalive 127.0.0.1 "$target" "$conns" 100000000 2>/dev/null) ;;
    esac
    w1=$(date +%s%N); b=$(ticks_sum "$pids")
    rate=$(grep -oE '^\s*Median:\s+[0-9]+' <<<"$out" | grep -oE '[0-9]+' | head -1)
    local failed; failed=$(grep -oE 'Failed: [0-9]+' <<<"$out" | grep -oE '[0-9]+' | head -1)
    [ "${failed:-0}" -gt 0 ] && rate=0
    local cli; cli=$(awk '{print $1 + $2}' "$WORK/c.t" 2>/dev/null || echo 0)
    awk -v r="${rate:-0}" -v d=$((b-a)) -v hz="$HZ" -v ns=$((w1-w0)) -v c="${cli:-0}" \
        'BEGIN{ s=ns/1e9; printf "%s %.3f %.3f", r, d/hz/s, c/s }'
}

# The floor at the same size and concurrency, which is what a row is measured
# against.  Serial rows take -m block and concurrent rows -m epoll; see the
# header for why one floor cannot serve both.
floor_for() {   # shape conns size -> "rate cores cli" or "" when there is none
    local shape=$1 conns=$2 size=$3 bytes
    case "$shape" in
      # An HTTP row is a request and a response, so its floor is a round trip of
      # the body's size and not of the file NAME -- stripping digits out of
      # "small.txt" yields an empty size, which is how the first draft of this
      # asked the floor for a zero-byte message.
      http-keepalive) case "$size" in large.txt) bytes=16384 ;; *) bytes=64 ;; esac ;;
      # `ingest` writes and never reads, and floor_server echoes: the reply would
      # fill the socket and the number would be the buffer.  No floor arm.
      ingest|conn)    echo ""; return ;;
      *)              bytes=$size ;;
    esac
    # The upstream fixture relays, so its floor is floor_relay's four handoffs.
    # Against the two-handoff floor it read +28.67 us over 18.78, and most of
    # that was hops the floor never makes.
    # And at the row's concurrency, not at one connection: UP-c32 against a
    # single-connection relay floor read -36.43 us, and a negative distance is
    # the tell that the two arms are not the same question.
    if [ "$FIX_NOW" = upstream ]; then
        if [ "$conns" -le 1 ]; then run_one "$P_FLOOR_R"  msg 1 "$bytes" "$FLOOR_R_PID"
        else                        run_one "$P_FLOOR_RE" concurrent "$conns" "$bytes" "$FLOOR_RE_PID"; fi
    elif [ "$conns" -le 1 ]; then      run_one "$P_FLOOR_B" msg 1 "$bytes" "$FLOOR_B_PID"
    else                               run_one "$P_FLOOR_E" concurrent "$conns" "$bytes" "$FLOOR_E_PID"; fi
}

# ─── Run ────────────────────────────────────────────────────────────────────

log_info "$PASSES passes per row, ${RUN_MS} ms per run, floor and fixture interleaved"
log_info "box load with nothing of ours running: $(box_load_cores) cores"
echo ""
: > "$WORK/rows.txt"
ROW_N=0
NROWS=$(printf '%s\n' "$ROWS" | grep -cE '^[A-Z]' || true)

while IFS='|' read -r name fix shape conns size; do
    case "$name" in ''|'#'*) continue ;; esac
    target=${FPORT[$fix]}
    FIX_NOW=$fix
    sv=""; sc=""; scl=""; fv=""; fc=""
    for ((pass = 1; pass <= PASSES; pass++)); do
        before=$(box_load_cores)
        # Interleaved and alternating, because this box drifts tens of percent
        # inside a minute: measure all of one arm and then all of the other and
        # that drift arrives as a distance above the floor.
        if (( pass % 2 )); then
            read -r r c cl <<<"$(run_one "$target" "$shape" "$conns" "$size" "${FPIDS[$fix]}")"
            fr=$(floor_for "$shape" "$conns" "$size")
        else
            fr=$(floor_for "$shape" "$conns" "$size")
            read -r r c cl <<<"$(run_one "$target" "$shape" "$conns" "$size" "${FPIDS[$fix]}")"
        fi
        after=$(box_load_cores)
        # A pass measured while somebody else was on the box is discarded whole,
        # never one arm of it -- a pass with one arm dropped is exactly the
        # unpaired comparison the interleaving exists to replace.
        if awk -v x="$before" -v y="$after" -v l="$QUIET_CORES" 'BEGIN{exit !(x>l||y>l)}'; then continue; fi
        [ "${r:-0}" -gt 0 ] || continue
        sv="$sv $r"; sc="$sc $c"; scl="$scl $cl"
        if [ -n "$fr" ]; then
            read -r fr_r fr_c _ <<<"$fr"
            [ "${fr_r:-0}" -gt 0 ] && { fv="$fv $fr_r"; fc="$fc $fr_c"; }
        fi
    done
    s=$(median_of "$sv"); sci=$(ci_pct_of "$sv")
    scm=$(median_of "$sc"); sclm=$(median_of "$scl")
    f=$(median_of "$fv"); fcm=$(median_of "$fc")
    ROW_N=$((ROW_N+1))
    # Said out loud as it happens: the table is sorted and printed only at the
    # end, so for twenty minutes a healthy run looks exactly like a hung one.
    printf '  [%2d/%2d] %-11s %10s ops/s  floor %10s  ±%s%%\n' \
        "$ROW_N" "$NROWS" "$name" "$s" "${f:-—}" "$sci" >&2
    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "$name" "$fix" "$shape" "$s" "$f" "$sci" "$scm" "$fcm" "$sclm" >> "$WORK/rows.txt"
done < <(printf '%s\n' "$ROWS" | grep -vE '^[[:space:]]*(#|$)')

# ─── The table ──────────────────────────────────────────────────────────────
#
# Sorted by the distance above the floor, because that is the column a reader
# came for: it is what the row costs that the kernel does not.
printf '\n  %-11s %11s %11s %9s %9s %8s %7s %7s %7s  %s\n' \
    row 'ops/sec' 'floor/sec' 'us/op' 'floor us' 'over' '±95%' 'cores' 'cli' verdict
printf '  %s\n' "$(printf '%.0s─' {1..112})"
sort -t'|' -k5 -g "$WORK/rows.txt" | while IFS='|' read -r name fix shape s f ci scm fcm sclm; do
    awk -v n="$name" -v s="$s" -v f="$f" -v ci="$ci" -v c="$scm" -v fc="$fcm" -v cl="$sclm" \
      'function verdict(  d, fus) {
         # The load generator first, because a row it dominates is a statement
         # about socketley_bench: measured on ws concurrent 32, the client
         # burned 10.989 cores against the worker s 0.482 and the rate did not
         # move from 8 connections to 32.  Read as a server number that was
         # +47.94 us over the floor; it was the client all along.
         if (cl > 4 * c && c < 0.85)
             return sprintf("client-bound (client %.1f cores, worker %.2f)", cl, c)
         if (ci + 0 > 15) return "interval too wide to read"
         if (f <= 0)      return "no floor for this shape"
         fus = 1e6/f; d = 1e6/s - fus
         if (d < 0)             return "NEGATIVE — the floor is mispaired, not beaten"
         if (d < fus * 0.25)    return "close to the floor"
         if (d < fus)           return "under the floor cost"
         return "MORE than the floor itself — look here"
       }
       BEGIN{
         if (s <= 0) { printf "  %-11s %11s %11s %9s %9s %8s %7s %7s %7s  %s\n",
                              n,"—","—","—","—","—",ci,"—","—","measured nothing"; exit }
         us = 1e6/s
         if (f > 0) printf "  %-11s %11d %11d %9.2f %9.2f %+8.2f %6s%% %7.3f %7.2f  %s\n",
                           n, s, f, us, 1e6/f, us-1e6/f, ci, c, cl, verdict()
         else       printf "  %-11s %11d %11s %9.2f %9s %8s %6s%% %7.3f %7.2f  %s\n",
                           n, s, "—", us, "—", "—", ci, c, cl, verdict()
       }'
done
echo ""
log_info "quote the distance above the floor, never the rate: this box is a guest,"
log_info "the host's governor moves under it unseen, and the floor moves with it."
