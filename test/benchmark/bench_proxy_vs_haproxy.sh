#!/bin/bash
# Proxy vs HAProxy — one backend, one client, and a stated resolution.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# bench_proxy.sh answers "how fast is the proxy" with no scale to read it
# against.  Its TCP number is 15k round trips a second on one connection and
# there is nothing in the suite that says whether that is good.  The cache has
# had that scale since bench_cache_resp.sh put it next to Redis; this is the
# same arrangement for the proxy.
#
# ─── WHAT MAKES THE COMPARISON FAIR, AND WHAT DOES NOT ──────────────────────
#
# One backend, and it is the same object.  Both proxies front the identical
# socketley server runtime with echo.lua, started once and left alone, so a
# difference between them cannot be a difference between two fixtures.  The
# backend is itself single-threaded, which matters: at high connection counts it
# can become the limit, and then the two proxies are being compared on how well
# they queue rather than how fast they forward.  Its CPU is measured across every
# run and a case that ran it near a whole core is labelled backend-bound instead
# of being reported as a proxy result.
#
# One client, socketley_bench, driving plain TCP round trips.  It is protocol
# agnostic — a request goes out, a reply is read before the next goes out — so
# it measures the same thing through either proxy.  Using each proxy's preferred
# client would measure the clients.
#
# One thread each was the old claim, and it was never true at run time.
# `nbthread 1` does hold haproxy to a single thread, and it is in the config
# below; but measured across a concurrent run haproxy burns 0.98–1.00 cores
# while socketley's proxy burns 1.6–2.1, because io_uring grows kernel worker
# threads on demand and they are created and reaped inside a run.  Counting
# threads afterwards, which is what this file used to do, sees one or two and
# reports parity.  So the CPU each proxy actually consumed is measured across
# every run and published beside its throughput: that, not a thread count, is
# what says whether a rate was bought at the same price.
#
# ─── WHAT MAKES A NUMBER HERE BELIEVABLE ────────────────────────────────────
#
# Everything below exists because the concurrent cases used to be unreadable.
# Seven repetitions of the 8-connection case as it was written spanned
# 36399..115116 round trips a second for haproxy — a factor of 3.2 — and the
# ratio it produced flipped between invocations by more than the difference
# anybody would be trying to measure.  A reader handed that ratio cannot tell a
# finding from the harness.  Four things changed, in the order they mattered:
#
#   Runs are timed, not counted.  `proxy concurrent 8 200` is 1600 round trips,
#   which on this machine is eighteen milliseconds, and eighteen milliseconds of
#   a ten-core box is one scheduling decision.  Interleaving a 1600-operation run
#   and a 1500-millisecond run against the same unchanged proxy, twelve of each,
#   so that both forms see the same machine: socketley's spread went from 1.49x
#   to 1.15x (coefficient of variation 10.1% -> 4.5%) and haproxy's from 2.79x
#   to 1.96x (40.0% -> 28.0%).  A count also has to be re-guessed every time the
#   code gets faster, and nothing announces when it has gone stale.
#
#   Those figures are smaller than the first ones measured for this change, and
#   the difference is instructive.  Timing seven short runs and then seven long
#   ones — rather than interleaving them — said 22.3% -> 2.1%, because the box
#   happened to be steadier during the second block.  The same mistake this file
#   makes about two proxies, made about two window lengths.
#
#   Timing the run squares the finish line as well.  With a count, each
#   connection stops when it personally is finished and the elapsed time charged
#   to all of them is the slowest one's, so the tail of the window has fewer
#   connections in flight than the head.  That effect turned out to be small
#   here — interleaving the two forms against one port put them 1.5% apart, the
#   counted one higher — and it is recorded at that size rather than the size it
#   first appeared to be.  Comparing the two forms in sequence rather than
#   interleaved made it look like 23%, because the box drifted 23% downward
#   during the comparison.  Which is the argument for the next paragraph.
#
#   The two proxies are measured in interleaved pairs, alternating which goes
#   first, and the answer is the median of the per-pair ratios.  Running all of
#   one arm and then all of the other lets any drift in the machine between the
#   two blocks arrive as a difference between the proxies, and this box drifts:
#   sixteen consecutive runs against one unchanged proxy fell from around 77000
#   to around 59000 round trips a second inside a minute, and stayed down.  Split
#   that sequence in half and call the halves A and B and you have measured a 23%
#   regression in something nobody touched.  A pair shares its weather instead:
#   when the box is slow both legs are slow and their ratio is untouched.  Under
#   a synthetic six-core background load the paired overhead measurement in
#   bench.c returned 69.4% and 69.6% on two invocations whose absolute rates
#   differed by 26%; the unpaired form, on the same load, returned overheads
#   between 11.1% and 75.8%.
#
#   Every case reports the smallest difference it could have resolved, and
#   refuses the ratio when that is wider than the question.  This is the part
#   that makes the rest safe: a number with no width beside it will be read as
#   exact by whoever finds it next.
#
# What did not work, so that nobody spends the afternoon again: pinning.  With
# taskset holding the backend on one core, both proxies on a dedicated pair, and
# the client on six, haproxy's coefficient of variation came out at 21.8% where
# the same case unpinned had measured 10.8%.  That pair of numbers was taken in
# sequence rather than interleaved, so treat it as "did not help" rather than as
# a measured harm — but there is no reason to expect it to help, and four
# independent readings say so.  During a concurrent run this box has around seven
# of its ten cores idle; steal time is zero; it exposes neither cpufreq nor
# cpuidle to the guest, so the guest has nothing to hold still; and a fixed-work
# calibration spin run either side of each measurement varies by ±10% while the
# rate it brackets varies by ±25%, which is most of the spread left unexplained
# by anything about CPU availability.  What is left behaves like a per-run
# condition rather than a per-second one, and only more runs average it out.
#
# ─── WHAT IT DOES NOT COVER ─────────────────────────────────────────────────
#
# Loopback on one machine, so no NIC, no real RTT, and none of the cases a proxy
# exists for: TLS termination, HTTP parsing, header rewriting, health checking,
# retries, connection reuse across many backends.  This measures forwarding, and
# only forwarding.  HAProxy doing that slower or faster than socketley says
# nothing about the rest of what HAProxy does.
#
# The interval each case prints describes repetitions of that case within one
# invocation of this script.  It does not cover the machine being in a different
# state tomorrow: the paired overhead measurement in bench.c read 74.7% on an
# idle box and 69.5% under a six-core load, both with intervals under ±3%.
# Within one machine state it holds up — three invocations at seven pairs, taken
# back to back on a quiet box, returned ratios of 0.54/0.54/0.56, 0.52/0.56/0.54,
# 0.64/0.66/0.67, 0.54/0.54/0.54, 0.82/0.76/0.78 and 0.95/0.93/0.95, every case
# reproducing inside ±4%.  The same 8-connection case, before this change,
# flipped from 0.64x to 1.51x between two invocations.

source "$(dirname "$0")/utils.sh"
# The paired-measurement machinery: interleaving, the quiet gate, the interval,
# the verdict.  bench_proxy_http_vs_haproxy.sh runs on the same one.
source "$(dirname "$0")/lib_paired.sh"

# ─── Ports ──────────────────────────────────────────────────────────────────
#
# One base, three consecutive ports.  These were fixed at 19091-19093, which is
# inside the block the integration suite uses, so this script and a suite run
# could not share a machine.
BENCH_PORT_BASE=${BENCH_PORT_BASE:-23000}
BACKEND_PORT=$((BENCH_PORT_BASE + 0))
SK_PORT=$((BENCH_PORT_BASE + 1))
HA_PORT=$((BENCH_PORT_BASE + 2))

PAIRS=${1:-${BENCH_HAPROXY_RUNS:-7}}
# Three is the floor, because two points have no spread worth the name and one
# has none at all.  The suite used to ask for a single repetition here, and a
# single repetition through this file would print a ratio with a ±0.0% beside
# it — the most confident-looking output the script can produce, from the least
# evidence it can gather.
if (( PAIRS < 3 )); then
    log_warn "raising pairs from $PAIRS to 3: fewer cannot produce an interval,"
    log_warn "and a ratio printed without one is the thing this file exists to stop"
    PAIRS=3
fi
SIZES=${BENCH_HAPROXY_SIZES:-"128 1024 16384"}
CONNS=${BENCH_HAPROXY_CONNS:-"1 8 32"}

# Milliseconds per measured run.  1500 is where the spread stops improving on
# this box: tripling the window, from 1700 ms to 4400 ms, moved haproxy's
# coefficient of variation only from 12% to 10%, because what is left is a
# per-run condition rather than something a longer average smooths out.  More
# pairs help there; a longer window does not, and it costs the same time.
RUN_MS=${BENCH_RUN_MS:-1500}
# An upper bound on operations, never the thing that ends a run.  Large enough
# that the clock always wins.
OPS_CAP=100000000

# The question the reader came with.  A case whose interval is wider than this
# is reported as unable to answer rather than answered badly.
TARGET_PCT=${BENCH_RESOLUTION_TARGET:-15}

# A pair measured while somebody else was using the machine is discarded.  This
# is the box's own load with none of our processes running, sampled either side
# of the pair, in cores.  The default allows for a developer's editor and shell;
# a parallel build lands far above it.
QUIET_CORES=${BENCH_QUIET_CORES:-1.0}

# Compare socketley against another socketley instead of against haproxy: point
# this at a second proxy's port and the B arm becomes that.  The pairing, the
# interval and the verdict are what make a 15% claim about one's own change
# checkable, and they should not require haproxy to be installed.
PEER_PORT=${BENCH_PEER_PORT:-}
PEER_NAME=${BENCH_PEER_NAME:-peer}

RESULTS_FILE="${RESULTS_DIR}/proxy_vs_haproxy_${TIMESTAMP}.json"
WORK=$(mktemp -d)
HA_PID=""

cleanup() {
    [[ -n "$HA_PID" ]] && kill "$HA_PID" 2>/dev/null
    socketley_cmd stop  hap_prox    2>/dev/null
    socketley_cmd stop  hap_backend 2>/dev/null
    sleep 0.4
    socketley_cmd remove hap_prox    2>/dev/null
    socketley_cmd remove hap_backend 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

if [[ -z "$PEER_PORT" ]] && ! command -v haproxy >/dev/null 2>&1; then
    log_error "haproxy not installed — nothing to compare against"
    log_info  "set BENCH_PEER_PORT to compare against another socketley proxy instead"
    exit 0
fi

if [[ -n "$PEER_PORT" ]]; then
    B_PORT=$PEER_PORT
    B_LABEL=$PEER_NAME
    HA_VERSION="peer proxy on port $PEER_PORT"
else
    B_PORT=$HA_PORT
    B_LABEL=hap
    HA_VERSION=$(haproxy -v 2>&1 | head -1 | sed 's/[",]/ /g')
fi

echo "[" > "$RESULTS_FILE"
FIRST_RESULT=true
append_result() {
    if [[ $FIRST_RESULT == true ]]; then FIRST_RESULT=false; else echo "," >> "$RESULTS_FILE"; fi
}

pid_on_port() {
    ss -ltnp 2>/dev/null | awk -v p=":$1\$" '$4 ~ p' \
        | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2
}

# ─── One measured run ───────────────────────────────────────────────────────
#
# Emits: rate proxy_cores backend_cores
# Both CPU figures are per wall-clock second of the run, so 1.00 means the
# process had one core busy for the whole of it.
measure() {
    local port=$1 mode=$2 a=$3 b=$4 px_pid=$5
    local p0 p1 e0 e1 w0 w1 out rate

    p0=$(cpu_ticks_of "$px_pid"); e0=$(cpu_ticks_of "$BE_PID"); w0=$(date +%s%N)
    if [[ $mode == serial ]]; then
        out=$(timeout "$BENCH_TIMEOUT_CMD" "$SOCKETLEY_BENCH" -r 1 -d "$RUN_MS" \
              proxy tcp 127.0.0.1 "$port" "$OPS_CAP" "$b" 2>/dev/null)
    else
        out=$(timeout "$BENCH_TIMEOUT_CMD" "$SOCKETLEY_BENCH" -r 1 -d "$RUN_MS" \
              proxy concurrent 127.0.0.1 "$port" "$a" "$OPS_CAP" 2>/dev/null)
    fi
    w1=$(date +%s%N); p1=$(cpu_ticks_of "$px_pid"); e1=$(cpu_ticks_of "$BE_PID")

    rate=$(grep -oE '^\s*Median:\s+[0-9]+' <<<"$out" | grep -oE '[0-9]+' | head -1)
    awk -v r="${rate:-0}" -v px=$((p1 - p0)) -v be=$((e1 - e0)) \
        -v hz="$HZ" -v ns=$((w1 - w0)) \
        'BEGIN { s = ns / 1e9; printf "%s %.3f %.3f", r, px / hz / s, be / hz / s }'
}

# ─── One measured run, per arm ──────────────────────────────────────────────
#
# lib_paired.sh drives the pairing and calls this; resolving an arm to a port
# and a pid is the part that is not shared between protocols.
arm_measure() {
    local arm=$1 mode=$2 a=$3 b=$4
    if [[ $arm == a ]]; then measure "$SK_PORT" "$mode" "$a" "$b" "$SK_PID"
    else                     measure "$B_PORT"  "$mode" "$a" "$b" "$B_PID"; fi
}

log_section "Proxy vs ${B_LABEL} — paired, timed, with a stated resolution"
log_info "$HA_VERSION"
log_info "ports ${BACKEND_PORT}/${SK_PORT}/${B_PORT}  ${PAIRS} pairs  ${RUN_MS} ms per run"

# ─── The shared backend ──────────────────────────────────────────────────────
#
# Only this script's own two runtimes are removed, not every runtime the daemon
# holds: cleanup_runtimes() sweeps all of them, and a benchmark that deletes
# whatever else is running is a benchmark nobody can leave unattended.
ensure_clean() {
    socketley_cmd stop  hap_prox    >/dev/null 2>&1
    socketley_cmd stop  hap_backend >/dev/null 2>&1
    sleep 0.4
    socketley_cmd remove hap_prox    >/dev/null 2>&1
    socketley_cmd remove hap_backend >/dev/null 2>&1
}

ensure_clean
socketley_cmd create server hap_backend -p "$BACKEND_PORT" --mode in \
    --lua "$BENCH_ECHO_LUA" -s
wait_for_port "$BACKEND_PORT" || { log_error "backend did not come up"; exit 1; }

socketley_cmd create proxy hap_prox -p "$SK_PORT" \
    --backend "127.0.0.1:$BACKEND_PORT" --protocol tcp -s
wait_for_port "$SK_PORT" || { log_error "socketley proxy did not come up"; exit 1; }

if [[ -z "$PEER_PORT" ]]; then
    cat > "$WORK/haproxy.cfg" <<EOF
global
    nbthread 1
    maxconn 8192

defaults
    mode tcp
    timeout connect 5s
    timeout client  30s
    timeout server  30s

frontend fe
    bind 127.0.0.1:$HA_PORT
    default_backend be

backend be
    server s1 127.0.0.1:$BACKEND_PORT
EOF

    haproxy -f "$WORK/haproxy.cfg" -db > "$WORK/haproxy.out" 2>&1 &
    HA_PID=$!
    wait_for_port "$HA_PORT" || { log_error "haproxy did not come up: $(cat "$WORK/haproxy.out")"; exit 1; }
else
    wait_for_port "$PEER_PORT" || { log_error "peer proxy on $PEER_PORT is not listening"; exit 1; }
fi
sleep 0.5

SK_PID=$(pid_on_port "$SK_PORT")
BE_PID=$(pid_on_port "$BACKEND_PORT")
B_PID=$(pid_on_port "$B_PORT")

if [[ -z "$SK_PID" || -z "$BE_PID" || -z "$B_PID" ]]; then
    log_error "could not identify one of the processes under test (sk=$SK_PID be=$BE_PID b=$B_PID)"
    log_error "every CPU figure below would be zero, so nothing is measured"
    exit 1
fi
log_info "socketley proxy pid=$SK_PID  ${B_LABEL} pid=$B_PID  backend pid=$BE_PID"

START_LOAD=$(box_load_cores)
log_info "box load with nothing of ours running: ${START_LOAD} cores (pairs above ${QUIET_CORES} are discarded)"

# ─── Reporting ──────────────────────────────────────────────────────────────
#
# The verdict column, not the ratio, is the thing to read first.  A ratio whose
# interval is wider than the difference it claims is not a weaker result, it is
# not a result.  paired_verdict() in lib_paired.sh decides it.
WORST_CI=0

emit() {   # label mode a b
    local label=$1 mode=$2 a=$3 b=$4
    paired_run_case "$mode" "$a" "$b"
    local v; v=$(paired_verdict "$C_CI" "$C_KEPT" "$C_BE")
    awk -v c="$C_CI" -v w="$WORST_CI" 'BEGIN { exit !(c > w) }' && WORST_CI=$C_CI

    local pa pb pr
    pa=$(printf '%.0f' "$C_A"); pb=$(printf '%.0f' "$C_B")
    pr=$(printf '%.2f' "$C_RATIO")
    printf "  %-11s %8s %8s   %6sx  ±%-6s %s\n" \
        "$label" "$pa" "$pb" "$pr" "${C_CI}%" "$v"

    append_result
    cat >> "$RESULTS_FILE" <<EOF
  {"test": "proxy_vs_${B_LABEL}_${mode}", "case": "$label",
   "payload_bytes": ${b:-64}, "connections": ${a:-1},
   "pairs_kept": $C_KEPT, "pairs_discarded_unquiet": $C_DROPPED,
   "pairs_discarded_failed": ${C_BADRUN:-0},
   "run_ms": $RUN_MS,
   "socketley_rt_sec": ${C_A:-0}, "${B_LABEL}_rt_sec": ${C_B:-0},
   "ratio_socketley_over_${B_LABEL}": ${C_RATIO:-0},
   "ratio_ci95_half_width_pct": ${C_CI:-0},
   "socketley_ci95_half_width_pct": ${C_A_CI:-0},
   "socketley_proxy_cores": ${C_APX:-0}, "${B_LABEL}_proxy_cores": ${C_BPX:-0},
   "backend_cores_during_socketley": ${C_ABE:-0},
   "backend_cores_during_${B_LABEL}": ${C_BBE:-0},
   "resolution_target_pct": $TARGET_PCT,
   "verdict": "$v",
   "peer_version": "$(sed 's/"/ /g' <<<"$HA_VERSION")"}
EOF
}

# ─── Serial: one connection, one request in flight ──────────────────────────
#
# The latency regime.  Nothing to batch, so every wake-up shows up in the
# number, which is exactly where the two implementations differ most.
echo ""
printf "  %-11s %8s %8s   %7s  %-7s %s\n" "payload" "sk" "$B_LABEL" "sk/$B_LABEL" "±95%CI" "verdict"
printf "  %-11s %8s %8s   %7s  %-7s %s\n" "─────────" "───────" "───────" "───────" "──────" "───────"
for sz in $SIZES; do
    emit "${sz} B" serial "" "$sz"
done

# ─── Concurrent: where the wake-ups amortise ────────────────────────────────
echo ""
printf "  %-11s %8s %8s   %7s  %-7s %s\n" "conns" "sk" "$B_LABEL" "sk/$B_LABEL" "±95%CI" "verdict"
printf "  %-11s %8s %8s   %7s  %-7s %s\n" "─────────" "───────" "───────" "───────" "──────" "───────"
for c in $CONNS; do
    emit "$c" concurrent "$c" 64
done

echo "" >> "$RESULTS_FILE"
echo "]" >> "$RESULTS_FILE"

echo ""
log_info "the widest interval in this run was ±${WORST_CI}% — a difference smaller"
log_info "than that, in any case above, is this machine and not the proxy"
if awk -v w="$WORST_CI" -v t="$TARGET_PCT" 'BEGIN { exit !(w > t) }'; then
    log_warn "at least one case could not resolve ${TARGET_PCT}%; raise the pair count"
    log_warn "(first argument, currently $PAIRS) — the interval narrows as 1/sqrt(pairs),"
    log_warn "so four times the pairs halves it.  A longer BENCH_RUN_MS will not help:"
    log_warn "measured on this box, 1700 ms to 4400 ms moved it by two points."
fi
log_info "results: $RESULTS_FILE"
