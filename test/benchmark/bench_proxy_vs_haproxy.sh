#!/bin/bash
# Proxy vs HAProxy — one thread each, one backend, one client.
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
# One thread each.  HAProxy defaults to a thread per available core, so against
# an untuned config this box would compare ten threads with one and the number
# would mean nothing.  `nbthread 1` is in the config below, and the thread count
# of BOTH processes is measured at run time and written into the results —
# a claim about a config file is not a measurement, and bench_cache_resp.sh
# records redis_io_threads for the same reason.
#
# One backend, and it is the same object.  Both proxies front the identical
# socketley server runtime with echo.lua, started once and left alone, so a
# difference between them cannot be a difference between two fixtures.  The
# backend is itself single-threaded, which matters: at high connection counts it
# can become the limit, and then the two proxies are being compared on how well
# they queue rather than how fast they forward.  The per-run CPU of the backend
# is recorded so that case is visible instead of silently changing the subject.
#
# One client, socketley_bench, driving plain TCP round trips.  It is protocol
# agnostic — a request goes out, a reply is read before the next goes out — so
# it measures the same thing through either proxy.  Using each proxy's preferred
# client would measure the clients.
#
# ─── WHAT IT DOES NOT COVER ─────────────────────────────────────────────────
#
# Loopback on one machine, so no NIC, no real RTT, and none of the cases a proxy
# exists for: TLS termination, HTTP parsing, header rewriting, health checking,
# retries, connection reuse across many backends.  This measures forwarding, and
# only forwarding.  HAProxy doing that slower or faster than socketley says
# nothing about the rest of what HAProxy does.

source "$(dirname "$0")/utils.sh"

BACKEND_PORT=19091
SK_PORT=19092
HA_PORT=19093

RUNS=${1:-${BENCH_HAPROXY_RUNS:-3}}
SIZES=${BENCH_HAPROXY_SIZES:-"128 1024 16384"}
CONNS=${BENCH_HAPROXY_CONNS:-"1 8 32"}
MSGS_PER_CONN=200
SERIAL_MSGS=3000

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

if ! command -v haproxy >/dev/null 2>&1; then
    log_error "haproxy not installed — nothing to compare against"
    exit 0
fi

HA_VERSION=$(haproxy -v 2>&1 | head -1 | sed 's/[",]/ /g')

echo "[" > "$RESULTS_FILE"
FIRST_RESULT=true
append_result() {
    if [[ $FIRST_RESULT == true ]]; then FIRST_RESULT=false; else echo "," >> "$RESULTS_FILE"; fi
}

# threads_of PID — how many threads a process actually has right now.
#
# The fairness check, not a formality: it is what separates "the config says one
# thread" from "one thread ran".  socketley's proxy grows io_uring kernel worker
# threads (iou-wrk-*) on demand when an operation cannot be completed on the
# fast path, so its count is not fixed by anything in its configuration either.
threads_of() { ls "/proc/$1/task" 2>/dev/null | wc -l; }

iou_workers_of() {
    local pid=$1 n=0 t
    for t in /proc/$pid/task/*; do
        [[ -r "$t/comm" ]] || continue
        [[ "$(cat "$t/comm" 2>/dev/null)" == iou-wrk-* ]] && n=$((n + 1))
    done
    echo "$n"
}

pid_on_port() {
    ss -ltnp 2>/dev/null | awk -v p=":$1\$" '$4 ~ p' \
        | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2
}

cpu_ticks_of() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0; }

log_section "Proxy vs HAProxy — one thread each"
log_info "$HA_VERSION"

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
sleep 0.5

SK_PID=$(pid_on_port "$SK_PORT")
BE_PID=$(pid_on_port "$BACKEND_PORT")
HA_RUN_PID=$(pgrep -x haproxy | head -1)

log_info "socketley proxy pid=$SK_PID  haproxy pid=$HA_RUN_PID  backend pid=$BE_PID"

# median_of "value value value" — the middle one, so a single outlier run does
# not become the reported number.
median_of() {
    tr ' ' '\n' <<<"$1" | grep -E '^[0-9]+$' | sort -n \
        | awk -v n="$(tr ' ' '\n' <<<"$1" | grep -cE '^[0-9]+$')" 'NR == int((n+1)/2)'
}

# one_case LABEL PORT MODE ARG1 ARG2 -> "median min max"
#
# The spread is returned, not just the middle.  A single median hid a run-to-run
# swing of 2.4x in the 8-connection case while this file was being written --
# reported alone it would have been a finding, and it was the harness.  A reader
# who can see min and max can tell the two apart; one who is handed one number
# cannot.
one_case() {
    local port=$2 mode=$3 a=$4 b=$5 vals="" i out n
    for ((i = 1; i <= RUNS; i++)); do
        if [[ $mode == serial ]]; then
            out=$(timeout "$BENCH_TIMEOUT_CMD" "$SOCKETLEY_BENCH" -r 1 proxy tcp \
                  127.0.0.1 "$port" "$a" "$b" 2>/dev/null)
        else
            out=$(timeout "$BENCH_TIMEOUT_CMD" "$SOCKETLEY_BENCH" -r 1 proxy concurrent \
                  127.0.0.1 "$port" "$a" "$b" 2>/dev/null)
        fi
        n=$(grep -oE '^\s*Median:\s+[0-9]+' <<<"$out" | grep -oE '[0-9]+' | head -1)
        vals+="${n:-0} "
    done
    local med lo hi
    med=$(median_of "$vals")
    lo=$(tr ' ' '\n' <<<"$vals" | grep -E '^[0-9]+$' | sort -n | head -1)
    hi=$(tr ' ' '\n' <<<"$vals" | grep -E '^[0-9]+$' | sort -n | tail -1)
    echo "$med $lo $hi"
}

ratio() { awk -v a="$1" -v b="$2" 'BEGIN { if (b+0 == 0) print "N/A"; else printf "%.2fx", a/b }'; }

# ─── Serial: one connection, one request in flight ──────────────────────────
#
# The latency regime.  Nothing to batch, so every wake-up shows up in the
# number, which is exactly where the two implementations differ most.
echo ""
printf "  %-12s %8s %-13s %8s %-13s %8s\n" "payload" "sk" "[min-max]" "hap" "[min-max]" "s/h"
printf "  %-12s %8s %-13s %8s %-13s %8s\n" "──────────" "───────" "───────────" "───────" "───────────" "───────"
for sz in $SIZES; do
    b0=$(cpu_ticks_of "$BE_PID")
    read -r SK SK_LO SK_HI <<<"$(one_case sk "$SK_PORT" serial "$SERIAL_MSGS" "$sz")"
    b1=$(cpu_ticks_of "$BE_PID")
    read -r HA HA_LO HA_HI <<<"$(one_case ha "$HA_PORT" serial "$SERIAL_MSGS" "$sz")"
    b2=$(cpu_ticks_of "$BE_PID")

    printf "  %-12s %8s [%s-%s] %8s [%s-%s] %8s\n" "${sz} B" \
        "$SK" "$SK_LO" "$SK_HI" "$HA" "$HA_LO" "$HA_HI" "$(ratio "$SK" "$HA")"

    append_result
    cat >> "$RESULTS_FILE" <<EOF
  {"test": "proxy_vs_haproxy_serial", "payload_bytes": $sz, "connections": 1,
   "messages": $SERIAL_MSGS, "runs": $RUNS,
   "socketley_rt_sec": ${SK:-0}, "socketley_rt_min": ${SK_LO:-0}, "socketley_rt_max": ${SK_HI:-0},\n   "haproxy_rt_sec": ${HA:-0}, "haproxy_rt_min": ${HA_LO:-0}, "haproxy_rt_max": ${HA_HI:-0},
   "socketley_threads": $(threads_of "$SK_PID"), "socketley_iou_workers": $(iou_workers_of "$SK_PID"),
   "haproxy_threads": $(threads_of "$HA_RUN_PID"),
   "backend_cpu_ticks_socketley_run": $((b1 - b0)),
   "backend_cpu_ticks_haproxy_run": $((b2 - b1)),
   "haproxy_version": "$(sed 's/"/ /g' <<<"$HA_VERSION")"}
EOF
done

# ─── Concurrent: where the wake-ups amortise ────────────────────────────────
echo ""
printf "  %-12s %8s %-13s %8s %-13s %8s\n" "conns" "sk" "[min-max]" "hap" "[min-max]" "s/h"
printf "  %-12s %8s %-13s %8s %-13s %8s\n" "──────────" "───────" "───────────" "───────" "───────────" "───────"
for c in $CONNS; do
    b0=$(cpu_ticks_of "$BE_PID")
    read -r SK SK_LO SK_HI <<<"$(one_case sk "$SK_PORT" concurrent "$c" "$MSGS_PER_CONN")"
    b1=$(cpu_ticks_of "$BE_PID")
    read -r HA HA_LO HA_HI <<<"$(one_case ha "$HA_PORT" concurrent "$c" "$MSGS_PER_CONN")"
    b2=$(cpu_ticks_of "$BE_PID")

    printf "  %-12s %8s [%s-%s] %8s [%s-%s] %8s\n" "$c" \
        "$SK" "$SK_LO" "$SK_HI" "$HA" "$HA_LO" "$HA_HI" "$(ratio "$SK" "$HA")"

    append_result
    cat >> "$RESULTS_FILE" <<EOF
  {"test": "proxy_vs_haproxy_concurrent", "payload_bytes": 64, "connections": $c,
   "messages_per_connection": $MSGS_PER_CONN, "runs": $RUNS,
   "socketley_rt_sec": ${SK:-0}, "socketley_rt_min": ${SK_LO:-0}, "socketley_rt_max": ${SK_HI:-0},\n   "haproxy_rt_sec": ${HA:-0}, "haproxy_rt_min": ${HA_LO:-0}, "haproxy_rt_max": ${HA_HI:-0},
   "socketley_threads": $(threads_of "$SK_PID"), "socketley_iou_workers": $(iou_workers_of "$SK_PID"),
   "haproxy_threads": $(threads_of "$HA_RUN_PID"),
   "backend_cpu_ticks_socketley_run": $((b1 - b0)),
   "backend_cpu_ticks_haproxy_run": $((b2 - b1)),
   "haproxy_version": "$(sed 's/"/ /g' <<<"$HA_VERSION")"}
EOF
done

echo "" >> "$RESULTS_FILE"
echo "]" >> "$RESULTS_FILE"

echo ""
log_info "socketley proxy: $(threads_of "$SK_PID") thread(s), $(iou_workers_of "$SK_PID") of them io_uring kernel workers"
log_info "haproxy:         $(threads_of "$HA_RUN_PID") thread(s)"
log_info "results: $RESULTS_FILE"
