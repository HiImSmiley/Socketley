#!/bin/bash
# Proxy Runtime Benchmark
# Uses socketley-bench (C binary) for TCP forwarding measurement.
# HTTP proxy tests still use bash (HTTP protocol specifics).

source "$(dirname "$0")/utils.sh"
# cpu_ticks_of() and HZ; the HTTP rows report who was saturated.
source "$(dirname "$0")/lib_paired.sh"

# Ports, from one base.  These were fixed at 19080-19082, inside the range the
# integration suite binds, so a benchmark and a test run could not share a
# machine — and neither of them says so when they collide; they say the proxy
# was slow.  bench_proxy_vs_haproxy.sh takes the same base and the offsets below
# keep the two scripts clear of each other.
BENCH_PORT_BASE=${BENCH_PORT_BASE:-23000}
PROXY_PORT=$((BENCH_PORT_BASE + 10))
BACKEND_PORT_1=$((BENCH_PORT_BASE + 11))
# Connections in flight for the two HTTP tests.  40 because that is what the
# bash version ran per batch, so the load the proxy sees is unchanged across
# every repair these two rows have had.
HTTP_CONCURRENCY=${HTTP_CONCURRENCY:-40}
# Timed, not counted.  A fixed request count is a window that narrows as the
# code gets faster: 2000 requests took 242 ms when the fixture was Python and
# would take 140 ms against the one below, which is short enough for the
# scheduler to be a visible share of it.  2000 ms x 3 runs, plus the run
# socketley_bench discards, is about 8 s per row.
HTTP_RUN_MS=${HTTP_RUN_MS:-2000}
HTTP_RUNS=${HTTP_RUNS:-3}
# The count becomes an upper bound when -d is given; it is here only so a run
# cannot end early.
HTTP_OPS_CAP=100000000
BACKEND_PORT_2=$((BENCH_PORT_BASE + 12))
RESULTS_FILE="${RESULTS_DIR}/proxy_${TIMESTAMP}.json"

echo "[" > "$RESULTS_FILE"
FIRST_RESULT=true

append_result() {
    if [[ $FIRST_RESULT == true ]]; then
        FIRST_RESULT=false
    else
        echo "," >> "$RESULTS_FILE"
    fi
}

ensure_clean() {
    socketley_cmd stop bench_proxy 2>/dev/null
    socketley_cmd stop backend1 2>/dev/null
    socketley_cmd stop named_backend 2>/dev/null
    sleep 0.5
    socketley_cmd remove bench_proxy 2>/dev/null
    socketley_cmd remove backend1 2>/dev/null
    socketley_cmd remove named_backend 2>/dev/null
}

# ─── The HTTP fixture, and why it stopped being Python ──────────────────────
#
# Both HTTP rows used to drive a Python raw-socket backend with a Python load
# generator, and reported about 8,000 req/sec.  b80eae0 had already replaced a
# bash client with http_load.py for exactly this reason and left the fixture
# question open; this is the answer, and the answer is that the client was only
# half of it.  Measured on one box, one afternoon, same proxy, same 40 concurrent
# connection-per-request load, medians of three:
#
#     python backend + python client      8,264 req/sec   <- what was published
#     python backend + C client           7,608 req/sec
#     socketley backend + python client   7,518 req/sec
#     socketley backend + C client       14,084 req/sec
#
# Replacing either component alone changes nothing, because both cap at almost
# the same rate.  Only replacing both moves the number, and it moves it 1.7x.
# What the published 8,475 measured was Python -- either Python, whichever was
# asked first.
#
# With the fixture below the proxy runs at 0.95 cores and the backend at 0.37,
# so the figure is the proxy's.  Both are reported on every row, because a
# backend at the same load as the proxy means the row is measuring the backend,
# and the reader has to be able to see that without re-running anything.
#
# For scale, the same proxy and backend on reused connections: 72,615 req/sec at
# 1.00 proxy cores.  Connection-per-request is kept because it is what these two
# rows have always measured and the harder case for a proxy; it is not the
# proxy's top speed and this file does not claim it is.
#
# `--http-cache` is not optional.  Without it every request is a disk read and
# what gets measured is the page cache.  The file is two bytes, the same body
# the Python backend returned, so the shape of the request is unchanged.

HTTP_FIXTURE_DIR=""
HTTP_BACKEND_NAMES=()

# A socketley server runtime serving one small file out of memory.
start_http_backend() {
    local name=$1 port=$2
    if [[ -z "$HTTP_FIXTURE_DIR" ]]; then
        HTTP_FIXTURE_DIR=$(mktemp -d -t socketley_bench_http.XXXXXX)
        printf 'OK' > "$HTTP_FIXTURE_DIR/test"
        chmod -R a+rX "$HTTP_FIXTURE_DIR"
    fi
    socketley_cmd stop "$name" >/dev/null 2>&1
    socketley_cmd remove "$name" >/dev/null 2>&1
    socketley_cmd create server "$name" -p "$port" \
        --http "$HTTP_FIXTURE_DIR" --http-cache -s >/dev/null 2>&1
    HTTP_BACKEND_NAMES+=( "$name" )
    wait_for_port "$port"
}

stop_http_backends() {
    local n
    for n in "${HTTP_BACKEND_NAMES[@]}"; do
        socketley_cmd stop "$n" >/dev/null 2>&1
        socketley_cmd remove "$n" >/dev/null 2>&1
    done
    HTTP_BACKEND_NAMES=()
}

cleanup_http_fixture() {
    stop_http_backends
    [[ -n "$HTTP_FIXTURE_DIR" ]] && rm -rf "$HTTP_FIXTURE_DIR"
    HTTP_FIXTURE_DIR=""
}

pid_on_port() {
    ss -ltnp 2>/dev/null | awk -v p=":$1\$" '$4 ~ p' \
        | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2
}

# ─── The oracle the C client does not have ──────────────────────────────────
#
# An http proxy routes on a leading "/<runtime-name>/" and answers everything
# else with its own 404, without opening a backend connection at all -- and that
# refusal is produced faster than the hop these rows exist to measure.
#
# http_load.py checked the status code for exactly this reason.  socketley_bench
# does not: http_read_response() accepts any well-formed response, so a 404
# counts as a served request and this file would carry the rate at which the
# proxy can refuse to proxy.  It is one rename away, the failure is silent, and
# it reads as a speed-up.  So the path is fetched once, before anything is
# timed, and has to answer 200 with a body of the expected length.
require_200() {   # port path expected_bytes
    local port=$1 path=$2 want=$3 got
    got=$(python3 - "$port" "$path" <<'REQ200' 2>/dev/null || echo "ERR 0"
import socket, sys
port, path = int(sys.argv[1]), sys.argv[2]
req = ("GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n" % path).encode()
try:
    s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(5)
    s.sendall(req)
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d: break
        buf += d
    head = buf.split(b"\r\n\r\n", 1)[0]
    status = head.split(b"\r\n")[0].split(b" ")[1].decode()
    cl = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            cl = int(line.split(b":")[1])
    s.close()
    print(status, cl)
except Exception:
    print("ERR", 0)
REQ200
)
    if [[ "$got" != "200 $want" ]]; then
        log_error "$path on port $port answered '$got', not '200 $want'"
        log_error "an http proxy answers anything outside /<proxy-name>/ with its"
        log_error "own 404 and never contacts the backend; a throughput figure"
        log_error "taken through this path would be the rate of that refusal"
        return 1
    fi
    log_info "  $path -> HTTP 200, $want bytes (the backend is being reached)"
    return 0
}

# One timed HTTP measurement through the proxy, with the CPU both ends spent.
#
# Sets HB_RATE, HB_LO, HB_HI, HB_SPREAD, HB_STABLE, HB_CI, HB_SUCCESS,
# HB_FAILED, HB_PROXY_CORES, HB_BACKEND_CORES.
measure_http_through_proxy() {   # port path proxy_pid backend_pid
    local port=$1 path=$2 px=$3 be=$4
    local p0 p1 e0 e1 w0 w1 out rc
    HB_RATE=0; HB_LO=0; HB_HI=0; HB_SPREAD=0; HB_STABLE=0; HB_CI=0
    HB_SUCCESS=0; HB_FAILED=0; HB_PROXY_CORES=0; HB_BACKEND_CORES=0

    p0=$(cpu_ticks_of "$px"); e0=$(cpu_ticks_of "$be"); now_us; w0=$NOW_US
    out=$(timeout "$BENCH_TIMEOUT_CMD" "$SOCKETLEY_BENCH" -j -r "$HTTP_RUNS" \
              -d "$HTTP_RUN_MS" -u "$path" \
              proxy http-close 127.0.0.1 "$port" "$HTTP_CONCURRENCY" "$HTTP_OPS_CAP" 2>/dev/null)
    rc=$?
    now_us; w1=$NOW_US; p1=$(cpu_ticks_of "$px"); e1=$(cpu_ticks_of "$be")
    [[ $rc -eq 124 ]] && log_bench "TIMEOUT" "socketley_bench proxy http-close $port"

    # Flat one-line JSON, pulled apart with grep so this file keeps working
    # without jq -- check_dependencies does not require it.
    HB_RATE=$(grep -oP '"median_round_trips_per_sec":\K[0-9.]+' <<<"$out")
    HB_LO=$(grep -oP '"min_per_sec":\K[0-9.]+' <<<"$out")
    HB_HI=$(grep -oP '"max_per_sec":\K[0-9.]+' <<<"$out")
    HB_SPREAD=$(grep -oP '"spread_ratio":\K[0-9.]+' <<<"$out")
    HB_STABLE=$(grep -oP '"stable":\K[0-9]+' <<<"$out")
    HB_CI=$(grep -oP '"ci95_half_width_pct":\K[0-9.]+' <<<"$out")
    HB_SUCCESS=$(grep -oP '"success":\K[0-9]+' <<<"$out")
    HB_FAILED=$(grep -oP '"failed":\K[0-9]+' <<<"$out")
    HB_RATE=${HB_RATE:-0}; HB_LO=${HB_LO:-0}; HB_HI=${HB_HI:-0}
    HB_SPREAD=${HB_SPREAD:-0}; HB_STABLE=${HB_STABLE:-0}; HB_CI=${HB_CI:-0}
    HB_SUCCESS=${HB_SUCCESS:-0}; HB_FAILED=${HB_FAILED:-0}

    read -r HB_PROXY_CORES HB_BACKEND_CORES < <(awk \
        -v px=$((p1 - p0)) -v be=$((e1 - e0)) -v hz="$HZ" -v us=$((w1 - w0)) \
        'BEGIN { s = us / 1e6; printf "%.2f %.2f", px / hz / s, be / hz / s }')
}

# Print and record one HTTP row.
report_http_row() {   # test_name [extra_key extra_value]...
    local test_name=$1; shift
    local wide="" backend_note=""
    [[ "$HB_STABLE" == "1" ]] || wide="  — too wide to quote the median alone"

    log_success "Throughput: $HB_RATE req/sec  (connection per request, $HTTP_CONCURRENCY concurrent)"
    log_info    "  spread $HB_LO .. $HB_HI (${HB_SPREAD}x)${wide}; resolves differences above ${HB_CI}% over $HTTP_RUNS runs"
    log_info    "  proxy $HB_PROXY_CORES cores, backend $HB_BACKEND_CORES cores"
    if awk -v b="$HB_BACKEND_CORES" -v p="$HB_PROXY_CORES" 'BEGIN{exit !(p > 0 && b >= p)}'; then
        backend_note="backend-bound: it spent at least as much CPU as the proxy"
        log_error "  $backend_note — this row is not a proxy figure"
    fi
    if [[ "$HB_FAILED" != "0" ]]; then
        log_error "  $HB_FAILED failed requests: a thread that gave up stopped contributing load"
    fi

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "measures"            "connection_per_request_http" \
        "fixture"             "socketley --http --http-cache backend, socketley_bench client" \
        "requests_per_sec"    "$HB_RATE" \
        "min_per_sec"         "$HB_LO" \
        "max_per_sec"         "$HB_HI" \
        "spread_ratio"        "$HB_SPREAD" \
        "stable"              "$HB_STABLE" \
        "ci95_half_width_pct" "$HB_CI" \
        "concurrency"         "$HTTP_CONCURRENCY" \
        "run_ms"              "$HTTP_RUN_MS" \
        "runs"                "$HTTP_RUNS" \
        "success"             "$HB_SUCCESS" \
        "failed"              "$HB_FAILED" \
        "proxy_cores"         "$HB_PROXY_CORES" \
        "backend_cores"       "$HB_BACKEND_CORES" \
        "backend_bound"       "$([[ -n "$backend_note" ]] && echo 1 || echo 0)" \
        "$@"
}

# Test 1: HTTP proxy throughput (single backend)
test_http_single_backend() {
    local test_name="proxy_http_single_backend"

    log_section "Test: HTTP Proxy Single Backend (${HTTP_RUN_MS} ms x ${HTTP_RUNS}, ${HTTP_CONCURRENCY} concurrent)"

    ensure_clean
    start_http_backend bench_be1 $BACKEND_PORT_1 || { log_error "Backend failed to start"; stop_http_backends; return 1; }

    socketley_cmd create proxy bench_proxy -p $PROXY_PORT --backend 127.0.0.1:$BACKEND_PORT_1 --protocol http -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; stop_http_backends; ensure_clean; return 1; }
    sleep 0.5

    require_200 "$PROXY_PORT" /bench_proxy/test 2 || { stop_http_backends; ensure_clean; return 1; }

    local px be
    px=$(pid_on_port $PROXY_PORT); be=$(pid_on_port $BACKEND_PORT_1)
    if [[ -z "$px" || -z "$be" ]]; then
        log_error "could not identify the proxy or backend process (proxy=$px backend=$be)"
        stop_http_backends; ensure_clean; return 1
    fi

    measure_http_through_proxy "$PROXY_PORT" /bench_proxy/test "$px" "$be"
    report_http_row "$test_name" "backends" "1"

    socketley_cmd stop bench_proxy
    sleep 0.5
    wait_for_port_free $PROXY_PORT
    socketley_cmd remove bench_proxy
    stop_http_backends
}

# Test 2: HTTP proxy with multiple backends (load balancing)
#
# The same client, the same fixture and the same window as test 1, and that is
# the point: these two numbers are read against each other.  While one forked
# `date` twice per request and the other did not, the comparison said a second
# backend made the proxy five times faster, which was a statement about bash.
# Now they differ in one thing.
test_http_load_balancing() {
    local test_name="proxy_http_load_balancing"

    log_section "Test: HTTP Proxy Load Balancing (2 backends, ${HTTP_RUN_MS} ms x ${HTTP_RUNS})"

    ensure_clean
    start_http_backend bench_be1 $BACKEND_PORT_1 || { log_error "Backend1 failed"; stop_http_backends; return 1; }
    start_http_backend bench_be2 $BACKEND_PORT_2 || { log_error "Backend2 failed"; stop_http_backends; return 1; }

    socketley_cmd create proxy bench_proxy -p $PROXY_PORT \
        --backend 127.0.0.1:$BACKEND_PORT_1,127.0.0.1:$BACKEND_PORT_2 \
        --strategy round-robin --protocol http -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; stop_http_backends; ensure_clean; return 1; }
    sleep 0.5

    require_200 "$PROXY_PORT" /bench_proxy/test 2 || { stop_http_backends; ensure_clean; return 1; }

    local px be
    px=$(pid_on_port $PROXY_PORT); be=$(pid_on_port $BACKEND_PORT_1)
    if [[ -z "$px" || -z "$be" ]]; then
        log_error "could not identify the proxy or backend process (proxy=$px backend=$be)"
        stop_http_backends; ensure_clean; return 1
    fi

    # backend_cores here is one of the two, so it understates the backend side by
    # about half.  Said rather than corrected: the check it feeds is "is the
    # backend the limit", and half the answer missing makes that check
    # conservative in the safe direction.
    measure_http_through_proxy "$PROXY_PORT" /bench_proxy/test "$px" "$be"
    report_http_row "$test_name" \
        "backends" "2" \
        "strategy" "round-robin" \
        "backend_cores_note" "one of two backends"

    socketley_cmd stop bench_proxy
    sleep 0.5
    wait_for_port_free $PROXY_PORT
    socketley_cmd remove bench_proxy
    stop_http_backends
}

# Test 3: TCP proxy throughput — uses socketley-bench
test_tcp_throughput() {
    local num_messages=${1:-5000}
    local message_size=${2:-128}
    local test_name="proxy_tcp_throughput"

    log_section "Test: TCP Proxy Throughput ($num_messages msgs, ${message_size}B)"

    ensure_clean
    # An echoing backend: this measures a request forwarded and its reply
    # returned, and a backend that answers nothing leaves the client timing a
    # write into the proxy's accept buffer.  Same reason test 5 has one.
    socketley_cmd create server backend1 -p $BACKEND_PORT_1 --mode in --lua "$BENCH_ECHO_LUA" -s
    wait_for_port $BACKEND_PORT_1 || { log_error "Backend failed"; ensure_clean; return 1; }

    socketley_cmd create proxy bench_proxy -p $PROXY_PORT \
        --backend 127.0.0.1:$BACKEND_PORT_1 --protocol tcp -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; ensure_clean; return 1; }
    sleep 0.5

    append_result
    bench_run -j proxy tcp 127.0.0.1 $PROXY_PORT $num_messages $message_size >> "$RESULTS_FILE"
    bench_run proxy tcp 127.0.0.1 $PROXY_PORT $num_messages $message_size

    socketley_cmd stop bench_proxy
    socketley_cmd stop backend1
    sleep 0.5
    wait_for_port_free $PROXY_PORT
    socketley_cmd remove bench_proxy
    socketley_cmd remove backend1
}

# Test 4: Concurrent connections through proxy — uses socketley-bench
test_concurrent_proxy_connections() {
    local num_clients=${1:-50}
    local requests_per_client=${2:-100}
    local test_name="proxy_concurrent_connections"

    log_section "Test: Concurrent Proxy Connections ($num_clients clients)"

    ensure_clean
    # An echoing backend: this measures a request forwarded and its reply
    # returned, and a backend that answers nothing leaves the client timing a
    # write into the proxy's accept buffer.  Same reason test 5 has one.
    socketley_cmd create server backend1 -p $BACKEND_PORT_1 --mode in --lua "$BENCH_ECHO_LUA" -s
    wait_for_port $BACKEND_PORT_1 || { log_error "Backend failed"; ensure_clean; return 1; }

    socketley_cmd create proxy bench_proxy -p $PROXY_PORT \
        --backend 127.0.0.1:$BACKEND_PORT_1 --protocol tcp -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; ensure_clean; return 1; }
    sleep 0.5

    append_result
    bench_run -j proxy concurrent 127.0.0.1 $PROXY_PORT $num_clients $requests_per_client >> "$RESULTS_FILE"
    bench_run proxy concurrent 127.0.0.1 $PROXY_PORT $num_clients $requests_per_client

    socketley_cmd stop bench_proxy
    socketley_cmd stop backend1
    sleep 0.5
    wait_for_port_free $PROXY_PORT
    socketley_cmd remove bench_proxy
    socketley_cmd remove backend1
}

# Test 5: Proxy connection overhead (direct vs proxied) — uses socketley-bench
#
# Timed and paired now, not counted and single-shot.  At 500 round trips a leg
# this test measured for seventeen milliseconds and then divided one such number
# by another: over seven repetitions on a quiet box its direct leg alone spanned
# 60976..75092, and under a six-core background load the same seven repetitions
# reported overheads between 11.1% and 75.8%.  Nothing in the output said which
# of those to believe, and an earlier form of it put a -106% in a results file.
# The paired form under that same load reported 69.4% ±3.1 and 69.6% ±2.4, and
# declined to answer on the third invocation instead of guessing.
#
# OVERHEAD_PAIRS pairs of OVERHEAD_MS milliseconds each: 5 x 2 x 800 ms is eight
# seconds of measurement, against the third of a second the old form spent.
test_proxy_overhead() {
    local ops_cap=${1:-100000000}
    local test_name="proxy_overhead"
    local pairs=${OVERHEAD_PAIRS:-5}
    local leg_ms=${OVERHEAD_MS:-800}

    log_section "Test: Proxy Overhead (Direct vs Proxied, $pairs pairs of ${leg_ms}ms)"

    ensure_clean
    # An echoing backend, unlike the other tests here.  This one compares two
    # paths, and a comparison needs each of them to have carried a request to
    # completion; a backend that answers nothing leaves both legs timing their
    # own writes, which is how this test came to report a negative overhead.
    socketley_cmd create server backend1 -p $BACKEND_PORT_1 --lua "$BENCH_ECHO_LUA" -s
    wait_for_port $BACKEND_PORT_1 || { log_error "Backend failed"; ensure_clean; return 1; }

    socketley_cmd create proxy bench_proxy -p $PROXY_PORT \
        --backend 127.0.0.1:$BACKEND_PORT_1 --protocol tcp -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; ensure_clean; return 1; }
    sleep 0.5

    append_result
    bench_run -j -r "$pairs" -W 1 -d "$leg_ms" proxy overhead 127.0.0.1 $PROXY_PORT \
        "$ops_cap" $BACKEND_PORT_1 >> "$RESULTS_FILE"
    bench_run -r "$pairs" -W 1 -d "$leg_ms" proxy overhead 127.0.0.1 $PROXY_PORT \
        "$ops_cap" $BACKEND_PORT_1

    socketley_cmd stop bench_proxy
    socketley_cmd stop backend1
    sleep 0.5
    wait_for_port_free $PROXY_PORT
    socketley_cmd remove bench_proxy
    socketley_cmd remove backend1
}

# Test 6: Backend by runtime name resolution
test_runtime_name_backend() {
    local num_requests=${1:-500}
    local test_name="proxy_runtime_name_backend"

    log_section "Test: Backend by Runtime Name ($num_requests requests)"

    ensure_clean
    socketley_cmd create server named_backend -p $BACKEND_PORT_1 --mode in --lua "$BENCH_ECHO_LUA" -s
    wait_for_port $BACKEND_PORT_1 || { log_error "Backend failed"; ensure_clean; return 1; }

    socketley_cmd create proxy bench_proxy -p $PROXY_PORT \
        --backend named_backend --protocol tcp -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; ensure_clean; return 1; }
    sleep 0.5

    append_result
    bench_run -j proxy tcp 127.0.0.1 $PROXY_PORT $num_requests 128 >> "$RESULTS_FILE"
    bench_run proxy tcp 127.0.0.1 $PROXY_PORT $num_requests 128

    socketley_cmd stop bench_proxy
    socketley_cmd stop named_backend
    sleep 0.5
    wait_for_port_free $PROXY_PORT
    socketley_cmd remove bench_proxy
    socketley_cmd remove named_backend
}

# Main execution
run_proxy_benchmarks() {
    log_section "PROXY RUNTIME BENCHMARKS"

    ensure_socketley_bench || return 1

    log_bench "START" "proxy_http_single_backend"
    test_http_single_backend
    log_bench "DONE" "proxy_http_single_backend"
    fresh_daemon

    log_bench "START" "proxy_http_load_balancing"
    test_http_load_balancing
    log_bench "DONE" "proxy_http_load_balancing"
    fresh_daemon

    log_bench "START" "proxy_tcp_throughput"
    test_tcp_throughput 3000 128
    log_bench "DONE" "proxy_tcp_throughput"
    fresh_daemon

    log_bench "START" "proxy_concurrent_connections"
    test_concurrent_proxy_connections 20 100
    log_bench "DONE" "proxy_concurrent_connections"
    fresh_daemon

    log_bench "START" "proxy_overhead"
    test_proxy_overhead
    log_bench "DONE" "proxy_overhead"
    fresh_daemon

    log_bench "START" "proxy_runtime_name_backend"
    test_runtime_name_backend 500
    log_bench "DONE" "proxy_runtime_name_backend"

    echo "]" >> "$RESULTS_FILE"
    cleanup_http_fixture

    log_section "Proxy Benchmark Complete"
    log_success "Results saved to: $RESULTS_FILE"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_binary || exit 1
    check_dependencies || exit 1
    # The two HTTP rows below are connection-per-request; see the comment on
    # bench_check_port_range in utils.sh for what that does to a port block
    # chosen inside the ephemeral range.
    bench_check_port_range "$PROXY_PORT" "$BACKEND_PORT_1" "$BACKEND_PORT_2" || true
    setup_cleanup_trap
    if should_manage_daemon; then
        start_daemon || exit 1
    fi
    run_proxy_benchmarks
fi
