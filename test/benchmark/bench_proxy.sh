#!/bin/bash
# Proxy Runtime Benchmark
# Uses socketley-bench (C binary) for TCP forwarding measurement.
# HTTP proxy tests still use bash (HTTP protocol specifics).

source "$(dirname "$0")/utils.sh"

# Ports, from one base.  These were fixed at 19080-19082, inside the range the
# integration suite binds, so a benchmark and a test run could not share a
# machine — and neither of them says so when they collide; they say the proxy
# was slow.  bench_proxy_vs_haproxy.sh takes the same base and the offsets below
# keep the two scripts clear of each other.
BENCH_PORT_BASE=${BENCH_PORT_BASE:-23000}
PROXY_PORT=$((BENCH_PORT_BASE + 10))
BACKEND_PORT_1=$((BENCH_PORT_BASE + 11))
# Connections in flight for the two HTTP tests.  40 because that is what the
# bash version ran per batch, so the load the proxy sees is unchanged and only
# the client measuring it is different.
HTTP_CONCURRENCY=${HTTP_CONCURRENCY:-40}
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

# ─── A number produced by the wrong request is not a slow number ────────────
#
# An http proxy routes on a "/<proxy-name>/" prefix and answers everything else
# 404 by itself, without ever opening a backend connection.  That refusal is
# several times faster than the hop these tests exist to measure, and
# http_load.py used to count any status line as a success -- so a request that
# had lost its prefix would have been published as a throughput record for the
# proxy, and the only visible sign would have been the proxy getting faster.
#
# http_load.py counts only 2xx now and reports the rest.  This prints it, because
# a figure nobody reads is not an oracle: the count belongs beside the
# throughput it invalidates, not three lines further down in the JSON.
#
# Measured while adding this: /bench_proxy/test against a proxy named
# bench_proxy returns 200 with the backend contacted, while / and /test on that
# same proxy return 404.  Both tests here ask for the first, so both are
# measuring the hop and neither was affected.
report_non2xx() {
    local out=$1
    local n
    n=$(echo "$out" | grep -oP 'non2xx=\K[0-9]+')
    n=${n:-0}
    [[ "$n" -eq 0 ]] && return 0
    log_error "$n non-2xx replies ($(echo "$out" | grep -oP 'codes=\K[0-9:,]+'))"
    log_error "the throughput above is NOT a proxy hop: an http proxy answers"
    log_error "anything outside /<proxy-name>/ with its own 404 and never"
    log_error "contacts the backend. Check the path this test requests."
}

# Simple HTTP request via bash /dev/tcp
http_request() {
    local port=$1
    local path=${2:-/}
    local resp
    exec 99<>/dev/tcp/localhost/$port 2>/dev/null || return 1
    printf 'GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' "$path" >&99
    IFS= read -r -t 2 resp <&99
    exec 99<&-
    printf '%s' "$resp"
}

# Start a raw-socket HTTP backend
start_python_http_backend() {
    local port=$1
    python3 -c "
import socket, threading
resp = b'HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', $port))
s.listen(1000)
while True:
    c, _ = s.accept()
    threading.Thread(target=lambda c=c: [c.recv(65536), c.sendall(resp), c.close()], daemon=True).start()
" >/dev/null 2>&1 &
    echo $!
}

# Test 1: HTTP proxy throughput (single backend) — still bash-based
test_http_single_backend() {
    local num_requests=${1:-2000}
    local test_name="proxy_http_single_backend"

    log_section "Test: HTTP Proxy Single Backend ($num_requests requests)"

    ensure_clean
    local backend_pid
    backend_pid=$(start_python_http_backend $BACKEND_PORT_1)
    wait_for_port $BACKEND_PORT_1 || { log_error "Backend failed to start"; kill "$backend_pid" 2>/dev/null; return 1; }

    socketley_cmd create proxy bench_proxy -p $PROXY_PORT --backend 127.0.0.1:$BACKEND_PORT_1 --protocol http -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; kill "$backend_pid" 2>/dev/null; ensure_clean; return 1; }
    sleep 0.5

    # See http_load.py for why this is not a bash loop any more.
    local out
    out=$(timeout "$BENCH_TIMEOUT_CMD" python3 "$(dirname "$0")/http_load.py" \
              localhost "$PROXY_PORT" /bench_proxy/test "$num_requests" "$HTTP_CONCURRENCY")
    if [[ $? -eq 124 ]]; then
        log_bench "TIMEOUT" "proxy_http_single_backend request loop"
    fi

    local success total_time rps avg_lat p99_lat
    success=$(echo "$out" | grep -oP 'success=\K[0-9]+')
    total_time=$(echo "$out" | grep -oP 'elapsed_ms=\K[0-9]+')
    avg_lat=$(echo "$out" | grep -oP 'avg_ms=\K[0-9.]+')
    p99_lat=$(echo "$out" | grep -oP 'p99_ms=\K[0-9.]+')
    success=${success:-0}; total_time=${total_time:-0}
    rps=0
    [[ "$total_time" -gt 0 ]] && rps=$(echo "scale=2; $success * 1000 / $total_time" | bc)

    log_success "Successful requests: $success / $num_requests"
    log_success "Throughput: $rps req/sec"
    log_info "Latency: avg=${avg_lat}ms p99=${p99_lat}ms (${HTTP_CONCURRENCY} concurrent)"
    report_non2xx "$out"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "requests" "$num_requests" \
        "success" "$success" \
        "total_time_ms" "$total_time" \
        "requests_per_sec" "$rps" \
        "concurrency" "$HTTP_CONCURRENCY" \
        "avg_latency_ms" "$avg_lat" \
        "p99_latency_ms" "$p99_lat"

    socketley_cmd stop bench_proxy
    sleep 0.5
    wait_for_port_free $PROXY_PORT
    socketley_cmd remove bench_proxy
    kill "$backend_pid" 2>/dev/null
    wait "$backend_pid" 2>/dev/null
}

# Test 2: HTTP proxy with multiple backends (load balancing) — still bash-based
test_http_load_balancing() {
    local num_requests=${1:-2000}
    local test_name="proxy_http_load_balancing"

    log_section "Test: HTTP Proxy Load Balancing ($num_requests requests, 2 backends)"

    ensure_clean
    local backend_pid1 backend_pid2
    backend_pid1=$(start_python_http_backend $BACKEND_PORT_1)
    backend_pid2=$(start_python_http_backend $BACKEND_PORT_2)
    wait_for_port $BACKEND_PORT_1 || { log_error "Backend1 failed"; kill "$backend_pid1" "$backend_pid2" 2>/dev/null; return 1; }
    wait_for_port $BACKEND_PORT_2 || { log_error "Backend2 failed"; kill "$backend_pid1" "$backend_pid2" 2>/dev/null; return 1; }

    socketley_cmd create proxy bench_proxy -p $PROXY_PORT \
        --backend 127.0.0.1:$BACKEND_PORT_1,127.0.0.1:$BACKEND_PORT_2 \
        --strategy round-robin --protocol http -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; kill "$backend_pid1" "$backend_pid2" 2>/dev/null; ensure_clean; return 1; }
    sleep 0.5

    local success=0

    # The same client as the single-backend test, and that is the point: these
    # two numbers are read against each other.  While one forked `date` twice
    # per request and the other did not, the comparison said a second backend
    # made the proxy five times faster, which was a statement about bash.
    local out
    out=$(timeout "$BENCH_TIMEOUT_CMD" python3 "$(dirname "$0")/http_load.py" \
              localhost "$PROXY_PORT" /bench_proxy/test "$num_requests" "$HTTP_CONCURRENCY")
    if [[ $? -eq 124 ]]; then
        log_bench "TIMEOUT" "proxy_http_load_balancing request loop"
    fi

    local total_time rps avg_lat p99_lat
    success=$(echo "$out" | grep -oP 'success=\K[0-9]+')
    total_time=$(echo "$out" | grep -oP 'elapsed_ms=\K[0-9]+')
    avg_lat=$(echo "$out" | grep -oP 'avg_ms=\K[0-9.]+')
    p99_lat=$(echo "$out" | grep -oP 'p99_ms=\K[0-9.]+')
    success=${success:-0}; total_time=${total_time:-0}
    rps=0
    [[ "$total_time" -gt 0 ]] && rps=$(echo "scale=2; $success * 1000 / $total_time" | bc)

    log_success "Successful requests: $success / $num_requests"
    log_success "Throughput: $rps req/sec"
    log_info "Latency: avg=${avg_lat}ms p99=${p99_lat}ms (${HTTP_CONCURRENCY} concurrent)"
    report_non2xx "$out"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "requests" "$num_requests" \
        "backends" "2" \
        "strategy" "round-robin" \
        "success" "$success" \
        "total_time_ms" "$total_time" \
        "requests_per_sec" "$rps" \
        "concurrency" "$HTTP_CONCURRENCY" \
        "avg_latency_ms" "$avg_lat" \
        "p99_latency_ms" "$p99_lat"

    socketley_cmd stop bench_proxy
    sleep 0.5
    wait_for_port_free $PROXY_PORT
    socketley_cmd remove bench_proxy
    kill "$backend_pid1" "$backend_pid2" 2>/dev/null
    wait "$backend_pid1" "$backend_pid2" 2>/dev/null
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
    test_http_single_backend 2000
    log_bench "DONE" "proxy_http_single_backend"
    fresh_daemon

    log_bench "START" "proxy_http_load_balancing"
    test_http_load_balancing 2000
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

    log_section "Proxy Benchmark Complete"
    log_success "Results saved to: $RESULTS_FILE"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_binary || exit 1
    check_dependencies || exit 1
    setup_cleanup_trap
    if should_manage_daemon; then
        start_daemon || exit 1
    fi
    run_proxy_benchmarks
fi
