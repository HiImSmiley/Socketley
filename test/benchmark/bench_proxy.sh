#!/bin/bash
# Proxy Runtime Benchmark
# Uses socketley-bench (C binary) for TCP forwarding measurement.
# HTTP proxy tests still use bash (HTTP protocol specifics).

source "$(dirname "$0")/utils.sh"

PROXY_PORT=19080
BACKEND_PORT_1=19081
BACKEND_PORT_2=19082
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

    local backend_pid
    backend_pid=$(start_python_http_backend $BACKEND_PORT_1)
    wait_for_port $BACKEND_PORT_1 || { log_error "Backend failed to start"; kill "$backend_pid" 2>/dev/null; return 1; }

    socketley_cmd create proxy bench_proxy -p $PROXY_PORT --backend 127.0.0.1:$BACKEND_PORT_1 --protocol http -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; kill "$backend_pid" 2>/dev/null; return 1; }
    sleep 0.5

    local latencies_file=$(mktemp)
    local results_dir=$(mktemp -d)
    local success=0
    local batch=40

    local start_time=$(get_time_ms)

    for i in $(seq 1 $num_requests); do
        (
            local t0=$(get_time_ms)
            local response=$(http_request $PROXY_PORT "/bench_proxy/test")
            local t1=$(get_time_ms)
            if [[ -n "$response" ]]; then
                echo "$((t1 - t0))" > "$results_dir/r_$i"
            fi
        ) &
        if [[ $((i % batch)) -eq 0 ]]; then
            wait
            echo -ne "\r  Progress: $i / $num_requests"
        fi
    done
    wait
    echo ""

    for f in "$results_dir"/r_*; do
        [[ -f "$f" ]] && { cat "$f" >> "$latencies_file"; ((success++)); }
    done
    rm -rf "$results_dir"

    local end_time=$(get_time_ms)
    local total_time=$((end_time - start_time))
    local rps=$(echo "scale=2; $success * 1000 / $total_time" | bc)

    local stats=$(calc_stats "$latencies_file")
    rm -f "$latencies_file"

    local avg_lat=$(echo "$stats" | grep -oP 'avg=\K[0-9.]+')
    local p99_lat=$(echo "$stats" | grep -oP 'p99=\K[0-9.]+')

    log_success "Successful requests: $success / $num_requests"
    log_success "Throughput: $rps req/sec"
    log_info "Latency: $stats"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "requests" "$num_requests" \
        "success" "$success" \
        "total_time_ms" "$total_time" \
        "requests_per_sec" "$rps" \
        "avg_latency_ms" "$avg_lat" \
        "p99_latency_ms" "$p99_lat"

    socketley_cmd stop bench_proxy
    sleep 0.5
    socketley_cmd remove bench_proxy
    kill "$backend_pid" 2>/dev/null
    wait "$backend_pid" 2>/dev/null
}

# Test 2: HTTP proxy with multiple backends (load balancing) — still bash-based
test_http_load_balancing() {
    local num_requests=${1:-2000}
    local test_name="proxy_http_load_balancing"

    log_section "Test: HTTP Proxy Load Balancing ($num_requests requests, 2 backends)"

    local backend_pid1 backend_pid2
    backend_pid1=$(start_python_http_backend $BACKEND_PORT_1)
    backend_pid2=$(start_python_http_backend $BACKEND_PORT_2)
    wait_for_port $BACKEND_PORT_1 || { log_error "Backend1 failed"; kill "$backend_pid1" "$backend_pid2" 2>/dev/null; return 1; }
    wait_for_port $BACKEND_PORT_2 || { log_error "Backend2 failed"; kill "$backend_pid1" "$backend_pid2" 2>/dev/null; return 1; }

    socketley_cmd create proxy bench_proxy -p $PROXY_PORT \
        --backend 127.0.0.1:$BACKEND_PORT_1,127.0.0.1:$BACKEND_PORT_2 \
        --strategy round-robin --protocol http -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; kill "$backend_pid1" "$backend_pid2" 2>/dev/null; return 1; }
    sleep 0.5

    local success=0
    local results_dir=$(mktemp -d)
    local batch=40

    local start_time=$(get_time_ms)

    for i in $(seq 1 $num_requests); do
        (
            local response=$(http_request $PROXY_PORT "/bench_proxy/test")
            [[ -n "$response" ]] && touch "$results_dir/ok_$i"
        ) &
        if [[ $((i % batch)) -eq 0 ]]; then
            wait
            echo -ne "\r  Progress: $i / $num_requests"
        fi
    done
    wait
    echo ""

    success=$(ls "$results_dir" | wc -l)
    rm -rf "$results_dir"

    local end_time=$(get_time_ms)
    local total_time=$((end_time - start_time))
    local rps=$(echo "scale=2; $success * 1000 / $total_time" | bc)

    log_success "Successful requests: $success / $num_requests"
    log_success "Throughput: $rps req/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "requests" "$num_requests" \
        "backends" "2" \
        "strategy" "round-robin" \
        "success" "$success" \
        "total_time_ms" "$total_time" \
        "requests_per_sec" "$rps"

    socketley_cmd stop bench_proxy
    sleep 0.5
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

    socketley_cmd create server backend1 -p $BACKEND_PORT_1 -s
    wait_for_port $BACKEND_PORT_1 || { log_error "Backend failed"; return 1; }

    socketley_cmd create proxy bench_proxy -p $PROXY_PORT \
        --backend 127.0.0.1:$BACKEND_PORT_1 --protocol tcp -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; return 1; }
    sleep 0.5

    append_result
    "$SOCKETLEY_BENCH" -j proxy tcp 127.0.0.1 $PROXY_PORT $num_messages $message_size >> "$RESULTS_FILE"
    "$SOCKETLEY_BENCH" proxy tcp 127.0.0.1 $PROXY_PORT $num_messages $message_size

    socketley_cmd stop bench_proxy
    socketley_cmd stop backend1
    sleep 0.5
    socketley_cmd remove bench_proxy
    socketley_cmd remove backend1
}

# Test 4: Concurrent connections through proxy — uses socketley-bench
test_concurrent_proxy_connections() {
    local num_clients=${1:-50}
    local requests_per_client=${2:-100}
    local test_name="proxy_concurrent_connections"

    log_section "Test: Concurrent Proxy Connections ($num_clients clients)"

    socketley_cmd create server backend1 -p $BACKEND_PORT_1 -s
    wait_for_port $BACKEND_PORT_1 || { log_error "Backend failed"; return 1; }

    socketley_cmd create proxy bench_proxy -p $PROXY_PORT \
        --backend 127.0.0.1:$BACKEND_PORT_1 --protocol tcp -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; return 1; }
    sleep 0.5

    append_result
    "$SOCKETLEY_BENCH" -j proxy concurrent 127.0.0.1 $PROXY_PORT $num_clients $requests_per_client >> "$RESULTS_FILE"
    "$SOCKETLEY_BENCH" proxy concurrent 127.0.0.1 $PROXY_PORT $num_clients $requests_per_client

    socketley_cmd stop bench_proxy
    socketley_cmd stop backend1
    sleep 0.5
    socketley_cmd remove bench_proxy
    socketley_cmd remove backend1
}

# Test 5: Proxy connection overhead (direct vs proxied) — uses socketley-bench
test_proxy_overhead() {
    local num_requests=${1:-1000}
    local test_name="proxy_overhead"

    log_section "Test: Proxy Overhead (Direct vs Proxied)"

    socketley_cmd create server backend1 -p $BACKEND_PORT_1 -s
    wait_for_port $BACKEND_PORT_1 || { log_error "Backend failed"; return 1; }

    socketley_cmd create proxy bench_proxy -p $PROXY_PORT \
        --backend 127.0.0.1:$BACKEND_PORT_1 --protocol tcp -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; return 1; }
    sleep 0.5

    append_result
    "$SOCKETLEY_BENCH" -j proxy overhead 127.0.0.1 $PROXY_PORT $num_requests $BACKEND_PORT_1 >> "$RESULTS_FILE"
    "$SOCKETLEY_BENCH" proxy overhead 127.0.0.1 $PROXY_PORT $num_requests $BACKEND_PORT_1

    socketley_cmd stop bench_proxy
    socketley_cmd stop backend1
    sleep 0.5
    socketley_cmd remove bench_proxy
    socketley_cmd remove backend1
}

# Test 6: Backend by runtime name resolution
test_runtime_name_backend() {
    local num_requests=${1:-500}
    local test_name="proxy_runtime_name_backend"

    log_section "Test: Backend by Runtime Name ($num_requests requests)"

    socketley_cmd create server named_backend -p $BACKEND_PORT_1 -s
    wait_for_port $BACKEND_PORT_1 || { log_error "Backend failed"; return 1; }

    socketley_cmd create proxy bench_proxy -p $PROXY_PORT \
        --backend named_backend --protocol tcp -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; return 1; }
    sleep 0.5

    append_result
    "$SOCKETLEY_BENCH" -j proxy tcp 127.0.0.1 $PROXY_PORT $num_requests 128 >> "$RESULTS_FILE"
    "$SOCKETLEY_BENCH" proxy tcp 127.0.0.1 $PROXY_PORT $num_requests 128

    socketley_cmd stop bench_proxy
    socketley_cmd stop named_backend
    sleep 0.5
    socketley_cmd remove bench_proxy
    socketley_cmd remove named_backend
}

# Main execution
run_proxy_benchmarks() {
    log_section "PROXY RUNTIME BENCHMARKS"

    ensure_socketley_bench || return 1

    test_http_single_backend 2000
    test_http_load_balancing 2000
    test_tcp_throughput 3000 128
    test_concurrent_proxy_connections 20 100
    test_proxy_overhead 500
    test_runtime_name_backend 500

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
