#!/bin/bash
# Proxy Runtime Benchmark
# Tests: HTTP forwarding, TCP forwarding, load balancing, connection handling

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

# Simple HTTP request
http_request() {
    local port=$1
    local path=${2:-/}
    echo -e "GET $path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" | nc -q1 localhost "$port" 2>/dev/null
}

# Test 1: HTTP proxy throughput (single backend)
test_http_single_backend() {
    local num_requests=${1:-2000}
    local test_name="proxy_http_single_backend"

    log_section "Test: HTTP Proxy Single Backend ($num_requests requests)"

    # Create backend server
    socketley_cmd create server backend1 -p $BACKEND_PORT_1 -s
    wait_for_port $BACKEND_PORT_1 || { log_error "Backend failed to start"; return 1; }

    # Create proxy
    socketley_cmd create proxy bench_proxy -p $PROXY_PORT --backend 127.0.0.1:$BACKEND_PORT_1 --protocol http -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; return 1; }
    sleep 0.5

    local latencies_file=$(mktemp)
    local success=0

    local start_time=$(get_time_ms)

    for i in $(seq 1 $num_requests); do
        local req_start=$(get_time_ms)
        local response=$(http_request $PROXY_PORT "/bench_proxy/test")
        local req_end=$(get_time_ms)

        if [[ -n "$response" ]]; then
            echo "$((req_end - req_start))" >> "$latencies_file"
            ((success++))
        fi

        if [[ $((i % 200)) -eq 0 ]]; then
            echo -ne "\r  Progress: $i / $num_requests (success: $success)"
        fi
    done
    echo ""

    local end_time=$(get_time_ms)
    local total_time=$((end_time - start_time))
    local rps=$(echo "scale=2; $success * 1000 / $total_time" | bc)

    local stats=$(calc_stats "$latencies_file")
    rm -f "$latencies_file"

    local avg_lat=$(echo "$stats" | grep -oP 'avg=\K[0-9.]+')
    local p99_lat=$(echo "$stats" | grep -oP 'p99=\K[0-9.]+')

    log_success "Successful requests: $success / $num_requests"
    log_success "Total time: $(format_duration $total_time)"
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
    socketley_cmd stop backend1
    socketley_cmd remove bench_proxy
    socketley_cmd remove backend1

    echo "$rps $avg_lat $p99_lat"
}

# Test 2: HTTP proxy with multiple backends (load balancing)
test_http_load_balancing() {
    local num_requests=${1:-2000}
    local test_name="proxy_http_load_balancing"

    log_section "Test: HTTP Proxy Load Balancing ($num_requests requests, 2 backends)"

    # Create backend servers
    socketley_cmd create server backend1 -p $BACKEND_PORT_1 -s
    socketley_cmd create server backend2 -p $BACKEND_PORT_2 -s
    wait_for_port $BACKEND_PORT_1 || { log_error "Backend1 failed"; return 1; }
    wait_for_port $BACKEND_PORT_2 || { log_error "Backend2 failed"; return 1; }

    # Create proxy with round-robin
    socketley_cmd create proxy bench_proxy -p $PROXY_PORT \
        --backend 127.0.0.1:$BACKEND_PORT_1,127.0.0.1:$BACKEND_PORT_2 \
        --strategy round-robin --protocol http -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; return 1; }
    sleep 0.5

    local success=0
    local start_time=$(get_time_ms)

    for i in $(seq 1 $num_requests); do
        local response=$(http_request $PROXY_PORT "/bench_proxy/test")
        [[ -n "$response" ]] && ((success++))

        if [[ $((i % 200)) -eq 0 ]]; then
            echo -ne "\r  Progress: $i / $num_requests"
        fi
    done
    echo ""

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
    socketley_cmd stop backend1
    socketley_cmd stop backend2
    socketley_cmd remove bench_proxy
    socketley_cmd remove backend1
    socketley_cmd remove backend2

    echo "$rps"
}

# Test 3: TCP proxy throughput
test_tcp_throughput() {
    local num_messages=${1:-5000}
    local message_size=${2:-128}
    local test_name="proxy_tcp_throughput"

    log_section "Test: TCP Proxy Throughput ($num_messages msgs, ${message_size}B)"

    # Create backend server
    socketley_cmd create server backend1 -p $BACKEND_PORT_1 -s
    wait_for_port $BACKEND_PORT_1 || { log_error "Backend failed"; return 1; }

    # Create TCP proxy
    socketley_cmd create proxy bench_proxy -p $PROXY_PORT \
        --backend 127.0.0.1:$BACKEND_PORT_1 --protocol tcp -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; return 1; }
    sleep 0.5

    local message=$(head -c $message_size /dev/urandom | base64 | head -c $message_size)
    local success=0

    local start_time=$(get_time_ms)

    # Use persistent connection
    exec 3<>/dev/tcp/localhost/$PROXY_PORT 2>/dev/null
    if [[ $? -ne 0 ]]; then
        log_error "Failed to connect to proxy"
        return 1
    fi

    for i in $(seq 1 $num_messages); do
        echo "$message" >&3 && ((success++))

        if [[ $((i % 1000)) -eq 0 ]]; then
            echo -ne "\r  Progress: $i / $num_messages"
        fi
    done
    echo ""

    exec 3<&-

    local end_time=$(get_time_ms)
    local total_time=$((end_time - start_time))
    local msg_rate=$(echo "scale=2; $success * 1000 / $total_time" | bc)
    local throughput_mb=$(echo "scale=2; $success * $message_size / 1024 / 1024 * 1000 / $total_time" | bc)

    log_success "Messages forwarded: $success"
    log_success "Message rate: $msg_rate msg/sec"
    log_success "Throughput: ${throughput_mb} MB/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "messages" "$num_messages" \
        "message_size_bytes" "$message_size" \
        "success" "$success" \
        "total_time_ms" "$total_time" \
        "messages_per_sec" "$msg_rate" \
        "throughput_mb_sec" "$throughput_mb"

    socketley_cmd stop bench_proxy
    socketley_cmd stop backend1
    socketley_cmd remove bench_proxy
    socketley_cmd remove backend1

    echo "$msg_rate $throughput_mb"
}

# Test 4: Concurrent connections through proxy
test_concurrent_proxy_connections() {
    local num_clients=${1:-50}
    local requests_per_client=${2:-100}
    local test_name="proxy_concurrent_connections"

    log_section "Test: Concurrent Proxy Connections ($num_clients clients)"

    # Create backend
    socketley_cmd create server backend1 -p $BACKEND_PORT_1 -s
    wait_for_port $BACKEND_PORT_1 || { log_error "Backend failed"; return 1; }

    # Create proxy
    socketley_cmd create proxy bench_proxy -p $PROXY_PORT \
        --backend 127.0.0.1:$BACKEND_PORT_1 --protocol tcp -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; return 1; }
    sleep 0.5

    local message="concurrent_proxy_test_message"
    local pids=()
    local results_dir=$(mktemp -d)

    local start_time=$(get_time_ms)

    for c in $(seq 1 $num_clients); do
        (
            local count=0
            exec 3<>/dev/tcp/localhost/$PROXY_PORT 2>/dev/null
            if [[ $? -eq 0 ]]; then
                for i in $(seq 1 $requests_per_client); do
                    echo "$message" >&3 && ((count++))
                done
                exec 3<&-
            fi
            echo "$count" > "$results_dir/client_$c"
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid"
    done

    local end_time=$(get_time_ms)
    local total_time=$((end_time - start_time))

    local total_msgs=0
    for f in "$results_dir"/client_*; do
        total_msgs=$((total_msgs + $(cat "$f")))
    done
    rm -rf "$results_dir"

    local msg_rate=$(echo "scale=2; $total_msgs * 1000 / $total_time" | bc)

    log_success "Total messages: $total_msgs"
    log_success "Total time: $(format_duration $total_time)"
    log_success "Aggregate rate: $msg_rate msg/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "num_clients" "$num_clients" \
        "requests_per_client" "$requests_per_client" \
        "total_messages" "$total_msgs" \
        "total_time_ms" "$total_time" \
        "messages_per_sec" "$msg_rate"

    socketley_cmd stop bench_proxy
    socketley_cmd stop backend1
    socketley_cmd remove bench_proxy
    socketley_cmd remove backend1

    echo "$msg_rate"
}

# Test 5: Proxy connection overhead (direct vs proxied)
test_proxy_overhead() {
    local num_requests=${1:-1000}
    local test_name="proxy_overhead"

    log_section "Test: Proxy Overhead (Direct vs Proxied)"

    # Create backend
    socketley_cmd create server backend1 -p $BACKEND_PORT_1 -s
    wait_for_port $BACKEND_PORT_1 || { log_error "Backend failed"; return 1; }

    # Create proxy
    socketley_cmd create proxy bench_proxy -p $PROXY_PORT \
        --backend 127.0.0.1:$BACKEND_PORT_1 --protocol tcp -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; return 1; }
    sleep 0.5

    local message="overhead_test_message"
    local direct_latencies=$(mktemp)
    local proxied_latencies=$(mktemp)

    # Test direct connections
    log_info "Testing direct connections..."
    for i in $(seq 1 $num_requests); do
        local start=$(get_time_ms)
        echo "$message" | nc -q0 localhost $BACKEND_PORT_1 >/dev/null 2>&1
        local end=$(get_time_ms)
        echo "$((end - start))" >> "$direct_latencies"
    done

    # Test proxied connections
    log_info "Testing proxied connections..."
    for i in $(seq 1 $num_requests); do
        local start=$(get_time_ms)
        echo "$message" | nc -q0 localhost $PROXY_PORT >/dev/null 2>&1
        local end=$(get_time_ms)
        echo "$((end - start))" >> "$proxied_latencies"
    done

    local direct_stats=$(calc_stats "$direct_latencies")
    local proxied_stats=$(calc_stats "$proxied_latencies")
    rm -f "$direct_latencies" "$proxied_latencies"

    local direct_avg=$(echo "$direct_stats" | grep -oP 'avg=\K[0-9.]+')
    local proxied_avg=$(echo "$proxied_stats" | grep -oP 'avg=\K[0-9.]+')
    local overhead=$(echo "scale=2; $proxied_avg - $direct_avg" | bc)
    local overhead_pct=$(echo "scale=1; ($proxied_avg - $direct_avg) * 100 / $direct_avg" | bc 2>/dev/null || echo "N/A")

    log_success "Direct avg latency: ${direct_avg}ms"
    log_success "Proxied avg latency: ${proxied_avg}ms"
    log_success "Overhead: ${overhead}ms (${overhead_pct}%)"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "requests" "$num_requests" \
        "direct_avg_latency_ms" "$direct_avg" \
        "proxied_avg_latency_ms" "$proxied_avg" \
        "overhead_ms" "$overhead" \
        "overhead_percent" "$overhead_pct"

    socketley_cmd stop bench_proxy
    socketley_cmd stop backend1
    socketley_cmd remove bench_proxy
    socketley_cmd remove backend1

    echo "$overhead $overhead_pct"
}

# Test 6: Backend by runtime name resolution
test_runtime_name_backend() {
    local num_requests=${1:-500}
    local test_name="proxy_runtime_name_backend"

    log_section "Test: Backend by Runtime Name ($num_requests requests)"

    # Create backend server
    socketley_cmd create server named_backend -p $BACKEND_PORT_1 -s
    wait_for_port $BACKEND_PORT_1 || { log_error "Backend failed"; return 1; }

    # Create proxy using runtime name as backend
    socketley_cmd create proxy bench_proxy -p $PROXY_PORT \
        --backend named_backend --protocol tcp -s
    wait_for_port $PROXY_PORT || { log_error "Proxy failed to start"; return 1; }
    sleep 0.5

    local message="runtime_name_test"
    local success=0

    local start_time=$(get_time_ms)

    exec 3<>/dev/tcp/localhost/$PROXY_PORT 2>/dev/null
    for i in $(seq 1 $num_requests); do
        echo "$message" >&3 && ((success++))
    done
    exec 3<&-

    local end_time=$(get_time_ms)
    local total_time=$((end_time - start_time))
    local rate=$(echo "scale=2; $success * 1000 / $total_time" | bc)

    log_success "Success: $success / $num_requests"
    log_success "Rate: $rate msg/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "requests" "$num_requests" \
        "success" "$success" \
        "total_time_ms" "$total_time" \
        "messages_per_sec" "$rate"

    socketley_cmd stop bench_proxy
    socketley_cmd stop named_backend
    socketley_cmd remove bench_proxy
    socketley_cmd remove named_backend

    echo "$rate"
}

# Main execution
run_proxy_benchmarks() {
    log_section "PROXY RUNTIME BENCHMARKS"

    test_http_single_backend 1000
    test_http_load_balancing 1000
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
