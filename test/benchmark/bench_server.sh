#!/bin/bash
# Server Runtime Benchmark
# Tests: connection handling, message throughput, broadcast performance

source "$(dirname "$0")/utils.sh"

SERVER_PORT=19000
RESULTS_FILE="${RESULTS_DIR}/server_${TIMESTAMP}.json"

# Initialize results file
echo "[" > "$RESULTS_FILE"
FIRST_RESULT=true

append_result() {
    if [[ $FIRST_RESULT == true ]]; then
        FIRST_RESULT=false
    else
        echo "," >> "$RESULTS_FILE"
    fi
}

# Test 1: Connection establishment rate
test_connection_rate() {
    local num_connections=${1:-1000}
    local test_name="server_connection_rate"

    log_section "Test: Connection Establishment Rate ($num_connections connections)"

    socketley_cmd create server bench_srv -p $SERVER_PORT -s
    wait_for_port $SERVER_PORT || { log_error "Server failed to start"; return 1; }

    local start_time=$(get_time_ms)
    local success=0
    local failed=0
    local latencies_file=$(mktemp)

    for i in $(seq 1 $num_connections); do
        local conn_start=$(get_time_ms)
        if timeout 1 bash -c "exec 3<>/dev/tcp/localhost/$SERVER_PORT" 2>/dev/null; then
            exec 3<&-
            local conn_end=$(get_time_ms)
            echo "$((conn_end - conn_start))" >> "$latencies_file"
            ((success++))
        else
            ((failed++))
        fi

        # Progress indicator every 100 connections
        if [[ $((i % 100)) -eq 0 ]]; then
            echo -ne "\r  Progress: $i / $num_connections"
        fi
    done
    echo ""

    local end_time=$(get_time_ms)
    local total_time=$((end_time - start_time))
    local rate=$(echo "scale=2; $success * 1000 / $total_time" | bc)

    local stats=$(calc_stats "$latencies_file")
    rm -f "$latencies_file"

    log_success "Connections: $success success, $failed failed"
    log_success "Total time: $(format_duration $total_time)"
    log_success "Connection rate: $rate conn/sec"
    log_info "Latency stats: $stats"

    # Extract stats values
    local avg_lat=$(echo "$stats" | grep -oP 'avg=\K[0-9.]+')
    local p99_lat=$(echo "$stats" | grep -oP 'p99=\K[0-9.]+')

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "connections_attempted" "$num_connections" \
        "connections_success" "$success" \
        "connections_failed" "$failed" \
        "total_time_ms" "$total_time" \
        "connections_per_sec" "$rate" \
        "avg_latency_ms" "$avg_lat" \
        "p99_latency_ms" "$p99_lat"

    socketley_cmd stop bench_srv
    socketley_cmd remove bench_srv

    echo "$rate $avg_lat $p99_lat"
}

# Test 2: Message throughput (single client)
test_single_client_throughput() {
    local num_messages=${1:-10000}
    local message_size=${2:-64}
    local test_name="server_single_client_throughput"

    log_section "Test: Single Client Message Throughput ($num_messages msgs, ${message_size}B)"

    socketley_cmd create server bench_srv -p $SERVER_PORT -s
    wait_for_port $SERVER_PORT || { log_error "Server failed to start"; return 1; }

    # Generate test message
    local message=$(head -c $message_size /dev/urandom | base64 | head -c $message_size)

    local start_time=$(get_time_ms)
    local success=0

    # Use a single persistent connection
    exec 3<>/dev/tcp/localhost/$SERVER_PORT

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

    log_success "Messages sent: $success"
    log_success "Total time: $(format_duration $total_time)"
    log_success "Message rate: $msg_rate msg/sec"
    log_success "Throughput: ${throughput_mb} MB/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "messages_sent" "$success" \
        "message_size_bytes" "$message_size" \
        "total_time_ms" "$total_time" \
        "messages_per_sec" "$msg_rate" \
        "throughput_mb_sec" "$throughput_mb"

    socketley_cmd stop bench_srv
    socketley_cmd remove bench_srv

    echo "$msg_rate $throughput_mb"
}

# Test 3: Concurrent clients throughput
test_concurrent_clients() {
    local num_clients=${1:-50}
    local msgs_per_client=${2:-200}
    local test_name="server_concurrent_clients"

    log_section "Test: Concurrent Clients ($num_clients clients, $msgs_per_client msgs each)"

    socketley_cmd create server bench_srv -p $SERVER_PORT -s
    wait_for_port $SERVER_PORT || { log_error "Server failed to start"; return 1; }

    local message="benchmark_test_message_payload_64bytes_padding_here"
    local pids=()
    local results_dir=$(mktemp -d)

    local start_time=$(get_time_ms)

    # Spawn concurrent clients
    for c in $(seq 1 $num_clients); do
        (
            local count=0
            exec 3<>/dev/tcp/localhost/$SERVER_PORT 2>/dev/null
            if [[ $? -eq 0 ]]; then
                for i in $(seq 1 $msgs_per_client); do
                    echo "$message" >&3 && ((count++))
                done
                exec 3<&-
            fi
            echo "$count" > "$results_dir/client_$c"
        ) &
        pids+=($!)
    done

    # Wait for all clients
    for pid in "${pids[@]}"; do
        wait "$pid"
    done

    local end_time=$(get_time_ms)
    local total_time=$((end_time - start_time))

    # Aggregate results
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
        "msgs_per_client" "$msgs_per_client" \
        "total_messages" "$total_msgs" \
        "total_time_ms" "$total_time" \
        "messages_per_sec" "$msg_rate"

    socketley_cmd stop bench_srv
    socketley_cmd remove bench_srv

    echo "$msg_rate"
}

# Test 4: Maximum concurrent connections
test_max_connections() {
    local max_attempt=${1:-5000}
    local test_name="server_max_connections"

    log_section "Test: Maximum Concurrent Connections (up to $max_attempt)"

    socketley_cmd create server bench_srv -p $SERVER_PORT -s
    wait_for_port $SERVER_PORT || { log_error "Server failed to start"; return 1; }

    local fds=()
    local success=0

    # Try to open as many connections as possible
    for i in $(seq 1 $max_attempt); do
        if exec {fd}<>/dev/tcp/localhost/$SERVER_PORT 2>/dev/null; then
            fds+=($fd)
            ((success++))
        else
            break
        fi

        if [[ $((i % 500)) -eq 0 ]]; then
            echo -ne "\r  Active connections: $success"
        fi
    done
    echo ""

    log_success "Maximum concurrent connections: $success"

    # Cleanup file descriptors
    for fd in "${fds[@]}"; do
        exec {fd}<&- 2>/dev/null
    done

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "attempted" "$max_attempt" \
        "max_concurrent" "$success"

    socketley_cmd stop bench_srv
    socketley_cmd remove bench_srv

    echo "$success"
}

# Test 5: Latency under load
test_latency_under_load() {
    local bg_clients=${1:-10}
    local measure_count=${2:-1000}
    local test_name="server_latency_under_load"

    log_section "Test: Latency Under Load ($bg_clients background clients)"

    socketley_cmd create server bench_srv -p $SERVER_PORT -s
    wait_for_port $SERVER_PORT || { log_error "Server failed to start"; return 1; }

    local message="latency_test_message"
    local bg_pids=()

    # Start background load generators
    for c in $(seq 1 $bg_clients); do
        (
            exec 3<>/dev/tcp/localhost/$SERVER_PORT 2>/dev/null
            while true; do
                echo "$message" >&3 2>/dev/null || break
                sleep 0.001
            done
        ) &
        bg_pids+=($!)
    done

    sleep 1  # Let load stabilize

    # Measure latency
    local latencies_file=$(mktemp)
    exec 4<>/dev/tcp/localhost/$SERVER_PORT

    for i in $(seq 1 $measure_count); do
        local start=$(get_time_ms)
        echo "$message" >&4
        # Note: Server doesn't echo back, so we just measure send latency
        local end=$(get_time_ms)
        echo "$((end - start))" >> "$latencies_file"
    done

    exec 4<&-

    # Stop background clients
    for pid in "${bg_pids[@]}"; do
        kill "$pid" 2>/dev/null
    done

    local stats=$(calc_stats "$latencies_file")
    rm -f "$latencies_file"

    local avg_lat=$(echo "$stats" | grep -oP 'avg=\K[0-9.]+')
    local p50_lat=$(echo "$stats" | grep -oP 'p50=\K[0-9.]+')
    local p95_lat=$(echo "$stats" | grep -oP 'p95=\K[0-9.]+')
    local p99_lat=$(echo "$stats" | grep -oP 'p99=\K[0-9.]+')

    log_success "Latency stats: $stats"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "background_clients" "$bg_clients" \
        "measurements" "$measure_count" \
        "avg_latency_ms" "$avg_lat" \
        "p50_latency_ms" "$p50_lat" \
        "p95_latency_ms" "$p95_lat" \
        "p99_latency_ms" "$p99_lat"

    socketley_cmd stop bench_srv
    socketley_cmd remove bench_srv

    echo "$avg_lat $p99_lat"
}

# Main execution
run_server_benchmarks() {
    log_section "SERVER RUNTIME BENCHMARKS"

    test_connection_rate 500
    test_single_client_throughput 5000 64
    test_single_client_throughput 5000 1024
    test_concurrent_clients 20 100
    test_max_connections 2000
    test_latency_under_load 5 500

    # Close JSON array
    echo "]" >> "$RESULTS_FILE"

    log_section "Server Benchmark Complete"
    log_success "Results saved to: $RESULTS_FILE"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_binary || exit 1
    check_dependencies || exit 1
    setup_cleanup_trap
    if should_manage_daemon; then
        start_daemon || exit 1
    fi
    run_server_benchmarks
fi
