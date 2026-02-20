#!/bin/bash
# WebSocket Benchmark
# Tests: WS handshake throughput, frame encoding throughput

source "$(dirname "$0")/utils.sh"

WS_PORT=19010
RESULTS_FILE="${RESULTS_DIR}/websocket_${TIMESTAMP}.json"

echo "[" > "$RESULTS_FILE"
FIRST_RESULT=true

append_result() {
    if [[ $FIRST_RESULT == true ]]; then
        FIRST_RESULT=false
    else
        echo "," >> "$RESULTS_FILE"
    fi
}

# WS handshake helper — returns HTTP response
ws_handshake() {
    printf 'GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n' | nc -q1 localhost $WS_PORT 2>/dev/null
}

# Test 1: WebSocket handshake throughput
test_ws_handshake() {
    local num_ops=${1:-500}
    local test_name="ws_handshake_throughput"

    log_section "Test: WebSocket Handshake Throughput ($num_ops handshakes)"

    socketley_cmd create server bench_ws -p $WS_PORT -s
    wait_for_port $WS_PORT || { log_error "Server failed to start"; return 1; }
    sleep 0.5

    local success=0
    local start_time=$(get_time_ms)

    for i in $(seq 1 $num_ops); do
        local resp=$(ws_handshake)
        if echo "$resp" | grep -q "101 Switching"; then
            ((success++))
        fi

        if [[ $((i % 100)) -eq 0 ]]; then
            echo -ne "\r  Progress: $i / $num_ops (success: $success)"
        fi
    done
    echo ""

    local end_time=$(get_time_ms)
    local total_time=$((end_time - start_time))
    local ops_sec=$(echo "scale=2; $num_ops * 1000 / $total_time" | bc)

    log_success "Handshakes: $success / $num_ops successful"
    log_success "Total time: $(format_duration $total_time)"
    log_success "Throughput: $ops_sec handshakes/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "operations" "$num_ops" \
        "successful" "$success" \
        "total_time_ms" "$total_time" \
        "ops_per_sec" "$ops_sec"

    socketley_cmd stop bench_ws
    socketley_cmd remove bench_ws
}

# Test 2: TCP coexistence throughput (mixed WS + TCP clients)
test_ws_tcp_coexistence() {
    local num_ops=${1:-500}
    local test_name="ws_tcp_coexistence"

    log_section "Test: WS + TCP Coexistence ($num_ops mixed connections)"

    socketley_cmd create server bench_ws -p $WS_PORT -s
    wait_for_port $WS_PORT || { log_error "Server failed to start"; return 1; }
    sleep 0.5

    local ws_success=0
    local tcp_success=0
    local start_time=$(get_time_ms)

    for i in $(seq 1 $num_ops); do
        if [[ $((i % 2)) -eq 0 ]]; then
            # WS handshake
            local resp=$(ws_handshake)
            if echo "$resp" | grep -q "101"; then
                ((ws_success++))
            fi
        else
            # Plain TCP message
            local resp=$(echo "hello tcp $i" | nc -q1 localhost $WS_PORT 2>/dev/null)
            ((tcp_success++))
        fi
    done

    local end_time=$(get_time_ms)
    local total_time=$((end_time - start_time))
    local ops_sec=$(echo "scale=2; $num_ops * 1000 / $total_time" | bc)

    log_success "WS handshakes: $ws_success, TCP messages: $tcp_success"
    log_success "Total time: $(format_duration $total_time)"
    log_success "Combined throughput: $ops_sec ops/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "total_operations" "$num_ops" \
        "ws_success" "$ws_success" \
        "tcp_success" "$tcp_success" \
        "total_time_ms" "$total_time" \
        "ops_per_sec" "$ops_sec"

    socketley_cmd stop bench_ws
    socketley_cmd remove bench_ws
}

# Test 3: Concurrent WebSocket connections
test_ws_concurrent() {
    local num_clients=${1:-20}
    local ops_per_client=${2:-25}
    local test_name="ws_concurrent"

    log_section "Test: Concurrent WebSocket ($num_clients clients, $ops_per_client ops each)"

    socketley_cmd create server bench_ws -p $WS_PORT -s
    wait_for_port $WS_PORT || { log_error "Server failed to start"; return 1; }
    sleep 0.5

    local pids=()
    local results_dir=$(mktemp -d)
    local start_time=$(get_time_ms)

    for c in $(seq 1 $num_clients); do
        (
            local count=0
            for i in $(seq 1 $ops_per_client); do
                local resp=$(ws_handshake)
                if echo "$resp" | grep -q "101"; then
                    ((count++))
                fi
            done
            echo "$count" > "$results_dir/client_$c"
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid"
    done

    local end_time=$(get_time_ms)
    local total_time=$((end_time - start_time))

    local total_ops=0
    for f in "$results_dir"/client_*; do
        total_ops=$((total_ops + $(cat "$f")))
    done
    rm -rf "$results_dir"

    local ops_sec=$(echo "scale=2; $total_ops * 1000 / $total_time" | bc)

    log_success "Total successful handshakes: $total_ops"
    log_success "Total time: $(format_duration $total_time)"
    log_success "Aggregate throughput: $ops_sec ops/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "num_clients" "$num_clients" \
        "ops_per_client" "$ops_per_client" \
        "total_ops" "$total_ops" \
        "total_time_ms" "$total_time" \
        "ops_per_sec" "$ops_sec"

    socketley_cmd stop bench_ws
    socketley_cmd remove bench_ws
}

# Main execution
run_ws_benchmarks() {
    log_section "WEBSOCKET BENCHMARKS"

    test_ws_handshake 300
    test_ws_tcp_coexistence 300
    test_ws_concurrent 10 20

    echo "]" >> "$RESULTS_FILE"

    log_section "WebSocket Benchmark Complete"
    log_success "Results saved to: $RESULTS_FILE"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_binary || exit 1
    check_dependencies || exit 1
    setup_cleanup_trap
    if should_manage_daemon; then
        start_daemon || exit 1
    fi
    run_ws_benchmarks
fi
