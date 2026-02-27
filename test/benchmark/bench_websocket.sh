#!/bin/bash
# WebSocket Benchmark
# Uses socketley-bench (C binary) for WS handshake, echo RTT, and concurrency.

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

ensure_clean() {
    socketley_cmd stop bench_ws 2>/dev/null
    sleep 0.5
    socketley_cmd remove bench_ws 2>/dev/null
}

# Test 1: WebSocket handshake throughput
test_ws_handshake() {
    local num_ops=${1:-500}
    local test_name="ws_handshake_throughput"

    log_section "Test: WebSocket Handshake Throughput ($num_ops handshakes)"

    ensure_clean
    wait_for_port_free $WS_PORT
    socketley_cmd create server bench_ws -p $WS_PORT -s
    wait_for_port $WS_PORT || { log_error "Server failed to start"; ensure_clean; return 1; }
    sleep 0.5

    append_result
    "$SOCKETLEY_BENCH" -j ws handshake 127.0.0.1 $WS_PORT $num_ops >> "$RESULTS_FILE"
    "$SOCKETLEY_BENCH" ws handshake 127.0.0.1 $WS_PORT $num_ops

    socketley_cmd stop bench_ws
    sleep 0.5
    socketley_cmd remove bench_ws
}

# Test 2: WebSocket echo RTT
test_ws_echo() {
    local num_ops=${1:-5000}
    local msg_size=${2:-64}
    local test_name="ws_echo_rtt"

    log_section "Test: WebSocket Echo RTT ($num_ops msgs, ${msg_size}B)"

    ensure_clean
    wait_for_port_free $WS_PORT
    socketley_cmd create server bench_ws -p $WS_PORT -s
    wait_for_port $WS_PORT || { log_error "Server failed to start"; ensure_clean; return 1; }
    sleep 0.5

    append_result
    "$SOCKETLEY_BENCH" -j ws echo 127.0.0.1 $WS_PORT $num_ops $msg_size >> "$RESULTS_FILE"
    "$SOCKETLEY_BENCH" ws echo 127.0.0.1 $WS_PORT $num_ops $msg_size

    socketley_cmd stop bench_ws
    sleep 0.5
    socketley_cmd remove bench_ws
}

# Test 3: Concurrent WebSocket connections
test_ws_concurrent() {
    local num_clients=${1:-20}
    local ops_per_client=${2:-25}
    local test_name="ws_concurrent"

    log_section "Test: Concurrent WebSocket ($num_clients clients, $ops_per_client ops each)"

    ensure_clean
    wait_for_port_free $WS_PORT
    socketley_cmd create server bench_ws -p $WS_PORT -s
    wait_for_port $WS_PORT || { log_error "Server failed to start"; ensure_clean; return 1; }
    sleep 0.5

    append_result
    "$SOCKETLEY_BENCH" -j ws concurrent 127.0.0.1 $WS_PORT $num_clients $ops_per_client >> "$RESULTS_FILE"
    "$SOCKETLEY_BENCH" ws concurrent 127.0.0.1 $WS_PORT $num_clients $ops_per_client

    socketley_cmd stop bench_ws
    sleep 0.5
    socketley_cmd remove bench_ws
}

# Test 4: TCP coexistence throughput (mixed WS + TCP clients) — bash-based
test_ws_tcp_coexistence() {
    local num_ops=${1:-500}
    local test_name="ws_tcp_coexistence"

    log_section "Test: WS + TCP Coexistence ($num_ops mixed connections)"

    ensure_clean
    wait_for_port_free $WS_PORT
    socketley_cmd create server bench_ws -p $WS_PORT -s
    wait_for_port $WS_PORT || { log_error "Server failed to start"; ensure_clean; return 1; }
    sleep 0.5

    local results_dir=$(mktemp -d)
    local batch=20
    local start_time=$(get_time_ms)

    for i in $(seq 1 $num_ops); do
        (
            if [[ $((i % 2)) -eq 0 ]]; then
                local resp
                exec 99<>/dev/tcp/localhost/$WS_PORT 2>/dev/null || exit 1
                printf 'GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n' >&99
                IFS= read -r -t 1 resp <&99
                exec 99<&-
                echo "$resp" | grep -q "101" && echo "ws" > "$results_dir/r_$i"
            else
                echo "hello tcp $i" | nc -q0 localhost $WS_PORT >/dev/null 2>&1
                echo "tcp" > "$results_dir/r_$i"
            fi
        ) &
        [[ $((i % batch)) -eq 0 ]] && wait
    done
    wait

    local ws_success=$(grep -rl "^ws$" "$results_dir" 2>/dev/null | wc -l)
    local tcp_success=$(grep -rl "^tcp$" "$results_dir" 2>/dev/null | wc -l)
    rm -rf "$results_dir"

    local end_time=$(get_time_ms)
    local total_time=$((end_time - start_time))
    local ops_sec=$(echo "scale=2; $num_ops * 1000 / $total_time" | bc)

    log_success "WS handshakes: $ws_success, TCP messages: $tcp_success"
    log_success "Combined throughput: $ops_sec ops/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "total_operations" "$num_ops" \
        "ws_success" "$ws_success" \
        "tcp_success" "$tcp_success" \
        "total_time_ms" "$total_time" \
        "ops_per_sec" "$ops_sec"

    socketley_cmd stop bench_ws
    sleep 0.5
    socketley_cmd remove bench_ws
}

# Main execution
run_ws_benchmarks() {
    log_section "WEBSOCKET BENCHMARKS"

    ensure_socketley_bench || return 1

    test_ws_handshake 200
    test_ws_echo 5000 64
    test_ws_concurrent 20 25
    test_ws_tcp_coexistence 200

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
