#!/bin/bash
# Server Runtime Benchmark
# Uses socketley-bench (C binary) for accurate throughput measurement.

source "$(dirname "$0")/utils.sh"

SERVER_PORT=19000
RESULTS_FILE="${RESULTS_DIR}/server_${TIMESTAMP}.json"

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
    socketley_cmd stop bench_srv 2>/dev/null
    sleep 0.5
    socketley_cmd remove bench_srv 2>/dev/null
}

# Test 1: Connection establishment rate (sequential connect/close)
test_connection_rate() {
    local num_connections=${1:-2000}
    local test_name="server_connection_rate"

    log_section "Test: Connection Establishment Rate ($num_connections connections)"

    ensure_clean
    wait_for_port_free $SERVER_PORT
    socketley_cmd create server bench_srv -p $SERVER_PORT -s
    wait_for_port $SERVER_PORT || { log_error "Server failed to start"; ensure_clean; return 1; }

    append_result
    "$SOCKETLEY_BENCH" -j server conn 127.0.0.1 $SERVER_PORT $num_connections >> "$RESULTS_FILE"
    "$SOCKETLEY_BENCH" server conn 127.0.0.1 $SERVER_PORT $num_connections

    socketley_cmd stop bench_srv
    sleep 0.5
    socketley_cmd remove bench_srv
}

# Test 2: Burst connections (open many simultaneously, hold, then close)
test_burst_connections() {
    local count=${1:-5000}
    local test_name="server_burst_connections"

    log_section "Test: Burst Connections ($count simultaneous)"

    ensure_clean
    wait_for_port_free $SERVER_PORT
    socketley_cmd create server bench_srv -p $SERVER_PORT -s
    wait_for_port $SERVER_PORT || { log_error "Server failed to start"; ensure_clean; return 1; }

    append_result
    "$SOCKETLEY_BENCH" -j server burst 127.0.0.1 $SERVER_PORT $count >> "$RESULTS_FILE"
    "$SOCKETLEY_BENCH" server burst 127.0.0.1 $SERVER_PORT $count

    socketley_cmd stop bench_srv
    sleep 0.5
    socketley_cmd remove bench_srv
}

# Test 3: Single-client message throughput
test_single_client_throughput() {
    local num_messages=${1:-100000}
    local message_size=${2:-64}
    local test_name="server_single_client_throughput"

    log_section "Test: Single Client Throughput ($num_messages msgs, ${message_size}B)"

    ensure_clean
    wait_for_port_free $SERVER_PORT
    socketley_cmd create server bench_srv -p $SERVER_PORT --mode in -s
    wait_for_port $SERVER_PORT || { log_error "Server failed to start"; ensure_clean; return 1; }

    append_result
    "$SOCKETLEY_BENCH" -j server msg 127.0.0.1 $SERVER_PORT $num_messages $message_size >> "$RESULTS_FILE"
    "$SOCKETLEY_BENCH" server msg 127.0.0.1 $SERVER_PORT $num_messages $message_size

    socketley_cmd stop bench_srv
    sleep 0.5
    socketley_cmd remove bench_srv
}

# Test 4: Concurrent clients
test_concurrent_clients() {
    local num_clients=${1:-100}
    local msgs_per_client=${2:-500}
    local test_name="server_concurrent_clients"

    log_section "Test: Concurrent Clients ($num_clients clients × $msgs_per_client msgs)"

    ensure_clean
    wait_for_port_free $SERVER_PORT
    socketley_cmd create server bench_srv -p $SERVER_PORT --mode in -s
    wait_for_port $SERVER_PORT || { log_error "Server failed to start"; ensure_clean; return 1; }

    append_result
    "$SOCKETLEY_BENCH" -j server concurrent 127.0.0.1 $SERVER_PORT $num_clients $msgs_per_client >> "$RESULTS_FILE"
    "$SOCKETLEY_BENCH" server concurrent 127.0.0.1 $SERVER_PORT $num_clients $msgs_per_client

    socketley_cmd stop bench_srv
    sleep 0.5
    socketley_cmd remove bench_srv
}

# Main
run_server_benchmarks() {
    log_section "SERVER RUNTIME BENCHMARKS"

    ensure_socketley_bench || return 1

    test_connection_rate     2000
    test_burst_connections   5000
    test_single_client_throughput 100000 64
    test_single_client_throughput 100000 1024
    test_concurrent_clients  100 500

    echo "]" >> "$RESULTS_FILE"

    log_section "Server Benchmark Complete"
    log_success "Results saved to: $RESULTS_FILE"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_binary || exit 1
    check_dependencies || exit 1
    setup_cleanup_trap
    if should_manage_daemon; then
        start_daemon || exit 1
    fi
    run_server_benchmarks
fi
