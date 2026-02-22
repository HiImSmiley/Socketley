#!/bin/bash
# Server Runtime Benchmark
# Uses bench_client (C binary) instead of bash subprocesses for accurate throughput.

source "$(dirname "$0")/utils.sh"

BENCH_CLIENT="${SCRIPT_DIR}/bench_client"
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

ensure_bench_client() {
    if [[ ! -x "$BENCH_CLIENT" ]]; then
        log_info "Compiling bench_client..."
        gcc -O3 -o "$BENCH_CLIENT" "${SCRIPT_DIR}/bench_client.c" -lpthread 2>/dev/null \
            || { log_error "Failed to compile bench_client"; return 1; }
    fi
}

# Test 1: Connection establishment rate (sequential connect/close)
test_connection_rate() {
    local num_connections=${1:-2000}
    local test_name="server_connection_rate"

    log_section "Test: Connection Establishment Rate ($num_connections connections)"

    socketley_cmd create server bench_srv -p $SERVER_PORT -s
    wait_for_port $SERVER_PORT || { log_error "Server failed to start"; return 1; }

    local output
    output=$("$BENCH_CLIENT" 127.0.0.1 $SERVER_PORT conn $num_connections 2>&1)
    echo "$output"

    local rate=$(echo "$output"     | grep -oP 'Rate: \K[0-9.]+')
    local success=$(echo "$output"  | grep -oP 'Success: \K[0-9]+')
    local failed=$(echo "$output"   | grep -oP 'Failed: \K[0-9]+')
    local lat_us=$(echo "$output"   | grep -oP 'Avg latency: \K[0-9.]+(?= us)')
    local avg_lat_ms=$(echo "scale=3; ${lat_us:-0} / 1000" | bc)
    local elapsed_s=$(echo "$output" | grep -oP 'Time: \K[0-9.]+')
    local total_ms=$(echo "scale=0; ${elapsed_s:-0} * 1000 / 1" | bc)

    log_success "Connection rate: $rate conn/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "connections_attempted" "$num_connections" \
        "connections_success"   "${success:-0}" \
        "connections_failed"    "${failed:-0}" \
        "total_time_ms"         "${total_ms:-0}" \
        "connections_per_sec"   "${rate:-0}" \
        "avg_latency_ms"        "${avg_lat_ms:-0}"

    socketley_cmd stop bench_srv
    socketley_cmd remove bench_srv

    echo "${rate:-0} ${avg_lat_ms:-0}"
}

# Test 2: Burst connections (open many simultaneously, hold, then close)
test_burst_connections() {
    local count=${1:-5000}
    local test_name="server_burst_connections"

    log_section "Test: Burst Connections ($count simultaneous)"

    socketley_cmd create server bench_srv -p $SERVER_PORT -s
    wait_for_port $SERVER_PORT || { log_error "Server failed to start"; return 1; }

    local output
    output=$("$BENCH_CLIENT" 127.0.0.1 $SERVER_PORT burst $count 2>&1)
    echo "$output"

    local rate=$(echo "$output"   | grep -oP 'Rate: \K[0-9.]+')
    local opened=$(echo "$output" | grep -oP 'Connections opened: \K[0-9]+')

    log_success "Burst rate: $rate conn/sec  ($opened opened)"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "attempted"           "$count" \
        "max_concurrent"      "${opened:-0}" \
        "connections_per_sec" "${rate:-0}"

    socketley_cmd stop bench_srv
    socketley_cmd remove bench_srv

    echo "${rate:-0} ${opened:-0}"
}

# Test 3: Single-client message throughput
test_single_client_throughput() {
    local num_messages=${1:-100000}
    local message_size=${2:-64}
    local test_name="server_single_client_throughput"

    log_section "Test: Single Client Throughput ($num_messages msgs, ${message_size}B)"

    socketley_cmd create server bench_srv -p $SERVER_PORT -s
    wait_for_port $SERVER_PORT || { log_error "Server failed to start"; return 1; }

    local output
    output=$("$BENCH_CLIENT" 127.0.0.1 $SERVER_PORT msg $num_messages $message_size 2>&1)
    echo "$output"

    local msg_rate=$(echo "$output"      | grep -oP 'Rate: \K[0-9.]+')
    local throughput=$(echo "$output"    | grep -oP 'Throughput: \K[0-9.]+')
    local elapsed_s=$(echo "$output"     | grep -oP 'Time: \K[0-9.]+')
    local total_ms=$(echo "scale=0; ${elapsed_s:-0} * 1000 / 1" | bc)

    log_success "Rate: $msg_rate msg/sec  throughput: ${throughput} MB/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "messages_sent"       "$num_messages" \
        "message_size_bytes"  "$message_size" \
        "total_time_ms"       "${total_ms:-0}" \
        "messages_per_sec"    "${msg_rate:-0}" \
        "throughput_mb_sec"   "${throughput:-0}"

    socketley_cmd stop bench_srv
    socketley_cmd remove bench_srv

    echo "${msg_rate:-0} ${throughput:-0}"
}

# Test 4: Concurrent clients
test_concurrent_clients() {
    local num_clients=${1:-100}
    local msgs_per_client=${2:-500}
    local test_name="server_concurrent_clients"

    log_section "Test: Concurrent Clients ($num_clients clients × $msgs_per_client msgs)"

    socketley_cmd create server bench_srv -p $SERVER_PORT -s
    wait_for_port $SERVER_PORT || { log_error "Server failed to start"; return 1; }

    local output
    output=$("$BENCH_CLIENT" 127.0.0.1 $SERVER_PORT concurrent $num_clients $msgs_per_client 2>&1)
    echo "$output"

    local msg_rate=$(echo "$output"   | grep -oP 'Aggregate rate: \K[0-9.]+')
    local total_msgs=$(echo "$output" | grep -oP 'Total messages: \K[0-9]+')
    local elapsed_s=$(echo "$output"  | grep -oP 'Time: \K[0-9.]+')
    local total_ms=$(echo "scale=0; ${elapsed_s:-0} * 1000 / 1" | bc)

    log_success "Aggregate rate: $msg_rate msg/sec"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "num_clients"      "$num_clients" \
        "msgs_per_client"  "$msgs_per_client" \
        "total_messages"   "${total_msgs:-0}" \
        "total_time_ms"    "${total_ms:-0}" \
        "messages_per_sec" "${msg_rate:-0}"

    socketley_cmd stop bench_srv
    socketley_cmd remove bench_srv

    echo "${msg_rate:-0}"
}

# Main
run_server_benchmarks() {
    log_section "SERVER RUNTIME BENCHMARKS"

    ensure_bench_client || return 1

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
