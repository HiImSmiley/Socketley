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
    bench_run -j server conn 127.0.0.1 $SERVER_PORT $num_connections >> "$RESULTS_FILE"
    bench_run server conn 127.0.0.1 $SERVER_PORT $num_connections

    socketley_cmd stop bench_srv
    sleep 0.5
    socketley_cmd remove bench_srv
}

# Test 2: Burst connections (open many simultaneously, hold, then close)
#
# This one declines monotonically across repetitions -- roughly 1.25 down to
# 0.83 of the first run -- and that is not noise to be averaged away.  Each run
# leaves 5000 sockets in TIME_WAIT, the next draws from a smaller ephemeral port
# range, and record_throughput.sh carries the measurement: a clean table gives
# +-9% where a table taken over ~10k lingering sockets spans 7x.
#
# Nothing in the harness can remove it -- a connection-rate benchmark that
# avoided consuming ports would not be measuring connection rate -- so it is
# stated here rather than quietly corrected.  The median now carries its range,
# so the decline shows up in the output instead of being discovered later.
# Before comparing a figure from this test against another, space the runs out
# or check `ss -s` first.
test_burst_connections() {
    local count=${1:-5000}
    local test_name="server_burst_connections"

    log_section "Test: Burst Connections ($count simultaneous)"

    ensure_clean
    wait_for_port_free $SERVER_PORT
    socketley_cmd create server bench_srv -p $SERVER_PORT -s
    wait_for_port $SERVER_PORT || { log_error "Server failed to start"; ensure_clean; return 1; }

    append_result
    bench_run -j server burst 127.0.0.1 $SERVER_PORT $count >> "$RESULTS_FILE"
    bench_run server burst 127.0.0.1 $SERVER_PORT $count

    socketley_cmd stop bench_srv
    sleep 0.5
    socketley_cmd remove bench_srv
}

# Test 3: Single-client round-trip throughput
#
# An echoing backend, because a plain server runtime answers nothing in any
# --mode and the loop would otherwise time its own writes -- the same reason
# 4f56712 gave the overhead test one.  --mode in as before: echo.lua replies to
# the sender itself, so the mode only decides whether the message is ALSO
# relayed, and here it should not be.
test_single_client_throughput() {
    local num_messages=${1:-100000}
    local message_size=${2:-64}
    local test_name="server_single_client_throughput"

    log_section "Test: Single Client Round Trips ($num_messages msgs, ${message_size}B)"

    ensure_clean
    wait_for_port_free $SERVER_PORT
    socketley_cmd create server bench_srv -p $SERVER_PORT --mode in --lua "$BENCH_ECHO_LUA" -s
    wait_for_port $SERVER_PORT || { log_error "Server failed to start"; ensure_clean; return 1; }

    append_result
    bench_run -j server msg 127.0.0.1 $SERVER_PORT $num_messages $message_size >> "$RESULTS_FILE"
    bench_run server msg 127.0.0.1 $SERVER_PORT $num_messages $message_size

    socketley_cmd stop bench_srv
    sleep 0.5
    socketley_cmd remove bench_srv
}

# Test 3b: Ingest rate — the write-only number, kept deliberately.
#
# A --mode in runtime never answers; that is the mode. So how fast it can be fed
# is the only thing measurable about it, and it is worth knowing. It is NOT a
# service rate — nothing here waits for the server — which is why it has a name
# and a JSON key of its own instead of being reported as throughput.
test_ingest_rate() {
    local num_messages=${1:-100000}
    local message_size=${2:-64}
    local test_name="server_ingest_rate"

    log_section "Test: Ingest Rate, write-only ($num_messages msgs, ${message_size}B)"

    ensure_clean
    wait_for_port_free $SERVER_PORT
    socketley_cmd create server bench_srv -p $SERVER_PORT --mode in -s
    wait_for_port $SERVER_PORT || { log_error "Server failed to start"; ensure_clean; return 1; }

    append_result
    bench_run -j server ingest 127.0.0.1 $SERVER_PORT $num_messages $message_size >> "$RESULTS_FILE"
    bench_run server ingest 127.0.0.1 $SERVER_PORT $num_messages $message_size

    socketley_cmd stop bench_srv
    sleep 0.5
    socketley_cmd remove bench_srv
}

# Test 4: Concurrent clients, one round trip in flight each
test_concurrent_clients() {
    local num_clients=${1:-100}
    local msgs_per_client=${2:-500}
    local test_name="server_concurrent_clients"

    log_section "Test: Concurrent Clients ($num_clients clients × $msgs_per_client round trips)"

    ensure_clean
    wait_for_port_free $SERVER_PORT
    socketley_cmd create server bench_srv -p $SERVER_PORT --mode in --lua "$BENCH_ECHO_LUA" -s
    wait_for_port $SERVER_PORT || { log_error "Server failed to start"; ensure_clean; return 1; }

    append_result
    bench_run -j server concurrent 127.0.0.1 $SERVER_PORT $num_clients $msgs_per_client >> "$RESULTS_FILE"
    bench_run server concurrent 127.0.0.1 $SERVER_PORT $num_clients $msgs_per_client

    socketley_cmd stop bench_srv
    sleep 0.5
    socketley_cmd remove bench_srv
}

# Main
run_server_benchmarks() {
    log_section "SERVER RUNTIME BENCHMARKS"

    ensure_socketley_bench || return 1

    log_bench "START" "server_connection_rate"
    test_connection_rate     2000
    log_bench "DONE" "server_connection_rate"
    fresh_daemon

    log_bench "START" "server_burst_connections"
    test_burst_connections   5000
    log_bench "DONE" "server_burst_connections"
    fresh_daemon

    log_bench "START" "server_throughput_64B"
    test_single_client_throughput 100000 64
    log_bench "DONE" "server_throughput_64B"
    fresh_daemon

    log_bench "START" "server_throughput_1024B"
    test_single_client_throughput 100000 1024
    log_bench "DONE" "server_throughput_1024B"
    fresh_daemon

    log_bench "START" "server_ingest_64B"
    test_ingest_rate 100000 64
    log_bench "DONE" "server_ingest_64B"
    fresh_daemon

    log_bench "START" "server_concurrent_clients"
    # 5,000 each: at 500 the run was 0.3 s and spread 1.38x.
    test_concurrent_clients  100 5000
    log_bench "DONE" "server_concurrent_clients"

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
