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
    socketley_cmd stop bench_ws >/dev/null 2>&1
    sleep 0.5
    socketley_cmd remove bench_ws >/dev/null 2>&1
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
    bench_run -j ws handshake 127.0.0.1 $WS_PORT $num_ops >> "$RESULTS_FILE"
    bench_run ws handshake 127.0.0.1 $WS_PORT $num_ops

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
    # The one test in this file that needs an answering server.  A plain server
    # relays to every client except the sender, so a single WebSocket client
    # sending frames at one was answered by nothing -- and a test called "echo
    # RTT" measured the cost of write().  echo.lua replies to the sender through
    # its own framing, so the client reads a text frame back.
    socketley_cmd create server bench_ws -p $WS_PORT --lua "$BENCH_ECHO_LUA" -s
    wait_for_port $WS_PORT || { log_error "Server failed to start"; ensure_clean; return 1; }
    sleep 0.5

    append_result
    bench_run -j ws echo 127.0.0.1 $WS_PORT $num_ops $msg_size >> "$RESULTS_FILE"
    bench_run ws echo 127.0.0.1 $WS_PORT $num_ops $msg_size

    socketley_cmd stop bench_ws
    sleep 0.5
    socketley_cmd remove bench_ws
}

# Test 3: Concurrent WebSocket connections
test_ws_concurrent() {
    local num_clients=${1:-20}
    local ops_per_client=${2:-25}
    local test_name="ws_concurrent"

    log_section "Test: Concurrent WebSocket handshakes ($num_clients clients, $ops_per_client each)"

    ensure_clean
    wait_for_port_free $WS_PORT
    socketley_cmd create server bench_ws -p $WS_PORT -s
    wait_for_port $WS_PORT || { log_error "Server failed to start"; ensure_clean; return 1; }
    sleep 0.5

    append_result
    bench_run -j ws concurrent 127.0.0.1 $WS_PORT $num_clients $ops_per_client >> "$RESULTS_FILE"
    bench_run ws concurrent 127.0.0.1 $WS_PORT $num_clients $ops_per_client

    socketley_cmd stop bench_ws
    sleep 0.5
    socketley_cmd remove bench_ws
}

# Test 4: WebSocket and TCP clients served on one port at once
#
# It was a bash loop -- a fork per operation, an nc for every other one -- whose
# own forks were 41% of every operation it timed, so its rate was refused as
# bash rather than printed.  socketley_bench ws mixed runs the same mix as
# round trips from C: even clients upgrade and echo frames, odd ones echo
# lines, and it prints each kind's rate beside the total so a runtime that
# served one and starved the other shows as that.
test_ws_tcp_coexistence() {
    local num_clients=${1:-20}
    local ops_per_client=${2:-2000}
    local test_name="ws_tcp_coexistence"

    log_section "Test: WS + TCP Coexistence ($num_clients clients, half each, $ops_per_client round trips)"

    ensure_clean
    wait_for_port_free $WS_PORT
    socketley_cmd create server bench_ws -p $WS_PORT --lua "$BENCH_ECHO_LUA" -s
    wait_for_port $WS_PORT || { log_error "Server failed to start"; ensure_clean; return 1; }
    sleep 0.5

    append_result
    bench_run -j ws mixed 127.0.0.1 $WS_PORT $num_clients $ops_per_client 64 >> "$RESULTS_FILE"
    bench_run ws mixed 127.0.0.1 $WS_PORT $num_clients $ops_per_client 64

    socketley_cmd stop bench_ws
    sleep 0.5
    socketley_cmd remove bench_ws
}

# Main execution
run_ws_benchmarks() {
    log_section "WEBSOCKET BENCHMARKS"

    ensure_socketley_bench || return 1

    log_bench "START" "ws_handshake_throughput"
    test_ws_handshake 2000
    log_bench "DONE" "ws_handshake_throughput"
    fresh_daemon

    log_bench "START" "ws_echo_rtt"
    test_ws_echo 5000 64
    log_bench "DONE" "ws_echo_rtt"
    fresh_daemon

    log_bench "START" "ws_concurrent"
    # 500 each: at 25 the threads finished at different times and the rate was
    # an average over a falling concurrency (79% overlap in one run).
    test_ws_concurrent 20 500
    log_bench "DONE" "ws_concurrent"
    fresh_daemon

    log_bench "START" "ws_tcp_coexistence"
    test_ws_tcp_coexistence 20 2000
    log_bench "DONE" "ws_tcp_coexistence"

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
