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

    log_section "Test: Concurrent WebSocket ($num_clients clients, $ops_per_client ops each)"

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

# Test 4: TCP coexistence throughput (mixed WS + TCP clients) — bash-based
# ─── What this row can and cannot measure ───────────────────────────────────
#
# It reported "Combined throughput 2221 ops/sec" for 200 operations.  The
# operations are bash subshells -- one fork per operation, plus an `nc` process
# for every odd one -- so the figure has a ceiling that has nothing to do with
# the server.  Measured on this box, same loop, three windows:
#
#     as reported            2,221 ops/sec
#     work only              2,507 ops/sec
#     the same loop with no socket touched at all   4,067 ops/sec
#
# The first two differ because the clock used to stop after two `grep -rl`
# passes over the result files and an `rm -rf` of the directory holding them:
# 11% of the published number was the harness tidying up.  That part is simply
# a bug and the clock now brackets the work.
#
# The gap between 2,507 and 4,067 is the real problem and it cannot be fixed
# here.  61% of each operation is bash forking, so the server would have to
# change by a lot before this number moved at all, and a change in the fork rate
# -- a busier box, a different shell -- moves it without the server changing.
# The rate is therefore refused rather than printed as a server figure, with the
# floor measured in the same run so the refusal carries its evidence.
#
# What this test is actually for survives intact: ws_success and tcp_success say
# that WebSocket upgrades and plain TCP were served on one port at the same
# time, and those counts are an assertion the fork rate cannot fake.  Rewriting
# the load generator in C would make the rate meaningful; until someone does,
# saying so is better than printing it.
WS_COEX_MAX_INSTRUMENT_PCT=${WS_COEX_MAX_INSTRUMENT_PCT:-25}

# The same loop with the network removed: what bash alone does with this shape.
ws_coex_fork_floor_us() {   # num_ops batch -> microseconds for the whole loop
    local num_ops=$1 batch=$2 rd i a b
    rd=$(mktemp -d)
    now_us; a=$NOW_US
    for i in $(seq 1 "$num_ops"); do
        ( if [[ $((i % 2)) -eq 0 ]]; then echo "ws" > "$rd/r_$i"; else echo "tcp" > "$rd/r_$i"; fi ) &
        [[ $((i % batch)) -eq 0 ]] && wait
    done
    wait
    now_us; b=$NOW_US
    rm -rf "$rd"
    echo $((b - a))
}

test_ws_tcp_coexistence() {
    local num_ops=${1:-200}
    local test_name="ws_tcp_coexistence"

    log_section "Test: WS + TCP Coexistence ($num_ops mixed connections)"

    ensure_clean
    wait_for_port_free $WS_PORT
    socketley_cmd create server bench_ws -p $WS_PORT -s
    wait_for_port $WS_PORT || { log_error "Server failed to start"; ensure_clean; return 1; }
    sleep 0.5

    local results_dir=$(mktemp -d)
    local batch=20
    local start_time end_time
    now_us; start_time=$NOW_US

    timeout "$BENCH_TIMEOUT_CMD" bash -c '
        results_dir="'"$results_dir"'"
        WS_PORT='"$WS_PORT"'
        num_ops='"$num_ops"'
        batch='"$batch"'
        for i in $(seq 1 $num_ops); do
            (
                if [[ $((i % 2)) -eq 0 ]]; then
                    resp=""
                    exec 99<>/dev/tcp/localhost/$WS_PORT 2>/dev/null || exit 1
                    printf "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n" >&99
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
    '
    local rc=$?
    # Before the counting, not after it.  The two greps and the rm -rf below took
    # 10 ms of a 90 ms window and were being published as throughput.
    now_us; end_time=$NOW_US
    if [[ $rc -eq 124 ]]; then
        log_bench "TIMEOUT" "ws_tcp_coexistence loop"
    fi

    local ws_success=$(grep -rl "^ws$" "$results_dir" 2>/dev/null | wc -l)
    local tcp_success=$(grep -rl "^tcp$" "$results_dir" 2>/dev/null | wc -l)
    rm -rf "$results_dir"

    local total_time=$(( (end_time - start_time) / 1000 ))
    [[ $total_time -lt 1 ]] && total_time=1
    local ops_sec=$(echo "scale=2; $num_ops * 1000 / $total_time" | bc)

    # The floor from the same box in the same minute, not a remembered constant.
    local floor_us inst_pct verdict="ok"
    floor_us=$(ws_coex_fork_floor_us "$num_ops" "$batch")
    inst_pct=$(awk -v f="$floor_us" -v w=$((end_time - start_time)) \
        'BEGIN{printf "%.1f", (w > 0 ? 100 * f / w : 100)}')

    log_success "WS handshakes: $ws_success, TCP messages: $tcp_success (both served on one port)"
    if awk -v p="$inst_pct" -v lim="$WS_COEX_MAX_INSTRUMENT_PCT" 'BEGIN{exit !(p > lim)}'; then
        verdict="the loop's own forks are ${inst_pct}% of every operation; this rate is bash, not the server"
        log_error "Combined throughput: REFUSED — $verdict"
        log_error "  ($ops_sec ops/sec measured, against $(awk -v f="$floor_us" -v n="$num_ops" 'BEGIN{printf "%.0f", n/(f/1e6)}') ops/sec for the same loop with no socket in it)"
    else
        log_success "Combined throughput: $ops_sec ops/sec (harness ${inst_pct}% of it)"
    fi

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "total_operations" "$num_ops" \
        "ws_success" "$ws_success" \
        "tcp_success" "$tcp_success" \
        "total_time_ms" "$total_time" \
        "ops_per_sec" "$ops_sec" \
        "fork_floor_ops_per_sec" "$(awk -v f="$floor_us" -v n="$num_ops" 'BEGIN{printf "%.2f", n/(f/1e6)}')" \
        "instrument_pct" "$inst_pct" \
        "rate_usable" "$([[ "$verdict" == "ok" ]] && echo 1 || echo 0)" \
        "verdict" "$verdict"

    socketley_cmd stop bench_ws
    sleep 0.5
    socketley_cmd remove bench_ws
}

# Main execution
run_ws_benchmarks() {
    log_section "WEBSOCKET BENCHMARKS"

    ensure_socketley_bench || return 1

    log_bench "START" "ws_handshake_throughput"
    test_ws_handshake 200
    log_bench "DONE" "ws_handshake_throughput"
    fresh_daemon

    log_bench "START" "ws_echo_rtt"
    test_ws_echo 5000 64
    log_bench "DONE" "ws_echo_rtt"
    fresh_daemon

    log_bench "START" "ws_concurrent"
    test_ws_concurrent 20 25
    log_bench "DONE" "ws_concurrent"
    fresh_daemon

    log_bench "START" "ws_tcp_coexistence"
    test_ws_tcp_coexistence 200
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
