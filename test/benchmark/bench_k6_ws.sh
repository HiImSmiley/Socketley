#!/bin/bash
# k6 WebSocket Benchmark
# Tests: WS connection establishment, echo RTT latency, concurrent connections

source "$(dirname "$0")/utils.sh"

WS_PORT=19021
K6_DIR="${SCRIPT_DIR}/k6"
LUA_ECHO="/tmp/k6_ws_echo.lua"
RESULTS_FILE="${RESULTS_DIR}/k6_ws_${TIMESTAMP}.json"

echo "[" > "$RESULTS_FILE"
FIRST_RESULT=true

append_result() {
    if [[ $FIRST_RESULT == true ]]; then
        FIRST_RESULT=false
    else
        echo "," >> "$RESULTS_FILE"
    fi
}

# Write echo Lua script
write_echo_lua() {
    cat > "$LUA_ECHO" << 'LUAEOF'
function on_message(id, msg)
    self.send(id, msg)
end
LUAEOF
}

# Parse k6 JSON summary export for WebSocket metrics
# k6 export format: metrics.{name}.{stat} (no 'values' nesting)
parse_k6_ws_summary() {
    local json_file=$1
    local test_name=$2

    local parsed
    parsed=$(python3 -c "
import json
d = json.load(open('$json_file'))
m = d.get('metrics', {})

def g(metric, key, default=0):
    v = m.get(metric, {})
    if 'values' in v:
        v = v['values']
    return v.get(key, default)

ws_conns = int(g('ws_connections', 'count'))
ws_msgs = int(g('ws_messages_sent', 'count'))
ws_echoes = int(g('ws_echoes_received', 'count'))
msgs_rate = g('ws_messages_sent', 'rate')
rtt_avg = g('ws_rtt', 'avg')
rtt_p50 = g('ws_rtt', 'med', g('ws_rtt', 'p(50)'))
rtt_p95 = g('ws_rtt', 'p(95)')
rtt_p99 = g('ws_rtt', 'p(99)')
error_val = g('ws_error_rate', 'value', g('ws_error_rate', 'rate', 0))

print(ws_conns)
print(ws_msgs)
print(ws_echoes)
print(f'{msgs_rate:.2f}')
print(f'{rtt_avg:.3f}')
print(f'{rtt_p50:.3f}')
print(f'{rtt_p95:.3f}')
print(f'{rtt_p99:.3f}')
print(f'{error_val * 100:.4f}')
" 2>/dev/null)

    if [[ -z "$parsed" ]]; then
        log_error "Failed to parse k6 summary"
        return 1
    fi

    local ws_conns ws_msgs ws_echoes msgs_rate rtt_avg rtt_p50 rtt_p95 rtt_p99 error_rate
    ws_conns=$(echo "$parsed" | sed -n '1p')
    ws_msgs=$(echo "$parsed" | sed -n '2p')
    ws_echoes=$(echo "$parsed" | sed -n '3p')
    msgs_rate=$(echo "$parsed" | sed -n '4p')
    rtt_avg=$(echo "$parsed" | sed -n '5p')
    rtt_p50=$(echo "$parsed" | sed -n '6p')
    rtt_p95=$(echo "$parsed" | sed -n '7p')
    rtt_p99=$(echo "$parsed" | sed -n '8p')
    error_rate=$(echo "$parsed" | sed -n '9p')

    log_success "Connections: $ws_conns  Messages sent: $ws_msgs  Echoes: $ws_echoes"
    log_success "Messages/sec: $msgs_rate"
    log_success "RTT avg: ${rtt_avg}ms  p50: ${rtt_p50}ms  p95: ${rtt_p95}ms  p99: ${rtt_p99}ms"
    log_success "Error rate: ${error_rate}%"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "ws_connections"    "$ws_conns" \
        "ws_messages_sent"  "$ws_msgs" \
        "ws_echoes_received" "$ws_echoes" \
        "messages_per_sec"  "$msgs_rate" \
        "rtt_avg_ms"        "$rtt_avg" \
        "rtt_p50_ms"        "$rtt_p50" \
        "rtt_p95_ms"        "$rtt_p95" \
        "rtt_p99_ms"        "$rtt_p99" \
        "error_rate_percent" "$error_rate"
}

# Test: WebSocket echo throughput & latency
test_ws_echo() {
    local test_name="k6_ws_echo"

    log_section "Test: k6 WebSocket Echo (throughput & latency)"

    write_echo_lua

    socketley_cmd create server bench_k6_ws -p $WS_PORT --lua "$LUA_ECHO" -s
    wait_for_port $WS_PORT || { log_error "Server failed to start"; return 1; }
    sleep 0.5

    local k6_export="/tmp/k6_ws_echo_${TIMESTAMP}.json"
    k6 run \
        --summary-export "$k6_export" \
        --env WS_URL="ws://localhost:${WS_PORT}" \
        --env MSGS_PER_VU=50 \
        --env MSG_INTERVAL_MS=20 \
        --quiet \
        "${K6_DIR}/ws_bench.js" 2>&1

    if [[ -f "$k6_export" ]]; then
        parse_k6_ws_summary "$k6_export" "$test_name"
        rm -f "$k6_export"
    else
        log_error "k6 summary export not found"
    fi

    socketley_cmd stop bench_k6_ws
    sleep 0.5
    socketley_cmd remove bench_k6_ws
}

# Main
run_k6_ws_benchmarks() {
    log_section "k6 WEBSOCKET BENCHMARKS"

    check_k6 || return 1

    test_ws_echo

    echo "]" >> "$RESULTS_FILE"

    log_section "k6 WebSocket Benchmark Complete"
    log_success "Results saved to: $RESULTS_FILE"

    # Cleanup
    rm -f "$LUA_ECHO"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_binary || exit 1
    check_dependencies || exit 1
    check_k6 || exit 1
    setup_cleanup_trap
    if should_manage_daemon; then
        start_daemon || exit 1
    fi
    run_k6_ws_benchmarks
fi
