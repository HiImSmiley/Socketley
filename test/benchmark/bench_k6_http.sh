#!/bin/bash
# k6 HTTP Static Serving Benchmark
# Tests: throughput, latency percentiles, spike handling (with and without --http-cache)

source "$(dirname "$0")/utils.sh"

HTTP_PORT=19020
K6_DIR="${SCRIPT_DIR}/k6"
HTTP_ROOT_SRC="${K6_DIR}/http-root"
HTTP_ROOT="$HTTP_ROOT_SRC"
RESULTS_FILE="${RESULTS_DIR}/k6_http_${TIMESTAMP}.json"

# When running under systemd, the daemon has ProtectHome=yes and runs as the
# socketley user, so it cannot access paths under /home/.  Copy the http-root
# to /tmp/ where the daemon can reach it.  Called after generate_large_bin so
# the copy includes all generated assets.
prepare_http_root() {
    if [[ "$USE_SYSTEMD" -eq 1 ]]; then
        HTTP_ROOT="/tmp/socketley_bench_http_root"
        rm -rf "$HTTP_ROOT"
        cp -a "$HTTP_ROOT_SRC" "$HTTP_ROOT"
        chmod -R a+rX "$HTTP_ROOT"
    fi
}

echo "[" > "$RESULTS_FILE"
FIRST_RESULT=true

append_result() {
    if [[ $FIRST_RESULT == true ]]; then
        FIRST_RESULT=false
    else
        echo "," >> "$RESULTS_FILE"
    fi
}

# Generate large.bin if missing (~100 KB) — always into the source dir so
# the systemd-mode copy picks it up.
generate_large_bin() {
    local target="${HTTP_ROOT_SRC}/large.bin"
    if [[ ! -f "$target" ]]; then
        log_info "Generating large.bin (100 KB)..."
        dd if=/dev/urandom of="$target" bs=1024 count=100 2>/dev/null
    fi
}

# Parse k6 JSON summary export and extract metrics
# k6 export format: metrics.{name}.{stat} (no 'values' nesting)
# Counters: {count, rate}  Trends: {avg, min, med, max, p(90), p(95)}  Rates: {value, passes, fails}
parse_k6_summary() {
    local json_file=$1
    local test_name=$2
    local mode=$3  # "disk" or "cached"

    local parsed
    parsed=$(python3 -c "
import json, sys
d = json.load(open('$json_file'))
m = d.get('metrics', {})

def g(metric, key, default=0):
    v = m.get(metric, {})
    if 'values' in v:
        v = v['values']
    return v.get(key, default)

reqs_total = int(g('http_reqs', 'count'))
reqs_rate = g('http_reqs', 'rate')
avg = g('http_req_duration', 'avg')
p50 = g('http_req_duration', 'med', g('http_req_duration', 'p(50)'))
p95 = g('http_req_duration', 'p(95)')
p99 = g('http_req_duration', 'p(99)')
failed_rate = g('http_req_failed', 'value', g('http_req_failed', 'rate', 0))

print(f'{reqs_total}')
print(f'{reqs_rate:.2f}')
print(f'{avg:.3f}')
print(f'{p50:.3f}')
print(f'{p95:.3f}')
print(f'{p99:.3f}')
print(f'{failed_rate * 100:.4f}')
" 2>/dev/null)

    if [[ -z "$parsed" ]]; then
        log_error "Failed to parse k6 summary"
        return 1
    fi

    local reqs_total reqs_rate avg p50 p95 p99 failed_pct
    reqs_total=$(echo "$parsed" | sed -n '1p')
    reqs_rate=$(echo "$parsed" | sed -n '2p')
    avg=$(echo "$parsed" | sed -n '3p')
    p50=$(echo "$parsed" | sed -n '4p')
    p95=$(echo "$parsed" | sed -n '5p')
    p99=$(echo "$parsed" | sed -n '6p')
    failed_pct=$(echo "$parsed" | sed -n '7p')

    log_success "Mode: $mode"
    log_success "  Requests: $reqs_total total, $reqs_rate req/sec"
    log_success "  Latency avg: ${avg}ms  p50: ${p50}ms  p95: ${p95}ms  p99: ${p99}ms"
    log_success "  Failed: ${failed_pct}%"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "mode"          "$mode" \
        "requests_total" "$reqs_total" \
        "requests_per_sec" "$reqs_rate" \
        "latency_avg_ms" "$avg" \
        "latency_p50_ms" "$p50" \
        "latency_p95_ms" "$p95" \
        "latency_p99_ms" "$p99" \
        "failed_percent" "$failed_pct"
}

# Test: HTTP static serving (disk)
test_http_disk() {
    local test_name="k6_http_disk"

    log_section "Test: k6 HTTP Static Serving (disk)"

    socketley_cmd stop bench_k6_http 2>/dev/null; sleep 0.5; socketley_cmd remove bench_k6_http 2>/dev/null
    wait_for_port_free $HTTP_PORT
    socketley_cmd create server bench_k6_http -p $HTTP_PORT --http "$HTTP_ROOT" -s
    wait_for_port $HTTP_PORT || { log_error "Server failed to start"; return 1; }
    sleep 0.5

    local k6_export="/tmp/k6_http_disk_${TIMESTAMP}.json"
    k6 run \
        --summary-export "$k6_export" \
        --env BASE_URL="http://localhost:${HTTP_PORT}" \
        --quiet \
        "${K6_DIR}/http_bench.js" 2>&1

    if [[ -f "$k6_export" ]]; then
        parse_k6_summary "$k6_export" "$test_name" "disk"
        rm -f "$k6_export"
    else
        log_error "k6 summary export not found"
    fi

    socketley_cmd stop bench_k6_http
    sleep 0.5
    socketley_cmd remove bench_k6_http
}

# Test: HTTP static serving (cached)
test_http_cached() {
    local test_name="k6_http_cached"

    log_section "Test: k6 HTTP Static Serving (--http-cache)"

    socketley_cmd stop bench_k6_http 2>/dev/null; sleep 0.5; socketley_cmd remove bench_k6_http 2>/dev/null
    wait_for_port_free $HTTP_PORT
    socketley_cmd create server bench_k6_http -p $HTTP_PORT --http "$HTTP_ROOT" --http-cache -s
    wait_for_port $HTTP_PORT || { log_error "Server failed to start"; return 1; }
    sleep 0.5

    local k6_export="/tmp/k6_http_cached_${TIMESTAMP}.json"
    k6 run \
        --summary-export "$k6_export" \
        --env BASE_URL="http://localhost:${HTTP_PORT}" \
        --quiet \
        "${K6_DIR}/http_bench.js" 2>&1

    if [[ -f "$k6_export" ]]; then
        parse_k6_summary "$k6_export" "$test_name" "cached"
        rm -f "$k6_export"
    else
        log_error "k6 summary export not found"
    fi

    socketley_cmd stop bench_k6_http
    sleep 0.5
    socketley_cmd remove bench_k6_http
}

# Main
run_k6_http_benchmarks() {
    log_section "k6 HTTP STATIC SERVING BENCHMARKS"

    check_k6 || return 1
    generate_large_bin
    prepare_http_root

    test_http_disk
    sleep 1
    test_http_cached

    echo "]" >> "$RESULTS_FILE"

    # Clean up temp http-root copy (systemd mode)
    if [[ "$USE_SYSTEMD" -eq 1 ]] && [[ -d "/tmp/socketley_bench_http_root" ]]; then
        rm -rf "/tmp/socketley_bench_http_root"
    fi

    log_section "k6 HTTP Benchmark Complete"
    log_success "Results saved to: $RESULTS_FILE"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_binary || exit 1
    check_dependencies || exit 1
    check_k6 || exit 1
    setup_cleanup_trap
    if should_manage_daemon; then
        start_daemon || exit 1
    fi
    run_k6_http_benchmarks
fi
