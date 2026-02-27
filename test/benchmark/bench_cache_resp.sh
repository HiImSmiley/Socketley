#!/bin/bash
# Cache vs Redis Benchmark (RESP2, redis-benchmark)
# Matches README methodology exactly: redis-benchmark, RESP2 protocol,
# 50 clients, P=1 (200K ops) and P=100 (2M ops).
# Takes median of N runs (default 3) for consistency.

source "$(dirname "$0")/utils.sh"

CACHE_PORT=19001
REDIS_PORT=6379
RESULTS_FILE="${RESULTS_DIR}/cache_resp_${TIMESTAMP}.json"

TESTS="SET,GET,LPUSH,LPOP,SADD,HSET"
CLIENTS=50
RUNS=${1:-3}

P1_REQUESTS=200000
P100_REQUESTS=2000000

TMPDIR_BENCH=$(mktemp -d)

echo "[" > "$RESULTS_FILE"
FIRST_RESULT=true

append_result() {
    if [[ $FIRST_RESULT == true ]]; then
        FIRST_RESULT=false
    else
        echo "," >> "$RESULTS_FILE"
    fi
}

# Extract ops/sec for a test from redis-benchmark -q output
# Lines look like: "SET: 188679.25 requests per second, p50=0.135 msec"
get_ops() {
    local file=$1 test=$2
    grep "requests per second" "$file" | \
    awk -v t="$test" '{
        gsub(/^[ \t]+/, "", $0)
        if ($0 ~ "^"t":") {
            match($0, /[0-9]+\.[0-9]+ requests/)
            s = substr($0, RSTART, RLENGTH)
            split(s, a, " ")
            print a[1]
        }
    }'
}

# Extract p50 latency
get_p50() {
    local file=$1 test=$2
    grep "requests per second" "$file" | \
    awk -v t="$test" '{
        gsub(/^[ \t]+/, "", $0)
        if ($0 ~ "^"t":") {
            match($0, /p50=[0-9.]+/)
            print substr($0, RSTART+4, RLENGTH-4)
        }
    }'
}

# Format ops/sec for display
fmt_ops() {
    local ops=$1
    if [[ -z "$ops" || "$ops" == "0" ]]; then echo "N/A"; return; fi
    awk -v ops="$ops" 'BEGIN {
        if (ops >= 1000000) printf "%.2fM", ops/1000000
        else if (ops >= 1000) printf "%.0fK", ops/1000
        else printf "%.0f", ops
    }'
}

# Calculate ratio a/b
calc_ratio() {
    local a=$1 b=$2
    if [[ -z "$a" || -z "$b" || "$b" == "0" ]]; then echo "N/A"; return; fi
    awk -v a="$a" -v b="$b" 'BEGIN { printf "%.1fx", a/b }'
}

# Run redis-benchmark N times and return the median result file (by SET ops/sec)
run_bench_median() {
    local label=$1 port=$2 pipeline=$3 requests=$4 runs=$5
    local -a files=()

    for ((i = 1; i <= runs; i++)); do
        local f="$TMPDIR_BENCH/${label}_p${pipeline}_run${i}.txt"
        redis-benchmark -p "$port" -c $CLIENTS -n "$requests" -P "$pipeline" \
            -t "$TESTS" -r 100000 -q --precision 3 2>/dev/null | sed 's/.*\r//' > "$f"
        files+=("$f")
        [[ $runs -gt 1 ]] && log_info "  Run $i/$runs done" >&2
    done

    if [[ $runs -eq 1 ]]; then
        echo "${files[0]}"
        return
    fi

    # Pick median by SET throughput
    local pairs=""
    for f in "${files[@]}"; do
        local ops=$(get_ops "$f" "SET")
        pairs+="${ops:-0} $f"$'\n'
    done

    echo "$pairs" | sort -n -k1 | awk -v mid=$(( (runs + 1) / 2 )) 'NR == mid { print $2 }'
}

# Print throughput comparison table
print_comparison() {
    local title=$1 s_file=$2 r_file=$3

    echo ""
    log_section "$title"

    printf "%-10s  %16s  %16s  %8s\n" "Operation" "Socketley" "Redis 7.0" "Ratio"
    printf "%-10s  %16s  %16s  %8s\n" "─────────" "────────────────" "────────────────" "────────"

    for test in SET GET LPUSH LPOP SADD HSET; do
        local s=$(get_ops "$s_file" "$test")
        local r=$(get_ops "$r_file" "$test")
        printf "%-10s  %13s/s  %13s/s  %8s\n" \
            "$test" "$(fmt_ops "$s")" "$(fmt_ops "$r")" "$(calc_ratio "$s" "$r")"
    done
}

# Print latency comparison
print_latency() {
    local title=$1 s_file=$2 r_file=$3

    echo ""
    log_info "$title"

    printf "%-10s  %14s  %14s\n" "Operation" "Socketley p50" "Redis p50"
    printf "%-10s  %14s  %14s\n" "─────────" "─────────────" "─────────────"

    for test in SET GET LPUSH LPOP SADD HSET; do
        local sp=$(get_p50 "$s_file" "$test")
        local rp=$(get_p50 "$r_file" "$test")
        printf "%-10s  %11s ms  %11s ms\n" "$test" "${sp:-N/A}" "${rp:-N/A}"
    done
}

# Write JSON results for one pipeline depth
write_results_json() {
    local pipeline=$1 s_file=$2 r_file=$3

    append_result
    cat >> "$RESULTS_FILE" <<JEOF
{
  "test": "cache_resp_vs_redis",
  "pipeline": $pipeline,
  "clients": $CLIENTS,
  "runs": $RUNS,
  "timestamp": "$(date -Iseconds)",
  "operations": {
JEOF

    local first=true
    for test in SET GET LPUSH LPOP SADD HSET; do
        local so=$(get_ops "$s_file" "$test")
        local ro=$(get_ops "$r_file" "$test")
        local sp=$(get_p50 "$s_file" "$test")
        local rp=$(get_p50 "$r_file" "$test")
        local ratio=$(calc_ratio "$so" "$ro")

        [[ $first == true ]] && first=false || echo "," >> "$RESULTS_FILE"
        echo -n "    \"$test\": {\"socketley_ops\": ${so:-0}, \"redis_ops\": ${ro:-0}, \"ratio\": \"$ratio\", \"socketley_p50_ms\": ${sp:-0}, \"redis_p50_ms\": ${rp:-0}}" >> "$RESULTS_FILE"
    done

    echo "" >> "$RESULTS_FILE"
    echo "  }" >> "$RESULTS_FILE"
    echo "}" >> "$RESULTS_FILE"
}

# Compare actual results against README claims
print_readme_comparison() {
    local s_p100=$1 r_p100=$2

    echo ""
    log_section "Actual vs README Claims (P=100)"

    # README claimed socketley ops/sec and ratios
    local -a ops=(SET GET LPUSH LPOP SADD HSET)
    local -a readme_s=(8930000 10200000 8200000 10400000 7170000 8300000)
    local -a readme_ratio=("2.8x" "2.5x" "2.8x" "3.9x" "2.0x" "2.8x")

    printf "%-10s  %14s  %14s  %12s  %12s\n" \
        "Operation" "README Ratio" "Actual Ratio" "README SKT" "Actual SKT"
    printf "%-10s  %14s  %14s  %12s  %12s\n" \
        "─────────" "──────────────" "──────────────" "────────────" "────────────"

    for ((i = 0; i < ${#ops[@]}; i++)); do
        local test=${ops[$i]}
        local actual_s=$(get_ops "$s_p100" "$test")
        local actual_r=$(get_ops "$r_p100" "$test")
        local actual_ratio=$(calc_ratio "$actual_s" "$actual_r")

        printf "%-10s  %14s  %14s  %9s/s  %9s/s\n" \
            "$test" "${readme_ratio[$i]}" "$actual_ratio" \
            "$(fmt_ops "${readme_s[$i]}")" "$(fmt_ops "$actual_s")"
    done
}

# ── Main ──────────────────────────────────────────────────────────────

run_cache_resp_benchmarks() {
    log_section "CACHE vs REDIS BENCHMARK (RESP2, redis-benchmark)"
    log_info "Methodology: redis-benchmark, $CLIENTS clients, RESP2 protocol"
    log_info "Runs per config: $RUNS (median selected)"

    if ! command -v redis-benchmark &>/dev/null; then
        log_error "redis-benchmark not found — install redis-tools"
        return 1
    fi

    if ! redis-cli -p $REDIS_PORT ping &>/dev/null; then
        log_error "Redis not running on port $REDIS_PORT"
        return 1
    fi

    redis-cli -p $REDIS_PORT FLUSHALL >/dev/null 2>&1

    # Start socketley cache with RESP protocol
    socketley_cmd stop bench_cache_resp 2>/dev/null
    sleep 0.5
    socketley_cmd remove bench_cache_resp 2>/dev/null
    wait_for_port_free $CACHE_PORT
    socketley_cmd create cache bench_cache_resp -p $CACHE_PORT --resp -s
    wait_for_port $CACHE_PORT || { log_error "Cache (RESP) failed to start"; socketley_cmd stop bench_cache_resp 2>/dev/null; sleep 0.5; socketley_cmd remove bench_cache_resp 2>/dev/null; return 1; }
    sleep 0.5

    # ── P=1 ──
    log_section "Pipeline Depth = 1 ($CLIENTS clients, $(( P1_REQUESTS / 1000 ))K ops)"

    log_info "Benchmarking Socketley (P=1)..."
    local s_p1=$(run_bench_median "socketley" $CACHE_PORT 1 $P1_REQUESTS $RUNS)

    log_info "Benchmarking Redis (P=1)..."
    local r_p1=$(run_bench_median "redis" $REDIS_PORT 1 $P1_REQUESTS $RUNS)

    print_comparison "Results: Pipeline Depth = 1" "$s_p1" "$r_p1"
    print_latency "Latency (P=1)" "$s_p1" "$r_p1"
    write_results_json 1 "$s_p1" "$r_p1"

    # Flush between runs
    redis-cli -p $REDIS_PORT FLUSHALL >/dev/null 2>&1

    # ── P=100 ──
    log_section "Pipeline Depth = 100 ($CLIENTS clients, $(( P100_REQUESTS / 1000 ))K ops)"

    log_info "Benchmarking Socketley (P=100)..."
    local s_p100=$(run_bench_median "socketley" $CACHE_PORT 100 $P100_REQUESTS $RUNS)

    log_info "Benchmarking Redis (P=100)..."
    local r_p100=$(run_bench_median "redis" $REDIS_PORT 100 $P100_REQUESTS $RUNS)

    print_comparison "Results: Pipeline Depth = 100" "$s_p100" "$r_p100"
    print_latency "Latency (P=100)" "$s_p100" "$r_p100"
    write_results_json 100 "$s_p100" "$r_p100"

    # Cleanup
    socketley_cmd stop bench_cache_resp
    sleep 0.5
    socketley_cmd remove bench_cache_resp
    redis-cli -p $REDIS_PORT FLUSHALL >/dev/null 2>&1

    echo "]" >> "$RESULTS_FILE"

    # README comparison
    print_readme_comparison "$s_p100" "$r_p100"

    rm -rf "$TMPDIR_BENCH"

    log_section "Cache RESP Benchmark Complete"
    log_success "Results saved to: $RESULTS_FILE"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_binary || exit 1
    check_dependencies || exit 1
    setup_cleanup_trap
    if should_manage_daemon; then
        start_daemon || exit 1
    fi
    run_cache_resp_benchmarks
fi
