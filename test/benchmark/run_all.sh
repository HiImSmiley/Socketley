#!/bin/bash
# Socketley Complete Benchmark Suite
# Runs all benchmarks and generates a summary report

set -e

source "$(dirname "$0")/utils.sh"

SUMMARY_FILE="${RESULTS_DIR}/summary_${TIMESTAMP}.md"

# Print banner
print_banner() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                               ║${NC}"
    echo -e "${CYAN}║           SOCKETLEY BENCHMARK SUITE                           ║${NC}"
    echo -e "${CYAN}║                                                               ║${NC}"
    echo -e "${CYAN}║   Testing: Server, Cache, Proxy Runtimes                     ║${NC}"
    echo -e "${CYAN}║   io_uring event loop performance baseline                    ║${NC}"
    echo -e "${CYAN}║                                                               ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Collect system info
collect_system_info() {
    log_section "System Information"

    local cpu_model=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)
    local cpu_cores=$(nproc)
    local mem_total=$(free -h | awk '/^Mem:/ {print $2}')
    local kernel=$(uname -r)
    local io_uring_ver=$(cat /proc/version | grep -oP 'io_uring' || echo "supported")

    echo "CPU: $cpu_model"
    echo "Cores: $cpu_cores"
    echo "Memory: $mem_total"
    echo "Kernel: $kernel"
    echo "io_uring: $io_uring_ver"

    # Write to summary
    cat > "$SUMMARY_FILE" << EOF
# Socketley Benchmark Results

**Date:** $(date)
**Timestamp:** $TIMESTAMP

## System Information

| Property | Value |
|----------|-------|
| CPU | $cpu_model |
| Cores | $cpu_cores |
| Memory | $mem_total |
| Kernel | $kernel |
| Binary | $SOCKETLEY_BIN |

---

EOF
}

# Run individual benchmark scripts
run_benchmarks() {
    local script_dir="$(dirname "$0")"

    # Export flag so subscripts don't manage daemon
    export SOCKETLEY_BENCH_PARENT=1

    # Server benchmarks
    log_section "Running Server Benchmarks"
    bash "$script_dir/bench_server.sh"

    cleanup_runtimes
    sleep 2

    # Cache benchmarks
    log_section "Running Cache Benchmarks"
    bash "$script_dir/bench_cache.sh"

    cleanup_runtimes
    sleep 2

    # Proxy benchmarks
    log_section "Running Proxy Benchmarks"
    bash "$script_dir/bench_proxy.sh"

    cleanup_runtimes
}

# Generate summary from JSON results
generate_summary() {
    log_section "Generating Summary Report"

    cat >> "$SUMMARY_FILE" << 'EOF'
## Results Summary

### Server Runtime

| Test | Metric | Value |
|------|--------|-------|
EOF

    # Parse server results
    local server_file="${RESULTS_DIR}/server_${TIMESTAMP}.json"
    if [[ -f "$server_file" ]]; then
        # Connection rate
        local conn_rate=$(grep -oP '"connections_per_sec":\s*\K[0-9.]+' "$server_file" | head -1)
        local conn_lat=$(grep -oP '"avg_latency_ms":\s*\K[0-9.]+' "$server_file" | head -1)
        echo "| Connection Rate | conn/sec | $conn_rate |" >> "$SUMMARY_FILE"
        echo "| Connection Latency | ms (avg) | $conn_lat |" >> "$SUMMARY_FILE"

        # Message throughput
        local msg_rate=$(grep -A5 '"test": "server_single_client_throughput"' "$server_file" | grep -oP '"messages_per_sec":\s*\K[0-9.]+' | head -1)
        local msg_mb=$(grep -A5 '"test": "server_single_client_throughput"' "$server_file" | grep -oP '"throughput_mb_sec":\s*\K[0-9.]+' | head -1)
        echo "| Single Client Throughput | msg/sec | $msg_rate |" >> "$SUMMARY_FILE"
        echo "| Single Client Throughput | MB/sec | $msg_mb |" >> "$SUMMARY_FILE"

        # Concurrent
        local concurrent_rate=$(grep -A5 '"test": "server_concurrent_clients"' "$server_file" | grep -oP '"messages_per_sec":\s*\K[0-9.]+' | head -1)
        echo "| Concurrent Clients | msg/sec | $concurrent_rate |" >> "$SUMMARY_FILE"

        # Max connections
        local max_conn=$(grep -oP '"max_concurrent":\s*\K[0-9]+' "$server_file" | head -1)
        echo "| Max Concurrent Connections | count | $max_conn |" >> "$SUMMARY_FILE"
    fi

    cat >> "$SUMMARY_FILE" << 'EOF'

### Cache Runtime

| Test | Metric | Value |
|------|--------|-------|
EOF

    # Parse cache results
    local cache_file="${RESULTS_DIR}/cache_${TIMESTAMP}.json"
    if [[ -f "$cache_file" ]]; then
        local set_ops=$(grep -A5 '"test": "cache_set_throughput"' "$cache_file" | grep -oP '"ops_per_sec":\s*\K[0-9.]+' | head -1)
        local get_ops=$(grep -A5 '"test": "cache_get_throughput"' "$cache_file" | grep -oP '"ops_per_sec":\s*\K[0-9.]+' | head -1)
        local mixed_ops=$(grep -A5 '"test": "cache_mixed_workload"' "$cache_file" | grep -oP '"ops_per_sec":\s*\K[0-9.]+' | head -1)
        local concurrent_ops=$(grep -A5 '"test": "cache_concurrent_access"' "$cache_file" | grep -oP '"ops_per_sec":\s*\K[0-9.]+' | head -1)

        echo "| SET Operations | ops/sec | $set_ops |" >> "$SUMMARY_FILE"
        echo "| GET Operations | ops/sec | $get_ops |" >> "$SUMMARY_FILE"
        echo "| Mixed Workload (80/20) | ops/sec | $mixed_ops |" >> "$SUMMARY_FILE"
        echo "| Concurrent Access | ops/sec | $concurrent_ops |" >> "$SUMMARY_FILE"

        local flush_time=$(grep -oP '"flush_time_ms":\s*\K[0-9]+' "$cache_file" | head -1)
        local load_time=$(grep -oP '"load_time_ms":\s*\K[0-9]+' "$cache_file" | head -1)
        echo "| Persistence FLUSH | ms | $flush_time |" >> "$SUMMARY_FILE"
        echo "| Persistence LOAD | ms | $load_time |" >> "$SUMMARY_FILE"
    fi

    cat >> "$SUMMARY_FILE" << 'EOF'

### Proxy Runtime

| Test | Metric | Value |
|------|--------|-------|
EOF

    # Parse proxy results
    local proxy_file="${RESULTS_DIR}/proxy_${TIMESTAMP}.json"
    if [[ -f "$proxy_file" ]]; then
        local http_rps=$(grep -A5 '"test": "proxy_http_single_backend"' "$proxy_file" | grep -oP '"requests_per_sec":\s*\K[0-9.]+' | head -1)
        local http_lb_rps=$(grep -A5 '"test": "proxy_http_load_balancing"' "$proxy_file" | grep -oP '"requests_per_sec":\s*\K[0-9.]+' | head -1)
        local tcp_rate=$(grep -A5 '"test": "proxy_tcp_throughput"' "$proxy_file" | grep -oP '"messages_per_sec":\s*\K[0-9.]+' | head -1)
        local tcp_mb=$(grep -A5 '"test": "proxy_tcp_throughput"' "$proxy_file" | grep -oP '"throughput_mb_sec":\s*\K[0-9.]+' | head -1)
        local overhead=$(grep -oP '"overhead_ms":\s*\K[0-9.]+' "$proxy_file" | head -1)
        local overhead_pct=$(grep -oP '"overhead_percent":\s*"?\K[0-9.]+' "$proxy_file" | head -1)

        echo "| HTTP Single Backend | req/sec | $http_rps |" >> "$SUMMARY_FILE"
        echo "| HTTP Load Balancing | req/sec | $http_lb_rps |" >> "$SUMMARY_FILE"
        echo "| TCP Throughput | msg/sec | $tcp_rate |" >> "$SUMMARY_FILE"
        echo "| TCP Throughput | MB/sec | $tcp_mb |" >> "$SUMMARY_FILE"
        echo "| Proxy Overhead | ms | $overhead |" >> "$SUMMARY_FILE"
        echo "| Proxy Overhead | % | $overhead_pct |" >> "$SUMMARY_FILE"
    fi

    cat >> "$SUMMARY_FILE" << EOF

---

## Raw Results Files

- Server: \`${RESULTS_DIR}/server_${TIMESTAMP}.json\`
- Cache: \`${RESULTS_DIR}/cache_${TIMESTAMP}.json\`
- Proxy: \`${RESULTS_DIR}/proxy_${TIMESTAMP}.json\`

---

## Notes

This benchmark establishes a baseline for the current io_uring implementation.
Future optimizations to compare:
- [ ] SQPOLL mode
- [ ] Fixed buffers
- [ ] Registered file descriptors
- [ ] Multishot accept
- [ ] Linked operations
EOF

    log_success "Summary saved to: $SUMMARY_FILE"
}

# Print final results
print_final_results() {
    log_section "BENCHMARK COMPLETE"

    echo ""
    echo "Results saved to:"
    echo "  - Summary: $SUMMARY_FILE"
    echo "  - Server:  ${RESULTS_DIR}/server_${TIMESTAMP}.json"
    echo "  - Cache:   ${RESULTS_DIR}/cache_${TIMESTAMP}.json"
    echo "  - Proxy:   ${RESULTS_DIR}/proxy_${TIMESTAMP}.json"
    echo ""

    # Display summary table
    if [[ -f "$SUMMARY_FILE" ]]; then
        echo -e "${CYAN}Quick Summary:${NC}"
        grep -A100 "## Results Summary" "$SUMMARY_FILE" | head -60
    fi
}

# Main
main() {
    print_banner

    # Pre-flight checks
    check_binary || exit 1
    check_dependencies || exit 1

    # Setup
    setup_cleanup_trap
    start_daemon || exit 1

    # Collect info
    collect_system_info

    # Run all benchmarks
    local total_start=$(get_time_ms)
    run_benchmarks
    local total_end=$(get_time_ms)
    local total_time=$((total_end - total_start))

    # Generate report
    generate_summary

    echo "" >> "$SUMMARY_FILE"
    echo "**Total benchmark time:** $(format_duration $total_time)" >> "$SUMMARY_FILE"

    print_final_results

    log_success "Total benchmark time: $(format_duration $total_time)"
}

# Handle command line arguments
case "${1:-}" in
    --server-only)
        check_binary || exit 1
        check_dependencies || exit 1
        setup_cleanup_trap
        start_daemon || exit 1
        bash "$(dirname "$0")/bench_server.sh"
        ;;
    --cache-only)
        check_binary || exit 1
        check_dependencies || exit 1
        setup_cleanup_trap
        start_daemon || exit 1
        bash "$(dirname "$0")/bench_cache.sh"
        ;;
    --proxy-only)
        check_binary || exit 1
        check_dependencies || exit 1
        setup_cleanup_trap
        start_daemon || exit 1
        bash "$(dirname "$0")/bench_proxy.sh"
        ;;
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --server-only    Run only server benchmarks"
        echo "  --cache-only     Run only cache benchmarks"
        echo "  --proxy-only     Run only proxy benchmarks"
        echo "  --help           Show this help"
        echo ""
        echo "Without options, runs the complete benchmark suite."
        ;;
    *)
        main
        ;;
esac
