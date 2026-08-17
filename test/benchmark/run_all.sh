#!/bin/bash
# Socketley Complete Benchmark Suite
# Runs all benchmarks and generates a summary report

# Note: do NOT use set -eE here — daemon lifecycle management (stop/start
# between suites) involves commands that may return non-zero legitimately
# (pkill on dead processes, rm on missing files). Individual benchmark
# errors are already handled by run_bench_script's || block.

# Pre-parse flags before sourcing utils.sh so BENCH_DEV is set first
for _arg in "$@"; do
    case "$_arg" in
        --fresh) export BENCH_FRESH_DAEMON=1 ;;
        --dev)   export BENCH_DEV=1 ;;
    esac
done

source "$(dirname "$0")/utils.sh"

# Run a bench script with timeout + logging. Does NOT propagate timeout exit code
# (set -e would abort run_all.sh otherwise).
run_bench_script() {
    local script=$1
    local name
    name=$(basename "$script")
    log_bench "SCRIPT_START" "$name"
    timeout "$BENCH_TIMEOUT_SCRIPT" bash "$script" || {
        local rc=$?
        if [[ $rc -eq 124 ]]; then
            log_bench "TIMEOUT" "$name (killed after ${BENCH_TIMEOUT_SCRIPT}s)"
        else
            log_bench "FAIL" "$name (exit code $rc)"
        fi
    }
    log_bench "SCRIPT_DONE" "$name"
}

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

    # Idle first: it measures CPU burned at zero load, so it has to run before
    # the load tests leave warm caches and lingering connections behind.
    # Shortened here so three scenarios still fit inside BENCH_TIMEOUT_SCRIPT;
    # run bench_idle.sh directly for longer, more stable samples.  Exported
    # explicitly rather than as an assignment prefix, which behaves ambiguously
    # in front of a shell function.
    export BENCH_IDLE_DURATION=10 BENCH_IDLE_RUNS=2
    run_bench_script "$script_dir/bench_idle.sh"
    unset BENCH_IDLE_DURATION BENCH_IDLE_RUNS
    restart_daemon

    run_bench_script "$script_dir/bench_server.sh"
    restart_daemon

    # The server numbers immediately above have no scale without this: the cache
    # is measured against Redis and the proxy against haproxy, and until this
    # existed the server runtime -- which has the most benchmarks of the three --
    # had nothing underneath it.  It runs here rather than on request so that a
    # server figure and the floor it sits on are always in the same report.
    run_bench_script "$script_dir/bench_server_floor.sh"
    restart_daemon

    run_bench_script "$script_dir/bench_cache.sh"
    restart_daemon

    # Redis comparison: this is the headline claim in the README, so it belongs
    # in the standard suite rather than being something one has to remember to
    # run.  One repetition keeps it around 40s; use --cache-resp-only for the
    # three-run median when the numbers actually matter.  It exits cleanly when
    # redis-benchmark or a running Redis is missing.
    export BENCH_RESP_RUNS=1
    run_bench_script "$script_dir/bench_cache_resp.sh"
    unset BENCH_RESP_RUNS
    restart_daemon

    run_bench_script "$script_dir/bench_proxy.sh"
    restart_daemon

    # The proxy's scale, the same arrangement bench_cache_resp.sh gives the
    # cache: one shared backend, one client, and both proxies measured in
    # interleaved pairs.  Three pairs inside the standard run: that is the
    # fewest that yields a confidence interval at all, and the file's own output
    # is built around printing one.  This used to be 1, which the script now
    # refuses — a single pair produces a ratio with no error bar, which is the
    # form the concurrent cases were unreadable in.  Raise BENCH_HAPROXY_RUNS
    # when the numbers matter: the interval narrows as 1/sqrt(pairs), and on a
    # ten-core box the 8-connection case needed about twenty pairs to get under
    # 15%.  Exits cleanly when haproxy is not installed.
    export BENCH_HAPROXY_RUNS=3
    run_bench_script "$script_dir/bench_proxy_vs_haproxy.sh"
    unset BENCH_HAPROXY_RUNS
    restart_daemon

    # The same comparison in HTTP, which is the mode haproxy is written for and
    # the one nothing in this suite had ever compared.  Two cases, because
    # keep-alive and connection-per-request disagree about which proxy is
    # faster and reporting only one of them would be picking a winner.
    #
    # Its own timeout: seven cases at three seconds a run is minutes, not the
    # tens of seconds the shared BENCH_TIMEOUT_SCRIPT allows, and a benchmark
    # killed mid-write leaves JSON that no longer parses.
    export BENCH_HTTP_RUNS=3
    BENCH_TIMEOUT_SCRIPT=900 run_bench_script "$script_dir/bench_proxy_http_vs_haproxy.sh"
    unset BENCH_HTTP_RUNS
    restart_daemon

    run_bench_script "$script_dir/bench_websocket.sh"
    restart_daemon

    # k6 benchmarks (optional — skip if k6 not installed)
    if check_k6 2>/dev/null; then
        run_bench_script "$script_dir/bench_k6_http.sh"
        restart_daemon

        run_bench_script "$script_dir/bench_k6_ws.sh"
        cleanup_runtimes
    else
        log_warn "Skipping k6 benchmarks (k6 not installed)"
    fi
}

# Generate summary from JSON results
generate_summary() {
    log_section "Generating Summary Report"

    cat >> "$SUMMARY_FILE" << 'EOF'
## Results Summary

### Idle CPU (100% = one saturated core, zero traffic)

| Scenario | CPU % |
|----------|-------|
EOF

    local idle_file="${RESULTS_DIR}/idle_${TIMESTAMP}.json"
    if [[ -f "$idle_file" ]]; then
        jq -rs '.[] | "| \(.label) | \(.cpu_percent_median) |"' "$idle_file" \
            >> "$SUMMARY_FILE" 2>/dev/null
    fi

    # One table per results file, built from what the file contains rather than
    # from a list of field names kept here.
    #
    # That list is why this report printed empty cells: it asked for
    # connections_per_sec, messages_per_sec, throughput_mb_sec and
    # max_concurrent, and none of them has ever appeared in these files.  Only
    # the handful of rows the shell scripts write themselves -- flush_time_ms,
    # requests_per_sec, overhead_percent -- happened to match, so the report came
    # out looking partly filled instead of broken, and an empty cell reads as
    # "not measured" rather than "not found".  A table derived from the data
    # cannot drift away from it.
    #
    # Two shapes share one file.  The C harness rows carry `metric` and repeat
    # `test` across message sizes -- so the size is part of the row's identity,
    # and selecting on the name alone is what collapsed 64B and 1024B into a
    # single line.  The rows the shell writes carry their own fields and are
    # listed as name/value pairs under the same heading.
    #
    # A file written before the metric split carries median_throughput and no
    # `metric`, so its harness rows land in the name/value table below rather
    # than in the main one.  That is deliberate: those numbers are not
    # comparable with these, and a row that will not line up is better than one
    # that lines up wrongly.
    bench_section() {
        local title=$1 file=$2 extra
        [[ -f "$file" ]] || return 0
        printf '\n### %s\n\n' "$title" >> "$SUMMARY_FILE"
        # "Measures" is a column and not a footnote.  A round-trip rate and a
        # write-only rate differ by about 10x on the same traffic, and a table
        # that put them in one "Median" column invited exactly the comparison
        # that number cannot support.  The rate arrives under a key named for
        # its kind, so this reads whichever one is present rather than a shared
        # field that would let the two merge again.
        # Spread is a column and not a footnote, and it is filled for every row.
        # These medians move by 1.2-1.6x between repetitions of the same test on
        # an otherwise idle machine, so a table of bare medians invites exactly
        # the comparison they cannot support: someone reads two reports a week
        # apart and sees a regression that is inside the noise.  A row whose
        # spread exceeds the warning line is marked, so "safe to quote alone"
        # and "quote only with its range" are distinguishable at a glance.  A
        # file written before spread_ratio existed leaves the cell "-", which
        # says the run was never checked rather than that it was steady.
        printf '| Test | Size | Measures | Median | Range (min..max) | Spread | Bandwidth | p50 us | p99 us |\n' >> "$SUMMARY_FILE"
        printf '|------|------|----------|--------|------------------|--------|-----------|--------|--------|\n' >> "$SUMMARY_FILE"
        jq -r '
            .[] | select(has("metric"))
            | "| \(.test)"
            + " | \(if .msg_size then "\(.msg_size) B" else "-" end)"
            + " | \(.metric)"
            + " | \(.median_round_trips_per_sec // .median_writes_per_sec // .median_connects_per_sec // "-")"
            + " | \(if .min_per_sec then "\(.min_per_sec | floor) .. \(.max_per_sec | floor)" else "-" end)"
            + " | \(if .spread_ratio then "\(.spread_ratio)x\(if .stable == 1 then "" else " (wide)" end)" else "-" end)"
            + " | \(if .median_MB_per_sec then "\(.median_MB_per_sec) MB/s" else "-" end)"
            + " | \(.rtt_p50_us // .write_p50_us // .connect_p50_us // "-")"
            + " | \(.rtt_p99_us // .write_p99_us // .connect_p99_us // "-") |"
        ' "$file" >> "$SUMMARY_FILE" 2>/dev/null

        extra=$(jq -r '
            .[] | select(has("metric") | not) | . as $o | .test as $t
            | ($o | keys_unsorted[] | select(. != "test" and . != "timestamp"))
            | "| \($t) | \(.) | \($o[.]) |"
        ' "$file" 2>/dev/null)
        if [[ -n "$extra" ]]; then
            printf '\n| Test | Field | Value |\n|------|-------|-------|\n' >> "$SUMMARY_FILE"
            printf '%s\n' "$extra" >> "$SUMMARY_FILE"
        fi
    }

    bench_section "Server Runtime" "${RESULTS_DIR}/server_${TIMESTAMP}.json"
    bench_section "Cache Runtime"  "${RESULTS_DIR}/cache_${TIMESTAMP}.json"
    bench_section "Cache vs Redis" "${RESULTS_DIR}/cache_resp_${TIMESTAMP}.json"
    bench_section "Proxy Runtime"  "${RESULTS_DIR}/proxy_${TIMESTAMP}.json"
    bench_section "WebSocket"      "${RESULTS_DIR}/websocket_${TIMESTAMP}.json"

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

# Parse --fresh / --dev from any position and strip them from args
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --fresh) export BENCH_FRESH_DAEMON=1 ;;
        --dev)   export BENCH_DEV=1 ;;
        *)       ARGS+=("$arg") ;;
    esac
done
set -- "${ARGS[@]}"

[[ "$BENCH_FRESH_DAEMON" -eq 1 ]] && log_info "Fresh-daemon mode: daemon will restart between each test"
[[ "${BENCH_DEV:-0}" -eq 1 ]] && log_info "Dev mode: using ${PROJECT_ROOT}/bin/Release/socketley"

# Handle command line arguments
case "${1:-}" in
    --server-only)
        check_binary || exit 1
        check_dependencies || exit 1
        setup_cleanup_trap
        start_daemon || exit 1
        export SOCKETLEY_BENCH_PARENT=1
        run_bench_script "$(dirname "$0")/bench_server.sh"
        ;;
    --cache-only)
        check_binary || exit 1
        check_dependencies || exit 1
        setup_cleanup_trap
        start_daemon || exit 1
        export SOCKETLEY_BENCH_PARENT=1
        run_bench_script "$(dirname "$0")/bench_cache.sh"
        ;;
    --proxy-only)
        check_binary || exit 1
        check_dependencies || exit 1
        setup_cleanup_trap
        start_daemon || exit 1
        export SOCKETLEY_BENCH_PARENT=1
        run_bench_script "$(dirname "$0")/bench_proxy.sh"
        ;;
    --websocket-only)
        check_binary || exit 1
        check_dependencies || exit 1
        setup_cleanup_trap
        start_daemon || exit 1
        export SOCKETLEY_BENCH_PARENT=1
        run_bench_script "$(dirname "$0")/bench_websocket.sh"
        ;;
    --k6-only)
        check_binary || exit 1
        check_dependencies || exit 1
        check_k6 || exit 1
        setup_cleanup_trap
        start_daemon || exit 1
        export SOCKETLEY_BENCH_PARENT=1
        run_bench_script "$(dirname "$0")/bench_k6_http.sh"
        cleanup_runtimes
        sleep 2
        run_bench_script "$(dirname "$0")/bench_k6_ws.sh"
        ;;
    --k6-http-only)
        check_binary || exit 1
        check_dependencies || exit 1
        check_k6 || exit 1
        setup_cleanup_trap
        start_daemon || exit 1
        export SOCKETLEY_BENCH_PARENT=1
        run_bench_script "$(dirname "$0")/bench_k6_http.sh"
        ;;
    --k6-ws-only)
        check_binary || exit 1
        check_dependencies || exit 1
        check_k6 || exit 1
        setup_cleanup_trap
        start_daemon || exit 1
        export SOCKETLEY_BENCH_PARENT=1
        run_bench_script "$(dirname "$0")/bench_k6_ws.sh"
        ;;
    --cache-resp-only)
        check_binary || exit 1
        check_dependencies || exit 1
        setup_cleanup_trap
        start_daemon || exit 1
        export SOCKETLEY_BENCH_PARENT=1
        run_bench_script "$(dirname "$0")/bench_cache_resp.sh"
        ;;
    --idle-only)
        check_binary || exit 1
        check_dependencies || exit 1
        setup_cleanup_trap
        export SOCKETLEY_BENCH_PARENT=1
        run_bench_script "$(dirname "$0")/bench_idle.sh"
        ;;
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --server-only    Run only server benchmarks"
        echo "  --cache-only     Run only cache benchmarks"
        echo "  --proxy-only     Run only proxy benchmarks"
        echo "  --websocket-only Run only WebSocket benchmarks"
        echo "  --k6-only        Run only k6 benchmarks (HTTP + WebSocket)"
        echo "  --k6-http-only   Run only k6 HTTP benchmarks"
        echo "  --k6-ws-only     Run only k6 WebSocket benchmarks"
        echo "  --cache-resp-only Run cache vs Redis (RESP2, redis-benchmark)"
        echo "  --idle-only      Run only the idle CPU benchmark"
        echo "  --fresh          Restart daemon between each test"
        echo "  --dev            Use dev binary (bin/Release/) instead of system"
        echo "  --help           Show this help"
        echo ""
        echo "Without options, runs the complete benchmark suite."
        echo "Flags can be combined: $0 --server-only --fresh"
        ;;
    *)
        main
        ;;
esac
