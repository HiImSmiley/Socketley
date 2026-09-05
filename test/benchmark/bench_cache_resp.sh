#!/bin/bash
# Cache vs Redis Benchmark (RESP2, redis-benchmark)
# Matches README methodology exactly: redis-benchmark, RESP2 protocol,
# 50 clients, P=1 (200K ops) and P=100 (2M ops).
#
# Measured as interleaved pairs, for the reasons lib_paired.sh sets out, and
# this file arrived at them the expensive way.  It used to run every socketley
# repetition, then every Redis one, and pick each arm's median by SET -- so the
# SADD line was whichever run happened to be median for a different operation.
# On 2026-09-04 that reported SADD at 156,862 against Redis's 197,239, a 0.8x
# that read as a defect in the set path and was a single unlucky run: five
# interleaved pairs put SADD at 202,020 against 197,239, the fastest of the six
# rather than the slowest.  A day went into profiling a target that did not
# exist.
#
# So: pairs, alternating which arm leads, and the answer per operation is the
# median of the per-pair ratios.  Never the ratio of two medians -- that is the
# unpaired comparison wearing a median's clothes.
#
# The client's own CPU is reported beside every number.  One redis-benchmark
# process saturates a core at around 200k ops/s on this box, and a reading taken
# without it cannot tell a fast server from a capped client: at P=1 both arms
# land within a few percent of each other because neither is the bottleneck.

source "$(dirname "$0")/utils.sh"
source "$(dirname "$0")/lib_paired.sh"

CACHE_PORT=19001
REDIS_PORT=6379
RESULTS_FILE="${RESULTS_DIR}/cache_resp_${TIMESTAMP}.json"

TESTS="SET,GET,LPUSH,LPOP,SADD,HSET"
OPS="SET GET LPUSH LPOP SADD HSET"
CLIENTS=50
# Positional argument wins, then the environment, then the default.
PAIRS=${1:-${BENCH_RESP_PAIRS:-3}}

# Three is the fewest that yields an interval at all, and one pair is refused
# outright: it produces a ratio with no error bar, which is the form the SADD
# reading above was unreadable in.  bench_proxy_http_vs_haproxy.sh refuses the
# same thing for the same reason -- the second refusal at the same point is why
# it is stated here rather than left to the caller.
if (( PAIRS < 3 )); then
    log_error "PAIRS=$PAIRS: a comparison with fewer than three pairs has no interval"
    exit 1
fi

# Five percent, not the fifteen the proxy comparisons use: at P=1 the whole
# question is whether the cache is within a few percent of Redis, so an
# instrument that resolves only 15% cannot answer it.
TARGET_PCT=${BENCH_RESOLUTION_TARGET:-5}
QUIET_CORES=${BENCH_QUIET_CORES:-1.0}

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

# Extract ops/sec for a test from redis-benchmark -q output.
#
# redis-benchmark draws a live progress counter with CARRIAGE RETURNS and no
# newline, so the final result shares one line with it:
#
#   " \rSET: rps=0.0 (overall: -nan) ... \r      \rSET: 6666666.50 requests per second,"
#
# Two traps, both of which have fired here:
#
#  1. Stripping only [ \t] leaves the line starting with \r, so "^SET:" does not
#     match and the whole reading vanishes.  The harness then recorded 0 -- and
#     summary_20260825_061125.md reports socketley_ops:0 against redis at
#     pipeline 100 for all six operations because of it.  The cache was fine:
#     the same redis-benchmark invocation reads 6,666,666 SET/s and 10,000,000
#     GET/s when the line is parsed correctly.
#
#  2. Taking the FIRST number on the line takes the progress counter's rps=0.0
#     rather than the result.  Take the LAST match.
get_ops() {
    local file=$1 test=$2
    tr '\r' '\n' < "$file" | grep "requests per second" | \
    awk -v t="$test" '{
        gsub(/^[ \t\r]+/, "", $0)
        if ($0 ~ "^"t":") {
            n = ""
            while (match($0, /[0-9]+\.[0-9]+ requests/)) {
                s = substr($0, RSTART, RLENGTH)
                split(s, a, " ")
                n = a[1]
                $0 = substr($0, RSTART + RLENGTH)
            }
            if (n != "") print n
        }
    }'
}

# Extract p50 latency
get_p50() {
    local file=$1 test=$2
    tr '\r' '\n' < "$file" | grep "requests per second" | \
    awk -v t="$test" '{
        gsub(/^[ \t\r]+/, "", $0)
        if ($0 ~ "^"t":" && match($0, /p50=[0-9.]+/))
            print substr($0, RSTART+4, RLENGTH-4)
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

# One leg: all six operations in one redis-benchmark invocation, with the
# client's own CPU beside them.  Sampled while it runs rather than read after
# it exits, because /proc/PID/stat is gone by then.
run_leg() {   # port pipeline requests outfile -> echoes client cores, or TIMEOUT
    local port=$1 pipeline=$2 requests=$3 out=$4
    local raw="$out.raw" t0 t1 ticks=0 pid rc t

    t0=$(date +%s%N)
    timeout "$BENCH_TIMEOUT_REDIS" redis-benchmark -p "$port" -c $CLIENTS -n "$requests" \
        -P "$pipeline" -t "$TESTS" -r 100000 -q --precision 3 >"$raw" 2>/dev/null &
    pid=$!

    # timeout(1) forks the process it is timing, so its own /proc entry shows
    # almost no CPU: sampling the pid $! returns reported 0.00 cores for a
    # redis-benchmark sitting at a full one.  The child is found once and not
    # per tick, because pgrep walks all of /proc and doing that every 100 ms is
    # load the run under measurement then pays for -- the version that did
    # widened this comparison's interval from 2% to 23%.
    local child=""
    for _ in 1 2 3 4 5; do
        child=$(pgrep -P "$pid" 2>/dev/null | head -1)
        [[ -n $child ]] && break
        sleep 0.05
    done
    while kill -0 "$pid" 2>/dev/null; do
        t=$(cpu_ticks_of "${child:-$pid}")
        # The last sample before exit is the one that counts, and the sample
        # taken after it is zero -- keeping only non-zero readings drops that.
        [[ ${t:-0} -gt 0 ]] && ticks=$t
        sleep 0.1
    done
    wait "$pid"; rc=$?
    t1=$(date +%s%N)
    sed 's/.*\r//' "$raw" > "$out"

    if (( rc == 124 )); then
        # A timeout must not become a NUMBER.  On 2026-08-25 a run timed out
        # once for socketley at P=100 and the summary then reported
        # socketley_ops:0 against redis at 2.1M for all six operations -- which
        # reads as a total failure of the cache and was nothing of the kind.
        log_bench "TIMEOUT" "redis-benchmark port $port P=$pipeline"
        echo "TIMEOUT"; return 1
    fi
    # The parentheses are load-bearing: awk reads `printf fmt, a > b` as a
    # redirection into the file named by b, so the unbracketed conditional was
    # a syntax error and every client-CPU reading came out empty.
    awk -v t="$ticks" -v hz="$HZ" -v ns=$((t1 - t0)) \
        'BEGIN { printf "%.2f", (ns > 0 ? t / hz / (ns / 1e9) : 0) }'
}

# One pipeline depth, as interleaved pairs.  Fills PC_* for every operation,
# every time, so a caller cannot read a stale value from the depth before.
declare -A PC_S PC_R PC_RATIO PC_CI PC_SP50 PC_RP50
PC_KEPT=0; PC_DROPPED=0; PC_BADRUN=0; PC_SCLIENT=0; PC_RCLIENT=0

paired_case() {   # pipeline requests
    local pipeline=$1 requests=$2
    local -A sv rv rt sp rp
    local kept=0 dropped=0 badrun=0 attempt=0
    local max_attempts=$((PAIRS * 2 + 2))
    local sc_all="" rc_all="" t a b

    for t in $OPS; do sv[$t]=""; rv[$t]=""; rt[$t]=""; sp[$t]=""; rp[$t]=""; done

    # A discarded warm-up pair.  A cache that has just been created pays for a
    # cold path on whichever arm goes first, and that is not a difference
    # between the arms.
    run_leg "$CACHE_PORT" "$pipeline" "$requests" "$TMPDIR_BENCH/warm_s" >/dev/null
    run_leg "$REDIS_PORT" "$pipeline" "$requests" "$TMPDIR_BENCH/warm_r" >/dev/null

    while (( kept < PAIRS && attempt < max_attempts )); do
        attempt=$((attempt + 1))
        local sf="$TMPDIR_BENCH/s_p${pipeline}_$attempt"
        local rf="$TMPDIR_BENCH/r_p${pipeline}_$attempt"
        local before after scores rcores

        before=$(box_load_cores)
        # Alternate which arm leads: whatever the leading arm pays that the
        # trailing one does not is then charged to each of them in turn.
        if (( attempt % 2 == 1 )); then
            scores=$(run_leg "$CACHE_PORT" "$pipeline" "$requests" "$sf")
            rcores=$(run_leg "$REDIS_PORT" "$pipeline" "$requests" "$rf")
        else
            rcores=$(run_leg "$REDIS_PORT" "$pipeline" "$requests" "$rf")
            scores=$(run_leg "$CACHE_PORT" "$pipeline" "$requests" "$sf")
        fi
        after=$(box_load_cores)

        if awk -v x="$before" -v y="$after" -v lim="$QUIET_CORES" \
               'BEGIN { exit !(x > lim || y > lim) }'; then
            dropped=$((dropped + 1)); continue
        fi

        # A pair is kept or dropped whole.  One leg short of an operation is
        # precisely the unpaired comparison this exists to replace.
        local ok=true
        for t in $OPS; do
            a=$(get_ops "$sf" "$t" | tail -1); b=$(get_ops "$rf" "$t" | tail -1)
            [[ -z "$a" || -z "$b" || "$a" == "0" || "$b" == "0" ]] && ok=false
        done
        if [[ $ok != true ]]; then badrun=$((badrun + 1)); continue; fi

        for t in $OPS; do
            a=$(get_ops "$sf" "$t" | tail -1); b=$(get_ops "$rf" "$t" | tail -1)
            sv[$t]+=" $a"; rv[$t]+=" $b"
            rt[$t]+=" $(awk -v x="$a" -v y="$b" 'BEGIN { printf "%.6f", x / y }')"
            sp[$t]+=" $(get_p50 "$sf" "$t" | tail -1)"
            rp[$t]+=" $(get_p50 "$rf" "$t" | tail -1)"
        done
        sc_all+=" $scores"; rc_all+=" $rcores"
        kept=$((kept + 1))
    done

    PC_KEPT=$kept; PC_DROPPED=$dropped; PC_BADRUN=$badrun
    PC_SCLIENT=0; PC_RCLIENT=0
    for t in $OPS; do PC_S[$t]=0; PC_R[$t]=0; PC_RATIO[$t]=0; PC_CI[$t]=0; PC_SP50[$t]=0; PC_RP50[$t]=0; done
    (( kept == 0 )) && return 0

    PC_SCLIENT=$(median_of "$sc_all"); PC_RCLIENT=$(median_of "$rc_all")
    for t in $OPS; do
        PC_S[$t]=$(median_of "${sv[$t]}")
        PC_R[$t]=$(median_of "${rv[$t]}")
        PC_RATIO[$t]=$(median_of "${rt[$t]}")
        PC_CI[$t]=$(ci_pct_of "${rt[$t]}")
        PC_SP50[$t]=$(median_of "${sp[$t]}")
        PC_RP50[$t]=$(median_of "${rp[$t]}")
    done
}

# The verdict column, not the ratio, is the thing to read first.  Named for the
# client rather than a backend because that is what saturates here.
resp_verdict() {   # ci client_cores
    local ci=$1 cl=$2
    if (( PC_KEPT == 0 )); then
        if (( PC_BADRUN > 0 )); then
            echo "no pair survived — ${PC_BADRUN} had a leg that returned nothing"
        else
            echo "no pair survived — the box was never quiet"
        fi
        return
    fi
    if (( PC_KEPT < 3 )); then echo "only $PC_KEPT pair(s) — no interval"; return; fi
    if awk -v c="$cl" 'BEGIN { exit !(c > 0.95) }'; then
        echo "client-bound (${cl} cores) — measures redis-benchmark"
        return
    fi
    if awk -v c="$ci" -v t="$TARGET_PCT" 'BEGIN { exit !(c > t) }'; then
        echo "cannot resolve ${TARGET_PCT}% — only ${ci}%"
        return
    fi
    echo "resolves ${TARGET_PCT}%"
}

# Print throughput comparison table
print_comparison() {
    local title=$1

    echo ""
    log_section "$title"

    printf "%-10s  %13s  %13s  %8s  %7s  %s\n" \
        "Operation" "Socketley" "Redis 7.0" "Ratio" "CI95" "Verdict"
    printf "%-10s  %13s  %13s  %8s  %7s  %s\n" \
        "─────────" "─────────────" "─────────────" "────────" "───────" "───────"

    local t
    for t in $OPS; do
        # The ratio is the median of the per-pair ratios, so it does not have to
        # agree with the two medians beside it, and when it does not that is the
        # box moving between the legs rather than a contradiction.
        printf "%-10s  %10s/s  %10s/s  %7.2fx  %6s%%  %s\n" \
            "$t" "$(fmt_ops "${PC_S[$t]}")" "$(fmt_ops "${PC_R[$t]}")" \
            "${PC_RATIO[$t]}" "${PC_CI[$t]}" "$(resp_verdict "${PC_CI[$t]}" "$PC_SCLIENT")"
    done

    echo ""
    log_info "$PC_KEPT pair(s) kept, $PC_DROPPED discarded for box load, $PC_BADRUN with an empty leg"
    log_info "client cores: ${PC_SCLIENT} against socketley, ${PC_RCLIENT} against redis" \
             "(one redis-benchmark process caps at 1.0)"
}

# Print latency comparison
print_latency() {
    local title=$1

    echo ""
    log_info "$title"

    printf "%-10s  %14s  %14s\n" "Operation" "Socketley p50" "Redis p50"
    printf "%-10s  %14s  %14s\n" "─────────" "─────────────" "─────────────"

    local t
    for t in $OPS; do
        printf "%-10s  %11s ms  %11s ms\n" "$t" "${PC_SP50[$t]}" "${PC_RP50[$t]}"
    done
}

# Write JSON results for one pipeline depth
write_results_json() {
    local pipeline=$1

    append_result
    cat >> "$RESULTS_FILE" <<JEOF
{
  "test": "cache_resp_vs_redis",
  "pipeline": $pipeline,
  "clients": $CLIENTS,
  "pairs_requested": $PAIRS,
  "pairs_kept": $PC_KEPT,
  "pairs_dropped_box_load": $PC_DROPPED,
  "pairs_dropped_empty_leg": $PC_BADRUN,
  "resolution_target_pct": $TARGET_PCT,
  "client_cores_socketley": $PC_SCLIENT,
  "client_cores_redis": $PC_RCLIENT,
  "timestamp": "$(date -Iseconds)",
  "redis_version": "$(redis-cli -p $REDIS_PORT info server 2>/dev/null | grep -oP 'redis_version:\K\S+')",
  "redis_uptime_s": $(redis-cli -p $REDIS_PORT info server 2>/dev/null | grep -oP 'uptime_in_seconds:\K\d+' || echo 0),
  "redis_appendonly": "$(redis-cli -p $REDIS_PORT config get appendonly 2>/dev/null | tail -1)",
  "redis_io_threads": "$(redis-cli -p $REDIS_PORT config get io-threads 2>/dev/null | tail -1)",
  "operations": {
JEOF

    local first=true t
    for t in $OPS; do
        [[ $first == true ]] && first=false || echo "," >> "$RESULTS_FILE"
        echo -n "    \"$t\": {\"socketley_ops\": ${PC_S[$t]}, \"redis_ops\": ${PC_R[$t]}" \
                ", \"ratio_median_of_pairs\": ${PC_RATIO[$t]}, \"ratio_ci95_half_width_pct\": ${PC_CI[$t]}" \
                ", \"socketley_p50_ms\": ${PC_SP50[$t]}, \"redis_p50_ms\": ${PC_RP50[$t]}}" >> "$RESULTS_FILE"
    done

    echo "" >> "$RESULTS_FILE"
    echo "  }" >> "$RESULTS_FILE"
    echo "}" >> "$RESULTS_FILE"
}

# Compare actual results against README claims
print_readme_comparison() {

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
        printf "%-10s  %14s  %13.1fx  %9s/s  %9s/s\n" \
            "$test" "${readme_ratio[$i]}" "${PC_RATIO[$test]}" \
            "$(fmt_ops "${readme_s[$i]}")" "$(fmt_ops "${PC_S[$test]}")"
    done
}

# ── Main ──────────────────────────────────────────────────────────────

run_cache_resp_benchmarks() {
    log_section "CACHE vs REDIS BENCHMARK (RESP2, redis-benchmark)"
    log_info "Methodology: redis-benchmark, $CLIENTS clients, RESP2 protocol"
    log_info "Pairs per depth: $PAIRS, interleaved; the ratio is the median of the per-pair ratios"

    if ! command -v redis-benchmark &>/dev/null; then
        log_error "redis-benchmark not found — install redis-tools"
        return 1
    fi

    if ! redis-cli -p $REDIS_PORT ping &>/dev/null; then
        log_error "Redis not running on port $REDIS_PORT"
        return 1
    fi

    # Whatever Redis happens to be running is what gets measured — this script
    # does not restart or reconfigure it.  Its version, uptime and the two
    # settings that would make the comparison unfair (AOF fsync, extra IO
    # threads) go into the results so a number can be judged later instead of
    # taken on trust.  Measured here: a freshly restarted Redis came out about
    # 7% slower than one warm from hours of use, so a long uptime does not
    # flatter Socketley.
    log_info "Redis $(redis-cli -p $REDIS_PORT info server 2>/dev/null | grep -oP 'redis_version:\K\S+')," \
             "uptime $(redis-cli -p $REDIS_PORT info server 2>/dev/null | grep -oP 'uptime_in_seconds:\K\d+')s," \
             "appendonly=$(redis-cli -p $REDIS_PORT config get appendonly 2>/dev/null | tail -1)," \
             "io-threads=$(redis-cli -p $REDIS_PORT config get io-threads 2>/dev/null | tail -1)"

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

    log_bench "START" "cache_resp_p1"
    log_info "Measuring both arms in interleaved pairs (P=1)..."
    paired_case 1 $P1_REQUESTS
    log_bench "DONE" "cache_resp_p1"

    print_comparison "Results: Pipeline Depth = 1"
    print_latency "Latency (P=1)"
    write_results_json 1

    # Flush between runs
    redis-cli -p $REDIS_PORT FLUSHALL >/dev/null 2>&1
    fresh_daemon

    # ── P=100 ──
    log_section "Pipeline Depth = 100 ($CLIENTS clients, $(( P100_REQUESTS / 1000 ))K ops)"

    log_bench "START" "cache_resp_p100"
    log_info "Measuring both arms in interleaved pairs (P=100)..."
    paired_case 100 $P100_REQUESTS
    log_bench "DONE" "cache_resp_p100"

    print_comparison "Results: Pipeline Depth = 100"
    print_latency "Latency (P=100)"
    write_results_json 100

    # Cleanup
    socketley_cmd stop bench_cache_resp
    sleep 0.5
    socketley_cmd remove bench_cache_resp
    redis-cli -p $REDIS_PORT FLUSHALL >/dev/null 2>&1

    echo "]" >> "$RESULTS_FILE"

    # README comparison
    print_readme_comparison

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
