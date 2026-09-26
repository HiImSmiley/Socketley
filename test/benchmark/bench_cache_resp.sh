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
# Client processes per arm, each with CLIENTS connections -- the README's four.
# One redis-benchmark pegs at 1.0 core near 200k ops/s here, so a single one
# measured itself at depth 1: every row of 2026-09-26 read "client-bound (0.98
# cores)", and at depth 100 the cache read 5.6 M SET/s where four clients read
# 11.6 M.
CLIENT_PROCS=${BENCH_RESP_CLIENT_PROCS:-4}
# Positional argument wins, then the environment, then the default.
PAIRS=${1:-${BENCH_RESP_PAIRS:-7}}

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

# Seconds per arm and not the README's 200K and 2M, which ran 0.7 s and 0.4 s
# here: a leg that short carries its start-up in the rate and gave CIs of 10
# to 56 per cent over three pairs.
P1_REQUESTS=1000000
P100_REQUESTS=10000000

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
run_leg() {   # port pipeline requests outfile -> echoes the busiest client's cores, or TIMEOUT
    local port=$1 pipeline=$2 requests=$3 out=$4
    local per=$((requests / CLIENT_PROCS)) t0 t1 i rc=0 spid s0 s1 t
    local -a pids=() kids=() ticks=()

    spid=$(ss -ltnpH "sport = :$port" 2>/dev/null | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
    # ss names only this user's processes, and redis-server runs as redis.
    [[ -z $spid && $port == "$REDIS_PORT" ]] && spid=$(pgrep -x redis-server | head -1)
    s0=$(cpu_ticks_of "${spid:-0}")
    t0=$(date +%s%N)
    for ((i = 0; i < CLIENT_PROCS; i++)); do
        timeout "$BENCH_TIMEOUT_REDIS" redis-benchmark -p "$port" -c $CLIENTS -n "$per" \
            -P "$pipeline" -t "$TESTS" -r 100000 -q --precision 3 >"$out.raw.$i" 2>/dev/null &
        pids+=($!); ticks+=(0)
    done

    # timeout(1) forks the process it is timing, so its own /proc entry shows
    # almost no CPU; each child is found once and not per tick, because pgrep
    # walks all of /proc and that is load the run under measurement pays for.
    for ((i = 0; i < CLIENT_PROCS; i++)); do
        kids[$i]=""
        for _ in 1 2 3 4 5; do
            kids[$i]=$(pgrep -P "${pids[$i]}" 2>/dev/null | head -1)
            [[ -n ${kids[$i]} ]] && break
            sleep 0.05
        done
    done
    local alive=1
    while (( alive )); do
        alive=0
        for ((i = 0; i < CLIENT_PROCS; i++)); do
            kill -0 "${pids[$i]}" 2>/dev/null || continue
            alive=1
            t=$(cpu_ticks_of "${kids[$i]:-${pids[$i]}}")
            # The last sample before exit is the one that counts.
            [[ ${t:-0} -gt 0 ]] && ticks[$i]=$t
        done
        (( alive )) && sleep 0.1
    done
    for ((i = 0; i < CLIENT_PROCS; i++)); do
        wait "${pids[$i]}" || rc=$?
    done
    t1=$(date +%s%N)
    s1=$(cpu_ticks_of "${spid:-0}")

    if (( rc == 124 )); then
        # A timeout must not become a NUMBER: on 2026-08-25 one did, and the
        # summary reported socketley_ops:0 against redis at 2.1M for all six.
        log_bench "TIMEOUT" "redis-benchmark port $port P=$pipeline"
        echo "TIMEOUT"; return 1
    fi

    # One file in the shape get_ops and get_p50 read: each operation's rate is
    # the sum over the processes, which ran together, and its p50 their median.
    : > "$out"
    for t in $OPS; do
        local rates="" p50s="" f
        for ((i = 0; i < CLIENT_PROCS; i++)); do
            f="$out.raw.$i"
            rates+=" $(get_ops "$f" "$t" | tail -1)"
            p50s+=" $(get_p50 "$f" "$t" | tail -1)"
        done
        awk -v t="$t" -v r="$rates" -v p="$p50s" 'BEGIN {
            n = split(r, a, " "); s = 0; for (i = 1; i <= n; i++) s += a[i]
            m = split(p, b, " "); for (i = 1; i <= m; i++) for (j = i + 1; j <= m; j++) if (b[j] < b[i]) { x = b[i]; b[i] = b[j]; b[j] = x }
            printf "%s: %.2f requests per second, p50=%.3f msec\n", t, s, (m ? b[int((m + 1) / 2)] : 0)
        }' >> "$out"
    done

    # The server's cores beside it, in a file because this runs in a subshell.
    awk -v d=$((s1 - s0)) -v hz="$HZ" -v ns=$((t1 - t0)) \
        'BEGIN { printf "%.3f\n", (ns > 0 ? d / hz / (ns / 1e9) : 0) }' > "$out.srv"

    # The busiest client, since one pegged process caps the arm whatever the
    # others do; the parentheses keep awk from reading `a > b` as a redirection.
    printf '%s\n' "${ticks[@]}" | awk -v hz="$HZ" -v ns=$((t1 - t0)) \
        '{ if ($1 > m) m = $1 } END { printf "%.2f", (ns > 0 ? m / hz / (ns / 1e9) : 0) }'
}

# One pipeline depth, as interleaved pairs.  Fills PC_* for every operation,
# every time, so a caller cannot read a stale value from the depth before.
declare -A PC_S PC_R PC_RATIO PC_CI PC_SP50 PC_RP50
PC_KEPT=0; PC_DROPPED=0; PC_BADRUN=0; PC_SCLIENT=0; PC_RCLIENT=0; PC_SSERVER=0; PC_RSERVER=0

paired_case() {   # pipeline requests
    local pipeline=$1 requests=$2
    local -A sv rv rt sp rp
    local kept=0 dropped=0 badrun=0 attempt=0
    local max_attempts=$((PAIRS * 2 + 2))
    local sc_all="" rc_all="" ss_all="" rs_all="" t a b

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
        ss_all+=" $(cat "$sf.srv" 2>/dev/null)"; rs_all+=" $(cat "$rf.srv" 2>/dev/null)"
        kept=$((kept + 1))
    done

    PC_KEPT=$kept; PC_DROPPED=$dropped; PC_BADRUN=$badrun
    PC_SCLIENT=0; PC_RCLIENT=0
    for t in $OPS; do PC_S[$t]=0; PC_R[$t]=0; PC_RATIO[$t]=0; PC_CI[$t]=0; PC_SP50[$t]=0; PC_RP50[$t]=0; done
    (( kept == 0 )) && return 0

    PC_SCLIENT=$(median_of "$sc_all"); PC_RCLIENT=$(median_of "$rc_all")
    PC_SSERVER=$(median_of "$ss_all"); PC_RSERVER=$(median_of "$rs_all")
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
    log_info "busiest client process: ${PC_SCLIENT} cores against socketley, ${PC_RCLIENT} against redis" \
             "($CLIENT_PROCS processes per arm; one caps at 1.0)"
    log_info "server cores: socketley ${PC_SSERVER}, redis ${PC_RSERVER}" \
             "-- at 1.0 the row is each server's cost per operation"
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
  "server_cores_socketley": $PC_SSERVER,
  "server_cores_redis": $PC_RSERVER,
  "client_processes": $CLIENT_PROCS,
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

# This run against the README's own table for the same depth, read from the
# README itself: the table this replaced was typed in once and still claimed
# 2.8x and 8.93 M SET/s long after the README said 3.45x and 10.31 M.
# The README's -r 100000 table, which is the keyspace this script measures;
# its two single-key tables keep one entry in L1 and are another question.
# Columns: | op | depth 1 | ratio | depth 100 | Redis | ratio | spread |
readme_row() {   # depth op -> "rate ratio" from README.md, or nothing
    local depth=$1 op=$2
    awk -v depth="$depth" -v op="$op" '
        index($0, "**With a real keyspace.**") == 1 { inside = 1; next }
        inside && /^\*\*|^### / { inside = 0 }
        inside && $0 ~ "^\\| *"op" *\\|" {
            split($0, c, "|")
            cell  = (depth == 1) ? c[3] : c[5]
            ratio = (depth == 1) ? c[4] : c[7]
            rate = 0; mul = 1
            if (match(cell, /[0-9.]+ *[KM]?/)) {
                tok = substr(cell, RSTART, RLENGTH)
                mul = (tok ~ /M/) ? 1e6 : ((tok ~ /K/) ? 1e3 : 1)
                gsub(/[ KM]/, "", tok); rate = tok
            }
            gsub(/[^0-9.]/, "", ratio)
            printf "%.0f %s\n", rate * mul, ratio; exit
        }' "$(dirname "$0")/../../README.md" 2>/dev/null
}

print_readme_comparison() {   # depth
    local depth=$1 t row

    echo ""
    log_section "This run against the README (P=$depth)"
    printf "%-10s  %12s  %12s  %12s  %12s\n" \
        "Operation" "README SKT" "This run" "README ratio" "This ratio"
    printf "%-10s  %12s  %12s  %12s  %12s\n" \
        "─────────" "────────────" "────────────" "────────────" "────────────"
    for t in $OPS; do
        row=$(readme_row "$depth" "$t")
        [[ -z $row ]] && { printf "%-10s  %12s\n" "$t" "not in README"; continue; }
        read -r rs rr <<<"$row"
        printf "%-10s  %10s/s  %10s/s  %11sx  %11.2fx\n" \
            "$t" "$(fmt_ops "$rs")" "$(fmt_ops "${PC_S[$t]}")" "$rr" "${PC_RATIO[$t]}"
    done
    log_info "the README's absolute rates are another day's clock; compare the ratios"
}

# ── Main ──────────────────────────────────────────────────────────────

run_cache_resp_benchmarks() {
    log_section "CACHE vs REDIS BENCHMARK (RESP2, redis-benchmark)"
    log_info "Methodology: $CLIENT_PROCS redis-benchmark processes x $CLIENTS clients per arm, RESP2 protocol"
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
    socketley_cmd stop bench_cache_resp >/dev/null 2>&1
    sleep 0.5
    socketley_cmd remove bench_cache_resp >/dev/null 2>&1
    wait_for_port_free $CACHE_PORT
    socketley_cmd create cache bench_cache_resp -p $CACHE_PORT --resp -s
    wait_for_port $CACHE_PORT || { log_error "Cache (RESP) failed to start"; socketley_cmd stop bench_cache_resp >/dev/null 2>&1; sleep 0.5; socketley_cmd remove bench_cache_resp >/dev/null 2>&1; return 1; }
    sleep 0.5

    # ── P=1 ──
    log_section "Pipeline Depth = 1 ($CLIENT_PROCS x $CLIENTS clients, $(( P1_REQUESTS / 1000 ))K ops)"

    log_bench "START" "cache_resp_p1"
    log_info "Measuring both arms in interleaved pairs (P=1)..."
    paired_case 1 $P1_REQUESTS
    log_bench "DONE" "cache_resp_p1"

    print_comparison "Results: Pipeline Depth = 1"
    print_latency "Latency (P=1)"
    write_results_json 1
    print_readme_comparison 1

    # Flush between runs
    redis-cli -p $REDIS_PORT FLUSHALL >/dev/null 2>&1
    fresh_daemon

    # ── P=100 ──
    log_section "Pipeline Depth = 100 ($CLIENT_PROCS x $CLIENTS clients, $(( P100_REQUESTS / 1000 ))K ops)"

    log_bench "START" "cache_resp_p100"
    log_info "Measuring both arms in interleaved pairs (P=100)..."
    paired_case 100 $P100_REQUESTS
    log_bench "DONE" "cache_resp_p100"

    print_comparison "Results: Pipeline Depth = 100"
    print_latency "Latency (P=100)"
    write_results_json 100
    print_readme_comparison 100

    # Cleanup
    socketley_cmd stop bench_cache_resp
    sleep 0.5
    socketley_cmd remove bench_cache_resp
    redis-cli -p $REDIS_PORT FLUSHALL >/dev/null 2>&1

    echo "]" >> "$RESULTS_FILE"

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
