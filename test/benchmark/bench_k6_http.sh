#!/bin/bash
# k6 HTTP Static Serving Benchmark
# Tests: throughput, latency percentiles, spike handling (with and without --http-cache)

source "$(dirname "$0")/utils.sh"

HTTP_PORT=19020
# Above this share of failed requests the latency rows are refused rather than
# printed; k6's own threshold in http_bench.js is the same 1%.
K6_MAX_FAILED_PCT=${K6_MAX_FAILED_PCT:-1.0}
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

# ─── Parse the k6 summary export ────────────────────────────────────────────
#
# This used to pull one p50 and one p99 out of http_req_duration and record them
# as the latency of the run:
#
#     k6_http_disk    p50 5.06 ms   p99 57.96 ms
#     k6_http_cached  p50 2.85 ms   p99 53.27 ms
#
# Both p99s sit +51 ms above their own median, identically, which reads as a
# tail defect that --http-cache does nothing about.  It is a percentile taken
# across a load profile that deliberately doubles to 200 VUs against a
# single-threaded server, with a 100 KB file in the mix.  The slowest 1% of the
# run is the spike, always, by construction -- so the number cannot move when
# the server gets faster and does move when the stage table is edited.
#
# k6/http_bench.js now keeps a Trend per stage.  Measured on the disk arm right
# after the change, one run:
#
#     whole run   p50 6.14 ms   p95 20.72 ms   p99  52.39 ms   433,175 reqs
#     ramp        p50 2.74      p95 10.82      p99  17.70       47,967
#     steady      p50 6.26      p95 16.68      p99  25.96      161,982
#     spike_ramp  p50 8.04      p95 23.80      p99  55.08       54,545
#     spike       p50 7.86      p95 31.81      p99 104.07      114,162
#     cooldown    p50 4.61      p95 18.24      p99  37.00       54,519
#
# The aggregate p99 of 52 ms is a blend of a 26 ms steady tail and a 104 ms
# spike tail and describes neither.  Quote `steady` for latency and `spike` for
# behaviour under a doubling; the aggregate is still recorded, under a label
# that says what it is, so older comparisons keep working.
#
# Each stage is written as its own row so that a comparison between two runs
# lines the stages up rather than the mixtures.

# Emit one summary row per stage, plus the whole-run row.
parse_k6_summary() {
    local json_file=$1
    local test_name=$2
    local mode=$3  # "disk" or "cached"
    local server_cores=$4

    local parsed
    parsed=$(python3 - "$json_file" <<'K6PARSE' 2>/dev/null
import json, sys
d = json.load(open(sys.argv[1]))
m = d.get('metrics', {})

def g(metric, key, default=0):
    v = m.get(metric, {})
    if 'values' in v:
        v = v['values']
    return v.get(key, default)

print('%d' % int(g('http_reqs', 'count')))
print('%.2f' % g('http_reqs', 'rate'))
print('%.3f' % g('http_req_duration', 'avg'))
print('%.3f' % g('http_req_duration', 'med', g('http_req_duration', 'p(50)')))
print('%.3f' % g('http_req_duration', 'p(95)'))
print('%.3f' % g('http_req_duration', 'p(99)'))
print('%.4f' % (g('http_req_failed', 'value', g('http_req_failed', 'rate', 0)) * 100))

# Discovered from the file rather than listed here, so a stage added to
# http_bench.js shows up without this being edited -- the same reason
# generate_summary() builds its tables from the data it was given.
order = ['ramp', 'steady', 'spike_ramp', 'spike', 'cooldown']
found = sorted(
    (k[len('stage_'):-len('_duration')] for k in m
     if k.startswith('stage_') and k.endswith('_duration')),
    key=lambda n: order.index(n) if n in order else 99)
for name in found:
    t = 'stage_%s_duration' % name
    print('STAGE %s %d %.3f %.3f %.3f %.3f %.3f' % (
        name, int(g(t, 'count')), g(t, 'avg'),
        g(t, 'med', g(t, 'p(50)')), g(t, 'p(95)'), g(t, 'p(99)'), g(t, 'max')))
K6PARSE
)

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

    # ─── The oracle these rows needed and did not have ──────────────────────
    #
    # A run where the server is not there produces percentiles, and they are
    # zero.  Observed on 2026-08-18: the daemon under this test went away
    # mid-run, k6 got "connection refused" 1,556,778 times out of 1,587,812,
    # and every per-stage row came out
    #
    #     steady   p50 0.0  p95 0.0  p99 0.0   n=633708
    #
    # -- six figures of sample count next to three zeros, which reads as a
    # server so fast it answers instantly.  The failure rate was printed four
    # lines away and nothing tied the two together.
    #
    # A latency figure over refused connections is not a slow measurement, it is
    # a measurement of something else, so above K6_MAX_FAILED_PCT the rows are
    # refused rather than printed and go into the file with usable:0.  The
    # threshold is k6's own: http_bench.js declares 'http_req_failed rate<0.01'.
    local usable=1 fail_note=""
    if awk -v f="$failed_pct" -v lim="$K6_MAX_FAILED_PCT" 'BEGIN{exit !(f > lim)}'; then
        usable=0
        fail_note="${failed_pct}% of requests failed — these are not latencies of a served request"
        log_error "  Failed: ${failed_pct}%"
        log_error "  REFUSED — $fail_note"
    else
        log_success "  Failed: ${failed_pct}%"
    fi

    log_success "  Whole run (mixes every stage — not a tail metric):"
    log_success "    avg ${avg}ms  p50 ${p50}ms  p95 ${p95}ms  p99 ${p99}ms"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "mode"            "$mode" \
        "stage"           "whole_run" \
        "measures"        "all stages mixed; quote the per-stage rows instead" \
        "requests_total"  "$reqs_total" \
        "requests_per_sec" "$reqs_rate" \
        "latency_avg_ms"  "$avg" \
        "latency_p50_ms"  "$p50" \
        "latency_p95_ms"  "$p95" \
        "latency_p99_ms"  "$p99" \
        "failed_percent"  "$failed_pct" \
        "usable"          "$usable" \
        "verdict"         "${fail_note:-ok}"

    # No per-stage rows means the script under k6 is an older copy that does not
    # record them.  Said rather than passed over: the aggregate above would then
    # be the only thing in the file, which is exactly the state this change
    # exists to leave behind.
    if ! echo "$parsed" | grep -q '^STAGE '; then
        log_error "  no per-stage metrics in the export — k6/http_bench.js is"
        log_error "  not the version that records them, and the run above is"
        log_error "  one percentile over a saturated phase and an unsaturated one"
        return 0
    fi

    log_success "  Per stage:"
    local name count s_avg s_p50 s_p95 s_p99 s_max label
    while read -r _ name count s_avg s_p50 s_p95 s_p99 s_max; do
        case "$name" in
            steady) label="steady state, 100 VUs" ;;
            spike)  label="under the spike, 200 VUs" ;;
            *)      label="transitional" ;;
        esac
        if [[ $usable -eq 1 ]]; then
            log_success "    $(printf '%-11s' "$name") p50 ${s_p50}ms  p95 ${s_p95}ms  p99 ${s_p99}ms  max ${s_max}ms  (${count} reqs, $label)"
        else
            log_error   "    $(printf '%-11s' "$name") REFUSED (would have read p50 ${s_p50}ms p99 ${s_p99}ms over ${count} mostly-failed requests)"
        fi
        append_result
        write_json_result "$test_name" "$RESULTS_FILE" \
            "mode"           "$mode" \
            "stage"          "$name" \
            "measures"       "$label" \
            "requests_total" "$count" \
            "latency_avg_ms" "$s_avg" \
            "latency_p50_ms" "$s_p50" \
            "latency_p95_ms" "$s_p95" \
            "latency_p99_ms" "$s_p99" \
            "latency_max_ms" "$s_max" \
            "failed_percent" "$failed_pct" \
            "server_cores"   "$server_cores" \
            "usable"         "$usable" \
            "verdict"        "${fail_note:-ok}"
    done < <(echo "$parsed" | grep '^STAGE ')
}

# Test: HTTP static serving, one arm.
#
# The two arms used to be two functions differing in a flag, a name and a path.
# They are one because the thing worth reading is the difference between them,
# and two copies of a measurement drift apart in exactly the part that makes
# them comparable.
#
# The server's own CPU is sampled across the k6 run.  Without it the summary
# puts 13,478 req/s (disk) next to 13,148 (--http-cache) and invites reading
# the cache as 2.4% slower; both arms leave the server around a tenth of a
# core, so both numbers are k6's ceiling and neither is the server's.  What the
# flag actually removes is one statx(2) per request -- counted, 1.000 against
# 0.000 -- and that is not visible at a rate the client sets.
test_http_arm() {
    local mode=$1 flag=$2
    local test_name="k6_http_${mode}"

    log_section "Test: k6 HTTP Static Serving (${mode})"

    socketley_cmd stop bench_k6_http >/dev/null 2>&1; sleep 0.5; socketley_cmd remove bench_k6_http >/dev/null 2>&1
    wait_for_port_free $HTTP_PORT
    socketley_cmd create server bench_k6_http -p $HTTP_PORT --http "$HTTP_ROOT" $flag -s
    wait_for_port $HTTP_PORT || { log_error "Server failed to start"; return 1; }
    sleep 0.5

    local k6_export="/tmp/k6_http_${mode}_${TIMESTAMP}.json"
    local c0 c1 t0 t1 server_cores
    c0=$(socketley_cpu_ticks); t0=$(date +%s%N)
    timeout "$BENCH_TIMEOUT_K6" k6 run \
        --summary-export "$k6_export" \
        --env BASE_URL="http://localhost:${HTTP_PORT}" \
        --quiet \
        "${K6_DIR}/http_bench.js" 2>&1
    if [[ $? -eq 124 ]]; then
        log_bench "TIMEOUT" "k6 http ${mode}"
    fi
    t1=$(date +%s%N); c1=$(socketley_cpu_ticks)
    server_cores=$(socketley_cores_since "$c0" "$c1" "$t0" "$t1")

    if awk -v c="$server_cores" 'BEGIN { exit !(c < 0.5) }'; then
        log_warn "  server used ${server_cores} cores — this rate is k6's ceiling, not the server's;" \
                 "read the per-stage latencies here and the wrk rows for throughput"
    else
        log_info "  server used ${server_cores} cores"
    fi

    if [[ -f "$k6_export" ]]; then
        parse_k6_summary "$k6_export" "$test_name" "$mode" "$server_cores"
        rm -f "$k6_export"
    else
        log_error "k6 summary export not found"
    fi

    socketley_cmd stop bench_k6_http
    sleep 0.5
    socketley_cmd remove bench_k6_http
}

# Throughput of the same files from a client that can saturate the server.
#
# k6 left the server at 0.27-0.30 cores on 2026-09-26, so its 13 k req/s was
# k6's ceiling and said nothing about static serving; it stays as the latency
# profile under its load shape, and this is the rate.  The server's cores are
# printed beside it, and a row under 0.9 says wrk was the limit instead.
WRK_THREADS=${WRK_THREADS:-4}
WRK_CONNS=${WRK_CONNS:-64}
WRK_SECS=${WRK_SECS:-5}
# Three runs and the median: one run read 153 k req/s where five interleaved
# passes of the same binary read 246 k, with a pass near 200 k in either arm.
WRK_RUNS=${WRK_RUNS:-3}

test_http_wrk_arm() {   # mode flag
    local mode=$1 flag=$2 path out rps p50 p99 c0 c1 t0 t1 cores

    log_section "Test: wrk HTTP Static Serving (${mode}, ${WRK_THREADS} threads x ${WRK_CONNS} connections, ${WRK_SECS}s)"

    socketley_cmd stop bench_wrk_http >/dev/null 2>&1; sleep 0.5; socketley_cmd remove bench_wrk_http >/dev/null 2>&1
    wait_for_port_free $HTTP_PORT
    socketley_cmd create server bench_wrk_http -p $HTTP_PORT --http "$HTTP_ROOT" $flag -s
    wait_for_port $HTTP_PORT || { log_error "Server failed to start"; return 1; }
    sleep 0.5

    for path in index.html large.bin; do
        local runs="" best="" r lo hi
        for ((r = 0; r < WRK_RUNS; r++)); do
            c0=$(socketley_cpu_ticks); t0=$(date +%s%N)
            out=$(timeout 60 wrk -t"$WRK_THREADS" -c"$WRK_CONNS" -d"${WRK_SECS}s" --latency \
                  "http://127.0.0.1:${HTTP_PORT}/${path}" 2>&1)
            t1=$(date +%s%N); c1=$(socketley_cpu_ticks)
            if grep -qE 'Non-2xx|Socket errors' <<<"$out"; then
                log_error "  /${path}: $(grep -E 'Non-2xx|Socket errors' <<<"$out" | tr -s ' ')"
            fi
            # Each run's rate, cores, p50 and p99 on one line, so the median
            # run's latencies are reported with its own rate.
            runs+="$(awk '/^Requests\/sec:/ { r = $2 } $1 == "50%" { a = $2 } $1 == "99%" { b = $2 }
                           END { printf "%s %s %s", r + 0, a, b }' <<<"$out") $(socketley_cores_since "$c0" "$c1" "$t0" "$t1")"$'\n'
        done
        best=$(sort -n <<<"${runs%$'\n'}" | awk '{ l[NR] = $0 } END { print l[int((NR + 1) / 2)] }')
        read -r rps p50 p99 cores <<<"$best"
        lo=$(sort -n <<<"${runs%$'\n'}" | head -1 | cut -d' ' -f1)
        hi=$(sort -n <<<"${runs%$'\n'}" | tail -1 | cut -d' ' -f1)
        log_info "  /${path}: ${WRK_RUNS} runs ${lo} .. ${hi} req/s, the median one below"
        if awk -v c="$cores" 'BEGIN { exit !(c < 0.9) }'; then
            log_warn "  /${path}: ${rps} req/s  p50 ${p50}  p99 ${p99}  server ${cores} cores — wrk was the limit"
        else
            log_success "  /${path}: ${rps} req/s  p50 ${p50}  p99 ${p99}  server ${cores} cores"
        fi
        append_result
        write_json_result "wrk_http_${mode}_${path%%.*}" "$RESULTS_FILE" \
            "requests_per_sec" "${rps:-0}" "p50" "${p50}" "p99" "${p99}" \
            "server_cores" "${cores:-0}" "connections" "$WRK_CONNS"
    done

    socketley_cmd stop bench_wrk_http
    sleep 0.5
    socketley_cmd remove bench_wrk_http
}

# Main
run_k6_http_benchmarks() {
    log_section "k6 HTTP STATIC SERVING BENCHMARKS"

    check_k6 || return 1
    generate_large_bin
    prepare_http_root

    log_bench "START" "k6_http_disk"
    test_http_arm disk ""
    log_bench "DONE" "k6_http_disk"
    fresh_daemon

    sleep 1

    log_bench "START" "k6_http_cached"
    test_http_arm cached "--http-cache"
    log_bench "DONE" "k6_http_cached"
    fresh_daemon

    if command -v wrk >/dev/null 2>&1; then
        log_bench "START" "wrk_http_disk"
        test_http_wrk_arm disk ""
        log_bench "DONE" "wrk_http_disk"
        fresh_daemon
        log_bench "START" "wrk_http_cached"
        test_http_wrk_arm cached "--http-cache"
        log_bench "DONE" "wrk_http_cached"
    else
        log_warn "wrk not installed: no HTTP throughput row, only k6's latency profile"
    fi

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
