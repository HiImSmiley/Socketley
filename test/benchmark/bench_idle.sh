#!/bin/bash
# Idle CPU benchmark — measures the CPU the daemon burns while doing nothing.
#
# This is the deciding metric for the io_uring SQPOLL idle timeout
# (event_loop.cpp, params.sq_thread_idle).  The SQPOLL kernel thread busy-polls
# the submission queue for sq_thread_idle milliseconds after the last SQE before
# it goes to sleep.  Any periodic timer with an interval shorter than that window
# re-arms the poller before it can sleep, so it burns a full core at zero load.
#
# Known periodic timers that interact with this:
#   - daemon health check      2 s     daemon_handler.cpp
#   - cache TTL sweep        100 ms    cache_instance.cpp
#   - server/cache idle sweep 30 s     *_instance.cpp  (only if idle_timeout > 0)
#
# The SQPOLL kernel thread is visible in /proc/<pid>/task/ as "iou-sqp-<pid>",
# so summing utime+stime over every thread of the daemon captures both the
# userspace event loop and the kernel poller.
#
# Usage: bench_idle.sh [duration_sec] [runs]

source "$(dirname "$0")/utils.sh"

# Positional args win, then the environment, then the defaults.  run_all.sh
# lowers both via the environment to stay inside BENCH_TIMEOUT_SCRIPT.
DURATION=${1:-${BENCH_IDLE_DURATION:-15}}
RUNS=${2:-${BENCH_IDLE_RUNS:-3}}
CACHE_PORT=19100
RESULTS_FILE="${RESULTS_DIR}/idle_${TIMESTAMP}.json"
HZ=$(getconf CLK_TCK)

# Resolve the daemon PID.  start_daemon() writes it for the dev/non-systemd
# path; fall back to a pattern match for the systemd-managed daemon.
daemon_pid() {
    if [[ -f "$DAEMON_PID_FILE" ]]; then
        local p
        p=$(cat "$DAEMON_PID_FILE" 2>/dev/null)
        if [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null; then
            echo "$p"
            return 0
        fi
    fi
    pgrep -f "${SOCKETLEY_BIN} daemon" | head -1
}

# Sum utime+stime (clock ticks) over every thread of a process.
# /proc/<pid>/stat field 2 is the comm in parens and may itself contain spaces
# or parens, so everything up to the LAST ')' is discarded before splitting.
# After that, utime is field 12 and stime field 13.
total_ticks() {
    local pid=$1 sum=0 t line rest
    for t in /proc/"$pid"/task/*/stat; do
        [[ -r "$t" ]] || continue
        line=$(cat "$t" 2>/dev/null) || continue
        rest=${line##*\) }
        # shellcheck disable=SC2086
        set -- $rest
        sum=$(( sum + ${12:-0} + ${13:-0} ))
    done
    echo "$sum"
}

# Per-thread "tid comm ticks", one line each.
thread_ticks() {
    local pid=$1 t line rest tid comm
    for t in /proc/"$pid"/task/*; do
        [[ -r "$t/stat" ]] || continue
        tid=$(basename "$t")
        comm=$(cat "$t/comm" 2>/dev/null)
        line=$(cat "$t/stat" 2>/dev/null) || continue
        rest=${line##*\) }
        # shellcheck disable=SC2086
        set -- $rest
        echo "$tid ${comm:-?} $(( ${12:-0} + ${13:-0} ))"
    done
}

# Measure one scenario: sample total ticks across DURATION, report CPU percent
# where 100% == one fully saturated core.  Echoes "percent" to stdout and prints
# a per-thread breakdown to stderr.
measure() {
    local pid=$1 dur=$2
    local before after t0 t1
    t0=$(mktemp) ; t1=$(mktemp)

    thread_ticks "$pid" > "$t0"
    before=$(total_ticks "$pid")
    sleep "$dur"
    after=$(total_ticks "$pid")
    thread_ticks "$pid" > "$t1"

    # Per-thread delta — only threads that actually consumed time
    join -j1 -o 0,1.2,1.3,2.3 "$t0" "$t1" 2>/dev/null | \
        awk -v hz="$HZ" -v d="$dur" '{
            delta = $4 - $3
            if (delta > 0) printf "      %-8s %-18s %6.2f%%\n", $1, $2, (delta/hz/d)*100
        }' >&2
    rm -f "$t0" "$t1"

    awk -v a="$before" -v b="$after" -v hz="$HZ" -v d="$dur" \
        'BEGIN { printf "%.2f", ((b-a)/hz/d)*100 }'
}

# Median of the values on stdin (one per line).
median() {
    sort -n | awk '{v[n++]=$1} END {
        if (n == 0) { print "0.00"; exit }
        print (n % 2) ? v[int(n/2)] : sprintf("%.2f", (v[n/2-1]+v[n/2])/2)
    }'
}

# Run one scenario RUNS times and leave the median in SCENARIO_RESULT.
# The median is returned via a global rather than stdout so that all the
# progress output stays visible instead of being swallowed by a pipeline.
# $1 = scenario key, $2 = human label, $3 = setup function (may be empty)
SCENARIO_RESULT=""
run_scenario() {
    local key=$1 label=$2 setup=$3
    local pid samples i val
    SCENARIO_RESULT="n/a"

    log_section "$label"
    restart_daemon >/dev/null 2>&1 || { log_error "daemon restart failed"; return 1; }

    pid=$(daemon_pid)
    if [[ -z "$pid" ]]; then
        log_error "could not resolve daemon PID"
        return 1
    fi

    if [[ -n "$setup" ]]; then
        if ! "$setup"; then
            log_error "$label: setup failed — reporting n/a rather than a number"
            return 1
        fi
    fi

    # Let the daemon settle so setup work isn't counted as idle cost
    sleep 3

    samples=$(mktemp)
    for i in $(seq 1 "$RUNS"); do
        echo "  Run $i/$RUNS (${DURATION}s, PID $pid) — per-Thread:"
        val=$(measure "$pid" "$DURATION")
        echo "    → ${val}% CPU"
        echo "$val" >> "$samples"
    done

    local med
    med=$(median < "$samples")
    rm -f "$samples"

    log_success "$label: ${med}% CPU (median of $RUNS runs)"
    write_json_result "idle_${key}" "$RESULTS_FILE" \
        scenario "$key" \
        label "$label" \
        cpu_percent_median "$med" \
        duration_sec "$DURATION" \
        runs "$RUNS"

    SCENARIO_RESULT="$med"
}

setup_cache() {
    # The port has to be given to create, not to start: passing it to start
    # leaves the runtime listening nowhere, and every later step then quietly
    # measures a daemon with no reachable cache.
    socketley_cmd create cache idle-cache -p "$CACHE_PORT" -s >/dev/null 2>&1
    if ! wait_for_port "$CACHE_PORT" 50; then
        log_error "cache port $CACHE_PORT never opened — scenario is invalid"
        return 1
    fi
}

setup_cache_with_ttl() {
    setup_cache || return 1
    # Seed keys whose TTL outlasts the whole measurement, so the sweep keeps
    # running without any key actually expiring.  This is the scenario that
    # decides whether a cache in real TTL use can ever let the SQPOLL thread
    # sleep, so it must be verified rather than assumed: a silent seeding
    # failure turns it into a copy of the no-keys scenario and looks like a
    # pass.
    {
        for i in $(seq 1 200); do
            printf 'setex ttlkey%d 3600 value%d\n' "$i" "$i"
        done
    } | bench_nc "$CACHE_PORT" >/dev/null 2>&1

    local keys
    keys=$(socketley_cmd stats idle-cache 2>/dev/null | grep -oP '^keys:\K[0-9]+' | head -1)
    if [[ "${keys:-0}" -lt 200 ]]; then
        log_error "TTL seeding failed: stats reports ${keys:-0} keys, expected 200"
        return 1
    fi
    log_success "seeded ${keys} keys with a TTL"
}

main() {
    check_binary || exit 1
    setup_cleanup_trap

    log_section "Idle CPU Benchmark"
    echo "Duration:  ${DURATION}s per run"
    echo "Runs:      $RUNS (median reported)"
    echo "CLK_TCK:   $HZ"
    echo "Binary:    $SOCKETLEY_BIN"
    echo ""
    echo "100% == one fully saturated core. Includes the iou-sqp-* SQPOLL"
    echo "kernel thread, which is where idle burn shows up."

    : > "$RESULTS_FILE"

    local d_only d_cache d_ttl
    run_scenario "daemon_only"    "Daemon only (no runtimes)"             ""
    d_only=$SCENARIO_RESULT
    run_scenario "cache_idle"     "Daemon + cache runtime (no keys)"      setup_cache
    d_cache=$SCENARIO_RESULT
    run_scenario "cache_ttl_keys" "Daemon + cache runtime (200 TTL keys)" setup_cache_with_ttl
    d_ttl=$SCENARIO_RESULT

    cleanup_runtimes >/dev/null 2>&1

    log_section "Summary"
    printf "  %-42s %10s\n" "Scenario" "CPU"
    printf "  %-42s %10s\n" "──────────────────────────────────────────" "──────────"
    printf "  %-42s %9s%%\n" "Daemon only (no runtimes)"        "$d_only"
    printf "  %-42s %9s%%\n" "Daemon + cache runtime (no keys)" "$d_cache"
    printf "  %-42s %9s%%\n" "Daemon + cache (200 TTL keys)"    "$d_ttl"
    echo ""
    echo "  Results: $RESULTS_FILE"
    echo ""
    echo "  Anything above a few percent here is wasted power: the daemon is"
    echo "  serving zero traffic. Compare against sq_thread_idle in event_loop.cpp"
    echo "  and the 100 ms cache TTL sweep in cache_instance.cpp."
}

main "$@"
