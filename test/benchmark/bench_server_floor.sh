#!/bin/bash
# Server runtime against its floor.
#
# The floor is test/benchmark/floor_server.c: accept, read, write, nothing else.
# It is not a competitor and the ratio here is not a defect -- it is the part of
# every server number that belongs to the kernel and the scheduler rather than
# to socketley, and its purpose is to say how much of the measured cost is
# actually available to be optimised away.  If the two numbers are close, that
# is the most useful thing this script can report: it means the server path has
# no headroom and work spent there will not pay.
#
# Both sides are driven by socketley_bench, on the same test, at the same sizes
# and the same concurrency, reporting the same metric.  That is the only reason
# the comparison means anything: measured by different client code, the gap
# between the two numbers would also contain the gap between two clients, and
# nothing here could separate them.
#
# Pairing, and why it is not one floor mode for both:
#
#   server msg (1 connection)  ->  floor -m block
#       No readiness syscall at all.  With one connection there is nothing to
#       multiplex, so epoll_wait would be overhead the floor never has to pay,
#       and including it would flatter socketley.
#
#   server concurrent (N)      ->  floor -m epoll
#       One thread, many connections, because socketley's worker is a
#       single-threaded event loop.  A floor spread over ten cores would be a
#       different architecture and the ratio would measure core count.
#
# See the header of floor_server.c for the longer form of both.

source "$(dirname "$0")/utils.sh"

FLOOR_BIN="${PROJECT_ROOT}/bin/Release/floor_server"
# 19030/19031: unclaimed.  The rest of test/benchmark already holds 19000,
# 19001, 19010 (websocket), 19020, 19021, 19080-19082 and 19100, and reusing one
# of those would put this script's bind right behind another script's TIME_WAIT.
FLOOR_PORT=${FLOOR_PORT:-19030}
SRV_PORT=${SRV_PORT:-19031}
RESULTS_FILE="${RESULTS_DIR}/server_floor_${TIMESTAMP}.json"
REPORT_FILE="${RESULTS_DIR}/server_floor_${TIMESTAMP}.md"

FLOOR_PID=""
FIRST_RESULT=true
ROWS=()

floor_stop() {
    if [[ -n "$FLOOR_PID" ]] && kill -0 "$FLOOR_PID" 2>/dev/null; then
        kill "$FLOOR_PID" 2>/dev/null
        wait "$FLOOR_PID" 2>/dev/null
    fi
    FLOOR_PID=""
}

floor_start() {
    local mode=$1
    floor_stop
    wait_for_port_free $FLOOR_PORT
    "$FLOOR_BIN" $FLOOR_PORT -m "$mode" &
    FLOOR_PID=$!
    wait_for_port $FLOOR_PORT || { log_error "floor_server ($mode) failed to start"; return 1; }
    return 0
}

srv_stop() {
    socketley_cmd stop floor_srv >/dev/null 2>&1
    sleep 0.3
    socketley_cmd remove floor_srv >/dev/null 2>&1
}

srv_start() {
    srv_stop
    wait_for_port_free $SRV_PORT
    # echo.lua for the same reason every round-trip benchmark needs it: no
    # --mode of a plain server runtime answers on its own, so a client that
    # reads nothing back would be timing its own writes.
    socketley_cmd create server floor_srv -p $SRV_PORT --mode in --lua "$BENCH_ECHO_LUA" -s
    wait_for_port $SRV_PORT || { log_error "socketley server failed to start"; return 1; }
    return 0
}

# Takes the record as an argument rather than on stdin, and that is the point.
# As the last stage of a pipeline this would run in a subshell, so
# FIRST_RESULT=false would be discarded the moment it returned and every record
# would believe it was the first: no separators were written at all and the
# file was invalid JSON that nothing read until jq was pointed at it.
add_record() {
    if [[ $FIRST_RESULT == true ]]; then
        FIRST_RESULT=false
    else
        printf ',\n' >> "$RESULTS_FILE"
    fi
    printf '%s\n' "$1" >> "$RESULTS_FILE"
}

# Add side/mode/pair to a raw -j record so the two halves of a comparison can be
# told apart in the results file.
tag_record() {
    python3 -c "
import sys, json
d = json.load(sys.stdin)
d['side'] = sys.argv[1]; d['floor_mode'] = sys.argv[2]; d['pair'] = sys.argv[3]
print(json.dumps(d))
" "$1" "$2" "$3"
}

metrics_of() {
    python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
print('%.0f %.1f %.1f %.2f' % (
    d.get('median_round_trips_per_sec', 0),
    d.get('rtt_p50_us', 0),
    d.get('rtt_p99_us', 0),
    d.get('spread_ratio', 0)))
"
}

run_pair() {
    local label=$1 floor_mode=$2 test=$3 p1=$4 p2=$5
    local fjson sjson f s

    log_section "$label  (socketley vs floor -m $floor_mode)"

    floor_start "$floor_mode" || return 1
    fjson=$("$SOCKETLEY_BENCH" -j server $test 127.0.0.1 $FLOOR_PORT $p1 $p2 2>/dev/null)
    floor_stop
    f=$(printf '%s' "$fjson" | metrics_of) || { log_error "floor produced no result for $label"; return 1; }

    srv_start || return 1
    sjson=$("$SOCKETLEY_BENCH" -j server $test 127.0.0.1 $SRV_PORT $p1 $p2 2>/dev/null)
    srv_stop
    s=$(printf '%s' "$sjson" | metrics_of) || { log_error "socketley produced no result for $label"; return 1; }

    add_record "$(printf '%s' "$fjson" | tag_record floor     "$floor_mode" "$label")"
    add_record "$(printf '%s' "$sjson" | tag_record socketley "$floor_mode" "$label")"

    ROWS+=("${label}|${floor_mode}|${f}|${s}")
    log_info "floor=$(awk '{print $1}' <<< "$f")/s   socketley=$(awk '{print $1}' <<< "$s")/s"
}

# The floor, measured against itself in the two CPU placements.
#
# The ratio in the table is routinely read as "what socketley costs", and on its
# own it is not that.  Both sides pay for waking a process, and on this machine
# that one term is larger than everything socketley does: the same floor binary,
# driven by the same client, runs at roughly 80k/s with both ends on one core
# and 27k/s across two.  A constant shared by numerator and denominator drags
# any ratio towards 1.00x, so a cross-core run flatters socketley and a
# co-located run makes it look worse -- while the difference in microseconds per
# round trip, which is what socketley actually adds, barely moves between them.
#
# Measuring it beats writing it down.  A reader who sees the floor itself move
# threefold cannot mistake the ratio for a property of the code, and this also
# says which placement today's run happened to get, which nothing else records.
PLACE_SAME=""
PLACE_DIFF=""
PLACE_CPUS=""
placement_probe() {
    command -v taskset >/dev/null 2>&1 || {
        log_info "taskset not available -- placement probe skipped"; return 0; }
    local ncpu; ncpu=$(nproc 2>/dev/null || echo 1)
    [[ $ncpu -ge 4 ]] || {
        log_info "fewer than 4 cpus -- placement probe skipped"; return 0; }

    local a=2 b=3
    PLACE_CPUS="$a/$b"
    log_section "placement probe  (floor against itself, 20k x 64B)"

    local arm
    for arm in same split; do
        floor_stop
        wait_for_port_free $FLOOR_PORT
        taskset -c $a "$FLOOR_BIN" $FLOOR_PORT -m block &
        FLOOR_PID=$!
        wait_for_port $FLOOR_PORT || {
            log_error "floor did not start for the placement probe"; floor_stop; return 1; }

        local client=$a
        [[ $arm == split ]] && client=$b
        local out
        out=$(taskset -c $client "$SOCKETLEY_BENCH" -j server msg \
                  127.0.0.1 $FLOOR_PORT 20000 64 2>/dev/null | metrics_of) || {
            log_error "placement probe produced no result ($arm)"; floor_stop; return 1; }
        floor_stop

        if [[ $arm == same ]]; then PLACE_SAME=$out; else PLACE_DIFF=$out; fi
    done

    log_info "co-located on cpu$a: $(awk '{print $1}' <<< "$PLACE_SAME")/s   split cpu$a/cpu$b: $(awk '{print $1}' <<< "$PLACE_DIFF")/s"
}

report() {
    {
        printf '\n## Server runtime vs floor\n\n'
        printf 'Floor = accept + read + write in C, no io_uring, no framing, no\n'
        printf 'statistics.  Same client (socketley_bench), same test, same metric.\n\n'
        printf '| Test | Floor mode | Floor rate | Socketley rate | Ratio | Cost over floor | Floor p50 us | Skl p50 us | Floor p99 us | Skl p99 us | Floor spread | Skl spread |\n'
        printf '|------|-----------|-----------:|---------------:|------:|----------------:|-------------:|-----------:|-------------:|-----------:|-------------:|-----------:|\n'
        local row
        for row in "${ROWS[@]}"; do
            IFS='|' read -r label mode f s <<< "$row"
            read -r frate fp50 fp99 fsp <<< "$f"
            read -r srate sp50 sp99 ssp <<< "$s"
            python3 -c "
frate=$frate; srate=$srate
ratio = srate/frate if frate else 0
cost  = (1e6/srate - 1e6/frate) if (frate and srate) else 0
print('| $label | $mode | %.0f | %.0f | %.2fx | %+.2f us | %.1f | %.1f | %.1f | %.1f | %.2fx | %.2fx |' % (
    frate, srate, ratio, cost, $fp50, $sp50, $fp99, $sp99, $fsp, $ssp))"
        done
        printf '\n'
        printf 'Read the "cost over floor" column, not the ratio.\n\n'
        printf 'Cost over floor is the extra time one round trip takes through socketley\n'
        printf 'rather than through accept+read+write: everything the runtime does that\n'
        printf 'the floor does not -- the ring, the dispatch, a Lua callback per message.\n'
        printf 'It is not a constant either, but it moves far less than the ratio does:\n'
        printf 'on the 1-connection 64B row it has been measured at +5.6us co-located and\n'
        printf '+6 to +8us across cores, while the ratio on those same runs swings from\n'
        printf '0.70x to 0.90x.  Being a difference of two noisy reciprocals it also\n'
        printf 'carries more relative noise than either rate, so read it with the spread\n'
        printf 'columns and over more than one run.\n\n'
        printf 'It is much smaller on the concurrent row than on the 1-connection rows,\n'
        printf 'and both are real rather than one being wrong.  With one connection every\n'
        printf 'request pays a full wakeup and a full trip through the runtime, nothing\n'
        printf 'shares anything.  At 100 connections both sides amortise: one epoll_wait\n'
        printf 'returns many ready sockets, one io_uring_enter carries many submissions,\n'
        printf 'and the per-request cost of both collapses -- the floor itself drops from\n'
        printf 'about 26us per round trip to about 7.5us.  So the 1-connection rows are\n'
        printf 'the latency cost of an idle link and the concurrent row is the marginal\n'
        printf 'cost under load.  Which one matters depends on the workload; they are not\n'
        printf 'two attempts at the same measurement.\n\n'
        printf 'The ratio does not stay put, and that is what the placement probe below\n'
        printf 'is for.  Waking a process on another core costs more here than anything\n'
        printf 'socketley does, both sides pay it, and a shared constant in both halves\n'
        printf 'of a quotient pulls it towards 1.00x.  Measured on this tree, on the\n'
        printf '1-connection shape: the same ~4us appears as 0.90x when the two processes\n'
        printf 'sit on different cores and as 0.70x (worker) or 0.77x (in-daemon) when\n'
        printf 'they share one.  Quoting the ratio without saying which placement it came\n'
        printf 'from says almost nothing.\n\n'
        printf 'The floor is not a target to reach -- it does no dispatch, keeps no\n'
        printf 'runtime state and runs no Lua.  A ratio above 1.00x does not mean\n'
        printf 'socketley beat it: the floor takes the same stalls, its spread reaches\n'
        printf '1.3-1.4x on the concurrent row, and one observed pass had it fall to\n'
        printf '108,821/s against its usual 133-140k.  Read both spread columns first;\n'
        printf 'if either is wide, the row compares two noisy numbers and needs another\n'
        printf 'pass.\n'

        if [[ -n "$PLACE_SAME" && -n "$PLACE_DIFF" ]]; then
            local sr sp50 x fr fp50 y
            read -r sr sp50 x _ <<< "$PLACE_SAME"
            read -r fr fp50 y _ <<< "$PLACE_DIFF"
            printf '\n### Placement probe: the floor against itself\n\n'
            printf 'Same binary, same client, same test (20k x 64B).  Only the cores differ.\n\n'
            printf '| Placement | Rate | p50 us |\n'
            printf '|-----------|-----:|-------:|\n'
            printf '| both on cpu%s | %s | %s |\n' "${PLACE_CPUS%%/*}" "$sr" "$sp50"
            printf '| split across cpu%s | %s | %s |\n' "$PLACE_CPUS" "$fr" "$fp50"
            printf '\n'
            python3 -c "
sr=$sr; fr=$fr
print('Co-location is worth %.2fx here, in code that does nothing but read and' % (sr/fr if fr else 0))
print('write.  None of that belongs to socketley, and any figure from this suite')
print('carries whichever placement the scheduler handed it that day.')" 2>/dev/null
        fi
    } | tee "$REPORT_FILE"
}

run_floor_comparison() {
    log_section "SERVER RUNTIME vs FLOOR"

    ensure_socketley_bench || return 1
    if [[ ! -x "$FLOOR_BIN" ]]; then
        log_info "Building floor_server..."
        (cd "$PROJECT_ROOT" && ./bin/premake5 gmake2 >/dev/null 2>&1 && \
         cd make && make config=release_x64 floor_server -j"$(nproc)" >/dev/null 2>&1) \
            || { log_error "Failed to build floor_server"; return 1; }
    fi
    [[ -x "$FLOOR_BIN" ]] || { log_error "floor_server not found at $FLOOR_BIN"; return 1; }

    echo "[" > "$RESULTS_FILE"

    # The sizes and the concurrency the server benchmarks already use
    # (bench_server.sh): 64B and 1024B on one connection, and 100 x 500.
    run_pair "msg 64B 1conn"      block msg        100000 64
    run_pair "msg 1024B 1conn"    block msg        100000 1024
    run_pair "concurrent 100x500" epoll concurrent 100    500

    # After the pairs, not before: it is context for reading them, and running
    # it first would put its own 5000 sockets into TIME_WAIT ahead of the
    # measurement it is meant to explain.
    placement_probe || log_warn "placement probe failed; the ratios above have no placement context"

    echo "]" >> "$RESULTS_FILE"

    report
    log_success "Results: $RESULTS_FILE"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_binary || exit 1
    check_dependencies || exit 1
    setup_cleanup_trap
    # setup_cleanup_trap installs its own EXIT trap, so this one replaces it and
    # repeats what it does rather than being chained onto it -- a second `trap
    # ... EXIT` would silently drop the first, which is how the floor process
    # would have been left holding its port after an interrupted run.
    if [[ "${SOCKETLEY_BENCH_PARENT:-}" != "1" ]]; then
        trap 'floor_stop; srv_stop; cleanup_all; stop_daemon' EXIT INT TERM
    else
        trap 'floor_stop; srv_stop; cleanup_all' EXIT INT TERM
    fi
    if should_manage_daemon; then
        start_daemon || exit 1
    fi
    run_floor_comparison
fi
