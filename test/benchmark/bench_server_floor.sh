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

report() {
    {
        printf '\n## Server runtime vs floor\n\n'
        printf 'Floor = accept + read + write in C, no io_uring, no framing, no\n'
        printf 'statistics.  Same client (socketley_bench), same test, same metric.\n\n'
        printf '| Test | Floor mode | Floor rate | Socketley rate | Ratio | Floor p50 us | Skl p50 us | Floor p99 us | Skl p99 us | Floor spread | Skl spread |\n'
        printf '|------|-----------|-----------:|---------------:|------:|-------------:|-----------:|-------------:|-----------:|-------------:|-----------:|\n'
        local row
        for row in "${ROWS[@]}"; do
            IFS='|' read -r label mode f s <<< "$row"
            read -r frate fp50 fp99 fsp <<< "$f"
            read -r srate sp50 sp99 ssp <<< "$s"
            python3 -c "
frate=$frate; srate=$srate
ratio = srate/frate if frate else 0
print('| $label | $mode | %.0f | %.0f | %.2fx | %.1f | %.1f | %.1f | %.1f | %.2fx | %.2fx |' % (
    frate, srate, ratio, $fp50, $sp50, $fp99, $sp99, $fsp, $ssp))"
        done
        printf '\n'
        printf 'Ratio is socketley / floor.  1.00x means socketley costs nothing beyond\n'
        printf 'accept+read+write and there is no headroom on this path; a low ratio is\n'
        printf 'where optimisation work could pay.  The floor is not a target to reach --\n'
        printf 'it does no dispatch, keeps no runtime state and runs no Lua.\n\n'
        printf 'A ratio above 1.00x does not mean socketley beat the floor.  The floor\n'
        printf 'runs on the same machine and takes the same stalls -- its own spread\n'
        printf 'column reaches 1.3-1.4x on the concurrent row, and one observed pass had\n'
        printf 'the floor fall to 108,821/s against its usual 133-140k.  Read the two\n'
        printf 'spread columns before reading the ratio; if either is wide, the ratio is\n'
        printf 'a comparison of two noisy numbers and needs another pass.\n'
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
