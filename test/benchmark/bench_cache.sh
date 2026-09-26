#!/bin/bash
# Cache Runtime Benchmark
# Uses socketley-bench (C binary) for pipelined persistent-connection benchmarks.

source "$(dirname "$0")/utils.sh"
# median_of / ci_pct_of live there; two copies of a statistical argument drift.
source "$(dirname "$0")/lib_paired.sh"

CACHE_PORT=19001
RESULTS_FILE="${RESULTS_DIR}/cache_${TIMESTAMP}.json"

echo "[" > "$RESULTS_FILE"
FIRST_RESULT=true

append_result() {
    if [[ $FIRST_RESULT == true ]]; then
        FIRST_RESULT=false
    else
        echo "," >> "$RESULTS_FILE"
    fi
}

# ─── How the data-structure tests are timed, and why they are timed that way ─
#
# Tests 7 to 10 (LIST, SET, HASH, TTL) used to be:
#
#     start=$(get_time_ms)
#     awk 'BEGIN{ ...5000 lines... }' | bench_nc $CACHE_PORT >/dev/null
#     end=$(get_time_ms)
#     ops=$(( 5000 * 1000 / (end - start) ))
#
# and reported lpush 833,333, lpop 1,000,000, sadd 714,285, hget 555,555 ops/sec.
# Every one of those is 5000 divided by a small integer: 5000/6, 5000/5, 5000/7,
# 5000/9.  The windows were five to nine milliseconds long, measured with a clock
# whose resolution is one millisecond and whose bias is one to two more, so the
# gap between "833,333" and "1,000,000" was one tick.  Reproduced here before
# changing anything: five repetitions of the old lpush measurement gave 5, 5, 8,
# 7 and 6 ms, i.e. 1,000,000 / 1,000,000 / 625,000 / 714,285 / 833,333 ops/sec
# for identical work.
#
# Three separate things were wrong, and only the first was the clock:
#
#   The window was five milliseconds.  Nothing about a machine is stable at that
#   scale.  Each measurement now probes once and picks the operation count that
#   gives it a CACHE_PIPE_TARGET_MS window, and the window it achieved is
#   printed with every result.
#
#   The generator was inside the window.  `awk | nc` times awk as well as the
#   cache, and awk emits about 4.0M lines/sec against a cache that answers about
#   4.7M ops/sec -- so a fifth to a half of what was published was the load
#   generator.  Measured: the same 500,000 LPUSHes report 1.0M ops/sec when awk
#   pipes them and 6.2M ops/sec when they are read from a file already written.
#   The stream is now generated to a file before the clock starts.
#
#   Nothing checked that the server had answered.  `nc -q0` quits the moment its
#   stdin ends, so a window can close with replies still in flight and publish
#   the client's write rate as the server's service rate.  Every run now counts
#   the replies and refuses the number unless it got exactly one per command.
#
# What is measured is unchanged in kind: one connection, commands pipelined
# without waiting for replies, one process relaying them.  It is a pipelined
# throughput figure and not a per-operation latency, which is why it is far
# above the round-trip rates `socketley_bench cache` reports.
#
# ─── The two instruments, side by side ──────────────────────────────────────
#
# Both run against the same cache on the same box, the old one interleaved with
# the new so neither got a quieter minute than the other.  The old column is
# five consecutive repetitions of the published measurement:
#
#   LPUSH  old  833333  833333 1666666  833333  833333    new  19,905,300/s
#   LPOP   old 1000000  833333 1000000  833333 1000000    new  22,085,900/s
#   SADD   old  714285  833333  833333  833333  714285    new   2,411,450/s
#   HGET   old  625000  714285  500000  500000  625000    new     211,701/s
#
# The old column is not five measurements of one thing.  It is 5000 divided by
# 6, 6, 3, 6 and 6 milliseconds, and by 5, 6, 5, 6 and 5, and so on -- the only
# values it can take are 5000/N.  1,666,666 is not the cache being twice as fast
# for one run; it is a 3 ms window instead of a 6 ms one.  Nothing in the old
# output distinguished that from a result.
#
# The new column is one figure per operation with its own window, its own
# spread and its own resolution beside it.  It disagrees with the old one by
# 1.7x to 26x depending on the operation, in both directions, because the two
# were never measuring the same thing: the old windows contained a `date` fork
# and an awk generator, and this one contains neither.
#
# ─── What the repaired benchmark resolves ───────────────────────────────────
#
# Measured on 2026-08-18 with two other agents benchmarking on the same box,
# which is why the spreads below are as wide as they are and why several rows
# are marked:
#
#   LPUSH     10,333,300/s  3.29M ops  318 ms  harness 1.15%  spread 2.98x  ±52.6%
#   LPOP      14,188,600/s  2.74M ops  193 ms  harness 1.90%  spread 3.49x  ±54.1%
#   SADD       1,335,340/s   777k ops  582 ms  harness 0.63%  spread 2.30x  ±39.1%
#   SISMEMBER  1,453,500/s   396k ops  273 ms  harness 1.35%  spread 1.39x  ±16.1%
#   HSET       1,881,010/s   590k ops  314 ms  harness 1.17%  spread 1.52x  ±20.5%
#   HGET       1,505,290/s   352k ops  234 ms  harness 1.57%  spread 1.47x  ±19.1%
#   EXPIRE       194,789/s   200k ops 1027 ms  harness 0.36%  spread 1.52x  ±19.3%
#   TTL          458,295/s   200k ops  436 ms  harness 0.84%  spread 1.54x  ±21.8%
#
# So: the harness is now under 2% of every window, against 11..20% before, and
# what limits these figures is the machine rather than the instrument.  The
# right-hand column is the smallest difference each row could have told from its
# own noise, and it is printed whether it is good or bad -- a resolution shown
# only when it is poor teaches the reader that its absence means the question
# was asked and answered well, when it means the question was never asked.
#
# A row whose spread exceeds CACHE_PIPE_SPREAD_WARN says so on the same line;
# a row the harness is too large a share of is refused outright and written
# with usable:0 rather than printed.
# ─── The knobs ──────────────────────────────────────────────────────────────
#
# CACHE_PIPE_TARGET_MS is the window each measurement aims for, and it is picked
# against the instrument rather than against taste.  One timed run costs a
# `timeout` and an `nc`: measured on this box that is about 2 ms before the
# cache has been asked for anything.  At a 250 ms window the harness is under
# 1% of what is being timed, which is the line below which two figures cannot
# differ because of it.  The achieved share is computed per run and printed, so
# nothing rests on this paragraph staying true.
#
# The count is not fixed, because the operations differ by an order of
# magnitude: LPUSH runs at about 11M/sec pipelined and HSET at about 1.5M, so
# one count cannot give both a usable window -- which is exactly how the old
# fixed 5000 ended up timing five milliseconds.  Each measurement probes once,
# then picks its own count.
CACHE_PIPE_TARGET_MS=${CACHE_PIPE_TARGET_MS:-250}
CACHE_PIPE_MIN_OPS=${CACHE_PIPE_MIN_OPS:-200000}
# The cap is memory, not time: the store holds everything a run writes into it,
# and 2M list entries is about 130 MB.
CACHE_PIPE_MAX_OPS=${CACHE_PIPE_MAX_OPS:-4000000}

# The write bound of the caches the pipelined rows run against.  nc writes the
# whole command file and reads the replies at its own pace, so at the op counts
# above the cache owed it more than the default 8 MiB and closed it as a client
# that stopped reading -- which is the product's rule and not the benchmark's
# question: LPOP at 4,000,000 ops collected 1,362,437 replies and read as 0 in
# every suite run from 2026-09-04 on.  With this, all 4,000,000 in 223 ms.
CACHE_PIPE_WRITE_BUFFER=${CACHE_PIPE_WRITE_BUFFER:-256M}
CACHE_PIPE_RUNS=${CACHE_PIPE_RUNS:-5}
# The harness's share of a window, above which the figure is refused.  This is
# the one hard gate, and it is about the instrument rather than about noise: a
# window the harness is a large fraction of cannot answer any question, however
# many times it is repeated.
CACHE_PIPE_MAX_INSTRUMENT_PCT=${CACHE_PIPE_MAX_INSTRUMENT_PCT:-2.0}
# Spread above which the median is not a number to quote on its own.  Same value
# and same treatment as SPREAD_WARN in bench.c, deliberately: it is reported and
# marked rather than refused, because on this box these rates legitimately span
# 1.2..1.8x between repetitions and a benchmark that exits non-zero on a real
# property of the machine it runs on is a benchmark that gets switched off.
# The distinction that matters is between "quotable alone" and "quote the range
# too", and the row says which it is.
CACHE_PIPE_SPREAD_WARN=${CACHE_PIPE_SPREAD_WARN:-1.5}
# Rounds of count-picking.  One is not enough: the probe run is the cold one, so
# the count it implies undershoots the warm rate -- measured, a single round
# picked 1.82M LPUSHes for a 250 ms target and got 154 ms.
CACHE_PIPE_CALIBRATIONS=${CACHE_PIPE_CALIBRATIONS:-3}
CACHE_PIPE_WORK=""

# Scratch for the generated command streams and the collected replies.
cache_pipe_workdir() {
    if [[ -z "$CACHE_PIPE_WORK" ]]; then
        CACHE_PIPE_WORK=$(mktemp -d -t socketley_bench_cache.XXXXXX)
    fi
    printf '%s' "$CACHE_PIPE_WORK"
}
cleanup_cache_pipe_work() {
    [[ -n "$CACHE_PIPE_WORK" ]] && rm -rf "$CACHE_PIPE_WORK"
    CACHE_PIPE_WORK=""
}

# What one timed run costs before the cache has done anything: the same
# `timeout nc` pipeline carrying a single command.
#
# The clock is no longer the instrument -- the process the window has to start
# is.  Measured here rather than assumed, because it is the number that decides
# how long a window has to be, and it is a property of this box.
#
# It assigns CACHE_PIPE_FLOOR_US rather than echoing it, and callers invoke it as
# a statement.  That is the same trap now_us() documents from the other side: a
# function whose value is taken with $( ) runs in a forked subshell, so anything
# it caches is discarded when the subshell exits -- this one would then re-run
# its five netcats on every single call.  It did, and the resulting floor moved
# between 2.4 ms and 5.5 ms inside one test, which is enough on its own to move
# a row from printed to REFUSED and back.  Measured once per script, so that
# every row in a run is judged against the same instrument.
CACHE_PIPE_FLOOR_US=""
cache_pipe_measure_floor() {
    [[ -n "$CACHE_PIPE_FLOOR_US" ]] && return 0
    local w f i a b samples=()
    w=$(cache_pipe_workdir); f="$w/floor.cmds"
    printf 'SIZE\n' > "$f"
    for i in 1 2 3 4 5 6 7; do
        now_us; a=$NOW_US
        timeout "$BENCH_TIMEOUT_NC" nc -q0 127.0.0.1 $CACHE_PORT < "$f" >/dev/null 2>&1
        now_us; b=$NOW_US
        samples+=( $((b - a)) )
    done
    CACHE_PIPE_FLOOR_US=$(printf '%s\n' "${samples[@]}" | sort -n | awk '{v[n++]=$1} END{print v[int(n/2)]}')
    [[ "${CACHE_PIPE_FLOOR_US:-0}" -lt 1 ]] && CACHE_PIPE_FLOOR_US=1
    return 0
}

# One untimed pass: the setup that puts the store back into the state every
# measured run starts from.
cache_pipe_apply() {
    local file=$1
    [[ -s "$file" ]] || return 0
    timeout "$BENCH_TIMEOUT_NC" nc -q0 127.0.0.1 $CACHE_PORT < "$file" >/dev/null 2>&1
}

# One timed pass.  Sets CP_LAST_US and CP_LAST_REPLIES.
cache_pipe_once() {
    local file=$1 out=$2 a b
    now_us; a=$NOW_US
    timeout "$BENCH_TIMEOUT_NC" nc -q0 127.0.0.1 $CACHE_PORT < "$file" > "$out" 2>/dev/null
    now_us; b=$NOW_US
    CP_LAST_US=$((b - a))
    [[ $CP_LAST_US -lt 1 ]] && CP_LAST_US=1
    CP_LAST_REPLIES=$(wc -l < "$out")
}

# One pipelined measurement.
#
#   cache_pipe_measure <label> <cmd-awk> <setup-awk>
#
# Both awk programs are BEGIN blocks given -v n=<operations>.  cmd-awk must
# produce exactly n commands, each answering with exactly one line.  setup-awk
# produces the commands that return the store to the state every timed run
# starts from, and it is run untimed before each of them.
#
# The reset is what makes the repetitions comparable.  Without one, a list that
# is pushed into five times in a row is five different lengths when it is
# measured, and the five rates are a growth curve rather than a repeated
# measurement -- observed exactly that way here: 40, 60, 100, 80 and 120 ns of
# cache CPU per LPUSH over five consecutive runs into the same list, a 1.98x
# spread that nothing in the output attributed to the benchmark.
#
# Sets CP_OPS, CP_RATE (median ops/sec), CP_LO, CP_HI, CP_SPREAD, CP_CI (95%
# half-width, percent), CP_WINDOW_US (median), CP_RES (percent of the window the
# instrument itself accounts for) and CP_VERDICT.  All of them every time, so a
# caller cannot read the previous case's value out of a failed one.
cache_pipe_measure() {
    local label=$1 prog=$2 setup=$3
    local w file setupfile out r rates=() windows=() bad=0
    CP_OPS=0; CP_RATE=0; CP_LO=0; CP_HI=0; CP_SPREAD=0; CP_CI=0
    CP_WINDOW_US=0; CP_RES=0; CP_VERDICT="ok"

    w=$(cache_pipe_workdir)
    file="$w/cmds"; setupfile="$w/setup"; out="$w/replies"

    # Both as statements, so the caching survives: see cache_pipe_measure_floor.
    bench_clock_floor_us >/dev/null
    cache_pipe_measure_floor

    # ── Pick the count this operation needs for the target window, by measuring
    # rather than by assuming.  A count picked once for all ten operations is
    # how the old version came to time five milliseconds: LPUSH runs about
    # eight times faster than HSET, so no single count suits both.
    #
    # These rounds double as the warm-up every one of these needs -- the first
    # pass through any of these paths allocates the structure it writes into,
    # and socketley_bench discards a first run for the same reason.
    local ops=$CACHE_PIPE_MIN_OPS prev=0 round
    for round in $(seq 1 "$CACHE_PIPE_CALIBRATIONS"); do
        if [[ "$ops" -ne "$prev" ]]; then
            awk -v n="$ops" "$setup" > "$setupfile"
            awk -v n="$ops" "$prog"  > "$file"
            prev=$ops
        fi
        cache_pipe_apply "$setupfile"
        cache_pipe_once "$file" "$out"
        [[ $round -eq $CACHE_PIPE_CALIBRATIONS ]] && break
        ops=$(awk -v cur="$ops" -v us="$CP_LAST_US" \
                  -v target="$((CACHE_PIPE_TARGET_MS * 1000))" \
                  -v lo="$CACHE_PIPE_MIN_OPS" -v hi="$CACHE_PIPE_MAX_OPS" \
            'BEGIN { n = cur * target / us; if (n < lo) n = lo; if (n > hi) n = hi; printf "%.0f", n }')
    done
    CP_OPS=$ops
    if [[ "$ops" -ne "$prev" ]]; then
        awk -v n="$ops" "$setup" > "$setupfile"
        awk -v n="$ops" "$prog"  > "$file"
    fi

    # ── Measure.  Twice at most: the calibration rounds run against a colder
    # store than the measured ones, so the count they imply can still be short.
    # Observed: SISMEMBER calibrated to 245,645 ops for a 250 ms target and then
    # measured 100 ms windows, because the measured runs went 2.4x faster than
    # the rounds that sized them.  Rather than publish a figure the harness is
    # 4% of, it re-sizes from what it actually saw and measures again.
    local attempt
    for attempt in 1 2; do
        rates=(); windows=(); bad=0; CP_VERDICT="ok"
        for r in $(seq 1 "$CACHE_PIPE_RUNS"); do
            cache_pipe_apply "$setupfile"
            cache_pipe_once "$file" "$out"

            # One reply per command, or the window closed before the cache had
            # finished and the rate below is the client's write rate.  A short count
            # is not a slow run, it is a different measurement.
            if [[ "$CP_LAST_REPLIES" -ne "$ops" ]]; then
                bad=$((bad + 1))
                CP_VERDICT="incomplete: run $r collected $CP_LAST_REPLIES replies for $ops commands"
                continue
            fi
            windows+=( "$CP_LAST_US" )
            rates+=( "$(awk -v n="$ops" -v us="$CP_LAST_US" 'BEGIN{printf "%.0f", n / (us/1e6)}')" )
        done

        if [[ ${#rates[@]} -lt 2 ]]; then
            [[ "$CP_VERDICT" == "ok" ]] && CP_VERDICT="fewer than two usable repetitions"
            return 1
        fi

        # median_of prints %.6g, which turns 14,745,800 into "1.47458e+07" -- a rate
        # in scientific notation in a JSON file other tooling parses.
        CP_RATE=$(awk -v m="$(median_of "${rates[*]}")" 'BEGIN{printf "%.0f", m}')
        CP_WINDOW_US=$(awk -v m="$(median_of "${windows[*]}")" 'BEGIN{printf "%.0f", m}')
        CP_CI=$(ci_pct_of "${rates[*]}")
        CP_LO=$(printf '%s\n' "${rates[@]}" | sort -n | head -1)
        CP_HI=$(printf '%s\n' "${rates[@]}" | sort -n | tail -1)
        CP_SPREAD=$(awk -v lo="$CP_LO" -v hi="$CP_HI" 'BEGIN{printf "%.2f", (lo > 0 ? hi/lo : 0)}')

        # The instrument's share of the window: the clock plus the process the
        # window has to start.  This is what "resolution" means for a bash-timed
        # measurement, and it is the thing the old five-millisecond window failed --
        # by this measure those windows were 11..20% harness.
        local floor
        floor=$(( BENCH_CLOCK_FLOOR_US + CACHE_PIPE_FLOOR_US ))
        CP_RES=$(awk -v f="$floor" -v w="$CP_WINDOW_US" 'BEGIN{printf "%.2f", (w>0 ? 100*f/w : 100)}')

        [[ $bad -gt 0 ]] && return 1
        awk -v r="$CP_RES" -v lim="$CACHE_PIPE_MAX_INSTRUMENT_PCT" 'BEGIN{exit !(r > lim)}' || return 0

        # The window was too short for the harness in it.  One re-size, from the
        # window actually achieved rather than from the calibration's guess.
        if [[ $attempt -eq 1 && "$ops" -lt "$CACHE_PIPE_MAX_OPS" ]]; then
            ops=$(awk -v cur="$ops" -v us="$CP_WINDOW_US" \
                      -v target="$((CACHE_PIPE_TARGET_MS * 1000))" \
                      -v lo="$CACHE_PIPE_MIN_OPS" -v hi="$CACHE_PIPE_MAX_OPS" \
                'BEGIN { n = cur * target / us; if (n < lo) n = lo; if (n > hi) n = hi; printf "%.0f", n }')
            CP_OPS=$ops
            awk -v n="$ops" "$setup" > "$setupfile"
            awk -v n="$ops" "$prog"  > "$file"
            continue
        fi
        CP_VERDICT="unresolved: the harness is ${CP_RES}% of a ${CP_WINDOW_US}us window; ${CACHE_PIPE_MAX_OPS} ops is not enough of this operation to fill ${CACHE_PIPE_TARGET_MS} ms"
        return 1
    done
    return 1
}

# Print and record one pipelined result.
#
# The kind of thing measured goes under `measures` rather than `metric`, and
# that is not arbitrary: generate_summary() puts every row carrying `metric`
# into the main table and reads its rate from median_round_trips_per_sec or one
# of its two siblings.  These rows carry lpush_ops_sec and friends, so a `metric`
# key here would file them in a table whose Median column can only print "-" for
# them.  Without it they land in the name/value table, which is where the rows
# this file writes itself have always gone.
#
# A refusal is printed as a refusal and
# recorded with usable:0 rather than being left out: a row that silently
# disappears reads to the next comparison as a test that was never run.
cache_pipe_report() {
    local test_name=$1 label=$2 key=$3 prog=$4 setup=${5:-'BEGIN{}'}
    local stable=1 wide=""
    if cache_pipe_measure "$label" "$prog" "$setup"; then
        log_success "  $label: $CP_RATE ops/sec"
    else
        log_error   "  $label: REFUSED — $CP_VERDICT"
    fi
    # A spread of 0 means it was never measured, which is not the same as steady
    # -- reporting stable:1 for it is the claim of perfect repeatability from
    # something never repeated that bench.c refuses to make.
    if awk -v sp="$CP_SPREAD" 'BEGIN{exit !(sp <= 0)}'; then
        stable=0
    elif awk -v sp="$CP_SPREAD" -v w="$CACHE_PIPE_SPREAD_WARN" 'BEGIN{exit !(sp > w)}'; then
        stable=0; wide="  — too wide to quote the median alone"
    fi
    log_info "    $CP_OPS ops/run, window $(awk -v u="$CP_WINDOW_US" 'BEGIN{printf "%.0f", u/1000}') ms, harness ${CP_RES}% of it"
    log_info "    spread $CP_LO .. $CP_HI (${CP_SPREAD}x)${wide}; resolves differences above ${CP_CI}% over $CACHE_PIPE_RUNS runs"
    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "operations"          "$CP_OPS" \
        "runs"                "$CACHE_PIPE_RUNS" \
        "measures"            "pipelined_ops_per_sec" \
        "$key"                "$CP_RATE" \
        "min_per_sec"         "$CP_LO" \
        "max_per_sec"         "$CP_HI" \
        "spread_ratio"        "$CP_SPREAD" \
        "stable"              "$stable" \
        "ci95_half_width_pct" "$CP_CI" \
        "window_us"           "$CP_WINDOW_US" \
        "instrument_pct"      "$CP_RES" \
        "usable"              "$([[ "$CP_VERDICT" == "ok" ]] && echo 1 || echo 0)" \
        "verdict"             "$CP_VERDICT"
}

# Ensure bench_cache runtime is cleaned up before starting a new test.
ensure_clean() {
    socketley_cmd stop bench_cache 2>/dev/null
    sleep 0.5
    socketley_cmd remove bench_cache 2>/dev/null
}

# ─── The second that was being reported as I/O ──────────────────────────────
#
# Every one-off command in this file went through
#
#     printf '%s\n' "$1" | timeout $BENCH_TIMEOUT_NC nc -q1 localhost $CACHE_PORT
#
# `-q1` means "after EOF on stdin, wait one second, then quit".  The wait is
# unconditional: it does not wait *for* anything, it waits.  test_persistence()
# had it inside its timing window, so it published flush_time_ms 1018 and
# load_time_ms 1006 for 10,000 keys and 649 KB -- which reads as 0.65 MB/s and
# was quoted as a persistence bottleneck.  Measured on the same store the same
# afternoon, the flush is about 12 ms and the load about 1: the file said 1006
# for a thing that took one, and 1005 of it was netcat sleeping.
#
# The linger is load-bearing in one direction, which is why -q0 is not the fix
# on its own: every caller needs the cache's answer (FLUSH and LOAD reply "ok",
# SIZE replies a count) and -q0 quits at EOF on stdin without waiting for it.
# So the reply is read explicitly, and a timed window ends when the reply
# arrives -- which is both what the caller wanted and what a duration should
# measure.  Verified: FLUSH, LOAD and SIZE each answer exactly one line.
#
# The connection is opened once and held, rather than opened per command, so
# that a timed window contains the command and its reply and nothing else: no
# connect, no process start.  On this box that is the difference between a
# 79 us round trip and a 2.6 ms one, against a flush of 12 ms.
#
# cache_conn_open sets CACHE_FD; cache_conn_rpc puts the reply in CACHE_REPLY.
CACHE_FD=""
CACHE_REPLY=""
cache_conn_open() {
    exec {CACHE_FD}<>/dev/tcp/127.0.0.1/$CACHE_PORT 2>/dev/null || { CACHE_FD=""; return 1; }
    return 0
}
cache_conn_rpc() {
    CACHE_REPLY=""
    [[ -z "$CACHE_FD" ]] && return 1
    printf '%s\n' "$1" >&$CACHE_FD || return 1
    IFS= read -r -t "$BENCH_TIMEOUT_NC" CACHE_REPLY <&$CACHE_FD || return 1
    return 0
}
cache_conn_close() {
    [[ -n "$CACHE_FD" ]] && exec {CACHE_FD}>&-
    CACHE_FD=""
}

# Test 1: SET throughput
test_set_throughput() {
    local num_ops=${1:-10000}
    local value_size=${2:-64}
    local test_name="cache_set_throughput"

    log_section "Test: SET Throughput ($num_ops ops, ${value_size}B values)"

    ensure_clean
    wait_for_port_free $CACHE_PORT
    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; ensure_clean; return 1; }
    sleep 0.5

    append_result
    bench_run -j cache set 127.0.0.1 $CACHE_PORT $num_ops $value_size >> "$RESULTS_FILE"
    bench_run cache set 127.0.0.1 $CACHE_PORT $num_ops $value_size

    socketley_cmd stop bench_cache
    sleep 0.5
    socketley_cmd remove bench_cache
}

# Test 2: GET throughput (pre-populated inside bench tool)
test_get_throughput() {
    local num_ops=${1:-10000}
    local test_name="cache_get_throughput"

    log_section "Test: GET Throughput ($num_ops ops)"

    ensure_clean
    wait_for_port_free $CACHE_PORT
    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; ensure_clean; return 1; }
    sleep 0.5

    append_result
    bench_run -j cache get 127.0.0.1 $CACHE_PORT $num_ops >> "$RESULTS_FILE"
    bench_run cache get 127.0.0.1 $CACHE_PORT $num_ops

    socketley_cmd stop bench_cache
    sleep 0.5
    socketley_cmd remove bench_cache
}

# Test 3: Mixed workload (80% GET, 20% SET)
test_mixed_workload() {
    local num_ops=${1:-10000}
    local test_name="cache_mixed_workload"

    log_section "Test: Mixed Workload ($num_ops ops, 80% GET / 20% SET)"

    ensure_clean
    wait_for_port_free $CACHE_PORT
    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; ensure_clean; return 1; }
    sleep 0.5

    append_result
    bench_run -j cache mixed 127.0.0.1 $CACHE_PORT $num_ops >> "$RESULTS_FILE"
    bench_run cache mixed 127.0.0.1 $CACHE_PORT $num_ops

    socketley_cmd stop bench_cache
    sleep 0.5
    socketley_cmd remove bench_cache
}

# Test 4: Concurrent client access (threaded pipeline clients)
test_concurrent_access() {
    local num_clients=${1:-20}
    local ops_per_client=${2:-2000}
    local test_name="cache_concurrent_access"

    log_section "Test: Concurrent Access ($num_clients clients × $ops_per_client ops)"

    ensure_clean
    wait_for_port_free $CACHE_PORT
    socketley_cmd create cache bench_cache -p $CACHE_PORT -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; ensure_clean; return 1; }
    sleep 0.5

    append_result
    bench_run -j cache concurrent 127.0.0.1 $CACHE_PORT $num_clients $ops_per_client >> "$RESULTS_FILE"
    bench_run cache concurrent 127.0.0.1 $CACHE_PORT $num_clients $ops_per_client

    socketley_cmd stop bench_cache
    sleep 0.5
    socketley_cmd remove bench_cache
}

# Test 5: Persistence (FLUSH / LOAD)
#
# ─── What this test used to report ──────────────────────────────────────────
#
# flush_time_ms 1018 and load_time_ms 1006 for 10,000 keys and a 649 KB file.
# Read as I/O that is 0.65 MB/s, which is a bottleneck worth a paragraph in a
# report -- and one was written.  Both figures were `nc -q1`: a fixed one-second
# linger after EOF, inside the timing window.  See the connection helpers above.
#
# Re-measured on the same store: the flush is about 12..14 ms and the load
# about 1..2 ms for the same 633 KB, i.e. 43..51 MB/s flushed and 260..483 MB/s
# loaded, and cache_store::save_v2 writes through mmap.  There was never an I/O
# problem here; there was a sleep.  Side by side:
#
#   FLUSH   old 1018 ms      new 12.0 ms  (10.3..17.4, 1.69x, resolves ±26.7%)
#   LOAD    old 1006 ms      new  1.3 ms  ( 1.0.. 2.4, 2.41x, resolves ±50.2%)
#
# The 1006 ms figure was 998 ms of netcat and 8 ms of work.  What the repaired
# figures resolve is printed with them: at five repetitions of a 1.3 ms
# operation the load number carries a ±50% interval, which is honest and which
# the old six-significant-figure "1006" was not.  Raise CACHE_PERSIST_RUNS or
# the key count if a tighter answer is wanted.
#
# ─── What it reports now ────────────────────────────────────────────────────
#
# Each of FLUSH and LOAD is timed on a connection that is already open, so the
# window holds the command and its reply and nothing else -- no connect, no
# process start, no linger.  The round trip on that same connection with a
# trivial command (SIZE) is measured too and printed beside the result: it is
# what the harness costs, and at 18 ms against a floor in the hundreds of
# microseconds it is what says the figure is about the store.
#
# Repeated, because one sample of a 20 ms operation on this box is not a number.
# The first is discarded: creating the file and overwriting it are not the same
# work, and measured here the first FLUSH after a populate runs about 18 ms
# against 25..46 ms for the ones after it.
CACHE_PERSIST_RUNS=${CACHE_PERSIST_RUNS:-5}

# Time one command on the already-open connection, RUNS times plus a discarded
# first.  Sets PS_MED_US, PS_LO_US, PS_HI_US, PS_CI, PS_SPREAD.
cache_time_command() {
    local cmd=$1 runs=$2
    local i a b samples=()
    PS_MED_US=0; PS_LO_US=0; PS_HI_US=0; PS_CI=0; PS_SPREAD=0
    for i in $(seq 0 "$runs"); do
        now_us; a=$NOW_US
        cache_conn_rpc "$cmd" || return 1
        now_us; b=$NOW_US
        [[ $i -eq 0 ]] && continue
        [[ "$CACHE_REPLY" == "ok" ]] || { log_warn "$cmd answered '$CACHE_REPLY', not ok"; return 1; }
        samples+=( $((b - a)) )
    done
    [[ ${#samples[@]} -lt 2 ]] && return 1
    PS_MED_US=$(median_of "${samples[*]}")
    PS_CI=$(ci_pct_of "${samples[*]}")
    PS_LO_US=$(printf '%s\n' "${samples[@]}" | sort -n | head -1)
    PS_HI_US=$(printf '%s\n' "${samples[@]}" | sort -n | tail -1)
    PS_SPREAD=$(awk -v lo="$PS_LO_US" -v hi="$PS_HI_US" 'BEGIN{printf "%.2f", (lo>0 ? hi/lo : 0)}')
    return 0
}

# The same round trip with a command that does no I/O, as the instrument floor.
cache_rpc_floor_us() {
    local i a b samples=()
    for i in 1 2 3 4 5; do
        now_us; a=$NOW_US
        cache_conn_rpc "SIZE" >/dev/null || { echo 0; return; }
        now_us; b=$NOW_US
        samples+=( $((b - a)) )
    done
    printf '%s\n' "${samples[@]}" | sort -n | awk '{v[n++]=$1} END{print v[int(n/2)]}'
}

test_persistence() {
    local num_keys=${1:-10000}
    local test_name="cache_persistence"

    log_section "Test: Persistence ($num_keys keys)"

    local persist_file="/tmp/bench_cache_persist.bin"
    rm -f "$persist_file"

    ensure_clean
    wait_for_port_free $CACHE_PORT
    socketley_cmd create cache bench_cache -p $CACHE_PORT --persistent "$persist_file" --mode admin -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; ensure_clean; return 1; }
    sleep 0.5

    local value="persistence_test_value_padding_padding_padding_p"

    log_info "Populating $num_keys keys..."
    local w; w=$(cache_pipe_workdir)
    awk -v n=$num_keys -v v="$value" \
        'BEGIN{ for(i=1;i<=n;i++) printf "SET key%d %s\n",i,v }' > "$w/populate"
    timeout "$BENCH_TIMEOUT_NC" nc -q0 localhost $CACHE_PORT < "$w/populate" >/dev/null 2>&1
    sleep 0.1

    cache_conn_open || { log_error "could not open a connection to the cache"; ensure_clean; return 1; }
    local floor_us; floor_us=$(cache_rpc_floor_us)

    local flush_us=0 flush_lo=0 flush_hi=0 flush_ci=0 flush_spread=0 verdict="ok"
    if cache_time_command "FLUSH" "$CACHE_PERSIST_RUNS"; then
        flush_us=$PS_MED_US; flush_lo=$PS_LO_US; flush_hi=$PS_HI_US
        flush_ci=$PS_CI;     flush_spread=$PS_SPREAD
        log_success "FLUSH: $(awk -v u="$flush_us" 'BEGIN{printf "%.1f", u/1000}') ms  (spread $(awk -v l=$flush_lo -v h=$flush_hi 'BEGIN{printf "%.1f..%.1f", l/1000, h/1000}') ms, ${flush_spread}x, resolves above ${flush_ci}%)"
    else
        verdict="flush did not complete"
        log_error "FLUSH: REFUSED — $verdict"
    fi
    cache_conn_close

    local file_size=$(stat -c%s "$persist_file" 2>/dev/null || echo 0)
    log_info "Persisted file: $((file_size / 1024)) KB"

    # Restart and LOAD
    socketley_cmd stop bench_cache
    sleep 0.5
    socketley_cmd start bench_cache
    wait_for_port $CACHE_PORT || { log_error "Cache failed to restart"; ensure_clean; return 1; }
    sleep 0.5

    cache_conn_open || { log_error "could not reopen a connection to the cache"; ensure_clean; return 1; }
    local load_us=0 load_lo=0 load_hi=0 load_ci=0 load_spread=0
    if cache_time_command "LOAD" "$CACHE_PERSIST_RUNS"; then
        load_us=$PS_MED_US; load_lo=$PS_LO_US; load_hi=$PS_HI_US
        load_ci=$PS_CI;     load_spread=$PS_SPREAD
        log_success "LOAD:  $(awk -v u="$load_us" 'BEGIN{printf "%.1f", u/1000}') ms  (spread $(awk -v l=$load_lo -v h=$load_hi 'BEGIN{printf "%.1f..%.1f", l/1000, h/1000}') ms, ${load_spread}x, resolves above ${load_ci}%)"
    else
        [[ "$verdict" == "ok" ]] && verdict="load did not complete" || verdict="$verdict; load did not complete"
        log_error "LOAD: REFUSED — $verdict"
    fi

    local size_result=""
    cache_conn_rpc "SIZE" && size_result=$CACHE_REPLY
    cache_conn_close
    log_info "Keys after LOAD: $size_result"

    # The oracle for both figures.  A LOAD that restored nothing is the fastest
    # LOAD there is, and without this the file would carry it as a record.
    if [[ "$size_result" != "$num_keys" ]]; then
        verdict="restored $size_result keys, not $num_keys"
        log_error "the durations above are not a persistence measurement: $verdict"
    fi

    # Beside the durations, because "1006 ms for 649 KB" was read as a rate and
    # the rate was what made it look like a defect.  Now the rate is stated.
    local flush_mb load_mb inst_pct
    flush_mb=$(awk -v b="$file_size" -v u="$flush_us" 'BEGIN{printf "%.1f", (u>0 ? b/1048576/(u/1e6) : 0)}')
    load_mb=$(awk  -v b="$file_size" -v u="$load_us"  'BEGIN{printf "%.1f", (u>0 ? b/1048576/(u/1e6) : 0)}')
    inst_pct=$(awk -v f="$floor_us" -v u="$flush_us"  'BEGIN{printf "%.2f", (u>0 ? 100*f/u : 100)}')
    log_info "  $flush_mb MB/s flushed, $load_mb MB/s loaded; the harness round trip itself is ${floor_us} us (${inst_pct}% of the flush)"

    append_result
    write_json_result "$test_name" "$RESULTS_FILE" \
        "num_keys"          "$num_keys" \
        "runs"              "$CACHE_PERSIST_RUNS" \
        "flush_time_ms"     "$(awk -v u="$flush_us" 'BEGIN{printf "%.3f", u/1000}')" \
        "flush_min_ms"      "$(awk -v u="$flush_lo" 'BEGIN{printf "%.3f", u/1000}')" \
        "flush_max_ms"      "$(awk -v u="$flush_hi" 'BEGIN{printf "%.3f", u/1000}')" \
        "flush_spread_ratio" "$flush_spread" \
        "flush_ci95_half_width_pct" "$flush_ci" \
        "flush_MB_per_sec"  "$flush_mb" \
        "load_time_ms"      "$(awk -v u="$load_us" 'BEGIN{printf "%.3f", u/1000}')" \
        "load_min_ms"       "$(awk -v u="$load_lo" 'BEGIN{printf "%.3f", u/1000}')" \
        "load_max_ms"       "$(awk -v u="$load_hi" 'BEGIN{printf "%.3f", u/1000}')" \
        "load_spread_ratio" "$load_spread" \
        "load_ci95_half_width_pct" "$load_ci" \
        "load_MB_per_sec"   "$load_mb" \
        "file_size_bytes"   "$file_size" \
        "keys_restored"     "$size_result" \
        "harness_rpc_us"    "$floor_us" \
        "usable"            "$([[ "$verdict" == "ok" ]] && echo 1 || echo 0)" \
        "verdict"           "$verdict"

    socketley_cmd stop bench_cache
    sleep 0.5
    socketley_cmd remove bench_cache
    rm -f "$persist_file"
}

# Test 6: Large value throughput (multiple sizes)
#
# Routed through cache_pipe_measure like tests 7-10, and for the reason the
# header of this file gives: the old fixed 2000 SETs per run were a 0.28 ms
# window at 64 B and 3.0 ms at 4 KB — the five-millisecond scale the header
# condemns — and with 3 rounds under Student t that came out as a CI95 of
# ±61..±107%, wider than any effect worth chasing.  The probe sizes the count
# to CACHE_PIPE_TARGET_MS instead, and the row prints the window it achieved.
#
# The keyspace stays at 2000 keys whatever count the probe picks: the measured
# stream cycles i % 2000, so every run overwrites the same keys in place and
# the store holds a flat 2000*size bytes.  Store growth and persistence were
# both ruled out for the old version; cycling keeps both rulings true.
#
# The count floor and cap scale with the value size, in bytes rather than ops:
# the defaults are tuned for short commands, and at 4 KB the 200k-op floor
# alone would be an 820 MB command stream.  The floor holds the probe's first
# stream near 13 MB at every size; the cap holds the largest stream a run can
# write near 512 MB (~131k ops at 4 KB), which this box's 11 GiB carries but a
# smaller one might not.  A cap-bound run gets a shorter window than the
# target and says so in its printed harness share.
test_large_values() {
    local value_sizes=(64 256 1024 4096)
    local test_name="cache_large_values"

    log_section "Test: Large Value Throughput"

    ensure_clean
    wait_for_port_free $CACHE_PORT
    socketley_cmd create cache bench_cache -p $CACHE_PORT --write-buffer "$CACHE_PIPE_WRITE_BUFFER" -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; ensure_clean; return 1; }
    sleep 0.5

    local size min_ops max_ops mkval prog setup
    for size in "${value_sizes[@]}"; do
        # The value is baked into the program text — cache_pipe_measure passes
        # only -v n.  sprintf's width builds it in one step.
        mkval='v = sprintf("%'"$size"'s", ""); gsub(/ /, "x", v);'
        prog='BEGIN{ '"$mkval"' for (i = 0; i < n; i++) printf "SET key%d %s\n", i % 2000, v }'
        # Every measured run starts from the same store: all 2000 keys already
        # present at this size, so run 1 pays the same overwrite the rest do.
        setup='BEGIN{ '"$mkval"' for (i = 0; i < 2000; i++) printf "SET key%d %s\n", i, v }'

        min_ops=$(( 12800000 / size ))
        max_ops=$(( 536870912 / size ))
        [[ $max_ops -gt $CACHE_PIPE_MAX_OPS ]] && max_ops=$CACHE_PIPE_MAX_OPS

        CACHE_PIPE_MIN_OPS=$min_ops CACHE_PIPE_MAX_OPS=$max_ops \
            cache_pipe_report "$test_name" "SET ${size}B" "set_${size}b_ops_sec" \
                "$prog" "$setup"
    done

    socketley_cmd stop bench_cache
    sleep 0.5
    socketley_cmd remove bench_cache
}

# Tests 7-10: pipelined data-structure throughput.
#
# The instrument these four share is cache_pipe_measure(), and the header of
# this file records what it replaced and what each part of it is for.  Every row
# prints the operation count it chose, the window it achieved, the share of that
# window the harness accounts for, the spread over repetitions and the smallest
# difference that repetition count could resolve.  A row that cannot answer says
# REFUSED and is written to the JSON with usable:0 rather than being left out.
#
# Every measured run is preceded by an untimed reset, so the five repetitions
# measure one thing five times instead of measuring a structure that grows.

# Test 7: LIST operations
test_list_throughput() {
    local test_name="cache_list_throughput"

    log_section "Test: LIST Throughput"

    ensure_clean
    wait_for_port_free $CACHE_PORT
    socketley_cmd create cache bench_cache -p $CACHE_PORT --write-buffer "$CACHE_PIPE_WRITE_BUFFER" -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; ensure_clean; return 1; }
    sleep 0.5

    cache_pipe_report "$test_name" "LPUSH" "lpush_ops_sec" \
        'BEGIN{ for(i=1;i<=n;i++) printf "LPUSH benchlist item%d\n", i }' \
        'BEGIN{ print "DEL benchlist" }'
    # A LPOP against an empty list is answered without removing anything, and
    # faster.  Each run therefore gets a list of exactly n items put there
    # outside its window; a run that popped an empty list would be publishing
    # the speed of refusing to pop.
    cache_pipe_report "$test_name" "LPOP" "lpop_ops_sec" \
        'BEGIN{ for(i=1;i<=n;i++) print "LPOP benchlist" }' \
        'BEGIN{ print "DEL benchlist"; for(i=1;i<=n;i++) printf "LPUSH benchlist item%d\n", i }'

    socketley_cmd stop bench_cache
    sleep 0.5
    socketley_cmd remove bench_cache
}

# Test 8: SET data structure operations
test_set_ds_throughput() {
    local test_name="cache_set_ds_throughput"

    log_section "Test: SET (data structure) Throughput"

    ensure_clean
    wait_for_port_free $CACHE_PORT
    socketley_cmd create cache bench_cache -p $CACHE_PORT --write-buffer "$CACHE_PIPE_WRITE_BUFFER" -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; ensure_clean; return 1; }
    sleep 0.5

    # The set is dropped before each run.  Re-adding a member the set already
    # holds is a lookup and a return, not an insert -- a different operation
    # under the same label, and a faster one.
    cache_pipe_report "$test_name" "SADD" "sadd_ops_sec" \
        'BEGIN{ for(i=1;i<=n;i++) printf "SADD benchset member%d\n", i }' \
        'BEGIN{ print "DEL benchset" }'
    # Every lookup hits, so this is the cost of finding a member rather than the
    # cost of failing to.
    cache_pipe_report "$test_name" "SISMEMBER" "sismember_ops_sec" \
        'BEGIN{ srand(42); for(i=1;i<=n;i++) printf "SISMEMBER benchset member%d\n", int(rand()*n)+1 }' \
        'BEGIN{ print "DEL benchset"; for(i=1;i<=n;i++) printf "SADD benchset member%d\n", i }'

    socketley_cmd stop bench_cache
    sleep 0.5
    socketley_cmd remove bench_cache
}

# Test 9: HASH operations
test_hash_throughput() {
    local test_name="cache_hash_throughput"

    log_section "Test: HASH Throughput"

    ensure_clean
    wait_for_port_free $CACHE_PORT
    socketley_cmd create cache bench_cache -p $CACHE_PORT --write-buffer "$CACHE_PIPE_WRITE_BUFFER" -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; ensure_clean; return 1; }
    sleep 0.5

    cache_pipe_report "$test_name" "HSET" "hset_ops_sec" \
        'BEGIN{ for(i=1;i<=n;i++) printf "HSET benchhash field%d value%d\n", i, i }' \
        'BEGIN{ print "DEL benchhash" }'
    cache_pipe_report "$test_name" "HGET" "hget_ops_sec" \
        'BEGIN{ srand(42); for(i=1;i<=n;i++) printf "HGET benchhash field%d\n", int(rand()*n)+1 }' \
        'BEGIN{ print "DEL benchhash"; for(i=1;i<=n;i++) printf "HSET benchhash field%d value%d\n", i, i }'

    socketley_cmd stop bench_cache
    sleep 0.5
    socketley_cmd remove bench_cache
}

# Test 10: TTL operations
test_ttl_throughput() {
    local test_name="cache_ttl_throughput"

    log_section "Test: TTL Throughput"

    ensure_clean
    wait_for_port_free $CACHE_PORT
    socketley_cmd create cache bench_cache -p $CACHE_PORT --write-buffer "$CACHE_PIPE_WRITE_BUFFER" -s
    wait_for_port $CACHE_PORT || { log_error "Cache failed to start"; ensure_clean; return 1; }
    sleep 0.5

    # EXPIRE against a key that does not exist is a lookup and a refusal, not an
    # expiry, so the keys are written in the untimed setup before every run.
    # Setting an expiry on a key that already has one is the same work, which is
    # why the setup does not have to remove them again.
    cache_pipe_report "$test_name" "EXPIRE" "expire_ops_sec" \
        'BEGIN{ for(i=1;i<=n;i++) printf "EXPIRE ttlkey%d 3600\n", i }' \
        'BEGIN{ for(i=1;i<=n;i++) printf "SET ttlkey%d val%d\n", i, i }'
    cache_pipe_report "$test_name" "TTL" "ttl_ops_sec" \
        'BEGIN{ srand(42); for(i=1;i<=n;i++) printf "TTL ttlkey%d\n", int(rand()*n)+1 }' \
        'BEGIN{ for(i=1;i<=n;i++) printf "SET ttlkey%d val%d\nEXPIRE ttlkey%d 3600\n", i, i, i }'

    socketley_cmd stop bench_cache
    sleep 0.5
    socketley_cmd remove bench_cache
}

# Main
run_cache_benchmarks() {
    log_section "CACHE RUNTIME BENCHMARKS"

    ensure_socketley_bench || return 1

    log_bench "START" "cache_set_throughput"
    # A million each, because these are pipelined rates above 10 M/s: 10,000
    # finished in under a millisecond and one run of GET read 1.6x the others.
    test_set_throughput     1000000 64
    log_bench "DONE" "cache_set_throughput"
    fresh_daemon

    log_bench "START" "cache_get_throughput"
    test_get_throughput     1000000
    log_bench "DONE" "cache_get_throughput"
    fresh_daemon

    log_bench "START" "cache_mixed_workload"
    test_mixed_workload     1000000
    log_bench "DONE" "cache_mixed_workload"
    fresh_daemon

    log_bench "START" "cache_concurrent_access"
    test_concurrent_access  20 50000
    log_bench "DONE" "cache_concurrent_access"
    fresh_daemon

    log_bench "START" "cache_persistence"
    test_persistence        10000
    log_bench "DONE" "cache_persistence"
    fresh_daemon

    log_bench "START" "cache_large_values"
    test_large_values
    log_bench "DONE" "cache_large_values"
    fresh_daemon

    log_bench "START" "cache_list_throughput"
    test_list_throughput
    log_bench "DONE" "cache_list_throughput"
    fresh_daemon

    log_bench "START" "cache_set_ds_throughput"
    test_set_ds_throughput
    log_bench "DONE" "cache_set_ds_throughput"
    fresh_daemon

    log_bench "START" "cache_hash_throughput"
    test_hash_throughput
    log_bench "DONE" "cache_hash_throughput"
    fresh_daemon

    log_bench "START" "cache_ttl_throughput"
    test_ttl_throughput
    log_bench "DONE" "cache_ttl_throughput"

    echo "]" >> "$RESULTS_FILE"
    cleanup_cache_pipe_work

    log_section "Cache Benchmark Complete"
    log_success "Results saved to: $RESULTS_FILE"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_binary || exit 1
    check_dependencies || exit 1
    setup_cleanup_trap
    if should_manage_daemon; then
        start_daemon || exit 1
    fi
    run_cache_benchmarks
fi
