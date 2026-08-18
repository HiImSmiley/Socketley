#!/bin/bash
# Benchmark utilities - shared functions

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# Use system-installed binary if available (run as root), else dev binary.
# Override with: SOCKETLEY_BIN=/path/to/socketley --dev
if [[ -n "${SOCKETLEY_SOCKET:-}" ]]; then
    # An already-exported SOCKETLEY_SOCKET wins over every branch below.  It is
    # how a run is given a private daemon, and it has to be honoured in both
    # directions: the CLI reads that variable, but start_daemon waits on
    # $IPC_SOCKET, and the two branches below set IPC_SOCKET to
    # /tmp/socketley.sock without exporting anything.  A caller who exported a
    # private socket therefore got a daemon on the private one and a wait on the
    # shared one — and two benchmark runs on this machine then measured, and
    # swept, each other.
    SOCKETLEY_BIN="${SOCKETLEY_BIN:-${PROJECT_ROOT}/bin/Release/socketley}"
    IPC_SOCKET="$SOCKETLEY_SOCKET"
    USE_SYSTEMD=0
elif [[ "${BENCH_DEV:-0}" -eq 1 ]]; then
    SOCKETLEY_BIN="${PROJECT_ROOT}/bin/Release/socketley"
    IPC_SOCKET="/tmp/socketley.sock"
    export SOCKETLEY_SOCKET="$IPC_SOCKET"
    USE_SYSTEMD=0
elif [[ -x "/usr/bin/socketley" ]] && [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    SOCKETLEY_BIN="/usr/bin/socketley"
    IPC_SOCKET="/run/socketley/socketley.sock"
    USE_SYSTEMD=1
else
    SOCKETLEY_BIN="${PROJECT_ROOT}/bin/Release/socketley"
    IPC_SOCKET="/tmp/socketley.sock"
    USE_SYSTEMD=0
fi
SOCKETLEY_BENCH="${PROJECT_ROOT}/bin/Release/socketley_bench"
# The echoing backend every round-trip measurement needs.  No --mode of a plain
# server runtime replies on its own, so a benchmark pointed at one without this
# times its own writes; see the file's own header and `enum metric_kind` in
# bench.c.  Named once here because five scripts need the same path and a
# private copy in each is a fifth chance to point at nothing.
BENCH_ECHO_LUA="${SCRIPT_DIR}/echo.lua"
RESULTS_DIR="${SCRIPT_DIR}/results"
# Keyed to the socket, so a run with a private SOCKETLEY_SOCKET also gets a
# private pid file.  One fixed path meant the second run overwrote the first
# run's pid and then stop_daemon killed a daemon it had never started.
DAEMON_PID_FILE="/tmp/socketley_bench_daemon$(printf '%s' "$IPC_SOCKET" | md5sum | cut -c1-8).pid"

# Ensure results directory exists
mkdir -p "$RESULTS_DIR"

# Timestamp for this run.  Exported so sub-scripts spawned by run_all.sh
# inherit the parent's value: generate_summary() looks for result files named
# with the parent's TIMESTAMP, and a freshly generated one in each child never
# matches (the child starts a second or more later, leaving the tables empty).
TIMESTAMP="${TIMESTAMP:-$(date +"%Y%m%d_%H%M%S")}"
export TIMESTAMP

# --fresh flag: restart daemon between every test
BENCH_FRESH_DAEMON="${BENCH_FRESH_DAEMON:-0}"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN} $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
}

# Check if binary exists
check_binary() {
    if [[ ! -x "$SOCKETLEY_BIN" ]]; then
        log_error "socketley binary not found at $SOCKETLEY_BIN"
        log_info "Run: cd ${PROJECT_ROOT}/make && make config=release_x64"
        return 1
    fi
    log_success "Binary found: $SOCKETLEY_BIN"
    return 0
}

# Check required tools
check_dependencies() {
    local missing=()

    for tool in nc timeout bc awk; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done

    # Check for wrk or hey (optional, for HTTP benchmarks)
    if command -v wrk &> /dev/null; then
        HTTP_BENCH_TOOL="wrk"
    elif command -v hey &> /dev/null; then
        HTTP_BENCH_TOOL="hey"
    else
        HTTP_BENCH_TOOL=""
        log_warn "Neither 'wrk' nor 'hey' found - HTTP proxy benchmarks will use basic method"
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing[*]}"
        return 1
    fi

    log_success "All required dependencies found"
    return 0
}

# Check if k6 is available
check_k6() {
    if command -v k6 &> /dev/null; then
        log_success "k6 found: $(k6 version 2>/dev/null || echo 'unknown version')"
        return 0
    else
        log_warn "k6 not found — install from https://grafana.com/docs/k6/latest/set-up/install-k6/"
        return 1
    fi
}

# Start daemon
start_daemon() {
    if [[ "$USE_SYSTEMD" -eq 1 ]]; then
        log_info "Starting socketley daemon (systemd)..."
        systemctl restart socketley.service 2>/dev/null
        # Wait for IPC socket to appear
        local wait_count=0
        while [[ ! -S "$IPC_SOCKET" ]] && [[ $wait_count -lt 50 ]]; do
            sleep 0.1
            ((wait_count++))
        done
        if [[ -S "$IPC_SOCKET" ]]; then
            log_success "Daemon started (systemd)"
            return 0
        else
            log_error "Daemon failed to start"
            return 1
        fi
    fi

    # In dev mode, stop the systemd service if it's running to avoid port conflicts
    systemctl stop socketley.service 2>/dev/null || true

    # Kill any existing dev daemon
    stop_daemon 2>/dev/null

    log_info "Starting socketley daemon..."
    "$SOCKETLEY_BIN" daemon &
    local pid=$!
    echo "$pid" > "$DAEMON_PID_FILE"

    # Wait for IPC socket to appear
    local wait_count=0
    while [[ ! -S "$IPC_SOCKET" ]] && [[ $wait_count -lt 50 ]]; do
        sleep 0.1
        ((wait_count++))
    done

    if [[ -S "$IPC_SOCKET" ]]; then
        log_success "Daemon started (PID: $pid)"
        return 0
    else
        log_error "Daemon failed to start"
        return 1
    fi
}

# Stop daemon — multi-stage kill with verification
stop_daemon() {
    if [[ "$USE_SYSTEMD" -eq 1 ]]; then
        systemctl stop socketley.service 2>/dev/null
        log_info "Daemon stopped (systemd)"
        return
    fi

    if [[ -f "$DAEMON_PID_FILE" ]]; then
        local pid=$(cat "$DAEMON_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            # Wait up to 3s for graceful exit
            local i
            for i in $(seq 1 30); do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.1
            done
            # Force kill if still alive
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null
                sleep 0.3
            fi
            # Final check
            if kill -0 "$pid" 2>/dev/null; then
                log_warn "Daemon PID $pid still alive after SIGKILL"
            fi
        fi
        rm -f "$DAEMON_PID_FILE"
    fi

    # Fallback: every process running our exact binary — the daemon and the
    # worker processes it forked.
    #
    # This was `pkill -9 -f "$SOCKETLEY_BIN daemon"`, which names one process of
    # however many are running: a worker is exec'd with `proxy-worker` on its
    # command line, not `daemon`, so with two runtimes started it finds one of
    # three.  Measured, it still left nothing behind — a worker whose control
    # socket has closed ends itself, which proxy_worker.cpp's run() does on
    # purpose so that a worker cannot go on serving a proxy nobody supervises.
    # So the old sweep was correct by someone else's care rather than its own,
    # and it is replaced for what it says, not for damage it did.
    #
    # Identity by command-line pattern is the part that is wrong here for the
    # usual reason: `-f` matches any process whose arguments merely carry the
    # string, and record_throughput.sh starts the daemon as
    # `taskset -c "$DCPU" "$BIN" daemon`, whose command line carries it exactly.
    # The executable behind the pid cannot be spoofed by an argument, reaches
    # the workers by identity rather than by inheritance, and still keeps a
    # systemd-managed daemon out of it — that one runs the installed binary,
    # not this build, which is the protection the old comment was reaching for
    # with "do not use pkill -x socketley".
    #
    # The " (deleted)" suffix below is not cosmetic.  Rebuild the binary while a
    # daemon from the previous build is still running and the kernel reports
    # that process's exe as "<path> (deleted)", because the inode it was started
    # from no longer carries that name.  An exact compare then stops recognising
    # the very daemon this tree started: the sweep steps over it, reports
    # success, and the next run finds its ports held by a process it has decided
    # belongs to somebody else.  Rebuilding between benchmark runs is the normal
    # case, so this was the normal case.  Observed exactly that way — a daemon
    # left holding 23020-23022 after a rebuild, with the fixture setup reporting
    # only "backend did not come up".
    local own_exe p exe
    own_exe=$(readlink -f "$SOCKETLEY_BIN" 2>/dev/null)
    if [ -n "$own_exe" ]; then
        for p in $(pgrep -x socketley 2>/dev/null || true); do
            exe=$(readlink -f "/proc/$p/exe" 2>/dev/null) || continue
            exe=${exe% (deleted)}
            if [ "$exe" = "$own_exe" ]; then
                kill -9 "$p" 2>/dev/null || true
            fi
        done
    fi
    sleep 0.3

    # Verify nothing of ours survived — the same identity test, so it answers
    # for the workers as well as for the daemon rather than for the daemon
    # alone.
    if [ -n "$own_exe" ]; then
        for p in $(pgrep -x socketley 2>/dev/null || true); do
            exe=$(readlink -f "/proc/$p/exe" 2>/dev/null) || continue
            exe=${exe% (deleted)}
            if [ "$exe" = "$own_exe" ]; then
                log_warn "A daemon or worker process still exists after cleanup"
                break
            fi
        done
    fi

    # Remove socket and stale state
    rm -f "$IPC_SOCKET"

    log_info "Daemon stopped"
}

# Execute socketley command (with 10s timeout to prevent hangs on dead daemon)
socketley_cmd() {
    timeout 10 "$SOCKETLEY_BIN" "$@" 2>&1
}

# Restart daemon — full stop + start for clean state between benchmark suites.
restart_daemon() {
    log_info "Restarting daemon for clean state..."
    cleanup_runtimes 2>/dev/null || true
    sleep 0.5
    stop_daemon 2>/dev/null || true
    sleep 1
    start_daemon || { log_warn "Daemon failed to restart"; return 1; }
}

# Cleanup all runtimes
cleanup_runtimes() {
    log_info "Cleaning up runtimes..."
    local runtimes=$(socketley_cmd ls 2>/dev/null | tail -n +2 | awk '{print $2}')
    for name in $runtimes; do
        socketley_cmd stop "$name" 2>/dev/null
        sleep 0.5
        socketley_cmd remove "$name" 2>/dev/null
    done
}

# Wait for port to be available
wait_for_port() {
    local port=$1
    local max_wait=${2:-100}
    local count=0

    while ! nc -z localhost "$port" 2>/dev/null && [[ $count -lt $max_wait ]]; do
        sleep 0.1
        ((count++))
    done

    if nc -z localhost "$port" 2>/dev/null; then
        sleep 0.2  # Extra settle time
        return 0
    fi
    return 1
}

# Wait for port to be free (not listening)
wait_for_port_free() {
    local port=$1
    local max_wait=${2:-50}
    local count=0

    while nc -z localhost "$port" 2>/dev/null && [[ $count -lt $max_wait ]]; do
        sleep 0.1
        ((count++))
    done
}

# ─── Clocks ─────────────────────────────────────────────────────────────────
#
# get_time_ms() is a fork.  `$(date +%s%N)` starts a process, and on this box a
# `date` costs 6.8 ms wall from fork to reap and about 1.5 ms from the fork to
# the moment it reads the clock -- most of it loading the timezone; the same
# call with TZ=UTC costs 1.3 ms.  Measured directly, the interval this reports
# for two calls with nothing between them is 1..2 ms.
#
# So every window timed with it carries a bias of one to two milliseconds on top
# of a resolution of one millisecond, and the cache data-structure tests timed
# windows of five to nine.  What they published -- 833,333 and 1,000,000 ops/sec
# for lpush and lpop -- is 5000/6 and 5000/5: two integers a millisecond apart,
# printed to six significant figures.  Nothing in the output said so.
#
# EPOCHREALTIME is a bash variable, so reading it forks nothing: 11 us per read
# in a loop, and 3 us for the interval between two reads.  That is the floor of
# what a bash-timed window can resolve, and it is 300x better than the fork.
#
# Both are kept.  get_time_ms() is still correct for the things it is used for
# elsewhere -- waiting, sleeping, second-scale phases -- and rewriting those
# would be a change with no measurement behind it.  Anything timing work that
# finishes in under a second uses get_time_us().
BENCH_CLOCK_KIND="epochrealtime"
if [[ -z "${EPOCHREALTIME:-}" ]]; then
    BENCH_CLOCK_KIND="date"
fi

# Microseconds since the epoch, into the variable NOW_US.  No subshell, no
# fork, no `date`.
#
# It assigns rather than echoes on purpose, and that is not a style choice: a
# function whose value is taken with $( ) is run in a forked subshell, and a
# fork costs about 400 us here.  Measured, the three idioms cost 3 us inlined,
# 11 us through `now_us`, and 267..931 us through `t=$(now_us_echoing)` -- so
# the convenient spelling would have put back two orders of magnitude of the
# very overhead this exists to remove.  Read NOW_US straight after the call.
#
# The digits are pulled out rather than the '.' being replaced, because
# EPOCHREALTIME uses the *locale's* decimal separator: under a locale with
# LC_NUMERIC=de_DE it reads "1787022899,674305", and ${x/./} would then leave
# the comma in place and produce a number bash refuses to do arithmetic on.
NOW_US=0
if [[ "$BENCH_CLOCK_KIND" == "epochrealtime" ]]; then
    now_us() { local t=${EPOCHREALTIME}; NOW_US=${t//[!0-9]/}; }
else
    # bash < 5.0.  A fork per reading, and bench_clock_floor_us() reports it.
    now_us() { NOW_US=$(($(date +%s%N) / 1000)); }
fi

# ─── A port block inside the ephemeral range is a benchmark that breaks itself ─
#
# The connection-per-request HTTP benchmarks in this directory open and close a
# connection per request.  Each close leaves a socket in TIME_WAIT on the client
# side for 60 s, and the client's side is an ephemeral port.  At the rates these
# run, the TIME_WAIT table fills to tcp_max_tw_buckets within a couple of minutes
# -- observed here at 65,527 of 65,536 -- and every ephemeral port is occupied.
#
# A listener whose port falls inside net.ipv4.ip_local_port_range (32768..60999
# on this box) then collides with one of those TIME_WAIT sockets and bind()
# returns EADDRINUSE, for a port nothing is listening on and that `ss -ltn`
# shows as free.  socketley reports that as
#
#     runtime X could not start: the worker did not accept its configuration
#
# which names neither the port nor the cause, and it arrives long after the run
# that caused it.  It cost an hour here before `nc -l` on an obviously unused
# port failed the same way and gave it away.
#
# The suite's own blocks are all below 32768 and are therefore safe by accident
# rather than by design.  This says so out loud, so the next person to point
# BENCH_PORT_BASE somewhere convenient finds out before the run instead of after.
bench_check_port_range() {
    local lo hi p bad=0
    read -r lo hi < /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null || return 0
    [[ -z "$lo" || -z "$hi" ]] && return 0
    for p in "$@"; do
        [[ "$p" =~ ^[0-9]+$ ]] || continue
        if [[ "$p" -ge "$lo" && "$p" -le "$hi" ]]; then
            log_warn "port $p is inside the ephemeral range ($lo..$hi)"
            bad=1
        fi
    done
    if [[ $bad -eq 1 ]]; then
        log_warn "a connection-per-request benchmark fills that range with TIME_WAIT"
        log_warn "sockets, after which these listeners fail to bind with EADDRINUSE"
        log_warn "on ports nothing is listening on. Move the block below $lo."
        return 1
    fi
    return 0
}

# Get high-resolution timestamp in milliseconds
get_time_ms() {
    echo $(($(date +%s%N) / 1000000))
}

# What the clock above costs, in microseconds: the median interval this harness
# reports for a window in which nothing happened.
#
# Measured rather than assumed, once per shell, because it is the number that
# decides whether a window is long enough to mean anything -- and because it is
# different by two orders of magnitude between the two branches of
# get_time_us().  A caller that lengthens a window until the clock stops
# mattering has to be told what "stops mattering" costs here.
bench_clock_floor_us() {
    if [[ -n "${BENCH_CLOCK_FLOOR_US:-}" ]]; then
        printf '%s' "$BENCH_CLOCK_FLOOR_US"
        return
    fi
    local i a b samples=()
    for i in 1 2 3 4 5 6 7 8 9; do
        now_us; a=$NOW_US; now_us; b=$NOW_US
        samples+=( $((b - a)) )
    done
    BENCH_CLOCK_FLOOR_US=$(printf '%s\n' "${samples[@]}" | sort -n | awk '{v[n++]=$1} END{print v[int(n/2)]}')
    [[ "$BENCH_CLOCK_FLOOR_US" -lt 1 ]] && BENCH_CLOCK_FLOOR_US=1
    printf '%s' "$BENCH_CLOCK_FLOOR_US"
}

# The resolution a window of WINDOW_US has, as a percentage: how much of it the
# clock alone could account for.
#
# Printed beside every figure derived from a bash-timed window, and not only
# when it is bad -- a resolution shown only when it is poor teaches the reader
# that its absence means the question was asked and answered well, when in fact
# it means the question was never asked.
bench_resolution_pct() {
    local window_us=$1 floor
    floor=$(bench_clock_floor_us)
    awk -v w="$window_us" -v f="$floor" \
        'BEGIN { if (w <= 0) { print "inf"; exit } printf "%.3f", 100 * f / w }'
}

# Is a window long enough for the clock behind it?  Echoes "ok" or "unresolved".
#
# BENCH_WINDOW_FLOOR_PCT is the largest share of a window the clock is allowed
# to be.  1% is not a statistical claim -- run-to-run spread is far wider than
# that and is reported separately -- it is the line below which the *instrument*
# stops being the reason two numbers differ.  The old cache tests sat at 11..20%
# by this measure and printed six significant figures.
BENCH_WINDOW_FLOOR_PCT=${BENCH_WINDOW_FLOOR_PCT:-1.0}
bench_window_verdict() {
    local window_us=$1
    awk -v p="$(bench_resolution_pct "$window_us")" -v lim="$BENCH_WINDOW_FLOOR_PCT" \
        'BEGIN { print (p == "inf" || p > lim) ? "unresolved" : "ok" }'
}

# Calculate statistics from a file of numbers (one per line)
calc_stats() {
    local file=$1
    awk '
    BEGIN { min = 999999999; max = 0; sum = 0; count = 0 }
    {
        if ($1 < min) min = $1
        if ($1 > max) max = $1
        sum += $1
        values[count++] = $1
    }
    END {
        if (count == 0) {
            print "count=0 min=0 max=0 avg=0 p50=0 p95=0 p99=0"
            exit
        }
        avg = sum / count

        # Sort for percentiles
        asort(values)
        p50 = values[int(count * 0.50)]
        p95 = values[int(count * 0.95)]
        p99 = values[int(count * 0.99)]

        printf "count=%d min=%.2f max=%.2f avg=%.2f p50=%.2f p95=%.2f p99=%.2f\n",
               count, min, max, avg, p50, p95, p99
    }' "$file"
}

# Format duration in human readable
format_duration() {
    local ms=$1
    if [[ $ms -lt 1000 ]]; then
        echo "${ms}ms"
    else
        echo "$(echo "scale=2; $ms / 1000" | bc)s"
    fi
}

# Which tree produced a number.
#
# Every record in results/ carries a test name and a timestamp and nothing that
# says what it was measured against, and the numbers in there span months of
# development under unchanged test names.  What that costs is not hypothetical:
# results/ holds four proxy_http_single_backend records from the night of
# 2026-08-07 reading 674, 685, 710 and 7220 req/sec, all with requests=2000 and
# success=2000.  Grouped by test and by day -- the grouping that is supposed to
# isolate measurement noise -- that is a 10.7x spread, and it was read as one
# until the timestamps were laid against the log: the fast one was taken nine
# seconds after b80eae0, "The two HTTP proxy benchmarks were comparing two bash
# fork rates".  The three slow numbers measured bash forking a subshell and a
# `date` per request.  The fast one measured the proxy.
#
# So the spread was the benchmark being repaired, and nothing in the file said
# so.  This does.  Computed once per run rather than per record, and empty
# rather than absent when there is no checkout to ask -- a packaged benchmark is
# a legitimate way to run these.
bench_build_id() {
    if [[ -n "${BENCH_BUILD_ID:-}" ]]; then
        printf '%s' "$BENCH_BUILD_ID"
        return
    fi
    local id=""
    if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
        id=$(git rev-parse --short HEAD 2>/dev/null || true)
        if [[ -n "$id" ]] && ! git diff --quiet 2>/dev/null; then
            id="${id}-dirty"
        fi
    fi
    BENCH_BUILD_ID="$id"
    printf '%s' "$id"
}

# Write result to JSON
write_json_result() {
    local test_name=$1
    local output_file=$2
    shift 2

    echo "{" >> "$output_file"
    echo "  \"test\": \"$test_name\"," >> "$output_file"
    echo "  \"timestamp\": \"$(date -Iseconds)\"," >> "$output_file"
    echo "  \"build\": \"$(bench_build_id)\"," >> "$output_file"

    local first=true
    while [[ $# -gt 0 ]]; do
        local key=$1
        local value=$2
        shift 2

        if [[ $first == true ]]; then
            first=false
        else
            echo "," >> "$output_file"
        fi

        # Check if value is numeric
        if [[ $value =~ ^[0-9]+\.?[0-9]*$ ]]; then
            echo -n "  \"$key\": $value" >> "$output_file"
        else
            echo -n "  \"$key\": \"$value\"" >> "$output_file"
        fi
    done

    echo "" >> "$output_file"
    echo "}" >> "$output_file"
}

# Print summary table row
print_table_row() {
    printf "│ %-25s │ %12s │ %12s │ %12s │\n" "$1" "$2" "$3" "$4"
}

print_table_header() {
    echo "┌───────────────────────────┬──────────────┬──────────────┬──────────────┐"
    printf "│ %-25s │ %12s │ %12s │ %12s │\n" "Test" "Throughput" "Avg Latency" "P99 Latency"
    echo "├───────────────────────────┼──────────────┼──────────────┼──────────────┤"
}

print_table_footer() {
    echo "└───────────────────────────┴──────────────┴──────────────┴──────────────┘"
}

# Ensure socketley-bench binary is compiled
ensure_socketley_bench() {
    if [[ ! -x "$SOCKETLEY_BENCH" ]]; then
        log_info "Building socketley-bench..."
        (cd "$PROJECT_ROOT" && ./bin/premake5 gmake2 >/dev/null 2>&1 && \
         cd make && make config=release_x64 socketley_bench -j$(nproc) >/dev/null 2>&1) \
            || { log_error "Failed to build socketley-bench"; return 1; }
    fi
    log_success "socketley-bench found: $SOCKETLEY_BENCH"
    return 0
}

# Kill all benchmark-related background processes
cleanup_all() {
    # Kill any python backends (used by proxy bench)
    pkill -9 -f "python3.*socket.*listen" 2>/dev/null || true
    # Kill any lingering nc processes from pipe benchmarks
    pkill -9 -f "nc.*localhost.*1900" 2>/dev/null || true
    # Kill any k6 processes
    pkill -9 -f "k6 run" 2>/dev/null || true
    # Kill any redis-benchmark
    pkill -9 -f "redis-benchmark.*1900" 2>/dev/null || true

    # This tree's socketley_bench, and only this tree's.
    #
    # It was `pkill -9 -f socketley_bench`, which kills every one on the machine
    # — including the one another worktree is halfway through a measurement
    # with.  Two benchmark runs on this box then destroy each other's numbers
    # while both report success, and the damage shows up as a spuriously slow
    # run rather than as an error.  `-f` also matches any shell whose arguments
    # merely carry the string, which is how a sweep reaches its own caller.
    #
    # The executable behind a pid cannot be spoofed by an argument and is
    # per-worktree, so it separates ours from theirs.  The " (deleted)" suffix
    # is stripped for the same reason as in stop_daemon: rebuild the binary and
    # the kernel stops reporting the path the process was started from.
    local bench_exe q qexe
    bench_exe=$(readlink -f "$SOCKETLEY_BENCH" 2>/dev/null)
    if [ -n "$bench_exe" ]; then
        for q in $(pgrep -x socketley_bench 2>/dev/null || true); do
            qexe=$(readlink -f "/proc/$q/exe" 2>/dev/null) || continue
            qexe=${qexe% (deleted)}
            [ "$qexe" = "$bench_exe" ] && kill -9 "$q" 2>/dev/null
        done
    fi
    # Clean up runtimes via IPC (best-effort, daemon might be dead)
    cleanup_runtimes 2>/dev/null || true
    log_bench "CLEANUP" "cleanup_all completed"
}

# Trap for cleanup on exit
setup_cleanup_trap() {
    if [[ "${SOCKETLEY_BENCH_PARENT:-}" != "1" ]]; then
        trap 'cleanup_all; stop_daemon' EXIT INT TERM
    else
        trap 'cleanup_all' EXIT INT TERM
    fi
}

# Check if daemon should be managed by this script
should_manage_daemon() {
    [[ "${SOCKETLEY_BENCH_PARENT:-}" != "1" ]]
}

# Restart daemon fresh (stop → start). Called between tests when --fresh is set.
fresh_daemon() {
    if [[ "$BENCH_FRESH_DAEMON" -ne 1 ]]; then
        return 0
    fi
    log_bench "FRESH" "restarting daemon"
    stop_daemon
    # Clear stale state so restored runtimes don't interfere
    rm -rf /tmp/socketley-runtimes/* /var/lib/socketley/runtimes/* 2>/dev/null || true
    sleep 0.5
    start_daemon
}

# ─── Benchmark safeguards ─────────────────────────────────────────────────────

# Bench log for tracking test progress — survives hangs
BENCH_LOG="${RESULTS_DIR}/bench_${TIMESTAMP}.log"

# Timeout constants (seconds) — hard cap 180s (3 min) per invocation
BENCH_TIMEOUT_CMD=180         # per socketley_bench invocation
BENCH_TIMEOUT_NC=180          # per nc pipeline
BENCH_TIMEOUT_K6=180          # per k6 run
BENCH_TIMEOUT_REDIS=180       # per redis-benchmark run
# How long a run measuring a socketley *server* runtime should last.
#
# Longer than anything the proxy benchmarks use, and it is not caution.  A
# server runtime carries a periodic cost that a short window either catches or
# misses, so short windows disagree with each other about a rate that is not
# changing.  Measured on an --http server with eight keep-alive connections,
# the two window lengths interleaved so both saw the same machine, seven runs
# each: one-second windows spanned 154872..237487 requests a second, eight-
# second windows 153385..194082 — coefficient of variation 16.0% against 8.9%,
# for medians of 170707 and 169763.  The same work, sampled better.
#
# The spread this removes is not the server being erratic: its core stayed at
# 0.99..1.00 in every one of those runs.  It is a sampling artefact of the
# measurement, and reading it as a defect costs an afternoon.
#
# Anything fronting a server inherits a diluted version of it — see
# bench_proxy_http_vs_haproxy.sh, which uses 3000 for that reason.
BENCH_SERVER_RUN_MS=${BENCH_SERVER_RUN_MS:-8000}

# Per bench_*.sh from run_all.sh.  bench_cache.sh alone runs well over three
# minutes (a dozen sub-tests, each restarting the runtime), and when the timeout
# fires mid-write it leaves a truncated JSON file that no longer parses — the
# suite then silently contributes nothing to a comparison.  Individual scripts
# raise this further via BENCH_TIMEOUT_SCRIPT in their own environment.
BENCH_TIMEOUT_SCRIPT=${BENCH_TIMEOUT_SCRIPT:-300}

# Log a timestamped benchmark event to the bench log file.
# The log file is the primary record — always written regardless of
# stdout/stderr redirection.  Also echoes to stderr when visible.
log_bench() {
    local tag=$1
    shift
    local ts
    ts=$(date +"%H:%M:%S")
    local msg="[$ts] [$tag] $*"
    echo "$msg" >> "$BENCH_LOG" 2>/dev/null
    case "$tag" in
        TIMEOUT|FAIL) log_error "$msg" 2>/dev/null || true ;;
        *)            log_info "$msg"  2>/dev/null || true ;;
    esac
}

# Run socketley_bench with timeout — drop-in replacement for "$SOCKETLEY_BENCH"
#
# Exit code 2 means the invocation did not produce a result it stands behind:
# either a run completed fewer operations than it was asked for — such a run did
# not measure throughput, it measured how long it waited — or the repetitions
# disagreed too widely for the figure to mean anything. Both are surfaced here
# rather than swallowed, because both put a number in a results file that reads
# exactly like a good one.
bench_run() {
    timeout "$BENCH_TIMEOUT_CMD" "$SOCKETLEY_BENCH" "$@"
    local rc=$?
    if [[ $rc -eq 124 ]]; then
        log_bench "TIMEOUT" "socketley_bench $*"
    elif [[ $rc -eq 2 ]]; then
        log_bench "UNUSABLE" "socketley_bench $* — run short, or repetitions too far apart to resolve"
    fi
    return $rc
}

# Pipe stdin through nc with timeout (-q0 mode)
bench_nc() {
    local port=$1
    timeout "$BENCH_TIMEOUT_NC" nc -q0 localhost "$port"
    local rc=$?
    if [[ $rc -eq 124 ]]; then
        echo "[$(date +%H:%M:%S)] [TIMEOUT] nc -q0 localhost:$port" >> "$BENCH_LOG" 2>/dev/null
    fi
    return $rc
}
