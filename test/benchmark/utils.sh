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
# Use system-installed binary if available (run as root), else dev binary
if [[ -x "/usr/bin/socketley" ]] && [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    SOCKETLEY_BIN="/usr/bin/socketley"
    IPC_SOCKET="/run/socketley/socketley.sock"
    USE_SYSTEMD=1
else
    SOCKETLEY_BIN="${PROJECT_ROOT}/bin/Release/socketley"
    IPC_SOCKET="/tmp/socketley.sock"
    USE_SYSTEMD=0
fi
RESULTS_DIR="${SCRIPT_DIR}/results"
DAEMON_PID_FILE="/tmp/socketley_bench_daemon.pid"

# Ensure results directory exists
mkdir -p "$RESULTS_DIR"

# Generate timestamp for this run
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

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

    # Kill any existing daemon
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

# Stop daemon
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
            sleep 0.5
            # Force kill if still running
            kill -9 "$pid" 2>/dev/null
        fi
        rm -f "$DAEMON_PID_FILE"
    fi

    # Also kill by name as fallback
    pkill -f "socketley daemon" 2>/dev/null

    # Remove socket
    rm -f "$IPC_SOCKET"

    log_info "Daemon stopped"
}

# Execute socketley command
socketley_cmd() {
    "$SOCKETLEY_BIN" "$@" 2>&1
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

# Get high-resolution timestamp in milliseconds
get_time_ms() {
    echo $(($(date +%s%N) / 1000000))
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

# Write result to JSON
write_json_result() {
    local test_name=$1
    local output_file=$2
    shift 2

    echo "{" >> "$output_file"
    echo "  \"test\": \"$test_name\"," >> "$output_file"
    echo "  \"timestamp\": \"$(date -Iseconds)\"," >> "$output_file"

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

# Trap for cleanup on exit
setup_cleanup_trap() {
    if [[ "${SOCKETLEY_BENCH_PARENT:-}" != "1" ]]; then
        trap 'cleanup_runtimes; stop_daemon' EXIT INT TERM
    else
        trap 'cleanup_runtimes' EXIT INT TERM
    fi
}

# Check if daemon should be managed by this script
should_manage_daemon() {
    [[ "${SOCKETLEY_BENCH_PARENT:-}" != "1" ]]
}
