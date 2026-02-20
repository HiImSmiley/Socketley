#!/usr/bin/env bash
# Run all socketley tests (unit + integration)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
BIN_DIR="$ROOT/bin/Release"
PASS=0; FAIL=0
DAEMON_PID=""

cleanup() {
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -f /tmp/socketley.sock
}
trap cleanup EXIT

run_test() {
    local name="$1"
    shift
    if "$@" 2>&1; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
    fi
    echo ""
}

echo "=============================="
echo " Socketley Test Suite"
echo "=============================="
echo ""

# Unit tests
echo "--- Unit Tests ---"
echo ""
run_test "command_hashing" "$BIN_DIR/test_command_hashing"
run_test "cache_store" "$BIN_DIR/test_cache_store"
run_test "resp_parser" "$BIN_DIR/test_resp_parser"
run_test "name_resolver" "$BIN_DIR/test_name_resolver"
run_test "ws_parser" "$BIN_DIR/test_ws_parser"

# Integration tests — start shared daemon
echo "--- Integration Tests ---"
echo ""

# Kill any existing daemon
pkill -f "socketley daemon" 2>/dev/null || true
sleep 0.2
rm -f /tmp/socketley.sock

export BIN="$BIN_DIR/socketley"
"$BIN" daemon 2>/dev/null &
DAEMON_PID=$!
sleep 0.5

if [ ! -S /tmp/socketley.sock ]; then
    echo "ERROR: daemon failed to start"
    exit 1
fi

for script in "$SCRIPT_DIR"/integration/test_*.sh; do
    [ -f "$script" ] || continue
    name=$(basename "$script" .sh)
    run_test "$name" bash "$script"
done

echo "=============================="
echo " Summary: $PASS passed, $FAIL failed"
echo "=============================="

exit "$FAIL"
