#!/usr/bin/env bash
# Run all socketley tests (unit + integration)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
# Which build to test.  Defaults to Release, which is what this suite has always
# used; the nightly sanitizer job sets SOCKETLEY_CONFIG=Sanitize so that both
# halves of the suite — the unit tests and the integration tests — run against
# the same instrumented binaries.  Setting only SOCKETLEY_BIN would have moved
# the integration half and left the unit half pointing at bin/Release, which is
# the split this variable exists to prevent.
SOCKETLEY_CONFIG="${SOCKETLEY_CONFIG:-Release}"
BIN_DIR="${SOCKETLEY_BIN_DIR:-$ROOT/bin/$SOCKETLEY_CONFIG}"
PASS=0; FAIL=0
DAEMON_PID=""

# Prefer the local build over an installed socketley.
#
# The unit tests always run out of bin/Release, so picking the installed binary
# for the integration tests meant the two halves of this suite could exercise
# different builds.  Worse, the installed binary can be months old: the suite
# would then report success for code that was never executed, which is exactly
# the kind of false confidence a test run must not produce.  Set SOCKETLEY_BIN
# explicitly to test an installed build on purpose.
if [ -n "${SOCKETLEY_BIN:-}" ]; then
    SYS_BIN="$SOCKETLEY_BIN"
elif [ -x "$BIN_DIR/socketley" ]; then
    SYS_BIN="$BIN_DIR/socketley"
else
    SYS_BIN="$(command -v socketley 2>/dev/null)"
fi
[ -x "$SYS_BIN" ] || { echo "ERROR: socketley not found (tried \$SOCKETLEY_BIN, $BIN_DIR/, PATH)"; exit 1; }
echo "Testing binary: $SYS_BIN"

# Use a fixed test socket path (avoids system-mode path resolution issues)
export SOCKETLEY_SOCKET="/tmp/socketley-test.sock"

cleanup() {
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -f "$SOCKETLEY_SOCKET"
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

# Kill any existing daemon of the binary this run is about to use.
#
# Matching on "socketley daemon" alone matches every socketley daemon on the
# machine, including ones belonging to a different checkout — two suites running
# from separate worktrees killed each other's daemon mid-test, and the resulting
# failures pointed at whatever test happened to be running rather than at the
# collision. The binary path is what distinguishes them.
pkill -f "$SYS_BIN daemon" 2>/dev/null || true
sleep 0.2
rm -f "$SOCKETLEY_SOCKET"

export BIN="$SYS_BIN"
"$BIN" daemon 2>/dev/null &
DAEMON_PID=$!
sleep 0.5

if [ ! -S "$SOCKETLEY_SOCKET" ]; then
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
