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
SYS_BIN=$(readlink -f "$SYS_BIN")
echo "Testing binary: $SYS_BIN"

# Use a fixed test socket path (avoids system-mode path resolution issues)
export SOCKETLEY_SOCKET="/tmp/socketley-test.sock"

# ...and a HOME of this run's own, because the socket is not the only path the
# daemon resolves.  SOCKETLEY_SOCKET moves the socket; the state directory comes
# from HOME, so a shared daemon started with only the socket overridden persists
# into the developer's real ~/.local/share/socketley/runtimes.  Measured, with
# nothing but SOCKETLEY_SOCKET set:
#
#     $ socketley create server sl_probe_tmp -p 19883 -s
#     $ ls ~/.local/share/socketley/runtimes/
#     sl_probe_tmp.json
#
# Two ways that costs somebody a morning.  A runtime a test fails to remove is
# left in the developer's own inventory, where their own daemon restores it on
# its next start.  And in the other direction, a developer whose runtimes are
# marked was_running has them restored BY THIS SUITE at the moment the shared
# daemon comes up — real services binding their real ports, in the middle of a
# test run, reported afterwards as a port collision in whichever test was
# unlucky.  The suite has been chasing exactly that shape of contamination.
#
# The directory is this run's alone and goes with it.  The individual tests that
# call daemon_isolate already set their own HOME and are unaffected.
SUITE_HOME=$(mktemp -d "${TMPDIR:-/tmp}/socketley-suite-home.XXXXXX") || {
    echo "ERROR: could not create a private HOME for this run"; exit 1; }
export HOME="$SUITE_HOME"

# Kill every daemon running THIS binary.
#
# Identity is the executable behind the process, read out of /proc/<pid>/exe,
# never a command-line pattern.  `pkill -f "$SYS_BIN daemon"`, which is what this
# used to be, matches any process whose command line merely contains that string
# — including a shell running this script with the path in its arguments — and an
# -f match one character too broad kills the run doing the killing.  The exe link
# cannot be spoofed by an argument and distinguishes checkouts and worktrees from
# each other, which is the property the old pattern was reaching for.
sweep_own_daemons() {
    local p exe
    for p in $(pgrep -x socketley 2>/dev/null || true); do
        case "$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null)" in
            *" daemon "*|*" daemon") ;;
            *) continue ;;
        esac
        exe=$(readlink -f "/proc/$p/exe" 2>/dev/null) || continue
        [ "$exe" = "$SYS_BIN" ] || continue
        kill -9 "$p" 2>/dev/null || true
    done
}

# A suite that leaves daemons behind poisons the next thing anyone measures,
# including its own next run: the survivors sit on the ports the next run wants
# and answer for state directories that have been deleted underneath them.  The
# individual tests each clean up their own daemon; this is the backstop for the
# case where one of them dies before its trap can run.
cleanup() {
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    sweep_own_daemons
    rm -f "$SOCKETLEY_SOCKET"
    # After the daemons are gone, never before: the private HOME holds their
    # state directory, and removing it out from under a live daemon is the
    # "answers for a state directory that has been deleted underneath it" case
    # this backstop exists to prevent.  Guarded on the name it was created with
    # so that an unset or inherited value cannot turn this into rm -rf on
    # somebody's home directory.
    case "${SUITE_HOME:-}" in
        */socketley-suite-home.*) rm -rf "$SUITE_HOME" ;;
    esac
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
# Every unit-test binary the build produced, rather than a list of five.
#
# The build produces thirteen.  test_conn_transfer, test_managed_runtime, the
# four SDK tests and the two single-header tests were compiled by every build
# and run by nothing — not here, not in ci.yml, not in nightly.yml.  A list of
# names goes stale the moment somebody adds a test and forgets one file, and it
# goes stale silently, which is the one property a test runner must not have.
# The integration half has always globbed; this half now does too.
unit_found=0
for t in "$BIN_DIR"/test_*; do
    [ -f "$t" ] && [ -x "$t" ] || continue
    unit_found=$((unit_found + 1))
    run_test "$(basename "$t" | sed 's/^test_//')" "$t"
done

# An empty glob would otherwise sail through this section reporting nothing
# wrong, which is how a build that produced no tests passes a test suite.
if [ "$unit_found" -eq 0 ]; then
    echo "ERROR: no unit test binaries found in $BIN_DIR"
    exit 1
fi

# Integration tests — start shared daemon
echo "--- Integration Tests ---"
echo ""

# Kill any existing daemon of the binary this run is about to use — including
# anything a previous run of this suite left behind.
#
# Killing every socketley daemon on the machine would take out ones belonging to
# a different checkout; two suites running from separate worktrees killed each
# other's daemon mid-test, and the resulting failures pointed at whatever test
# happened to be running rather than at the collision.  The executable is what
# distinguishes them.
sweep_own_daemons
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
