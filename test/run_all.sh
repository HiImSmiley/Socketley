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

# ─── A port window of this run's own ────────────────────────────────────────
#
# Claimed here, once, and exported: every port any test binds is derived from
# it.  Holding it for the whole run rather than per file is what stops two
# suites swapping windows underneath each other between tests — see
# integration/lib_ports.sh for what a window is, how it is claimed, and the
# eight-files-deep failure that fixed ports produced when two runs overlapped.
#
# A test run on its own claims its own window the same way, so this is a
# convenience for the suite rather than the mechanism.
. "$SCRIPT_DIR/integration/lib_ports.sh"
echo "Port window:    $SL_PORT_BASE-$((SL_PORT_BASE + 1999))"

# A HOME of this run's own, because the socket is not the only path the
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

# ─── The socket nothing is supposed to use ──────────────────────────────────
#
# This was /tmp/socketley-test.sock — one path, shared by every run on the
# machine — and a daemon was started on it for the whole suite to share.
#
# Nothing has driven that daemon since ad06685 gave each file its own.  Checked
# rather than assumed: on 8d0658b, with the suite mid-run, the shared daemon's
# state directory held nothing but `.adopted` and `ps -a` listed no runtime, and
# every file in integration/ either calls daemon_isolate or exports a socket of
# its own before its first CLI command.  What the shared daemon still did was
# couple the runs — one fixed path, removed by whichever run finished first, and
# a daemon on it that the other run's sweep was entitled to kill.
#
# So it is private, and nothing is started on it.  It survives only as the value
# a test inherits before it isolates; the check after the test loop reports it if
# one ever arrives here, rather than letting a test quietly share a daemon with
# whatever runs next.
export SOCKETLEY_SOCKET="$SUITE_HOME/suite.sock"

# ─── Kill the daemons belonging to THIS run, and no others ──────────────────
#
# Two facts together, and neither is sufficient alone.
#
# The executable, read out of /proc/<pid>/exe.  `pkill -f "$SYS_BIN daemon"`,
# which this used to be, matches any process whose command line merely contains
# that string — including a shell running this script with the path in its
# arguments — and an -f match one character too broad kills the run doing the
# killing.  The exe link cannot be spoofed by an argument.
#
# And the port window, read out of the environment.  The exe alone was still too
# broad, and that cost a day on 2026-08-06: an agent verifying in a worktree and
# a suite run in the same worktree share the executable, so each run's sweep
# SIGKILLed the other's daemons.  What it looks like is `Killed` in the log,
# failures wandering between tests and the score falling run to run — a leak, or
# the OOM killer, or anything but two runs of the same file.  SL_PORT_BASE is
# exported above and inherited by every daemon any test of this run starts, and
# it is different in every concurrent run by construction.
#
# The environment check cannot hit this script or the test shells, because they
# do not satisfy the exe test — which is the trap the -f form fell into.
sweep_own_daemons() {
    local d p
    for d in /proc/[0-9]*; do
        p=${d#/proc/}
        [ "/proc/$p/exe" -ef "$SYS_BIN" ] || continue
        case "$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null)" in
            *" daemon "*|*" daemon") ;;
            *) continue ;;
        esac
        # NOT `grep -q`: it exits at its first match and SIGPIPEs the writer,
        # and under `set -o pipefail` the pipeline then reports 141 — taking the
        # "no match" branch precisely when it matched.  lib_daemon.sh carries the
        # same warning for the same reason.
        { tr '\0' '\n' <"/proc/$p/environ"; } 2>/dev/null \
            | grep -x "SL_PORT_BASE=$SL_PORT_BASE" >/dev/null || continue
        kill -9 "$p" 2>/dev/null || true
    done
}

# A suite that leaves daemons behind poisons the next thing anyone measures,
# including its own next run: the survivors sit on the ports the next run wants
# and answer for state directories that have been deleted underneath them.  The
# individual tests each clean up their own daemon; this is the backstop for the
# case where one of them dies before its trap can run.
cleanup() {
    sweep_own_daemons
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
# premake5.lua defines eleven.  test_conn_transfer, test_managed_runtime and the
# four SDK tests were compiled by every build and run by nothing — not here, not
# in ci.yml, not in nightly.yml.  A list of names goes stale the moment somebody
# adds a test and forgets one file, and it goes stale silently, which is the one
# property a test runner must not have.  The integration half has always
# globbed; this half now does too.
#
# It globs the output directory rather than premake5.lua, so anything stale left
# in there is run too — which is how the count above was first written down as
# thirteen: bin/Release still held test_single_header and test_single_header_lua
# from February, with no project, no source and nothing that rebuilds them.
# They passed, and passing said nothing about this tree.
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

# Integration tests — each file brings up its own daemon
echo "--- Integration Tests ---"
echo ""

# Anything a previous run left behind on this window.  It can only be a daemon
# whose ports are already gone, because a window with a live listener in it is
# not a window this run would have been given — but it would still be holding a
# state directory that no longer exists, and it costs nothing to be sure.
sweep_own_daemons
sleep 0.2

export BIN="$SYS_BIN"

for script in "$SCRIPT_DIR"/integration/test_*.sh; do
    [ -f "$script" ] || continue
    name=$(basename "$script" .sh)
    run_test "$name" bash "$script"
done

# Did anything drive the run-level socket?
#
# Nothing should: every file in integration/ brings up a daemon of its own, on a
# socket out of mktemp.  If one stops doing that, its first CLI command
# auto-starts a daemon on the path exported at the top, and the evidence is that
# the path now exists.  Named rather than ignored — a test sharing a daemon with
# whatever ran before it is how this suite used to delete runtimes it had never
# created, and the report for that was twenty red assertions in an innocent file.
if [ -e "$SOCKETLEY_SOCKET" ]; then
    echo "WARNING: a test used this run's fallback socket, $SOCKETLEY_SOCKET."
    echo "         Every file here is supposed to isolate before its first CLI"
    echo "         command; one of them did not, and shared a daemon with"
    echo "         whichever files ran around it."
    echo ""
fi

echo "=============================="
echo " Summary: $PASS passed, $FAIL failed"
echo "=============================="

exit "$FAIL"
