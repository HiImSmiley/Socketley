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
own_daemon_pids() {
    local d p out=""
    for d in /proc/[0-9]*; do
        p=${d#/proc/}
        [ "/proc/$p/exe" -ef "$SYS_BIN" ] || continue
        # Brace group, as on the environ read below, and not `tr ... <file
        # 2>/dev/null`.  Redirections are applied left to right, so in that
        # form the INPUT one is attempted while stderr is still the terminal
        # and bash reports a vanished process as an error the run cannot act
        # on:  "run_all.sh: line 118: /proc/425042/cmdline: No such file".
        # This walk races every exiting daemon by construction.
        case "$( { tr '\0' ' ' <"/proc/$p/cmdline"; } 2>/dev/null )" in
            *" daemon "*|*" daemon") ;;
            *) continue ;;
        esac
        # NOT `grep -q`: it exits at its first match and SIGPIPEs the writer,
        # and under `set -o pipefail` the pipeline then reports 141 — taking the
        # "no match" branch precisely when it matched.  lib_daemon.sh carries the
        # same warning for the same reason.
        { tr '\0' '\n' <"/proc/$p/environ"; } 2>/dev/null \
            | grep -x "SL_PORT_BASE=$SL_PORT_BASE" >/dev/null || continue
        out="$out $p"
    done
    printf '%s' "${out# }"
}

# Split out from the sweep so the same two facts can be used to ASK the
# question as well as to act on it -- see the per-file leak check in the
# integration loop, which needs the pids rather than their absence.
sweep_own_daemons() {
    local p
    for p in $(own_daemon_pids); do
        kill -9 "$p" 2>/dev/null || true
    done
    return 0
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
# premake5.lua defines fourteen.  test_conn_transfer, test_managed_runtime and the
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
# They passed, and passing said nothing about this tree.  They are still run,
# and are now named as they go past -- see the check immediately below, which
# reads premake5.lua for the expectation the glob cannot supply.

# ─── What the build was supposed to produce ─────────────────────────────────
#
# The glob above answers "what is in the directory", and that is not the same
# question as "did everything get built".  Measured on 2026-08-20: a Sanitize
# run started while `make` was still linking found bin/Sanitize without
# test_managed_runtime and test_worker_map in it -- they link last -- and the
# suite reported `172 passed, 0 failed` and exited 0.  Both binaries pass
# standalone.  A run that skipped two whole test binaries is indistinguishable
# from a run that had nothing to skip, because the only number that moved was a
# total nobody has a reference value for.
#
# So the expectation is read from premake5.lua, which is the one authority on
# what this tree defines, and a shortfall is fatal rather than quiet.  The same
# reasoning as the empty-glob check below it, applied to a PARTIAL glob: an
# empty one was already caught, and the partial one is the case that produces a
# green run instead of an obvious one.
#
# Derived, never listed -- for the reason the glob is a glob.  A hand-kept
# expected count would go stale the moment somebody adds a project, and it would
# go stale by reporting a PASS.
#
# It stays a check on names, not a replacement for the glob: the glob still runs
# whatever is there, so a stale binary from a deleted project is still executed
# and is now also NAMED, which is what the comment above wanted and could not
# have.
expected_targets() {   # PREFIX -> the project names premake5.lua defines
    sed -n "s/^project \"\($1[A-Za-z0-9_]*\)\".*/\1/p" "$ROOT/premake5.lua"
}

# missing_targets PREFIX  -> names defined by the build but absent from BIN_DIR
missing_targets() {
    local n missing=""
    for n in $(expected_targets "$1"); do
        [ -f "$BIN_DIR/$n" ] && [ -x "$BIN_DIR/$n" ] && continue
        missing="$missing $n"
    done
    printf '%s' "${missing# }"
}

UNIT_TARGETS=$(expected_targets test_ | tr '\n' ' ')
unit_expected=$(printf '%s' "$UNIT_TARGETS" | wc -w)
unit_missing=$(missing_targets test_)
# premake5.lua unreadable, moved, or its project syntax changed: the expectation
# is then vacuous and would wave through exactly the build this check exists to
# stop.  Fatal, because a check that cannot fail is worse than no check.
if [ "$unit_expected" -eq 0 ]; then
    echo "ERROR: no test_* projects found in $ROOT/premake5.lua."
    echo "       This check derives what the build owes from that file; with no"
    echo "       expectation it cannot tell a complete build from half of one."
    exit 1
fi
# Before a single test runs, not after.  A shortfall makes every number below
# it meaningless, and ten minutes of integration tests on top of a half-linked
# build is ten minutes spent producing a total that must be thrown away.
if [ -n "$unit_missing" ]; then
    echo "ERROR: premake5.lua defines $unit_expected unit test targets and"
    echo "       $BIN_DIR holds fewer.  Missing:"
    for m in $unit_missing; do echo "         $m"; done
    echo "       A build that is still linking looks exactly like this: the glob"
    echo "       finds what has been written so far, every one of them passes,"
    echo "       and the run reports a smaller total as a success.  Finish the"
    echo "       build (or delete the stale directory) and run again."
    exit 1
fi
echo "  ($unit_expected unit targets defined in premake5.lua, all present)"
echo ""

unit_found=0
for t in "$BIN_DIR"/test_*; do
    [ -f "$t" ] && [ -x "$t" ] || continue
    unit_found=$((unit_found + 1))
    case " $UNIT_TARGETS " in
        *" $(basename "$t") "*) ;;
        *) echo "NOTE: $(basename "$t") is in $BIN_DIR but no project builds it;"
           echo "      it is run below, and what it passes says nothing about this tree." ;;
    esac
    run_test "$(basename "$t" | sed 's/^test_//')" "$t"
done

# An empty glob would otherwise sail through this section reporting nothing
# wrong, which is how a build that produced no tests passes a test suite.
if [ "$unit_found" -eq 0 ]; then
    echo "ERROR: no unit test binaries found in $BIN_DIR"
    exit 1
fi

# ─── Fuzz corpora, replayed ─────────────────────────────────────────────────
#
# Not a fuzz run: no mutation, no coverage feedback, no time budget.  Each
# target is handed its committed corpus once, deterministically, and every
# FUZZ_CHECK in it has to hold.  47 seconds for all ten, against a suite that
# takes ten minutes.
#
# It is here because these targets assert properties nothing a developer runs
# was asserting: two parsers over one grammar must agree, a returned view must
# point inside the bytes the parse claims to have consumed, a rewritten request
# must not gain a header.  Until now those were reachable only from CI.
#
# What was measured, stated exactly, because the first version of this comment
# overstated it and had to be corrected.  Making the two RESP parsers disagree
# by one byte — the defect fuzz_resp.cpp names as its purpose — is caught by
# fuzz_resp in 289ms.  It is ALSO caught by five integration files (RESP2
# protocol, cache with --lua, the RESP relay ordering test, cache-in-a-worker,
# and a worker asks the daemon).  So that mutation does not on its own prove
# the fuzz targets catch anything the suite could not; what it proves is that
# `test_resp_parser`, the unit test named for this parser, passes 42 of 42 on a
# build where the two parsers describe different wire formats.
#
# The case for running them here is therefore cost and reach, not a single
# uncaught defect: 47 seconds, and the property assertions above have no other
# local reader.  A subtler divergence — one the integration fixtures happen not
# to send — is exactly what a corpus is for, and nobody had a way to find out
# locally whether they had written one.
#
# Globbed, with the corpus derived from the target's own name, for the reason
# the unit section above gives: a hand-kept list of ten goes stale silently and
# the entry it loses is the one that mattered.  A target with no mapping, or a
# mapping to a corpus that is not there, is an ERROR rather than a skip — the
# replay driver already refuses to run without input, on the grounds that a
# fuzzer with no input is a green check mark attached to nothing, and skipping
# quietly here would put that back.
echo "--- Fuzz Corpus Replay ---"
echo ""
FUZZ_CORPUS_DIR="$SCRIPT_DIR/fuzz/corpus"
# The same partial-glob check as the unit section, for the same reason and from
# the same authority.  These link last of all, so a run started mid-build loses
# them first.
FUZZ_TARGETS=$(expected_targets fuzz_ | tr '\n' ' ')
fuzz_expected=$(printf '%s' "$FUZZ_TARGETS" | wc -w)
fuzz_missing=$(missing_targets fuzz_)
if [ "$fuzz_expected" -eq 0 ]; then
    echo "ERROR: no fuzz_* projects found in $ROOT/premake5.lua."
    exit 1
fi
if [ -n "$fuzz_missing" ]; then
    echo "ERROR: premake5.lua defines $fuzz_expected fuzz targets and $BIN_DIR"
    echo "       holds fewer.  Missing:"
    for m in $fuzz_missing; do echo "         $m"; done
    echo "       A target that is not there replays no corpus and reports no"
    echo "       finding, which is what a target that found nothing also does."
    exit 1
fi
echo "  ($fuzz_expected fuzz targets defined in premake5.lua, all present)"
echo ""
fuzz_found=0
for f in "$BIN_DIR"/fuzz_*; do
    [ -f "$f" ] && [ -x "$f" ] || continue
    fname=$(basename "$f")
    case "$fname" in
        fuzz_resp)           corpus=resp ;;
        fuzz_ws_frame)       corpus=ws ;;
        fuzz_http_request)   corpus=http ;;
        fuzz_http_response)  corpus=httpresp ;;
        fuzz_cache_ops)      corpus=cache ;;
        fuzz_client_ops)     corpus=client ;;
        fuzz_server_ops)     corpus=server ;;
        fuzz_proxy_ops)      corpus=proxy ;;
        fuzz_proxy_tunnel)   corpus=proxytunnel ;;
        fuzz_event_loop)     corpus=eventloop ;;
        fuzz_lua_json)       corpus=luajson ;;
        *)
            echo "ERROR: $fname has no corpus mapping in run_all.sh."
            echo "       A target nothing replays is a target that does not run."
            exit 1 ;;
    esac
    if [ ! -d "$FUZZ_CORPUS_DIR/$corpus" ]; then
        echo "ERROR: $fname maps to corpus '$corpus', which is not in $FUZZ_CORPUS_DIR"
        exit 1
    fi
    fuzz_found=$((fuzz_found + 1))
    run_test "${fname#fuzz_} corpus" timeout 300 "$f" "$FUZZ_CORPUS_DIR/$corpus"
done

if [ "$fuzz_found" -eq 0 ]; then
    echo "ERROR: no fuzz targets found in $BIN_DIR"
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

# ─── Which file left a daemon behind ────────────────────────────────────────
#
# The sweep at the top and the one in the EXIT trap keep the MACHINE clean, and
# between them they have hidden this for as long as they have existed: a test
# that leaks its daemon is invisible, because the backstop tidies up after it
# without saying so, and the damage lands on whatever runs next.
#
# It is a real generator, not a hypothetical.  Measured on 2026-08-20 in
# test_cache_publish_subscriber_reachable.sh: `OUT=$(run_arm ...)` runs the
# function in a SUBSHELL, so the SOCKETLEY_DPID that daemon_start exports there
# never reaches the trap in the parent shell, and the file's own cleanup finds
# nothing to stop.  Four processes survived each invocation -- two daemons and
# two workers -- holding their ports.  What that looks like several runs later
# is `FATAL: no free 2000-port window` from lib_ports.sh, attributed to
# whichever file was unlucky enough to be next.
#
# So the question is asked after every file, and the answer is attributed to the
# file that produced it.  The check costs one /proc walk per file, the same walk
# the sweep already does; only a file that leaks pays the extra second.
#
# Printed rather than counted as a failure, for the reason lib_daemon.sh gives
# where it prints invariant violations: a library check that can turn 151 files
# red is a check somebody switches off.  The summary at the end names the files,
# which is the number that was missing -- the leak itself was always visible in
# `ss`, and never attributable.
LEAKED_FILES=""
check_leaked_daemons() {
    local name=$1 pids i
    pids=$(own_daemon_pids)
    [ -n "$pids" ] || return 0
    # A daemon on its way out is not a leak.  daemon_stop sends SIGTERM and
    # waits, but the file's own trap can return before the kernel has reaped
    # the process, and a check with no grace would report every well-behaved
    # test as a leaking one.  Only a file that already looks like it leaked
    # pays this second.
    for i in 1 2 3 4 5 6 7 8 9 10; do
        sleep 0.1
        pids=$(own_daemon_pids)
        [ -n "$pids" ] || return 0
    done
    echo "WARNING: $name left this run's daemons running: $pids"
    echo "         They hold the ports of window $SL_PORT_BASE, and every file"
    echo "         after this one runs beside them.  Killed here so the rest of"
    echo "         this run is not measuring them."
    LEAKED_FILES="$LEAKED_FILES $name"
    sweep_own_daemons
    echo ""
    return 0
}

for script in "$SCRIPT_DIR"/integration/test_*.sh; do
    [ -f "$script" ] || continue
    name=$(basename "$script" .sh)
    run_test "$name" bash "$script"
    check_leaked_daemons "$name"
done

if [ -n "$LEAKED_FILES" ]; then
    echo "─── files that left a daemon running ──────────────────────────────"
    for f in $LEAKED_FILES; do echo "    $f"; done
    echo "    Each of these ran its cleanup and its daemon survived it.  The"
    echo "    usual cause is a variable the trap needs being assigned inside a"
    echo "    command substitution or another subshell, where it dies with the"
    echo "    subshell -- see the comment at the top of run_arm() in"
    echo "    integration/test_cache_publish_subscriber_reachable.sh."
    echo ""
fi

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
