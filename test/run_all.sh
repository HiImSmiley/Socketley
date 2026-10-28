#!/usr/bin/env bash
# Run all socketley tests (unit + integration)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
# Which build to test, so both halves of the suite run against the same
# binaries -- setting only SOCKETLEY_BIN would have moved the integration half
# and left the unit half on bin/Release.
SOCKETLEY_CONFIG="${SOCKETLEY_CONFIG:-Release}"
BIN_DIR="${SOCKETLEY_BIN_DIR:-$ROOT/bin/$SOCKETLEY_CONFIG}"
PASS=0; FAIL=0

# Prefer the local build over an installed socketley, because the installed one
# can be months old and the suite would report success for code that was never
# executed.
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
# The port window is claimed once and exported, held for the whole run so two
# suites cannot swap windows underneath each other between tests.
. "$SCRIPT_DIR/integration/lib_ports.sh"
echo "Port window:    $SL_PORT_BASE-$((SL_PORT_BASE + 1999))"

# A HOME of this run's own, because the state directory comes from HOME and a
# shared daemon started with only the socket overridden persists into the
# developer's real inventory -- and restores their was_running runtimes onto
# real ports in the middle of a test run.
# What the caller installed under their own home stays found -- python's --user packages, the Pebble the ACME tests
# default to, the compatibility clients -- since the private HOME below is for socketley's state alone.
export PYTHONUSERBASE="${PYTHONUSERBASE:-$HOME/.local}"
export PEBBLE_DIR="${PEBBLE_DIR:-$HOME/socketley-perf/acme}"
export SOCKETLEY_COMPAT_BIN="${SOCKETLEY_COMPAT_BIN:-$HOME/socketley-perf/compat/bin}"
SUITE_HOME=$(mktemp -d "${TMPDIR:-/tmp}/socketley-suite-home.XXXXXX") || {
    echo "ERROR: could not create a private HOME for this run"; exit 1; }
export HOME="$SUITE_HOME"

# The run-level socket is private and nothing is started on it, because one
# fixed path coupled the runs -- removed by whichever finished first, with a
# daemon on it the other run's sweep was entitled to kill.
export SOCKETLEY_SOCKET="$SUITE_HOME/suite.sock"

# Two facts together, neither sufficient alone: the executable read out of
# /proc/<pid>/exe, which an argument cannot spoof, and the port window read out
# of the environment, because two runs in one worktree share the executable and
# each sweep SIGKILLed the other's daemons.
own_daemon_pids() {
    local d p out=""
    for d in /proc/[0-9]*; do
        p=${d#/proc/}
        [ "/proc/$p/exe" -ef "$SYS_BIN" ] || continue
        # A brace group rather than a redirection on the command, because
        # redirections apply left to right and bash reports a vanished process
        # as an error this walk races by construction.
        case "$( { tr '\0' ' ' <"/proc/$p/cmdline"; } 2>/dev/null )" in
            *" daemon "*|*" daemon") ;;
            *) continue ;;
        esac
        # Not `grep -q`, because it exits at its first match and under pipefail
        # the pipeline reports 141, taking the no-match branch precisely when
        # it matched.
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

# A suite that leaves daemons behind poisons the next thing anyone measures, so
# this is the backstop for a test that dies before its own trap can run.
cleanup() {
    sweep_own_daemons
    # After the daemons are gone and never before, guarded on the name it was
    # created with so an unset value cannot turn this into rm -rf on somebody's
    # home directory.
    case "${SUITE_HOME:-}" in
        */socketley-suite-home.*) rm -rf "$SUITE_HOME" ;;
    esac
}
trap cleanup EXIT

# A file that skipped some or all of itself exits 0 like one that ran, so what it said it skipped is collected and
# named at the end instead of being counted as a pass in silence.
SKIPPED=""
FAILED=""
note_skips() {   # name, log
    local line
    line=$(grep -m1 -E '^[[:space:]]*SKIP' "$2" 2>/dev/null | sed 's/^[[:space:]]*//' | cut -c1-120)
    [ -n "$line" ] && SKIPPED="$SKIPPED$1: $line"$'\n'
    return 0
}

run_test() {
    local name="$1" log
    shift
    log=$(mktemp)
    if "$@" 2>&1 | tee "$log"; [ "${PIPESTATUS[0]}" = 0 ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1)); FAILED="$FAILED$name"$'\n'
    fi
    note_skips "$name" "$log"
    rm -f "$log"
    echo ""
}

echo "=============================="
echo " Socketley Test Suite"
echo "=============================="
echo ""

# Unit tests
echo "--- Unit Tests ---"
echo ""
# Every unit-test binary the build produced rather than a list of names,
# because a list goes stale silently -- and it globs the output directory, so a
# stale binary from a deleted project is run and now named.

# The expectation is read from premake5.lua, because a run started mid-build
# found two binaries missing and reported 172 passed and exited 0 -- a partial
# glob being the case that produces a green run rather than an obvious one.
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
# An unreadable premake5.lua makes the expectation vacuous and would wave
# through exactly the build this check exists to stop, so it is fatal.
if [ "$unit_expected" -eq 0 ]; then
    echo "ERROR: no test_* projects found in $ROOT/premake5.lua."
    echo "       This check derives what the build owes from that file; with no"
    echo "       expectation it cannot tell a complete build from half of one."
    exit 1
fi
# Before a single test runs, because a shortfall makes every number below it
# meaningless and ten minutes of integration tests would produce a total to be
# thrown away.
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
# Not a fuzz run but a deterministic replay of each committed corpus, here for
# cost and reach rather than a single uncaught defect -- globbed with the
# corpus derived from the target's name, where a missing mapping is an error
# rather than a skip.
echo "--- Fuzz Corpus Replay ---"
echo ""
FUZZ_CORPUS_DIR="$SCRIPT_DIR/fuzz/corpus"
# The same partial-glob check as the unit section and from the same authority,
# because these link last of all and a run started mid-build loses them first.
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
        fuzz_raft_msg)       corpus=raftmsg ;;
        fuzz_s3_sigv4)       corpus=s3sigv4 ;;
        fuzz_bucket_policy)  corpus=bucketpolicy ;;
        fuzz_storage_parsers) corpus=storageparsers ;;
        fuzz_dns)            corpus=dns ;;
        fuzz_db)             corpus=db ;;
        fuzz_mqtt)           corpus=mqtt ;;
        fuzz_mail)           corpus=mail ;;
        fuzz_tunnel_mux)     corpus=tunnelmux ;;
        fuzz_ssh_cert)       corpus=sshcert ;;
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

# Anything a previous run left on this window, which can only be a daemon whose
# ports are gone but which still holds a state directory that no longer exists.
sweep_own_daemons
sleep 0.2

export BIN="$SYS_BIN"

# ─── Which file left a daemon behind ────────────────────────────────────────
# The leak question is asked after every file and attributed to the file that
# produced it, because the sweeps tidy up silently and the damage lands on
# whatever runs next -- printed rather than counted as a failure, since a
# library check that can turn 151 files red gets switched off.
LEAKED_FILES=""
check_leaked_daemons() {
    local name=$1 pids i
    pids=$(own_daemon_pids)
    [ -n "$pids" ] || return 0
    # A daemon on its way out is not a leak, so only a file that already looks
    # like it leaked pays this second of grace.
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

# ─── Side by side, then alone ───────────────────────────────────────────────
# Most files bring their own daemon, HOME and port window, and spend their
# time waiting on timeouts with fifteen cores idle -- run one after another the
# pair of suites took three hours.  So those run as many at a time as there are
# free port windows, the slowest first, and each claims a window of its own
# rather than inheriting this run's; a file that shares the suite's daemon, or
# says `# suite: quiet` because it measures time, CPU or the machine's memory,
# runs alone afterwards exactly as before.  Every file's output is printed in
# glob order once the parallel pass is over, and counted the same way.
. "$SCRIPT_DIR/lib_suite.sh"
PAR_LIST=$(mktemp); SERIAL_LIST=$(mktemp); RESDIR=$(mktemp -d)
for script in "$SCRIPT_DIR"/integration/test_*.sh; do
    [ -f "$script" ] || continue
    if suite_wants_serial "$script"; then echo "$script" >> "$SERIAL_LIST"
    else echo "$script" >> "$PAR_LIST"; fi
done
PAR="${SUITE_PAR:-$(suite_free_windows)}"
[ "$PAR" -gt "$(nproc)" ] && PAR=$(nproc)
if [ "$SOCKETLEY_CONFIG" = Sanitize ] && [ -z "${SUITE_PAR:-}" ]; then
    MEM_PAR=$(suite_sanitize_slots)
    [ "$PAR" -gt "$MEM_PAR" ] && PAR=$MEM_PAR
fi
# Marks every process of this run, so a daemon a parallel file leaked can be
# found without the window it claimed.
export SOCKETLEY_SUITE_RUN="$SUITE_HOME"

run_one_parallel() {   # file -> its log, exit code and seconds in RESDIR
    local f=$1 name t0 rc tries=0
    name=$(basename "$f")
    t0=$(date +%s)
    while :; do
        ( unset SL_PORT_BASE; timeout 900 bash "$f" ) >"$RESDIR/$name.log" 2>&1
        rc=$?
        # A window taken by a file that is still tearing down is a wait, not a
        # failure -- counted as one, it emptied the whole list in seconds.
        if [ "$rc" = 2 ] && grep -q 'no free 2000-port window' "$RESDIR/$name.log" &&
           [ "$tries" -lt 300 ]; then
            tries=$((tries + 1)); sleep 1; continue
        fi
        break
    done
    echo "$rc" > "$RESDIR/$name.rc"
    echo $(( $(date +%s) - t0 )) > "$RESDIR/$name.secs"
}
export -f run_one_parallel
export RESDIR

if [ "$PAR" -gt 1 ]; then
    echo "  ($(wc -l < "$PAR_LIST") files $PAR at a time, $(wc -l < "$SERIAL_LIST") alone after them)"
    echo ""
    suite_longest_first "$PAR_LIST" | xargs -d '\n' -n1 -P"$PAR" bash -c 'run_one_parallel "$1"' _
    # A file red beside others and green alone is load, not this tree -- but it
    # is named at the end, because a race that load exposes is still a race.
    ALONE_ONLY=""
    while IFS= read -r script; do
        name=$(basename "$script")
        cat "$RESDIR/$name.log" 2>/dev/null
        note_skips "$name" "$RESDIR/$name.log"
        if [ "$(cat "$RESDIR/$name.rc" 2>/dev/null)" = 0 ]; then PASS=$((PASS+1)); echo ""; continue; fi
        echo "  -- red beside $PAR others; run again alone:"
        if bash "$script" 2>&1; then PASS=$((PASS+1)); ALONE_ONLY="$ALONE_ONLY $name"
        else FAIL=$((FAIL+1)); FAILED="$FAILED$name"$'\n'; fi
        echo ""
    done < "$PAR_LIST"
    # What a parallel file left running, found by this run's mark.
    for d in /proc/[0-9]*; do
        p=${d#/proc/}
        [ "/proc/$p/exe" -ef "$SYS_BIN" ] || continue
        { tr '\0' '\n' <"/proc/$p/environ"; } 2>/dev/null \
            | grep -x "SOCKETLEY_SUITE_RUN=$SUITE_HOME" >/dev/null || continue
        echo "WARNING: a parallel file left pid $p running; killed"
        kill -9 "$p" 2>/dev/null || true
    done
else
    cat "$PAR_LIST" >> "$SERIAL_LIST"
fi

while IFS= read -r script; do
    name=$(basename "$script" .sh)
    t0=$(date +%s)
    run_test "$name" bash "$script"
    echo $(( $(date +%s) - t0 )) > "$RESDIR/$name.sh.secs"
    check_leaked_daemons "$name"
done < <(sort "$SERIAL_LIST")
suite_save_durations "$RESDIR"
rm -rf "$PAR_LIST" "$SERIAL_LIST" "$RESDIR"

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

# Did anything drive the run-level socket, which nothing should, and is named
# rather than ignored -- because a test sharing a daemon is how this suite used
# to delete runtimes it never created.
if [ -e "$SOCKETLEY_SOCKET" ]; then
    echo "WARNING: a test used this run's fallback socket, $SOCKETLEY_SOCKET."
    echo "         Every file here is supposed to isolate before its first CLI"
    echo "         command; one of them did not, and shared a daemon with"
    echo "         whichever files ran around it."
    echo ""
fi

if [ -n "${ALONE_ONLY:-}" ]; then
    echo "─── green only when run alone ─────────────────────────────────────"
    for f in $ALONE_ONLY; do echo "    $f"; done
    echo "    Each failed beside the parallel pass and passed on its own.  Counted"
    echo "    as passed; read each one's first log above before calling it load."
    echo ""
fi

if [ -n "$SKIPPED" ]; then
    echo "─── files that skipped something ──────────────────────────────────"
    printf '%s' "$SKIPPED" | sed 's/^/    /'
    echo "    Counted as passed, since each ran what it could; what it could not is"
    echo "    a missing tool or permission on this machine, and the line says which."
    echo ""
fi

if [ -n "$FAILED" ]; then
    echo "─── failed ────────────────────────────────────────────────────────"
    printf '%s' "$FAILED" | sed 's/^/    /'
    echo ""
fi

echo "=============================="
echo " Summary: $PASS passed, $FAIL failed"
echo "=============================="

exit "$FAIL"
