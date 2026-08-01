# A daemon of one's own.
#
# Not a test — run_all.sh globs test_*.sh, so this file is only ever sourced.
#
# ─── WHAT THIS REPLACES ─────────────────────────────────────────────────────
#
# Twenty-four tests in this directory opened with some spelling of
#
#     "$BIN" daemon 2>/dev/null &
#     sleep 0.3
#
# and set no SOCKETLEY_SOCKET at all, so they resolved the default path.  In a
# dev tree that is /tmp/socketley.sock — one path, shared by every checkout,
# every worktree and every hand-started daemon on the machine.  What that line
# actually does is therefore not "start a daemon": if anything already holds
# that socket, the new process exits immediately and the test spends the rest of
# its life driving somebody else's daemon.
#
# The bill for that is not hypothetical.  A foreign daemon holding
# /tmp/socketley.sock turns test_cache.sh into this:
#
#     runtime already exists: testcache      <- create refused, swallowed by || true
#       FAIL [SET]: got '', expected 'ok'    <- nothing was ever listening on 19150
#       ... 20 more ...
#     (foreign daemon's inventory afterwards: empty)
#
# Every assertion red against a binary with nothing wrong with it, and — worse —
# the trap at the end ran `stop testcache; remove testcache` against the foreign
# daemon and destroyed a runtime this test did not create.  A suite that can
# delete another workload's runtimes is not measuring anything; it is a hazard
# that occasionally reports numbers.
#
# So each test gets its own socket, its own state directory and its own daemon
# process, and none of them can see any of the others.  This is the same
# arrangement the proxy tests already make inline (test_proxy_routing.sh has the
# long form and the reasoning); it is a library because twenty-four copies of a
# cleanup sweep is twenty-four chances to get one of them subtly wrong.
#
# Usage:
#
#     . "$(dirname "$0")/lib_daemon.sh"
#     daemon_isolate cache            # before anything touches the daemon
#     cleanup() { ...; daemon_stop; } # daemon_stop LAST: it deletes the state dir
#     trap cleanup EXIT
#     daemon_start "$BIN"

# daemon_isolate TAG
#
# Claim a private socket, state directory and log.  Must be called before the
# first CLI command, because every CLI command except `daemon`, `version` and
# `help` auto-starts a daemon against whatever SOCKETLEY_SOCKET says at the time.
#
# HOME is part of the isolation, not decoration: the state directory is derived
# from it, and two tests sharing one state directory share runtime names, the
# was_running auto-restart, and each other's leftovers.
daemon_isolate() {
    local tag=${1:-test}
    SOCKETLEY_TMPD=$(mktemp -d "/tmp/socketley-$tag-XXXXXX")
    export HOME="$SOCKETLEY_TMPD/home"
    export SOCKETLEY_SOCKET="$SOCKETLEY_TMPD/daemon.sock"
    mkdir -p "$HOME"
    SOCKETLEY_DLOG="$SOCKETLEY_TMPD/daemon.log"
    SOCKETLEY_DPID=""
}

# daemon_start BIN [daemon args...]
#
# Start this test's daemon and wait until it is actually serving.
#
# The wait is on the daemon's own "daemon started" line, never on a poll with a
# CLI command: a CLI command issued before the socket answers starts a second
# daemon of its own, which is a race against the one just launched and a leaked
# process when it loses.  The line is printed after the IPC socket is bound and
# after any persisted state is restored, so it means ready rather than alive.
#
# A daemon that never comes up is fatal, not a failed assertion.  Everything
# after this point would otherwise be measuring the machine rather than the
# build, which is the failure mode this whole file exists to remove — and an
# assertion can be counted, argued with, and waved through as flaky.
daemon_start() {
    local bin=$1; shift
    "$bin" daemon "$@" >>"$SOCKETLEY_DLOG" 2>&1 &
    SOCKETLEY_DPID=$!
    local i
    for i in $(seq 1 100); do
        grep -q "daemon started" "$SOCKETLEY_DLOG" 2>/dev/null && break
        sleep 0.1
    done
    if [ ! -S "$SOCKETLEY_SOCKET" ] || ! kill -0 "$SOCKETLEY_DPID" 2>/dev/null; then
        echo "  FATAL: this test's own daemon never came up on $SOCKETLEY_SOCKET;"
        echo "         nothing below would be measuring this build."
        tail -5 "$SOCKETLEY_DLOG" 2>/dev/null | sed 's/^/         /'
        exit 2
    fi
    return 0
}

# daemon_stop
#
# Kill this test's daemon and delete everything it owned.  Call it last in
# cleanup: it removes the state directory, so anything that still wants to talk
# to the daemon has to have run already.
#
# Killing $SOCKETLEY_DPID is not enough on its own.  Every CLI command except
# `daemon`, `version` and `help` auto-starts a daemon when the socket does not
# answer, forking and setsid-ing one detached from this shell — so a `stop` or
# `remove` in a cleanup that runs after the daemon has already gone resurrects
# it, and that copy outlives the test for good.  The sweep below is what catches
# it.
#
# Matched by exact process name and by this run's socket, never by a
# command-line pattern: `pgrep -f 'socketley daemon'` also matches any shell
# whose own command line carries that string — including the test runner — and
# an -f match one character too broad kills the run doing the matching.  The
# socket path comes from mktemp, so the environ check can only ever hit daemons
# belonging to this run.
daemon_stop() {
    if [ -n "${SOCKETLEY_DPID:-}" ]; then
        kill "$SOCKETLEY_DPID" 2>/dev/null || true
        local i
        for i in $(seq 1 50); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
        kill -9 "$SOCKETLEY_DPID" 2>/dev/null || true
        wait "$SOCKETLEY_DPID" 2>/dev/null || true
    fi
    daemon_sweep "${SOCKETLEY_SOCKET:-}"
    [ -n "${SOCKETLEY_TMPD:-}" ] && rm -rf "$SOCKETLEY_TMPD"
    return 0
}

# daemon_alive SOCKET
#
# True when a daemon process is actually serving SOCKET.  `[ -S "$sock" ]` is not
# the same question: the socket file outlives the process that bound it, so a
# test that cleans up with a CLI command "because the socket is still there"
# reaches a dead daemon and auto-starts a live one in its place.
#
# The /proc reads are wrapped in `{ …; } 2>/dev/null` rather than written as
# `tr … <"/proc/$p/…" 2>/dev/null`.  In the latter the shell opens the redirect
# before tr exists to have its stderr redirected, so the shell's own complaint
# goes to the terminal: every sweep over a process belonging to another user
# printed "Permission denied" for /proc/<pid>/environ, and every sweep over a
# pid that exited mid-loop printed "No such file or directory".  Both are
# expected here — this walks every socketley on the machine — and both landed in
# exactly the output someone is reading because something has already gone
# wrong.  The brace group redirects the group's stderr first, so the open is
# covered too.
daemon_alive() {
    local sock=$1 p
    [ -n "$sock" ] || return 1
    for p in $(pgrep -x socketley 2>/dev/null || true); do
        case "$({ tr '\0' ' ' <"/proc/$p/cmdline"; } 2>/dev/null)" in
            *" daemon "*|*" daemon") ;;
            *) continue ;;
        esac
        if { tr '\0' '\n' <"/proc/$p/environ"; } 2>/dev/null \
           | grep -qx "SOCKETLEY_SOCKET=$sock"; then
            return 0
        fi
    done
    return 1
}

# daemon_sweep SOCKET
#
# Kill every `socketley daemon` whose environment names SOCKET.  Split out from
# daemon_stop because the cluster tests run several daemons on several sockets
# and kill one of them mid-test on purpose.
daemon_sweep() {
    local sock=$1
    [ -n "$sock" ] || return 0
    local p
    for p in $(pgrep -x socketley 2>/dev/null || true); do
        case "$({ tr '\0' ' ' <"/proc/$p/cmdline"; } 2>/dev/null)" in
            *" daemon "*|*" daemon") ;;
            *) continue ;;
        esac
        if { tr '\0' '\n' <"/proc/$p/environ"; } 2>/dev/null \
           | grep -qx "SOCKETLEY_SOCKET=$sock"; then
            kill -9 "$p" 2>/dev/null || true
        fi
    done
    return 0
}

# ─── STOPPING WITHOUT VANISHING ─────────────────────────────────────────────
#
# The other half of "a refused create must be visible".  Under `set -euo
# pipefail` a lone `VAR=$(cmd)` is a simple command whose exit status *is* the
# substitution's, so when cmd fails the file ends at that line: no assertion, no
# `Results`, no `OK`/`FAILED`.  What a broken test_cache.sh printed was
#
#     FAIL [cache created]: create refused, exit 2 …    <- ba7a147 added this
#     FAIL [SET]: got '', expected 'ok'
#     … 20 more …
#     (nothing — the file is gone, at `TTL=$(send_cmd 'ttl ttlkey')`)
#
# and it exited 1 rather than 26, because the status that escaped was nc's.  Five
# assertions after that line never ran and the counts never printed, so a run
# that broke twenty-six things is indistinguishable from one that broke one.
#
# Most such sites should simply survive: the assertion underneath is the thing
# with something to say about a command that failed, and it can only say it if
# the file is still running.  Those are guarded where they stand.
#
# The rest are what these two are for.

# daemon_bail LABEL REASON [DETAIL...]
#
# End the run here — but end it *reporting*.  Counts the bail-out as the failure
# it is and prints the same two closing lines every test in this directory ends
# with, so a file that stops early still answers the only question the summary
# exists to answer: was it one thing or twenty?
daemon_bail() {
    local label=$1 reason=$2; shift 2
    TOTAL=$(( ${TOTAL:-0} + 1 ))
    FAIL=$(( ${FAIL:-0} + 1 ))
    echo "  FAIL [$label]: $reason"
    local line
    for line in "$@"; do echo "        $line"; done
    echo "  Results: ${PASS:-0}/$TOTAL passed ($FAIL failed)"
    echo "  FAILED"
    exit "$FAIL"
}

# daemon_required LABEL [SOCKET]
#
# Decide, at a CLI command that has just failed, which of the two kinds of
# failure it was — and return 0 either way so it can be written as the `||`
# branch of the capture itself:
#
#     OUT=$("$BIN" stats mesh_proxy 2>&1) || daemon_required "stats mesh_proxy"
#
# A daemon that is still serving means the command failed on its own merits —
# usually a runtime that a refused create never built.  That is not fatal: $OUT
# holds whatever the CLI said, the assertion below judges it, and the file goes
# on to test the four unrelated things it also covers.  Returning 0 is what lets
# it, and it hides nothing, because something below is looking.
#
# A daemon that is gone is the other case.  Twenty assertions about the
# behaviour of a socket nobody is serving are not twenty findings; they are one
# finding printed twenty times, and they bury it.  So that stops — via
# daemon_bail, which is the whole point: stopping is fine, disappearing is not.
daemon_required() {
    daemon_alive "${2:-${SOCKETLEY_SOCKET:-}}" && return 0
    daemon_bail "$1" "this test's daemon is no longer serving its socket" \
        "${2:-${SOCKETLEY_SOCKET:-<unset>}}" \
        "every assertion below this point would be measuring a dead socket," \
        "so they are not run — this one failure is the finding, not twenty."
}
