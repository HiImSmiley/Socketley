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
daemon_alive() {
    local sock=$1 p
    [ -n "$sock" ] || return 1
    for p in $(pgrep -x socketley 2>/dev/null || true); do
        case "$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null)" in
            *" daemon "*|*" daemon") ;;
            *) continue ;;
        esac
        if tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null \
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
        case "$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null)" in
            *" daemon "*|*" daemon") ;;
            *) continue ;;
        esac
        if tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null \
           | grep -qx "SOCKETLEY_SOCKET=$sock"; then
            kill -9 "$p" 2>/dev/null || true
        fi
    done
    return 0
}
