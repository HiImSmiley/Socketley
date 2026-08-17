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
# A daemon of one's own is half of it.  The other half is ports, which are not
# private to a daemon: two runs of this suite each start their own daemons and
# then ask the same kernel for the same 19200.  That is lib_ports.sh, and a test
# that binds anything sources it too.
#
# Usage:
#
#     . "$(dirname "$0")/lib_daemon.sh"
#     . "$(dirname "$0")/lib_ports.sh"
#     daemon_isolate cache            # before anything touches the daemon
#     PORT=$((SL_PORT_BASE + 150))    # never a literal
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
    # Which executable this run's daemons are, by path — see daemon_starting_pids.
    # Set here so a file that never calls daemon_start still clears any value
    # inherited from the environment.
    SOCKETLEY_DBIN=""
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
    SOCKETLEY_DBIN=$bin
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

    # ── surface what the daemon said before deleting where it said it ───────
    #
    # An invariant violation is reported by skl_inv::fail on the PROCESS's
    # stderr, which for every test here is the daemon's, which daemon_start
    # sends to $SOCKETLEY_DLOG.  A test's own stdout never carries it: with the
    # half-close hold deliberately broken, test_proxy_half_close_hold.sh printed
    # six FAILs and daemon.log held 43 `[invariant]` lines, none of which
    # appeared in the suite output.
    #
    # That matters beyond debugging.  The nightly's invariants job greps its
    # suite log for `[invariant]` and fails the job on a hit — and under
    # -DSOCKETLEY_INVARIANTS_WARN_ONLY a violation only prints, so the grep was
    # the whole enforcement.  Against a stream the line cannot reach, that step
    # could not fail, and the deletion below is what put it out of reach.
    #
    # Sited here rather than in each test for the reason the proxy's answer-owed
    # check is sited in close_pair: 102 of the 128 files in this directory reach
    # this function, and none of them has to know about it.  The 26 that do not
    # call daemon_isolate at all are the ones that never start a daemon.
    #
    # Printed, not asserted.  What a violation means is the job's decision --
    # the nightly fails on it, an interactive run wants to see it and carry on --
    # and turning 102 tests red from one library function is the kind of change
    # that gets a useful check switched off within the week.
    if [ -n "${SOCKETLEY_DLOG:-}" ] && [ -f "$SOCKETLEY_DLOG" ]; then
        if grep -F '[invariant]' "$SOCKETLEY_DLOG" >/dev/null 2>&1; then
            echo "  --- invariant violations from this test's daemon ---"
            grep -F '[invariant]' "$SOCKETLEY_DLOG" | sort | uniq -c | head -20
        fi
    fi

    # SOCKETLEY_KEEP_TMPD keeps the run's socket, state directory and daemon.log
    # instead of deleting them, for when the summary above is not enough.
    if [ -n "${SOCKETLEY_KEEP_TMPD:-}" ]; then
        echo "  kept: ${SOCKETLEY_TMPD:-}" >&2
    else
        [ -n "${SOCKETLEY_TMPD:-}" ] && rm -rf "$SOCKETLEY_TMPD"
    fi
    return 0
}

# ─── NOT BY THE PROCESS'S NAME ──────────────────────────────────────────────
#
# Both functions below used to open with `pgrep -x socketley`, which asks the
# wrong question in a way that is expensive to be wrong about.
#
# Agents working in this tree routinely copy the binary into their own worktree
# so a concurrent rebuild cannot truncate the file out from under a running
# test.  The copy does not have to keep its name, and the moment it does not,
# `pgrep -x socketley` cannot see the daemon at all: daemon_alive returns false
# for a daemon that is up and serving, and daemon_required then stops the run
# with "this test's daemon is no longer serving its socket" — a sentence that
# sends whoever reads it looking for a daemon crash that never happened.  It
# cost an agent a confusing run.  Measured, with the binary copied to
# `sockletey-worktree-copy`:
#
#     daemon pid=4015933  socket=/tmp/socketley-lookup-Pm7tea/d.sock
#     pgrep -x socketley -> 3979889 4015559 4015569      (ours is not there)
#     /proc/net/unix     -> ... 60881938 /tmp/.../d.sock
#     holder of inode    -> 4015933                      (ours, exactly)
#
# So the question is asked of the socket instead.  "Is a daemon serving this
# socket" has an exact answer that owes nothing to what anything is called, and
# it is also a stricter answer than the old one: the old form matched a daemon
# whose *environment* named the socket, which stays true for a process that
# never managed to bind.

# daemon_pids SOCKET
#
# The pids actually serving SOCKET, space separated, empty if none.
#
# `[ -S "$sock" ]` is not the same question and never was: the socket file
# outlives the process that bound it, so a test that cleans up with a CLI
# command "because the socket is still there" reaches a dead daemon and
# auto-starts a live one in its place.  A killed daemon leaves the file on disk
# and its /proc/net/unix row goes away in the same instant — measured both ways
# — which is exactly the distinction wanted here.
#
# In /proc/net/unix the columns are Num RefCount Protocol Flags Type St Inode
# Path, so field 8 is the bound path and field 7 the inode; the pid is then
# whoever holds that inode as an open descriptor.  A full /proc walk costs about
# half a second on this machine, and it happens in cleanup and on the
# already-failing daemon_required path, never in a measurement window.
#
# The Flags test is what makes this the *listening* socket rather than merely a
# socket with that path.  Once a client is connected, the path appears on more
# than one row — measured, with one CLI client attached:
#
#     ... 00000003 00000000 00000000 0001 03 60910290 /tmp/.../d.sock   accepted
#     ... 00000002 00000000 00010000 0001 01 60912247 /tmp/.../d.sock   listening
#
# and taking simply the first would mean asking about whichever accepted
# connection happened to sort first — an fd the daemon may already have closed,
# whereupon daemon_alive reports a live daemon dead.  00010000 is SO_ACCEPTCON:
# exactly one row per bound path carries it, and it is the row that means
# "serving".
daemon_pids() {
    local sock=$1 ino fd p pids=""
    [ -n "$sock" ] || return 0
    ino=$(awk -v s="$sock" '$4 == "00010000" && $8 == s { print $7; exit }' \
          /proc/net/unix 2>/dev/null) || ino=""
    [ -n "$ino" ] || return 0
    # readlink's stderr is redirected inside the substitution, not on the `for`:
    # this walks every process on the machine, so "Permission denied" for another
    # user's fd and "No such file or directory" for a pid that exited mid-loop
    # are both expected, and both would otherwise land in exactly the output
    # someone is reading because something has already gone wrong.
    for fd in /proc/[0-9]*/fd/*; do
        [ "$({ readlink "$fd"; } 2>/dev/null)" = "socket:[$ino]" ] || continue
        p=${fd#/proc/}; p=${p%%/*}
        case " $pids " in *" $p "*) ;; *) pids="$pids $p" ;; esac
    done
    printf '%s' "${pids# }"
}

# daemon_starting_pids SOCKET
#
# The other half: a daemon that has been forked but has not bound yet owns no
# socket, so daemon_pids cannot see it, and a sweep that misses it leaves it
# running for good on this run's ports.  Those are found by environment instead
# — but an environment match alone would also hit the test script itself, whose
# SOCKETLEY_SOCKET is the very variable being matched, and killing the shell
# doing the killing is the accident this whole file exists to prevent.
#
# So the gate is `/proc/<pid>/exe -ef` the daemon binary: a device+inode
# comparison through the symlink, which a shell can never satisfy and a binary
# copied under another name always will.  Nothing here looks at a name.
daemon_starting_pids() {
    local sock=$1 dbin=${SOCKETLEY_DBIN:-${BIN:-}} d p pids=""
    [ -n "$sock" ] && [ -n "$dbin" ] && [ -e "$dbin" ] || return 0
    for d in /proc/[0-9]*; do
        p=${d#/proc/}
        [ "/proc/$p/exe" -ef "$dbin" ] || continue
        # NOT `grep -q`.  These files are sourced into scripts that run under
        # `set -o pipefail`, and `grep -q` exits at its first match, which hands
        # the writer a SIGPIPE; the pipeline then reports 141 and this takes the
        # "no match" branch precisely when it matched.  An environ is small
        # enough that tr is usually finished before grep looks, so the bug is
        # only latent here — but "latent" is not a property worth relying on in
        # the function that decides what to kill.  grep without -q reads to the
        # end, so the status is grep's.
        { tr '\0' '\n' <"/proc/$p/environ"; } 2>/dev/null \
            | grep -x "SOCKETLEY_SOCKET=$sock" >/dev/null || continue
        case " $pids " in *" $p "*) ;; *) pids="$pids $p" ;; esac
    done
    printf '%s' "${pids# }"
}

# daemon_alive SOCKET
#
# True when a daemon process is actually serving SOCKET.
daemon_alive() {
    local sock=$1
    [ -n "$sock" ] || return 1
    [ -n "$(daemon_pids "$sock")" ]
}

# daemon_sweep SOCKET
#
# Kill every daemon serving SOCKET, and every one on its way to serving it.
# Split out from daemon_stop because the cluster tests run several daemons on
# several sockets and kill one of them mid-test on purpose.
daemon_sweep() {
    local sock=$1 p
    [ -n "$sock" ] || return 0
    for p in $(daemon_pids "$sock") $(daemon_starting_pids "$sock"); do
        kill -9 "$p" 2>/dev/null || true
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
