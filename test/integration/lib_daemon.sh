# A daemon of one's own -- not a test, since run_all.sh globs test_*.sh and
# this file is only ever sourced.
# ─── WHAT THIS REPLACES ─────────────────────────────────────────────────────
# Each test gets its own socket, state directory and daemon process, because
# twenty-four tests used to resolve the shared default path and would then
# drive -- and in cleanup destroy runtimes belonging to -- whatever daemon
# already held it; ports are the other half and live in lib_ports.sh, so a test
# that binds anything sources both, calls daemon_isolate before touching the
# daemon, and puts daemon_stop last in cleanup because it deletes the state
# directory.

# Claim a private socket, state directory and log, before the first CLI command
# auto-starts a daemon against whatever SOCKETLEY_SOCKET says -- HOME included,
# because the state directory is derived from it.
daemon_isolate() {
    local tag=${1:-test}
    SOCKETLEY_TMPD=$(mktemp -d "/tmp/socketley-$tag-XXXXXX")
    # Python's packages installed with --user stay found, which the test's own HOME would hide.
    [ -n "${PYTHONUSERBASE:-}" ] || export PYTHONUSERBASE="$HOME/.local"
    export HOME="$SOCKETLEY_TMPD/home"
    export SOCKETLEY_SOCKET="$SOCKETLEY_TMPD/daemon.sock"
    mkdir -p "$HOME"
    SOCKETLEY_DLOG="$SOCKETLEY_TMPD/daemon.log"
    SOCKETLEY_DPID=""
    # Set here so a file that never calls daemon_start still clears any value
    # inherited from the environment.
    SOCKETLEY_DBIN=""
    daemon_watch "$SOCKETLEY_TMPD"
}

# ─── A TEST THAT DIES TAKES ITS PROCESSES WITH IT ───────────────────────────
# daemon_stop runs from a trap, and a test killed with SIGKILL runs no trap:
# a run stopped from outside left its daemons, their workers and its peers
# serving for hours.  So a watcher in a session of its own waits for this
# test's shell to go and then kills every process whose SOCKETLEY_SOCKET lies
# under this test's TMPD -- its daemons, their workers and whatever the test
# started with the variable exported -- and then removes TMPD.  After a normal end the test's
# own trap has done both and the watcher finds nothing to kill.  Its descriptors are closed so a
# runner reading this test's output does not wait on it.
#
# cap_dir  -- a fresh directory where a copy's file capabilities count, for a test that setcap's one: not on a nosuid
# mount, which /tmp often is and where the kernel ignores them; the caller removes it.
cap_dir() {
    local d
    for d in /var/tmp "$HOME"; do
        if [ -w "$d" ] && ! findmnt -no OPTIONS --target "$d" 2>/dev/null | grep -qw nosuid; then
            mktemp -d "$d/socketley-cap-XXXXXX" && return 0
        fi
    done
    mktemp -d /tmp/socketley-cap-XXXXXX
}

#
# daemon_watch TMPD  -- for a file that does not use daemon_isolate, whose
# daemons' sockets all lie under TMPD, exported or given per command.
daemon_watch() {
    local tmpd=$1
    [ -n "$tmpd" ] && [ -d "$tmpd" ] || return 0
    local me=$$ born
    born=$(awk '{print $22}' "/proc/$me/stat" 2>/dev/null) || born=""
    # Without the variable itself, so the watcher and its helpers never match it.
    env -u SOCKETLEY_SOCKET setsid -f bash -c '
        me=$1 born=$2 tmpd=$3 keep=$4
        # The same pid with the same start time, so a reused pid is not mistaken for the test.
        alive() { [ "$(awk "{print \$22}" "/proc/$me/stat" 2>/dev/null)" = "$born" ]; }
        while alive; do sleep 1; done
        killed=0
        for d in /proc/[0-9]*; do
            p=${d#/proc/}
            [ "$p" = "$$" ] && continue
            # A binary with file capabilities hides its environ, not its argv[0].
            { tr "\0" "\n" <"$d/environ"; } 2>/dev/null | grep -q "^SOCKETLEY_SOCKET=$tmpd/" ||
                { head -z -n1 "$d/cmdline" | tr -d "\0"; } 2>/dev/null | grep -q "^$tmpd/" || continue
            kill -9 "$p" 2>/dev/null && killed=1
        done
        # Only after a kill: a test that ended through its own trap may keep what it chose to.
        [ "$killed" = 1 ] && [ -z "$keep" ] && rm -rf "$tmpd"
        exit 0
    ' daemon-watch "$me" "$born" "$tmpd" "${SOCKETLEY_KEEP_TMPD:-}" \
        </dev/null >/dev/null 2>&1
    return 0
}

# Wait on the daemon's own "daemon started" line, which is printed after the
# socket is bound and state restored, never on a CLI poll that would start a
# second daemon -- and a daemon that never comes up is fatal rather than a
# failed assertion, because an assertion can be waved through as flaky.
daemon_start() {
    local bin=$1; shift
    SOCKETLEY_DBIN=$bin
    # A second start in one test appends to the log, whose first "daemon started" is not this one's.
    local from
    from=$(( $( { wc -l < "$SOCKETLEY_DLOG"; } 2>/dev/null || echo 0) + 1 ))
    "$bin" daemon "$@" >>"$SOCKETLEY_DLOG" 2>&1 &
    SOCKETLEY_DPID=$!
    local i
    for i in $(seq 1 100); do
        tail -n +"$from" "$SOCKETLEY_DLOG" 2>/dev/null | grep -q "daemon started" && break
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

# Kill this test's daemon and delete everything it owned, last in cleanup
# because it removes the state directory -- with a sweep matched on exact
# process name and this run's socket, since killing $SOCKETLEY_DPID alone
# leaves behind the copy a late `stop` resurrected, and a `pgrep -f` pattern
# one character too broad kills the run doing the matching.
daemon_stop() {
    if [ -n "${SOCKETLEY_DPID:-}" ]; then
        kill "$SOCKETLEY_DPID" 2>/dev/null || true
        local i
        for i in $(seq 1 50); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
        kill -9 "$SOCKETLEY_DPID" 2>/dev/null || true
        wait "$SOCKETLEY_DPID" 2>/dev/null || true
    fi
    daemon_sweep "${SOCKETLEY_SOCKET:-}"

    # Surface what the daemon said before deleting where it said it, because
    # skl_inv::fail writes to the daemon's stderr and the nightly's enforcement
    # is a grep over this log -- printed rather than asserted, since turning
    # 102 tests red from one library function gets a useful check switched off
    # within the week.
    if [ -n "${SOCKETLEY_DLOG:-}" ] && [ -f "$SOCKETLEY_DLOG" ]; then
        if grep -F '[invariant]' "$SOCKETLEY_DLOG" >/dev/null 2>&1; then
            echo "  --- invariant violations from this test's daemon ---"
            grep -F '[invariant]' "$SOCKETLEY_DLOG" | sort | uniq -c | head -20
        fi

        # LeakSanitizer runs at exit and reports to this log while signalling
        # through an exit status the `wait ... || true` above deliberately
        # discards, so a leak in the daemon passed the whole Sanitize suite
        # without a trace -- printed, not asserted, exactly as the invariant
        # block above.
        if grep -qE 'Sanitizer:|runtime error:' "$SOCKETLEY_DLOG" 2>/dev/null; then
            echo "  --- sanitizer reports from this test's daemon ---"
            grep -E 'Sanitizer:|runtime error:' "$SOCKETLEY_DLOG" \
                | sed 's/^==[0-9]*==//' | sort | uniq -c | head -20
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
# The question is asked of the socket rather than of a process name, because
# agents copy the binary into their worktree under another name and `pgrep -x
# socketley` then reports a live daemon dead -- and it is the stricter
# question, since the old form also matched a process that never managed to
# bind.

# The pids actually serving SOCKET, read out of /proc/net/unix rather than
# tested with `[ -S ]`, because the socket file outlives the process that bound
# it -- and the SO_ACCEPTCON flag picks the listening row, since once a client
# is connected the path appears on more than one.
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

# A daemon forked but not yet bound owns no socket, so it is found by
# environment instead -- gated on `/proc/<pid>/exe -ef` the daemon binary,
# which a shell can never satisfy and a binary copied under another name always
# will.
daemon_starting_pids() {
    local sock=$1 dbin=${SOCKETLEY_DBIN:-${BIN:-}} d p pids=""
    [ -n "$sock" ] && [ -n "$dbin" ] && [ -e "$dbin" ] || return 0
    for d in /proc/[0-9]*; do
        p=${d#/proc/}
        [ "/proc/$p/exe" -ef "$dbin" ] || continue
        # Not `grep -q`: it exits at its first match and under pipefail the
        # pipeline reports 141, taking the no-match branch precisely when it
        # matched.
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

# Kill every daemon serving SOCKET and every one on its way to serving it,
# split out from daemon_stop because the cluster tests run several daemons and
# kill one mid-test on purpose.
daemon_sweep() {
    local sock=$1 p
    [ -n "$sock" ] || return 0
    for p in $(daemon_pids "$sock") $(daemon_starting_pids "$sock"); do
        kill -9 "$p" 2>/dev/null || true
    done
    return 0
}

# ─── STOPPING WITHOUT VANISHING ─────────────────────────────────────────────
# Under pipefail a lone `VAR=$(cmd)` ends the file at that line with no
# assertions and no counts, so a run that broke twenty-six things is
# indistinguishable from one that broke one.

# End the run here, but end it reporting: the bail-out is counted as the
# failure it is and the closing lines still print, so a file that stops early
# still says whether it was one thing or twenty.
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

# Decide at a failed CLI command which kind of failure it was, returning 0
# either way so it can be the `||` branch of the capture: a live daemon means
# the command failed on its own merits and the assertion below judges it, while
# a daemon that is gone bails, because twenty assertions about an unserved
# socket are one finding printed twenty times.
daemon_required() {
    daemon_alive "${2:-${SOCKETLEY_SOCKET:-}}" && return 0
    daemon_bail "$1" "this test's daemon is no longer serving its socket" \
        "${2:-${SOCKETLEY_SOCKET:-<unset>}}" \
        "every assertion below this point would be measuring a dead socket," \
        "so they are not run — this one failure is the finding, not twenty."
}
