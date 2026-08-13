# Two thousand ports of one's own.
#
# Not a test — run_all.sh globs test_*.sh, so this file is only ever sourced.
#
# ─── WHAT THIS REPLACES ─────────────────────────────────────────────────────
#
# lib_daemon.sh gave every test its own daemon, its own socket and its own state
# directory, and that removed one of the two things two suite runs share.  This
# removes the other.
#
# Ports are not private to a daemon.  A test that starts a daemon of its own and
# then creates a runtime on 19200 is still asking the kernel for 19200, and the
# kernel has one of those.  Two runs of this suite on one machine — an agent
# verifying a change while somebody measures a baseline, which is the ordinary
# state of this tree — therefore collided on every fixed port in the directory.
#
# What that costs is not a clear error.  The recorded signature, from two runs
# in separate worktrees on 2026-08-06, was a proxy answering 504, a backend
# reporting no accepts, and a parent answering where a sub-server should have —
# eight files deep, each failure named after a real behaviour, each one read at
# the time as an independent product defect.  None of them was.
#
# It is still the live state of this machine.  While this file was being
# written, ports 19350 and 19681-19684 were held by another worktree's tests;
# the run that produced them and the run reading this would have met on
# test_proxy_tls_verify.sh and blamed the build.
#
# ─── THE WINDOW ─────────────────────────────────────────────────────────────
#
# Each sourcing shell claims a window of two thousand ports and holds it for its
# own lifetime.  Most of this directory's port literals were 19abc, so the rule
# for those is simply that 19abc becomes SL_PORT_BASE + abc, and a run that gets
# the first window binds exactly the ports it always bound.  The forty-odd that
# had wandered off to 21801, 23050, 29901 and 31932 are the second thousand:
# SL_PORT_BASE + 1000 + their last three digits.  Nothing is left on a literal.
#
# Claimed rather than derived.  A window computed from the pid is one modulo
# away from two runs picking the same one, and the failure that produces is the
# one above — the failure this file exists to make impossible rather than
# unlikely.  A claim can be checked.
#
# Two things have to be true of a window, and neither implies the other:
#
#   * No other sourcing shell holds it.  That is the lock file: flock -n on
#     /tmp/socketley-ports-<base>.lock, kept open on a descriptor for as long as
#     this shell lives, released by the kernel when it exits — including when it
#     is killed, which a trap-based scheme would not survive.
#
#   * Nothing else on the machine is listening in it.  That is not the same
#     question: agents in this tree run daemons by hand outside any suite, and
#     one of those sitting on 24010 makes the 24000 window unusable while no
#     lock file says so.  So the window is also scanned, once, at claim time.
#
# 19000 is tried first so that one run on a quiet machine binds the numbers this
# directory has always bound, and a `ss -ltn` taken during a normal run still
# looks like the one in every comment here.  The rest are ordered away from it.
# None of them reaches this kernel's ephemeral range — 32768 upwards, per
# /proc/sys/net/ipv4/ip_local_port_range — because a window overlapping that is
# quietly stolen by an outgoing connection, which fails as a bind error in
# whichever test happened to be next.
#
# ─── USAGE ──────────────────────────────────────────────────────────────────
#
#     . "$(dirname "$0")/lib_ports.sh"
#     PORT=$((SL_PORT_BASE + 200))          # was PORT=19200
#
# SL_PORT_BASE is exported, which is what lets run_all.sh claim one window for a
# whole run: every test sources this file, finds the variable already set, and
# uses the run's window rather than claiming one of its own.  It is also
# how a python child reads its ports out of the environment instead of being
# passed every one of them on its command line.

# Already claimed by this shell (or handed down deliberately by a parent that
# claimed one): use it and do not claim a second.
if [ -z "${SL_PORT_BASE:-}" ]; then

    # A caller that knows what it wants overrides everything.  Two uses: pinning
    # a window while debugging a collision, and a harness that has already
    # claimed one and wants its children inside it.
    if [ -n "${SOCKETLEY_PORT_BASE:-}" ]; then
        SL_PORT_BASE=$SOCKETLEY_PORT_BASE
    else
        # Every port with a listener right now, one per line.  One ss call for
        # the whole search rather than one per window.  -H drops the header, -n
        # keeps ports numeric; the local address is field 4 and the port is what
        # follows the last colon, which is also correct for [::]:19200.
        sl_listening=$(ss -ltnH 2>/dev/null | awk '{ n = split($4, a, ":"); print a[n] }')

        SL_PORT_BASE=""
        for sl_try in 19000 21000 23000 25000 27000 29000 \
                      5000 7000 9000 11000 13000 15000 17000; do
            # The lock first: it is cheap, and it is what makes two shells
            # racing for the same window resolve rather than both proceed.
            #
            # Descriptor 9 stays open for the life of this shell.  Nothing else
            # in this directory uses it, and the one thing that must not happen
            # — the lock being released while the ports are still in use — is
            # then impossible without the shell exiting.
            # The `2>/dev/null` that used to sit on this line applied to the
            # SHELL, not to the command.  A bare `exec` — one with no program to
            # run — installs its redirections permanently, so that suffix
            # silenced stderr for the whole of every test that sources this file:
            # 124 of the 128.  ASan and UBSan write there, python tracebacks
            # write there, `nc` and the shell's own error messages write there,
            # and none of it reached a suite log.  Under Sanitize above all,
            # which is where this project's serious findings surface.
            #
            # So the creatability test happens in a subshell, where a redirection
            # is scoped to what it is written next to, and the exec that follows
            # carries none.
            ( : >"/tmp/socketley-ports-$sl_try.lock" ) 2>/dev/null || continue
            exec 9>"/tmp/socketley-ports-$sl_try.lock"
            flock -n 9 2>/dev/null || continue

            # And then the machine's own opinion.  A window can be unlocked and
            # still occupied: a daemon somebody started by hand owes nothing to
            # this scheme.
            sl_busy=""
            for sl_p in $sl_listening; do
                case "$sl_p" in
                    ''|*[!0-9]*) continue ;;
                esac
                if [ "$sl_p" -ge "$sl_try" ] && [ "$sl_p" -lt $((sl_try + 2000)) ]; then
                    sl_busy=$sl_p
                    break
                fi
            done
            if [ -n "$sl_busy" ]; then
                # Give the lock back before moving on, or the next run finds
                # this window locked by a shell that is not using it.
                flock -u 9 2>/dev/null || true
                # Bare, for the reason given at the open above: a redirection
                # here would outlive this line and take the rest of the test's
                # stderr with it.  Closing a descriptor this shell just opened
                # does not fail.
                exec 9>&-
                continue
            fi

            SL_PORT_BASE=$sl_try
            break
        done
        unset sl_try sl_p sl_busy sl_listening

        # Thirteen windows all taken means thirteen concurrent runs, or a
        # machine with listeners scattered through all of them.  Falling back to
        # the historical base would be the one behaviour this file exists to
        # prevent: two runs on one window, failing as product defects.
        if [ -z "$SL_PORT_BASE" ]; then
            echo "  FATAL: no free 2000-port window is available." >&2
            echo "         Every window is either locked by another run or has a" >&2
            echo "         listener in it.  Running here would collide with that" >&2
            echo "         run and report the collision as a product failure." >&2
            exit 2
        fi
    fi
fi
export SL_PORT_BASE
