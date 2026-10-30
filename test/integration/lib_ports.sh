# Two thousand ports of one's own -- only ever sourced, since run_all.sh globs
# test_*.sh.
# ─── WHAT THIS REPLACES ─────────────────────────────────────────────────────
# Ports are not private to a daemon, so two runs of this suite on one machine
# collided on every fixed port in the directory -- and what that cost was not a
# clear error but eight files of failures each named after a real behaviour and
# each read at the time as an independent product defect.
# ─── THE WINDOW ─────────────────────────────────────────────────────────────
# Each sourcing shell claims a window of two thousand ports for its own
# lifetime, claimed rather than derived because a window computed from the pid
# is one modulo away from two runs picking the same one -- and two things have
# to be true of it, that no other sourcing shell holds it, which is the flock,
# and that nothing else on the machine is listening in it, which is a scan,
# since a hand-started daemon owes nothing to this scheme; 19000 is tried first
# so a quiet run binds the numbers this directory always bound, and none of the
# windows reaches the ephemeral range.
# ─── USAGE ──────────────────────────────────────────────────────────────────
# SL_PORT_BASE is exported, which is what lets run_all.sh claim one window for
# a whole run and what lets a python child read its ports out of the
# environment.

# Already claimed by this shell (or handed down deliberately by a parent that
# claimed one): use it and do not claim a second.
if [ -z "${SL_PORT_BASE:-}" ]; then

    # A caller that knows what it wants overrides everything: pinning a window
    # while debugging a collision, and a harness that has already claimed one.
    if [ -n "${SOCKETLEY_PORT_BASE:-}" ]; then
        SL_PORT_BASE=$SOCKETLEY_PORT_BASE
    else
        # Every port with a listener right now, one ss call for the whole
        # search, with the port being what follows the last colon -- which is
        # also correct for [::]:19200.
        sl_listening=$(ss -ltnH 2>/dev/null | awk '{ n = split($4, a, ":"); print a[n] }')

        SL_PORT_BASE=""
        . "$(dirname "${BASH_SOURCE[0]}")/lib_windows.sh"
        for sl_try in $(sl_port_windows); do
            # The lock first, because it is cheap and is what makes two shells
            # racing for one window resolve rather than both proceed, on a
            # descriptor that stays open for the life of this shell -- with the
            # creatability test in a subshell, since a bare `exec` installs its
            # redirections permanently and the `2>/dev/null` that used to sit
            # here silenced stderr for 124 of the 128 files that source this.
            ( : >"/tmp/socketley-ports-$sl_try.lock" ) 2>/dev/null || continue
            exec 9>"/tmp/socketley-ports-$sl_try.lock"
            flock -n 9 2>/dev/null || continue

            # And then the machine's own opinion, because a window can be
            # unlocked and still occupied by a daemon somebody started by hand.
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
                # Bare, because a redirection here would outlive this line and
                # take the rest of the test's stderr with it, and closing a
                # descriptor this shell just opened does not fail.
                exec 9>&-
                continue
            fi

            SL_PORT_BASE=$sl_try
            break
        done
        unset sl_try sl_p sl_busy sl_listening

        # Thirteen windows all taken means thirteen concurrent runs or
        # listeners scattered through all of them, and falling back to the
        # historical base would be the one behaviour this file exists to
        # prevent.
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
