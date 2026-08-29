# Measurement windows anchored to what happened rather than to what time it is
# -- the companion of lib_ready.sh, and only ever sourced, since run_all.sh
# globs test_*.sh.
# ─── WHAT THIS REPLACES ─────────────────────────────────────────────────────
# Every boundary used to be a clock reading that assumed a control command
# lands in the time allotted to it, which inside the full suite it does not --
# so an empty window was reported as "a member that joined never received
# traffic" and read by a second agent as the feature being broken.
# ─── WHAT AN ANCHORED WINDOW IS ─────────────────────────────────────────────
# A window opens and closes on an observation -- the last response of the
# member that left, the first of the one that joined, the moment the runtime's
# own stats show the change, enough traffic carried -- none of which a fast
# machine can reach early or a slow one miss, with bounded waits whose expiry
# is itself a result, and a request belonging to a window only if it was both
# sent and answered inside it.
# ─── NOT MEASURABLE IS NOT A FAILURE ────────────────────────────────────────
# A window that carried no traffic proves nothing and must never be reported in
# the same words as one that carried traffic and routed it wrongly, so it is
# counted separately and still ends the run non-zero.

WIN_PY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib_window.py"

# win_now — epoch seconds, full float precision, on the same clock the drivers
# stamp their events with.
win_now() { python3 "$WIN_PY" now; }

# Blocks until the window holds at least MIN_EVENTS requests and has been open
# at least MIN_SECS, printing the count it reached and returning non-zero when
# TIMEOUT expired first.
win_wait_events() { python3 "$WIN_PY" wait-events "$@"; }

# Blocks until BACKEND -- or any of them -- serves a request at or after SINCE,
# printing when that response completed.
win_wait_backend() { python3 "$WIN_PY" wait-backend "$@"; }

# Blocks until BACKEND has stopped serving, meaning CLEAR_N consecutive
# successful responses from anyone else, with a timeout covering both traffic
# that never stopped going there and traffic that stopped succeeding
# altogether.
win_wait_drained() { python3 "$WIN_PY" wait-drained "$@"; }

# Runs CMD until its output matches PATTERN, or stops matching when PATTERN
# begins with '!', printing the control plane's own account of when the change
# landed.
win_wait_output() { python3 "$WIN_PY" wait-output "$@"; }

# One WINDOW line per window, with the counts the assertions read.
win_report() { python3 "$WIN_PY" report "$@"; }

# The individual failures inside a window with how long each waited, printed
# once an assertion has already failed so the run says what was lost and not
# merely how many.
win_detail() { python3 "$WIN_PY" detail "$@"; }

# win_field OUTPUT LABEL FIELD — a number out of a WINDOW line, "" when absent.
win_field() {
    printf '%s\n' "$1" | grep "^WINDOW $2 " | grep -o "\b$3=[0-9]*" | cut -d= -f2 | head -1
}

# win_kind OUTPUT LABEL KIND — how many of one failure kind that window holds.
win_kind() {
    printf '%s\n' "$1" | grep "^WINDOW $2 " | sed 's/.*kinds://' \
        | tr ',' '\n' | grep "^$3=" | cut -d= -f2 | head -1
}
