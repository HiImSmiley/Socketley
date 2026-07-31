# Measurement windows, anchored to what happened rather than to what time it is.
#
# Not a test — run_all.sh globs test_*.sh, so this file is only ever sourced.
# It is the companion of lib_ready.sh: that one replaced "sleep and hope the
# thing is up" with "ask it to do its job and wait until it does", and this one
# does the same for the windows the load tests measure inside.
#
# ─── WHAT THIS REPLACES ─────────────────────────────────────────────────────
#
# Both load tests split a run into phases and asked what happened in each:
#
#     sleep "$WIN"; stop the member; sleep 1; PHASE=after-leave
#     ...
#     deadline = t0 + 3 * WIN + 2.5
#
# Every boundary there is a clock reading, and every one of them is a guess that
# a control command lands in the time allotted to it.  On an idle machine it
# does.  Inside `bash test/run_all.sh` it does not: `socketley stop` and
# `socketley create` took seconds instead of milliseconds, the driver was
# blocked in subprocess.run for that whole time, and the last window opened
# after the run had already ended.  The measured result was
#
#     PHASE after-join total=0 ok=0 be:none kinds:none
#
# and the test reported it as "a member that joined never received traffic" —
# a product failure, in a run where the product was never asked.  It cost an
# argument: a second agent building the same commit saw the same line and
# reported the feature broken.  Standalone, the same test on the same binaries
# measured 4340 requests in that window and passed.
#
# ─── WHAT AN ANCHORED WINDOW IS ─────────────────────────────────────────────
#
# A window opens on an observation and closes on one:
#
#   * the last response served by the member that left  (win_wait_drained)
#   * the first response served by the member that joined  (win_wait_backend)
#   * the moment the runtime's own stats show the change  (win_wait_output)
#   * enough traffic having actually been carried  (win_wait_events)
#
# None of those can be reached early by a fast machine or missed by a slow one,
# because each is the event whose having happened is the precondition of the
# measurement.  The waits are bounded, and a bound that expires is itself a
# result: "the member that left was still serving 15 s later" is a finding about
# the product, and it is stated as one.
#
# A request belongs to a window only if it was both sent and answered inside it.
# One that straddles a boundary is counted apart (straddle=N) and judged
# nowhere, because the change it straddles is the one thing the phase is
# supposed to be on one side of.
#
# ─── NOT MEASURABLE IS NOT A FAILURE ────────────────────────────────────────
#
# A window that carried no traffic proves nothing, and must never be reported
# in the same words as a window that carried traffic and routed it wrongly.
# Tests using this library report the first as
#
#     NOT MEASURABLE [claim]: reason
#
# counted separately from FAIL and printed differently, so the two are not
# confused again.  It still ends the run non-zero: an assertion that was never
# evaluated has not passed.

WIN_PY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib_window.py"

# win_now — epoch seconds, full float precision, on the same clock the drivers
# stamp their events with.
win_now() { python3 "$WIN_PY" now; }

# win_wait_events FILE SINCE MIN_EVENTS MIN_SECS TIMEOUT
#
# Blocks until the window opened at SINCE holds at least MIN_EVENTS requests and
# has been open at least MIN_SECS.  Prints the count it reached; non-zero when
# TIMEOUT expired first, which the caller reports as not measurable.
win_wait_events() { python3 "$WIN_PY" wait-events "$@"; }

# win_wait_backend FILE BACKEND SINCE TIMEOUT
#
# Blocks until BACKEND ("any" for any of them) serves a request at or after
# SINCE, and prints when that response completed.  Non-zero on timeout.
win_wait_backend() { python3 "$WIN_PY" wait-backend "$@"; }

# win_wait_drained FILE BACKEND SINCE CLEAR_N TIMEOUT
#
# Blocks until BACKEND has stopped serving: CLEAR_N consecutive successful
# responses at or after SINCE, none of them from it.  Prints when that was
# reached.  Non-zero on timeout — which is the case where traffic never stopped
# going there, or stopped succeeding altogether.
win_wait_drained() { python3 "$WIN_PY" wait-drained "$@"; }

# win_wait_output TIMEOUT PATTERN CMD...
#
# Runs CMD until its output matches the extended regex PATTERN, or until it
# stops matching when PATTERN begins with '!'.  Prints the timestamp of the
# first poll that satisfied it — the control plane's own account of when the
# change landed.  Non-zero on timeout.
win_wait_output() { python3 "$WIN_PY" wait-output "$@"; }

# win_report FILE label:from:to ...
#
# One WINDOW line per window, with the counts the assertions read.
win_report() { python3 "$WIN_PY" report "$@"; }

# win_detail FILE FROM TO
#
# The individual failures inside a window, with how long each one waited before
# it failed.  Printed when an assertion about a window has already failed, so
# the run says what was lost and not merely how many.
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
