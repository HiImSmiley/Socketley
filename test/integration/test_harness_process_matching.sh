#!/usr/bin/env bash
# Integration test: no harness file finds a process by its command line.
#
# ─── THE RULE, AND WHY A TEST ENFORCES IT RATHER THAN A COMMENT ─────────────
#
# `pgrep -f` and `pkill -f` match the WHOLE command line, so they also match any
# process that merely carries the pattern in its own arguments — including the
# shell running the script that is doing the matching, and including `bash
# test_x.sh` when the pattern names the binary that script was handed.  What
# that produces is not a wrong answer; it is the run killing itself.
#
# The tree already knows this.  Fourteen files in this directory carry a comment
# saying so, lib_daemon.sh devotes a section to it, and run_all.sh's sweep was
# rewritten around it after `pkill -f "$SYS_BIN daemon"` killed the run doing
# the killing.  Every one of those is a comment sited where the mistake was made
# LAST time, which is the one place the next author is not looking.
#
# It came back twice on 2026-08-20, both times in newly written harness code:
# once the sweep killed the shell that invoked it, and once `tail --pid` was
# pointed at a freshly forked `pgrep` shell instead of the suite it meant to
# wait for, so seven consecutive ten-minute waits waited on nothing and returned
# instantly.  A rule that is re-learned twice in a day at a cost of seventy
# minutes is a rule that belongs in the suite.
#
# ─── WHAT IT WOULD CATCH ────────────────────────────────────────────────────
#
# A new harness file — or an edit to an existing one — that finds socketley
# processes with `pgrep -f 'socketley daemon'`, `pkill -f "$BIN daemon"`, or any
# short-flag spelling of the same thing.  It fails on the line, by name and line
# number, before that file is ever run.  It is not vacuous: the check is
# demonstrated red by inserting one such line, and it stays red until it is
# removed.
#
# The replacement is always the same two facts and never a name: match
# `pgrep -x socketley`, then confirm the process is ours by comparing
# /proc/<pid>/exe against the binary under test, or by reading this run's
# SOCKETLEY_SOCKET or SL_PORT_BASE out of /proc/<pid>/environ.  lib_daemon.sh's
# daemon_pids/daemon_starting_pids are the worked version; run_all.sh's
# own_daemon_pids is the other.
#
# ─── WHAT IT DELIBERATELY DOES NOT COVER ────────────────────────────────────
#
# test/benchmark/ is excluded, and the exclusion is not an oversight.  Four
# `pkill -9 -f` calls live in benchmark/utils.sh's cleanup_all, and all four
# target processes that are not socketley: a python3 backend, `nc`, `k6` and
# `redis-benchmark`.  The recipe above cannot be applied to them — there is no
# socketley exe to compare against — and the correct fix is to record each
# helper's pid where it is spawned, which is a change across benchmark/ and
# belongs to whoever holds that territory.  They are over-broad in a different
# way, too: `pkill -9 -f "nc.*localhost.*1900"` reaches another worktree's
# benchmark run, which is the same fault the socketley_bench sweep directly
# below them was already fixed for.  Named here so the exclusion is a decision
# on the record rather than a gap.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
TESTROOT=$(cd "$HERE/.." && pwd)

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: the harness never matches a process by its command line ==="

# Every shell file under test/ except benchmark/, which the header exempts by
# name.  Derived from a find rather than listed, for the reason run_all.sh globs
# instead of naming: a list goes stale by reporting a pass.
#
# This file is excluded from its own scan, and has to be: it carries both
# offending spellings on purpose, in the probe below, and the probe is the only
# thing that proves the pattern matches anything at all.  The exclusion is by
# basename rather than by a marker comment so that a copy of this file under
# another name is still scanned.
SELF=$(basename "$0")
FILES=$(find "$TESTROOT" -name '*.sh' -type f \
             -not -path "$TESTROOT/benchmark/*" -not -name "$SELF" | sort)

N_FILES=$(printf '%s\n' "$FILES" | grep -c . || true)
if [ "$N_FILES" -ge 100 ]; then
    ok
else
    bad "the scan has files to scan" \
        "found $N_FILES shell files under $TESTROOT, expected at least 100" \
        "Everything below passes trivially against an empty file list, which is" \
        "how a check that scans nothing reports that nothing is wrong."
fi

# The match.  `-f` may be spelled on its own or folded into a short-flag cluster
# (`pgrep -xf`, `pkill -9f`), so the pattern is the flag cluster rather than a
# literal " -f".  A line whose first non-blank character is `#` is a comment and
# is exempt: 28 comment lines across 25 files in this tree explain the rule in
# prose that quotes it, and every one of them would otherwise be a failure.
#
# One variable, used by both the scan and the probe below.  Two copies of a
# regex is two things to keep level, and the one that would drift is the probe
# -- which is the assertion that the scan's green tick means anything.
PAT='(^|[^A-Za-z0-9_-])(pgrep|pkill)[[:space:]]+(-[A-Za-z0-9]*[[:space:]]+)*-[A-Za-z0-9]*f'

HITS=$(printf '%s\n' "$FILES" | while IFS= read -r f; do
    [ -n "$f" ] || continue
    grep -nE "$PAT" "$f" 2>/dev/null \
        | grep -vE '^[0-9]+:[[:space:]]*#' \
        | sed "s|^|${f#$TESTROOT/}:|"
done)

if [ -z "$HITS" ]; then
    ok
else
    bad "no harness file finds a process with pgrep -f or pkill -f" \
        "$(printf '%s\n' "$HITS" | grep -c .) line(s) match the whole command line" \
        "$(printf '%s\n' "$HITS" | head -10)" \
        "-f matches any process whose arguments merely carry the pattern," \
        "including the shell running this suite.  Match pgrep -x socketley and" \
        "confirm ownership from /proc/<pid>/exe or /proc/<pid>/environ instead —" \
        "lib_daemon.sh:daemon_pids and run_all.sh:own_daemon_pids are the two" \
        "worked versions."
fi

# The other half, so the check above cannot pass because the pattern is wrong.
# A file that does contain a `-f` match must be found by it.
PROBE=$(mktemp "${TMPDIR:-/tmp}/socketley-hygiene-probe-XXXXXX.sh")
trap 'rm -f "$PROBE"' EXIT
cat > "$PROBE" <<'PROBEEOF'
#!/usr/bin/env bash
# a comment mentioning pkill -f must NOT match
pgrep -f "socketley daemon"
pkill -9f "socketley daemon"
PROBEEOF
PROBE_HITS=$(grep -nE "$PAT" "$PROBE" \
             | grep -vE '^[0-9]+:[[:space:]]*#' | grep -c . || true)
if [ "$PROBE_HITS" -eq 2 ]; then
    ok
else
    bad "the pattern finds what it is meant to find" \
        "a file with two offending lines and one comment matched $PROBE_HITS of them, expected 2" \
        "The check above is only worth its green tick if this is 2: at 0 it" \
        "passes on every tree, at 3 it fails on every comment."
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
