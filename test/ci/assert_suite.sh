#!/usr/bin/env bash
# Run test/run_all.sh and refuse to call the result a pass unless it really was.
#
#   ./test/ci/assert_suite.sh [log-file]
#
# ─── WHY THIS WRAPPER EXISTS ────────────────────────────────────────────────
#
# test/run_all.sh exits with the number of failed tests, which is the right
# contract but not a sufficient one: it also exits 0 when it ran nothing.  A
# missing binary, a daemon that never came up, a glob that matched no files, a
# suite that stopped after the first test — all of those produce "0 failed", and
# all of them have produced a green check mark here before.
#
# So this wrapper checks three things the exit code cannot express:
#
#   1. the suite printed a summary line at all;
#   2. that line reports zero failures;
#   3. it reports at least as many passes as there are tests on disk.
#
# (3) is the one that catches silence.  If someone adds an integration test and
# the runner does not pick it up, or a test binary stops being built, the count
# drops and this fails — instead of the suite quietly getting smaller.
#
# ─── WHAT IT DOES NOT CHECK ─────────────────────────────────────────────────
#
# Whether the tests are any good, or whether a test that "passed" actually
# asserted anything.  It only guarantees that the expected number of tests ran
# and none of them failed.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG="${1:-$ROOT/suite.log}"

# What the suite owes, from the two places that define it: premake5.lua for the
# binaries and the directory listing for the integration files.
#
# This was a hand-written list of five unit tests, and the floor it produced was
# too low to do the job (3) claims for it.  The suite runs fourteen unit
# binaries and eleven fuzz replays; against a floor of 5 + integration, a run
# that lost two whole unit binaries still cleared it by twenty and reported
# PASS.  That is the exact failure this wrapper was written to catch, in the
# wrapper: measured on 2026-08-20, a Sanitize run started while make was still
# linking skipped test_managed_runtime and test_worker_map and reported
# "172 passed, 0 failed".
#
# Derived, so it cannot go stale the way the list did.  run_all.sh now refuses
# to start when a defined target is missing from the build directory, which is
# the earlier and better place for it; this stays as the check on what actually
# RAN, which is a different question and the one a wrapper can answer.
unit_count=$(sed -n 's/^project "\(test_[A-Za-z0-9_]*\)".*/\1/p' "$ROOT/premake5.lua" | wc -l)
fuzz_count=$(sed -n 's/^project "\(fuzz_[A-Za-z0-9_]*\)".*/\1/p' "$ROOT/premake5.lua" | wc -l)
integration_count=$(find "$ROOT/test/integration" -maxdepth 1 -name 'test_*.sh' -type f | wc -l)
expected=$((unit_count + fuzz_count + integration_count))

if [ "$integration_count" -eq 0 ]; then
    echo "ERROR: found no integration tests in $ROOT/test/integration — refusing to report a pass."
    exit 2
fi
if [ "$unit_count" -eq 0 ] || [ "$fuzz_count" -eq 0 ]; then
    echo "ERROR: premake5.lua names $unit_count test_* and $fuzz_count fuzz_* projects."
    echo "       With no expectation to compare against, the count check below"
    echo "       would pass on a run that executed almost nothing."
    exit 2
fi

echo "expecting $unit_count unit + $fuzz_count fuzz + $integration_count integration = $expected"

bash "$ROOT/test/run_all.sh" 2>&1 | tee "$LOG"
suite_rc=${PIPESTATUS[0]}

if [ ! -s "$LOG" ]; then
    echo "ERROR: the suite produced no output at all."
    exit 2
fi

summary="$(grep -E '^ Summary: [0-9]+ passed, [0-9]+ failed' "$LOG" | tail -1)"
if [ -z "$summary" ]; then
    echo "ERROR: the suite printed no summary line — it did not finish."
    echo "--- last 40 lines ---"
    tail -40 "$LOG"
    exit 2
fi

passed="$(echo "$summary" | sed -n 's/.*Summary: \([0-9]*\) passed.*/\1/p')"
failed="$(echo "$summary" | sed -n 's/.*passed, \([0-9]*\) failed.*/\1/p')"

echo "suite reported: $passed passed, $failed failed (exit $suite_rc)"

rc=0
if [ "${failed:-1}" -ne 0 ]; then
    echo "FAIL: $failed test(s) failed."
    grep -nE 'FAIL|ERROR|Assertion|Sanitizer|runtime error:' "$LOG" | head -40
    rc=1
fi

if [ "${passed:-0}" -lt "$expected" ]; then
    echo "FAIL: only $passed test(s) passed but $expected exist on disk."
    echo "      Something did not run.  That is a failure, not a smaller suite."
    rc=1
fi

if [ "$suite_rc" -ne 0 ] && [ "$rc" -eq 0 ]; then
    echo "FAIL: the suite exited $suite_rc despite a clean summary line."
    rc=1
fi

# Sanitizer output never appears in a healthy run, and a sanitizer report does
# not necessarily fail the test that produced it — the process can print a
# warning and carry on.  Treat any of it as a failure of the run.
if grep -qE 'ERROR: (Address|Leak|Thread|UndefinedBehavior)Sanitizer|SUMMARY: .*Sanitizer|runtime error:' "$LOG"; then
    echo "FAIL: sanitizer output in the suite log."
    grep -nE 'ERROR: .*Sanitizer|SUMMARY: .*Sanitizer|runtime error:' "$LOG" | head -20
    rc=1
fi

# The invariants header reports violations on stderr and, in warn-only mode,
# keeps going — so a violated invariant leaves no trace in any exit code.
if grep -q '\[invariant\]' "$LOG"; then
    echo "FAIL: invariant violation reported during the suite."
    grep -n '\[invariant\]' "$LOG" | head -20
    rc=1
fi

[ "$rc" -eq 0 ] && echo "PASS: $passed/$expected tests, no failures, no sanitizer or invariant output."
exit "$rc"
