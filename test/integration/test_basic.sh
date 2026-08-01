#!/usr/bin/env bash
# Integration test: basic runtime lifecycle (create/run/stop/remove)
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
daemon_isolate basic
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop testsvr 2>/dev/null || true
    "$BIN" stop autosvr 2>/dev/null || true
    sleep 0.5
    "$BIN" remove testsvr 2>/dev/null || true
    "$BIN" remove autosvr 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

# assert_ok STATUS LABEL [OUTPUT]
#
# The status is passed in.  It used to be read from $? inside the function, one
# line after `TOTAL=$((TOTAL+1))` — and an assignment is a command, so $? was the
# status of the arithmetic, which is 0 whatever the caller did.  Every one of the
# five lifecycle steps below therefore passed unconditionally: this file reported
# 9/9 for `create`, `start`, `stop` and `remove` no matter what the daemon said.
# The `|| true` on each call made the point moot from the other end as well.
assert_ok() {
    TOTAL=$((TOTAL+1))
    local rc="$1" label="$2" out="${3:-}"
    if [ "$rc" -eq 0 ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: exit $rc"
        # An `if` rather than `[ -n … ] && printf`: the latter is the last
        # command of the function, so an empty message would make the function
        # return 1 and `set -e` would end the run at the first failed assertion.
        if [ -n "$out" ]; then printf '        said: %s\n' "$out"; fi
    fi
}

assert_contains() {
    TOTAL=$((TOTAL+1))
    if echo "$1" | grep -q "$2"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL: expected '$2' in output"
    fi
}

echo "=== Integration: basic lifecycle ==="

# Ensure daemon is running (started by run_all.sh or already running)
daemon_start "$BIN"

# Test: create server
create_ok "create server" "$BIN" create server testsvr -p 19000

# Test: ls shows it
#
# The guard is not decoration.  `OUT=$(cmd)` on a line of its own is a simple
# command whose exit status is the substitution's, so under `set -euo pipefail`
# a failing `ls` ended this file here — at an assignment, with no assertion, no
# `Results` line and no `OK`/`FAILED`.  daemon_required rather than `|| true`
# because the two failures are not the same one: an `ls` that fails while the
# daemon still answers is a finding the assertion below states exactly, and an
# `ls` that fails because the daemon is gone makes every assertion after it
# noise.  Only the second stops, and it stops printing counts.  See lib_daemon.sh.
OUT=$("$BIN" ls 2>&1) || daemon_required "ls"
assert_contains "$OUT" "testsvr"

# Test: start
RC=0; OUT=$("$BIN" start testsvr 2>&1) || RC=$?
assert_ok "$RC" "start server" "$OUT"
sleep 0.2

# Test: ps shows running
OUT=$("$BIN" ps 2>&1) || daemon_required "ps"
assert_contains "$OUT" "testsvr"

# Test: stop
RC=0; OUT=$("$BIN" stop testsvr 2>&1) || RC=$?
assert_ok "$RC" "stop server" "$OUT"
sleep 0.2

# Test: remove
RC=0; OUT=$("$BIN" remove testsvr 2>&1) || RC=$?
assert_ok "$RC" "remove server" "$OUT"

# Test: ls no longer shows testsvr
OUT=$("$BIN" ls 2>&1) || daemon_required "ls"
TOTAL=$((TOTAL+1))
if ! echo "$OUT" | grep -q "testsvr"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: testsvr still in ls after remove"
fi

# Test: create with -s (start immediately)
create_ok "create+start" "$BIN" create server autosvr -p 19001 -s
sleep 0.2
OUT=$("$BIN" ps 2>&1) || daemon_required "ps"
assert_contains "$OUT" "autosvr"

# Cleanup
"$BIN" stop autosvr 2>/dev/null || true
sleep 0.5
"$BIN" remove autosvr 2>/dev/null || true

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
