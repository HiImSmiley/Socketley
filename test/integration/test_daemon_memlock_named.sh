#!/usr/bin/env bash
# Integration test: a ring the kernel refuses for locked memory says so.
#
# Each io_uring is charged to its user's RLIMIT_MEMLOCK, which every process of
# that user shares, and systemd's default is 8 MiB: under the packaged unit the
# daemon stopped creating runtimes near the thirtieth, each worker logging
# "could not initialise io_uring" and the CLI "the worker did not accept its
# configuration".  The unit lifts the limit now, and a refusal names it.
#
# A limit of zero refuses any ring the kernel charges, whatever else this user
# holds, so the refusal is certain where the charge exists at all.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
. "$(dirname "$0")/lib_daemon.sh"
daemon_isolate memlock
PASS=0; FAIL=0; TOTAL=0
trap daemon_stop EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a ring refused for locked memory names RLIMIT_MEMLOCK ==="

if grep -qx 'LimitMEMLOCK=infinity' "$ROOT/packaging/socketley.service"; then
    pass "the packaged unit lifts the locked-memory limit"
else
    fail "the packaged unit lifts the locked-memory limit" "no LimitMEMLOCK=infinity in packaging/socketley.service"
fi

OUT=$( (ulimit -S -l 0 && exec timeout 5 "$BIN" daemon) 2>&1 ); RC=$?
if [ "$RC" -eq 124 ]; then
    echo "  SKIP: this kernel does not charge an io_uring to RLIMIT_MEMLOCK, so the daemon started at a limit of 0"
elif [ "$RC" -eq 1 ] && grep -q 'refused an io_uring (Cannot allocate memory).*RLIMIT_MEMLOCK is 0 KiB' <<<"$OUT"; then
    pass "a daemon at a locked-memory limit of 0 says the limit refused its ring"
else
    fail "a daemon at a locked-memory limit of 0 says the limit refused its ring" \
         "exit $RC, said: $(tr '\n' ' ' <<<"$OUT" | cut -c1-300)"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
