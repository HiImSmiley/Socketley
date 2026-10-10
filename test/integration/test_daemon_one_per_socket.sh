#!/usr/bin/env bash
# Integration test: daemons started at once on one socket leave exactly one.
#
# A starting daemon asked whether its socket was free and then unlinked and
# bound it, so two started together both found it free and the second took the
# path from the first: two daemons on one state directory, the first serving
# nobody and never exiting.  A CLI command's auto-start racing a daemon started
# by hand is the ordinary way to get there.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
daemon_isolate onesock
PASS=0; FAIL=0; TOTAL=0

daemons() {   # this test's daemon processes
    for p in $(pgrep -x socketley 2>/dev/null); do
        [[ "$(readlink /proc/$p/exe 2>/dev/null)" == "$BIN" ]] || continue
        grep -qs "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" "/proc/$p/environ" || continue
        tr '\0' ' ' < "/proc/$p/cmdline" | grep -q ' daemon' && echo "$p"
    done
}
cleanup() {
    for p in $(daemons); do kill -9 "$p" 2>/dev/null; done
    daemon_stop
}
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: one daemon per socket ==="

for round in 1 2 3; do
    for _ in 1 2 3 4; do "$BIN" daemon >/dev/null 2>&1 & done
    "$BIN" ping >/dev/null 2>&1
    # A loser waits for the winner's socket to answer and then leaves, so a moment is given to it.
    n=0
    for _ in $(seq 1 40); do
        n=$(daemons | wc -l)
        [ "$n" -eq 1 ] && break
        sleep 0.1
    done
    if [ "$n" -eq 1 ]; then pass "round $round: five starts at once leave one daemon"
    else fail "round $round: five starts at once leave one daemon" "$n daemons on $SOCKETLEY_SOCKET"; fi

    # The one left is the one the socket reaches.
    OWNER=$(ss -xlpn 2>/dev/null | grep -F "$SOCKETLEY_SOCKET " | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
    if [ -n "$OWNER" ] && [ "$OWNER" = "$(daemons | head -1)" ]; then pass "round $round: and it holds the socket"
    else fail "round $round: and it holds the socket" "socket owner '${OWNER:-none}', daemons: $(daemons | tr '\n' ' ')"; fi

    for p in $(daemons); do kill -9 "$p" 2>/dev/null; done
    for _ in $(seq 1 30); do [ -z "$(daemons)" ] && break; sleep 0.1; done
    rm -f "$SOCKETLEY_SOCKET"
done

# A daemon started while one is serving changes nothing and says nothing.
"$BIN" daemon >/dev/null 2>&1 &
for _ in $(seq 1 50); do "$BIN" ping >/dev/null 2>&1 && break; sleep 0.1; done
# The ping may have started one of its own, which leaves once the other answers.
for _ in $(seq 1 40); do [ "$(daemons | wc -l)" -eq 1 ] && break; sleep 0.1; done
FIRST=$(daemons)
OUT=$("$BIN" daemon 2>&1); RC=$?
if [ "$RC" -eq 0 ] && [ -z "$OUT" ] && [ "$(daemons)" = "$FIRST" ]; then pass "a second start beside a serving daemon is a silent no-op"
else fail "a second start beside a serving daemon is a silent no-op" "exit $RC, said '$OUT', daemons '$FIRST' then '$(daemons | tr '\n' ' ')'"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
