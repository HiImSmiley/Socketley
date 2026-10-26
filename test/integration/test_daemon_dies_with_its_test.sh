#!/usr/bin/env bash
# Integration test: a test killed from outside takes its daemon, the daemon's
# workers and its own helper processes with it
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# daemon_stop runs from a test's EXIT trap, and SIGKILL runs no trap: runs
# stopped from outside left daemons, workers and peers serving for ten hours,
# holding ports and state directories that later runs then had to route
# around.  lib_daemon.sh's daemon_watch waits for the test's shell to go and
# kills whatever carries its SOCKETLEY_SOCKET.  Here a child test starts a
# daemon with a worker-backed runtime and a helper process, and is killed with
# SIGKILL.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the killed test's daemon, worker or helper still running
#   * its state directory left behind
#   * a test that ends normally losing anything to the watcher
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
PASS=0; FAIL=0; TOTAL=0
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
echo "=== Integration: a test killed from outside takes its processes with it ==="

WORK=$(mktemp -d /tmp/socketley-dieswith-XXXXXX)
# The processes carrying one socket in their environment, the watcher's own test.
carriers() {
    local sock=$1 d p out=""
    for d in /proc/[0-9]*; do
        p=${d#/proc/}
        { tr '\0' '\n' <"$d/environ"; } 2>/dev/null | grep -qx "SOCKETLEY_SOCKET=$sock" || continue
        out="$out $p"
    done
    printf '%s' "${out# }"
}
# This file cleans up after a child the watcher failed to, so a red run leaves nothing either.
cleanup(){ [ -s "$WORK/sock" ] && for p in $(carriers "$(cat "$WORK/sock")"); do kill -9 "$p" 2>/dev/null; done; rm -rf "$WORK" "$(cat "$WORK/tmpd" 2>/dev/null)"; }
trap cleanup EXIT

cat > "$WORK/child.sh" <<CHILD
set -e
. "$HERE/lib_daemon.sh"
daemon_isolate dieswith-child
daemon_start "$BIN"
"$BIN" create server dw -p $((SL_PORT_BASE + 1901)) -s >/dev/null 2>&1 || true
sleep 300 &
echo "\$SOCKETLEY_SOCKET" > "$WORK/sock"
echo "\$SOCKETLEY_TMPD" > "$WORK/tmpd"
sleep 300
CHILD

# ── 1-3. killed with SIGKILL ───────────────────────────────────────────────
SL_PORT_BASE=$SL_PORT_BASE bash "$WORK/child.sh" >/dev/null 2>&1 &
CHILD=$!
for _ in $(seq 1 100); do [ -s "$WORK/tmpd" ] && break; sleep 0.1; done
SOCK=$(cat "$WORK/sock" 2>/dev/null || true); TMPD=$(cat "$WORK/tmpd" 2>/dev/null || true)
BEFORE=$(carriers "$SOCK")
echo "  child test: $(echo $BEFORE | wc -w) processes carry its socket before the kill"
[ "$(echo $BEFORE | wc -w)" -ge 3 ] && pass || fail "the child started a daemon, a worker and a helper" "carriers: '$BEFORE'"
{ kill -9 "$CHILD"; wait "$CHILD"; } 2>/dev/null || true
LEFT="$BEFORE"
for _ in $(seq 1 50); do LEFT=$(carriers "$SOCK"); [ -z "$LEFT" ] && break; sleep 0.1; done
[ -z "$LEFT" ] && pass || fail "nothing of a killed test is left running" "still running: $LEFT"
for _ in $(seq 1 30); do [ -d "$TMPD" ] || break; sleep 0.1; done
[ -n "$TMPD" ] && [ ! -d "$TMPD" ] && pass || fail "a killed test's state directory is removed" "$TMPD is still there"

# ── 4. a test that ends normally keeps what it cleans up itself ────────────
daemon_isolate dieswith-self
daemon_start "$BIN"
MINE=$SOCKETLEY_SOCKET
sleep 2
daemon_alive "$MINE" && pass || fail "the watcher leaves a live test alone" "this test's own daemon is gone"
daemon_stop

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
