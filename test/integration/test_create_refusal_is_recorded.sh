#!/usr/bin/env bash
# Integration test: a `create -s` refused by the address check is written down.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# cmd_create's refusal-with-a-sentence keeps the runtime on purpose -- the
# comment there says so: "the runtime stays where `ls` shows it and `edit` can
# reach it".  But it returned nine lines above the only save_runtime() in the
# function, so what it kept had no state file.
#
# That is verbatim the failure the --test block further down in the same
# function was written to stop, and its comment says it in full: "what it left
# was startable: `start` on it bound the port and served, with no state file,
# so the daemon's next restart dropped a running runtime with no record that it
# had been there."  The same hole, one branch over.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# The two controls at the end.  A build that restored nothing would pass "the
# refused runtime did not come back Up" for entirely the wrong reason, and a
# build that started everything on boot would pass "it survives the restart"
# the same way.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate createrec

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
         local l; for l in "${@:3}"; do echo "        $l"; done; }
cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: a refused create -s is still written down ==="
daemon_start "$BIN"
P=$((SL_PORT_BASE + 1540))

"$BIN" create server cr_hold -p "$P" -s >/dev/null 2>&1 || true
sleep 0.8
RC=0; OUT=$("$BIN" create server cr_kept -p "$P" -s 2>&1) || RC=$?
sleep 0.5

# Control: the refusal happened, and it is the address one rather than some
# other failure that also exits non-zero.
case "$RC:$OUT" in
    1:*"already serving"*) pass ;;
    *) fail "the second create is refused for the address" \
            "exit $RC: ${OUT:-<nothing>}" ;;
esac

# Control: the documented behaviour -- the runtime is kept.
if "$BIN" ls --name 2>/dev/null | grep -qx cr_kept; then pass
else fail "a refused create keeps the runtime" "ls does not list cr_kept"; fi

# ─── The assertion ──────────────────────────────────────────────────────────
# Written by the state writer's own thread, synced with its directory, so it is waited for rather than slept on.
REC=""
for _ in $(seq 1 50); do
    REC=$(find "$HOME/.local/share/socketley" -name 'cr_kept.json' -type f -print -quit 2>/dev/null)
    [ -n "$REC" ] && break
    sleep 0.1
done
if [ -n "$REC" ] && [ -f "$REC" ]; then pass
else fail "the kept runtime has a state record" \
          "no cr_kept.json under $HOME/.local/share/socketley" \
          "it is listed and it is startable, and the next daemon start drops" \
          "it without a word"; fi

restart_daemon() {
    kill "$SOCKETLEY_DPID" 2>/dev/null || true
    local i; for i in $(seq 1 60); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
    wait "$SOCKETLEY_DPID" 2>/dev/null || true
    : > "$SOCKETLEY_DLOG"
    "$BIN" daemon >>"$SOCKETLEY_DLOG" 2>&1 & SOCKETLEY_DPID=$!
    for i in $(seq 1 100); do
        grep -q "daemon started" "$SOCKETLEY_DLOG" 2>/dev/null && break; sleep 0.1
    done
    sleep 1.5
}
restart_daemon
status_of() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2 == n { print $7 }'; }

# ─── The consequence ────────────────────────────────────────────────────────
if "$BIN" ls --name 2>/dev/null | grep -qx cr_kept; then pass
else fail "the kept runtime survives a daemon restart" \
          "ls no longer lists cr_kept"; fi

# Control: a build that restored nothing would pass the line above vacuously.
if [ "$(status_of cr_hold)" = "Up" ]; then pass
else fail "the runtime that was running comes back" \
          "ls says '$(status_of cr_hold)' for cr_hold"; fi

# Control: it must come back stopped -- the start was refused, not performed,
# and starting it would bind the port cr_hold holds.
if [ "$(status_of cr_kept)" != "Up" ]; then pass
else fail "a runtime whose start was refused does not come back Up" \
          "two runtimes would be serving the same address"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
