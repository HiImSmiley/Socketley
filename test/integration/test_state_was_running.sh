#!/usr/bin/env bash
# Integration test: was_running survives a stop, and auto-restart works after one
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# flip_was_running() searched a state file for `"was_running": <old>` and then
# wrote the new literal at `pos + 16`.  `"was_running": ` is FIFTEEN characters.
# So every flip landed one byte into the value and one byte past its end:
#
#     "was_running": true,    ->    "was_running": tfalse
#     "was_running": false,   ->    "was_running": ftrue
#
# and it sealed itself, because the next flip looked for `": true` or
# `": false`, found neither, and returned having changed nothing.  One `stop`
# corrupted the field for the rest of that install.
#
# The comma it ate is load-bearing.  json_get_string reads a non-string value up
# to the next `,`, `]` or `}`, so `"was_running": true` with no comma parses as
# `true\n    "out_of_process": true` -- not "true", so the field falls back to
# its default of false.  A value that looks right in the file and reads as
# wrong.
#
# What it cost is the whole of what the man page calls "Runtimes that were
# running when the daemon last stopped are auto-started": any runtime ever
# stopped once stopped coming back, silently, for good.
#
# ─── WHAT THESE ASSERTIONS WOULD CATCH ──────────────────────────────────────
#
# The file checks are on the exact text, including the comma, because that is
# what distinguishes the bug from its symptom: a build with only the off-by-one
# fixed writes `"was_running": true` with no comma and still does not restore.
# The behaviour checks are on `ls` after a real daemon restart, with a stopped
# runtime beside the running one so that "everything comes back" cannot pass.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
# lib_ports.sh opens its lock with `exec 9>`; put stderr back afterwards.
exec 2>&1
daemon_isolate waswrun
PASS=0; FAIL=0; TOTAL=0

cleanup() { daemon_stop; }
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: was_running survives a stop ==="

daemon_start "$BIN"
P=$((SL_PORT_BASE + 1480))

STATE_DIR=$(find "$HOME/.local/share/socketley" -maxdepth 1 -type d -name 'runtimes*' 2>/dev/null | head -1)

"$BIN" create server wr_live -p $((P + 1)) -s >/dev/null 2>&1 || true
"$BIN" create server wr_dead -p $((P + 2)) -s >/dev/null 2>&1 || true
sleep 0.8

if [ -z "$STATE_DIR" ]; then
    STATE_DIR=$(find "$HOME/.local/share/socketley" -maxdepth 1 -type d -name 'runtimes*' 2>/dev/null | head -1)
fi
REC="$STATE_DIR/wr_live.json"

if [ -f "$REC" ]; then pass
else fail "the state record exists" "no file at $REC; every check below is vacuous"; fi

# ─── 1. The three writes, on the exact text ─────────────────────────────────
line_of() { grep -o '"was_running": [^ ]*' "$1" 2>/dev/null | head -1; }

AFTER_CREATE=$(line_of "$REC")
if [ "$AFTER_CREATE" = '"was_running": true,' ]; then pass
else fail "create -s records was_running true" \
          "the record says '${AFTER_CREATE:-<nothing>}'"; fi

"$BIN" stop wr_live >/dev/null 2>&1 || true
sleep 0.5
AFTER_STOP=$(line_of "$REC")
if [ "$AFTER_STOP" = '"was_running": false,' ]; then pass
else fail "stop records was_running false, comma and all" \
          "the record says '${AFTER_STOP:-<nothing>}'" \
          "'tfalse' is the off-by-one; 'false' with no comma is the half-fix" \
          "that still does not restore, because the value scanner reads to the" \
          "next comma"; fi

"$BIN" start wr_live >/dev/null 2>&1 || true
sleep 0.8
AFTER_START=$(line_of "$REC")
if [ "$AFTER_START" = '"was_running": true,' ]; then pass
else fail "a second start records was_running true again" \
          "the record says '${AFTER_START:-<nothing>}'" \
          "the old flip sealed itself here: it searched for the literal it had" \
          "already destroyed and returned having changed nothing"; fi

# ─── 2. And the behaviour that field exists for ─────────────────────────────
"$BIN" stop wr_dead >/dev/null 2>&1 || true
sleep 0.5

restart_daemon() {
    kill "$SOCKETLEY_DPID" 2>/dev/null || true
    local i
    for i in $(seq 1 60); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
    wait "$SOCKETLEY_DPID" 2>/dev/null || true
    : > "$SOCKETLEY_DLOG"
    "$BIN" daemon >>"$SOCKETLEY_DLOG" 2>&1 &
    SOCKETLEY_DPID=$!
    for i in $(seq 1 100); do
        grep -q "daemon started" "$SOCKETLEY_DLOG" 2>/dev/null && break
        sleep 0.1
    done
    sleep 1.5
}
restart_daemon

status_of() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2 == n { print $7 }'; }

LIVE=$(status_of wr_live)
DEAD=$(status_of wr_dead)

if [ "$LIVE" = "Up" ]; then pass
else fail "a runtime that was running is auto-started" \
          "ls reports '${LIVE:-<nothing>}' for wr_live after a daemon restart" \
          "it had been stopped and started once, which is the case that broke"; fi

# The control.  Without it, a build that started everything on boot would pass
# the assertion above while getting the field exactly as wrong.
if [ "$DEAD" != "Up" ]; then pass
else fail "a runtime that was stopped stays stopped" \
          "ls reports Up for wr_dead, which was stopped before the restart"; fi

# ─── 3. A record an older build damaged is repaired ─────────────────────────
#
# Installs upgrading into this fix have directories full of these, and a value
# patch alone does not recover one -- see the header.
kill "$SOCKETLEY_DPID" 2>/dev/null || true
for i in $(seq 1 60); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
wait "$SOCKETLEY_DPID" 2>/dev/null || true

python3 - "$REC" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
s = re.sub(r'"was_running": (?:true|false),', '"was_running": tfalse', s)
open(p, 'w').write(s)
PY
DAMAGED=$(line_of "$REC")
if [ "$DAMAGED" = '"was_running": tfalse' ]; then pass
else fail "the damage fixture looks like the old build's output" \
          "the record says '${DAMAGED:-<nothing>}'"; fi

"$BIN" daemon >>"$SOCKETLEY_DLOG" 2>&1 &
SOCKETLEY_DPID=$!
for i in $(seq 1 100); do
    grep -q "daemon started" "$SOCKETLEY_DLOG" 2>/dev/null && break
    sleep 0.1
done
sleep 1
"$BIN" start wr_live >/dev/null 2>&1 || true
sleep 0.8

HEALED=$(line_of "$REC")
if [ "$HEALED" = '"was_running": true,' ]; then pass
else fail "a damaged record is repaired on the next flip" \
          "the record says '${HEALED:-<nothing>}'"; fi

restart_daemon
LIVE2=$(status_of wr_live)
if [ "$LIVE2" = "Up" ]; then pass
else fail "and the repaired record restores" \
          "ls reports '${LIVE2:-<nothing>}'"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
