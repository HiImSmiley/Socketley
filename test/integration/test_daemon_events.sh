#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: daemon.events, the mqtt runtime the daemon publishes its runtimes' states and its alerts on.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a runtime's state not kept retained on socketley/runtimes/<name>/state, so a subscriber that comes later does
#     not read how it stands, or a stop or a removal not told
#   * a state the daemon published before the broker existed lost rather than kept in the outbox until it runs
#   * an alert not kept on socketley/alerts/<id>, or one cleared that stays
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate dmnevents
T="$SOCKETLEY_TMPD"
M=$((SL_PORT_BASE+1960))
PB=$((SL_PORT_BASE+1961))
S0=$((SL_PORT_BASE+1962))
S1=$((SL_PORT_BASE+1963))
trap 'daemon_stop' EXIT

echo "=== Integration: the daemon's events on an mqtt runtime ==="

cat > "$T/daemon.lua" <<EOF
daemon = { metrics_port = $M, events = "bus" }
EOF
export SOCKETLEY_CONFIG="$T/daemon.lua"
daemon_start "$BIN"

# Made, started and stopped before the broker exists, so its states can only arrive from the outbox.
"$BIN" create server early -p "$S0" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$S0" || bad "the first server listens" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create mqtt bus -p "$PB" --anonymous -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$PB" || bad "the broker listens" "$(tail -3 "$SOCKETLEY_DLOG")"

# The retained messages a subscriber to socketley/# is handed, then whatever comes in the next `wait` seconds,
# as `topic retained payload` lines.
listen() {
    PYTHONPATH="$HERE" python3 - "$PB" "$1" "${2:-}" <<'PY'
import sys, time
from lib_mqtt import *
port, wait, until = int(sys.argv[1]), float(sys.argv[2]), sys.argv[3]
c = connected(port, "watch-%d" % int(time.time() * 1000))
c.subscribe(("socketley/#", 1))
end = time.time() + wait
seen = []
while time.time() < end:
    m = c.message(0.5)
    if m is None:
        continue
    line = "%s %d %s" % (m.topic, 1 if m.retain else 0, m.payload.decode(errors="replace"))
    seen.append(line)
    try:
        print(line, flush=True)
    except BrokenPipeError:
        # A reader that had what it wanted and went, and the flush at exit is not told so again.
        import os
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
    if until and until in line:
        break
c.disconnect()
PY
}

# A broker that came up after the states were made, so the first of them waits out a retry.
for _ in $(seq 1 40); do listen 1 | grep -q '^socketley/runtimes/early/state 1 .*"running"' && break; sleep 0.5; done
out=$(listen 2)
expect "a runtime's state made before the broker existed is kept on it, retained" \
    "$(echo "$out" | grep -c '^socketley/runtimes/early/state 1 {"name":"early","type":"server","state":"running"')" 1
expect "and the broker's own" "$(echo "$out" | grep -c '^socketley/runtimes/bus/state 1 .*"state":"running"')" 1

"$BIN" stop early >/dev/null 2>&1
for _ in $(seq 1 40); do listen 1 | grep -q '^socketley/runtimes/early/state 1 .*"stopped"' && break; sleep 0.25; done
expect "a stop is told, and kept" "$(listen 1 | grep -c '^socketley/runtimes/early/state 1 .*"state":"stopped"')" 1

listen 10 '"name":"live"' > "$T/live" &
L=$!
sleep 1
"$BIN" create server live -p "$S1" -s >/dev/null 2>&1
wait "$L"
got=$(cat "$T/live")
expect "a subscriber is told of a runtime made while it listens" \
    "$(echo "$got" | grep -c '^socketley/runtimes/live/state 0 .*"name":"live"')" 1

"$BIN" remove early >/dev/null 2>&1
for _ in $(seq 1 40); do listen 1 | grep -q '^socketley/runtimes/early/' || break; sleep 0.25; done
expect "a removed runtime's state is cleared from the broker" "$(listen 1 | grep -c '^socketley/runtimes/early/')" 0

# An alert, raised by a runtime that fails: its script is broken after it was made.
echo '-- fine' > "$T/s.lua"
"$BIN" create server broke -p $((SL_PORT_BASE+1964)) --lua "$T/s.lua" -s >/dev/null 2>&1
echo 'this is not lua (' > "$T/s.lua"
"$BIN" stop broke >/dev/null 2>&1
"$BIN" start broke >/dev/null 2>&1
for _ in $(seq 1 60); do listen 1 | grep -q '^socketley/alerts/failed:broke 1 ' && break; sleep 0.5; done
a=$(listen 1 | grep '^socketley/alerts/failed:broke 1 ' | cut -d' ' -f3-)
expect "an alert is kept on socketley/alerts/<id>, as its JSON" \
    "$(echo "$a" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["id"], d["level"], d["title"])' 2>&1)" \
    "failed:broke critical broke failed"
echo '-- fine' > "$T/s.lua"
"$BIN" start broke >/dev/null 2>&1
for _ in $(seq 1 60); do listen 1 | grep -q '^socketley/alerts/failed:broke ' || break; sleep 0.5; done
expect "and cleared from it once the runtime runs again" "$(listen 1 | grep -c '^socketley/alerts/failed:broke ')" 0

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
