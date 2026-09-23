#!/usr/bin/env bash
# Integration test: the Prometheus metrics endpoint reports the daemon it is in
#
# daemon/metrics_endpoint.cpp measured 3.7% line coverage -- 349 lines, 336 of
# them never executed by any test.  The reason is structural rather than
# neglectful: the endpoint only exists when `metrics_port` is set in the daemon
# config file, and no test had ever written one.  A test can, because
# daemon_isolate gives each file a private HOME and the dev-mode config path is
# $HOME/.config/socketley/config.lua.
#
# What is asserted is that the numbers TRACK THE WORLD, not that they are
# present.  Grepping for `socketley_runtimes_total` passes against a build that
# prints a hardcoded 0, and against one that prints last week's figure.  So the
# runtime count is read three times -- with none, with one, with two -- and each
# reading has to differ from the last.
#
# There is a trap next door worth knowing about.  SOCKETLEY_CONFIG is the
# documented way to point a daemon at this file, and test/run_all.sh uses the
# same variable name to choose which build to run.  run_all.sh only assigns it,
# so it does not leak -- but CI sets it in the environment, and so does anyone
# typing `SOCKETLEY_CONFIG=Sanitize bash test/run_all.sh`.  In those runs every
# daemon the suite starts looks for a config file named "Sanitize", finds
# nothing, and silently uses none.  This file therefore uses the config path and
# never the variable.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate metrics

# lib_ports.sh:99 runs `exec 9>lockfile 2>/dev/null`; an exec with no command
# applies both redirections to the shell, so sourcing it discards stderr for the
# rest of the file.  Put back.  Fixed on fix/p0-crashes as 2eab0cf, not on main.
exec 2>&1

# The collision described above, disarmed for this file's own daemon.  It is not
# hypothetical: with SOCKETLEY_CONFIG=Coverage in the environment -- which is how
# `SOCKETLEY_CONFIG=Coverage bash test/run_all.sh` and the nightly Sanitize job
# both run -- the daemon takes "Coverage" as the path to its config file, finds
# nothing there, never reads metrics_port, and never opens the port.  Every
# assertion below then reports an empty response.  Measured: 11/11 without the
# variable, 4/11 with it.
#
# Safe to unset here: run_all.sh has already resolved it into BIN_DIR and
# exported BIN, so nothing downstream needs it.
unset SOCKETLEY_CONFIG

MPORT=$((SL_PORT_BASE+340))
S1=$((SL_PORT_BASE+341))
S2=$((SL_PORT_BASE+342))

PASS=0; FAIL=0; TOTAL=0
ok()  { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
bad() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  FAIL [$1]: $2"; }

cleanup() {
    for r in m_one m_two; do
        "$BIN" stop "$r" >/dev/null 2>&1 || true
        "$BIN" remove "$r" >/dev/null 2>&1 || true
    done
    daemon_stop
}
trap cleanup EXIT

# Written before the daemon starts: the port is read once, at startup.
mkdir -p "$HOME/.config/socketley"
cat > "$HOME/.config/socketley/config.lua" <<LUA
config = {
    metrics_port = $MPORT
}
LUA

get() {  # path -> raw response
    printf 'GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' "$1" \
        | timeout 8 nc 127.0.0.1 "$MPORT" 2>/dev/null || true
}
metric() {  # name -> value, or empty
    get /metrics | awk -v n="$1" '$1==n{print $2; exit}'
}

echo "=== Integration: the metrics endpoint reports its own daemon ==="

daemon_start "$BIN"

# Wait for the listener, do not sleep at it.  A fixed 0.5s passed against the
# Release build and failed against Coverage, which is unoptimised and slower to
# reach the bind -- four assertions went red reporting an empty response, and
# the honest report is "the port never opened", which is a different sentence.
# 20s because the slowest build here is the instrumented one, and a deadline
# that only fits the fastest is a deadline that tests the machine.
LISTENING=0
for _ in $(seq 200); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$MPORT") 2>/dev/null; then exec 3<&- 3>&-; LISTENING=1; break; fi
    sleep 0.1
done
if [ "$LISTENING" = "1" ]; then ok
else bad "the daemon opens the metrics port" \
         "nothing accepted on $MPORT within 20s; config.lua was written before daemon_start, so either it was not read or the bind failed — every assertion below would report an empty response and none of them would say this"; fi

# ── It is there at all ──────────────────────────────────────────────────────
RESP=$(get /metrics)
if grep -q "200 OK" <<<"$RESP"; then ok
else bad "GET /metrics answers 200" "config.lua set metrics_port=$MPORT before the daemon started; got: $(head -1 <<<"$RESP")"; fi

# The content type is the contract a scraper reads.  Without this, serving the
# dashboard's HTML here would pass every assertion below that greps for a name.
if grep -qi "text/plain; version=0.0.4" <<<"$RESP"; then ok
else bad "the exposition format is declared" "no Prometheus content-type in the response headers"; fi

# ── And the numbers are this daemon's ───────────────────────────────────────
#
# Three readings, each required to differ from the one before it.  A build that
# answers a constant -- 0, or a figure computed once at startup -- satisfies
# "the metric is present" and fails here.
M0=$(metric socketley_runtimes_total)
create_ok "first runtime" "$BIN" create server m_one -p "$S1" --mode inout -s
sleep 1
M1=$(metric socketley_runtimes_total)
create_ok "second runtime" "$BIN" create server m_two -p "$S2" --mode inout -s
sleep 1
M2=$(metric socketley_runtimes_total)

echo "  socketley_runtimes_total: none=$M0 one=$M1 two=$M2"

if [ -n "$M0" ] && [ -n "$M1" ] && [ -n "$M2" ]; then ok
else bad "socketley_runtimes_total is exported" "one of the three readings was absent: '$M0' '$M1' '$M2'"; fi

if [ "${M1:-x}" != "${M0:-y}" ] && [ "${M2:-x}" != "${M1:-y}" ]; then ok
else bad "the count follows the runtimes" \
         "readings were $M0, $M1, $M2 — a metric that does not move when a runtime is created is reporting something other than this daemon"; fi

# Direction, not just change: a counter that drifts would also satisfy the above.
if [ "${M2%%.*}" -gt "${M0%%.*}" ] 2>/dev/null; then ok
else bad "the count rises when runtimes are added" "went $M0 -> $M2"; fi

# ── The running gauge answers a different question from the total ───────────
R_BEFORE=$(metric socketley_runtimes_running)
"$BIN" stop m_two >/dev/null 2>&1 || true
sleep 1
R_AFTER=$(metric socketley_runtimes_running)
T_AFTER=$(metric socketley_runtimes_total)
echo "  running: before=$R_BEFORE after_stop=$R_AFTER   total_after=$T_AFTER"

if [ "${R_AFTER:-x}" != "${R_BEFORE:-y}" ]; then ok
else bad "stopping a runtime moves the running gauge" \
         "running stayed at $R_AFTER across a stop, so it is not measuring what its name says"; fi

# The one that separates the two gauges.  If both tracked the same thing, every
# assertion above would still pass.
if [ "${T_AFTER:-x}" = "${M2:-y}" ]; then ok
else bad "stopping a runtime does not change the total" \
         "total went $M2 -> $T_AFTER across a stop; a stopped runtime still exists"; fi

# ── The dashboard shares the port ───────────────────────────────────────────
DASH=$(get /)
if grep -q "200 OK" <<<"$DASH" && grep -qi "html" <<<"$DASH"; then ok
else bad "GET / serves the dashboard" "got: $(head -1 <<<"$DASH")"; fi

# ── Three endpoints, one cache ─────────────────────────────────────────────
# /metrics, /api/overview and /api/runtimes share m_cached_* and one
# m_cache_time, and each refresh empties the other two.  Both JSON endpoints
# carry an `else if (…empty())` that rebuilds what a sibling cleared; /metrics
# did not, so a dashboard poll inside the 1s TTL left it answering 200 OK with
# Content-Length: 0 -- a scrape Prometheus records as successful with every
# series missing.
#
# Both requests are issued from one process rather than two `nc` spawns, so the
# gap is microseconds and the second is inside the TTL on any build.  A pair
# that straddled the TTL would refresh and pass while measuring nothing.
# The clearing happens ONLY on the refresh branch, so the pair has to begin
# with one.  Without this wait the assertions above have just refreshed, the
# overview takes its `else if` arm instead, clears nothing, and the check below
# passes against a build that still has the defect -- measured: 13/13 green
# before this line was here.
sleep 1.2
PAIR=$(python3 - "$MPORT" <<'PYEOF'
import socket, sys
port = int(sys.argv[1])
def fetch(path):
    s = socket.create_connection(("127.0.0.1", port), 8); s.settimeout(8)
    s.sendall(("GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" % path).encode())
    out = b""
    while True:
        try: d = s.recv(65536)
        except Exception: break
        if not d: break
        out += d
    s.close()
    return out.decode("latin1", "replace")
first = fetch("/api/overview")
second = fetch("/metrics")
body = second.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in second else ""
print("overview_ok=%s" % ("200 OK" in first.split("\r\n")[0]))
print("metrics_status=%s" % second.split("\r\n")[0].strip())
print("metrics_body_bytes=%d" % len(body))
print("has_series=%s" % ("socketley_runtimes_total" in body))
PYEOF
)
echo "  after a dashboard poll: $(echo "$PAIR" | tr '\n' ' ')"

case "$PAIR" in
    *"overview_ok=True"*) ok ;;
    *) bad "the dashboard endpoint answers, so it did refresh the shared cache" \
           "$(echo "$PAIR" | tr '\n' ' ')" ;;
esac

case "$PAIR" in
    *"has_series=True"*) ok ;;
    *) bad "/metrics still carries its series right after a dashboard poll" \
           "$(echo "$PAIR" | tr '\n' ' ')" ;;
esac

echo ""
echo "  passed: $PASS / $TOTAL"
[ "$FAIL" -eq 0 ]
