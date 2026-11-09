#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a worker is sent the runtime map only once its runtime reads it, and what it reads then is all of it.
#
# What it would catch: every worker woken for every row that moves anywhere in the daemon -- a create in a daemon of N
# runtimes waking N processes, which is what made the 200th create half as fast as the 20th -- and, on the other side,
# a reader handed a map that misses the runtimes made before its first read, or the ones made after it.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate mapdemand
T=$SOCKETLEY_TMPD; P=$((SL_PORT_BASE+1760))
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
trap 'daemon_stop' EXIT

# Answers nothing and reads nothing, so nothing in it needs the map.
cat >"$T/quiet.lua" <<'LUA'
function on_client_message(id, msg) self.send(id, "quiet") return true end
LUA

# Reads the map at its top level, which is during its start, and again on every request.
cat >"$T/reader.lua" <<'LUA'
local at_start = #socketley.list()
function on_client_message(id, msg)
    if msg == "start" then self.send(id, tostring(at_start)) end
    if msg == "now" then self.send(id, tostring(#socketley.list())) end
    return true
end
LUA

ask() { printf '%s\n' "$2" | timeout 3 nc -q 1 127.0.0.1 "$1" 2>/dev/null | head -1 | tr -d '\r'; }
worker_pid() { "$BIN" stats "$1" 2>/dev/null | awk -F: '/^pid:/{print $2}' | tr -d ' '; }
switches() { awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$1/status" 2>/dev/null; }
# expect_answer LABEL PORT REQUEST WANT -- the runtime answers WANT within five seconds.
expect_answer() {
    local got=""
    for _ in $(seq 1 50); do
        got=$(ask "$2" "$3")
        [ "$got" = "$4" ] && { ok; return; }
        sleep 0.1
    done
    bad "$1" "got '$got' want '$4'"
}

echo "=== Integration: the runtime map goes to a worker when its runtime reads it, and whole ==="
daemon_start "$BIN"
"$BIN" create server sink -p "$P" -s >/dev/null || bad "create the sink" "refused"
"$BIN" create server quiet -p $((P + 1)) --lua "$T/quiet.lua" -s >/dev/null || bad "create quiet" "refused"
"$BIN" create server early -p $((P + 2)) --lua "$T/reader.lua" -s >/dev/null || bad "create early" "refused"
expect_answer "quiet answers" $((P + 1)) x quiet
expect_answer "a reader sees what was there at its start" $((P + 2)) start 3

qpid=$(worker_pid quiet); epid=$(worker_pid early)
[ -n "$qpid" ] && [ -n "$epid" ] || bad "worker pids" "quiet '$qpid' early '$epid'"
sleep 0.5
q0=$(switches "$qpid"); e0=$(switches "$epid")

# Twenty creates with no port, so the endpoint table, which every worker is sent, does not move.
for i in $(seq 1 20); do
    "$BIN" create client "c$i" -t "127.0.0.1:$P" -s >/dev/null || bad "create c$i" "refused"
done
# Counted before anything asks either of them, so only what the daemon sent them can wake them.
sleep 0.5
q1=$(switches "$qpid"); e1=$(switches "$epid")

# The reader is the instrument's control: a worker that holds the map is woken for these creates.
if [ -n "$e0" ] && [ -n "$e1" ] && [ $((e1 - e0)) -ge 20 ]; then ok
else bad "the reader is woken by the creates it follows" "voluntary switches $e0 -> $e1"; fi
if [ -n "$q0" ] && [ -n "$q1" ] && [ $((q1 - q0)) -lt 10 ]; then ok
else bad "a worker that never reads the map sleeps through twenty creates" "voluntary switches $q0 -> $q1"; fi
expect_answer "a reader follows every create after its first read" $((P + 2)) now 23

# A reader made after them all reads all of them at its start, itself included.
"$BIN" create server late -p $((P + 3)) --lua "$T/reader.lua" -s >/dev/null || bad "create late" "refused"
expect_answer "a reader made later sees every runtime at its start" $((P + 3)) start 24

"$BIN" remove c1 >/dev/null; "$BIN" remove c2 >/dev/null
expect_answer "and every remove after it" $((P + 3)) now 22

# A reader whose worker died starts empty again and is filled at its next read.
lpid=$(worker_pid late)
[ -n "$lpid" ] && kill -9 "$lpid" 2>/dev/null
for _ in $(seq 1 100); do
    new=$(worker_pid late)
    [ -n "$new" ] && [ "$new" != "$lpid" ] && [ -n "$(ask $((P + 3)) now)" ] && break
    sleep 0.1
done
"$BIN" create client c21 -t "127.0.0.1:$P" -s >/dev/null || bad "create c21" "refused"
expect_answer "a restarted reader holds the whole map and the create after it" $((P + 3)) now 23

# quiet was never sent a row, and is still served.
expect_answer "quiet still answers" $((P + 1)) x quiet

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
