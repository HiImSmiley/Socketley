#!/usr/bin/env bash
# Integration test: --drain flushes what was queued
#
# --drain had no behavioural test.  The flag appears once under test/, as a
# string inside a name-resolution unit test that never starts a runtime, so
# nothing has ever checked that it does what the man page says: "closes its
# listener but flushes all pending write queues before closing connections."
#
# The measurement needs a backlog that actually exists at the moment of the
# stop, so the fixture queues 6.4 MB to a client that deliberately does not
# read.  A socket buffer is a few hundred KB; the rest sits in the runtime's own
# write queue, which is the thing --drain is about.
#
# Both arms, always.  "The client received a lot" is equally true of a build
# that ignores the flag, so what is asserted is the DIFFERENCE between a runtime
# stopped with --drain and one stopped without it.  The without arm is not
# decoration: it is the only assertion here that fails if --drain becomes a
# no-op.
#
# It used to run that pair TWICE, once in a worker and once in the daemon, with
# a third assertion that the worker drained at least as well.  --daemon-process
# is gone and every runtime is a worker, so the second pair was the same
# configuration under a different name and the third assertion compared a number
# with itself.  Both are removed rather than left passing: an assertion that
# cannot fail is not coverage.  What it was guarding against is still worth
# knowing -- --reconnect worked only in the daemon for a while, which was
# invisible because the daemon was where tests looked -- and the guard now is
# that there is nowhere else to look.
#
# Thresholds are ratios and floors, not the observed constants.  Measured on
# this tree the two arms are 4,930,596 and 2,636,801 bytes, identical across
# three rounds — but a figure that
# reproduces to the byte today is still a figure a buffer size could move, and
# a test that pins it would fail for a reason that is not a defect.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate drain

# lib_ports.sh:99 runs `exec 9>lockfile 2>/dev/null`; an exec with no command
# applies both redirections to the shell, so sourcing it discards this file's
# stderr for the rest of the run.  Put back — a failure that reports nothing but
# its own existence is most of an hour.  Fixed on fix/p0-crashes as 2eab0cf,
# which has not reached main.
exec 2>&1

PASS=0; FAIL=0; TOTAL=0
ok()  { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
bad() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  FAIL [$1]: $2"; }

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/socketley-drain.XXXXXX")
cleanup() {
    for r in dw_on dw_off; do
        "$BIN" stop "$r"   >/dev/null 2>&1 || true
        "$BIN" remove "$r" >/dev/null 2>&1 || true
    done
    rm -rf "$TMPD"
    daemon_stop
}
trap cleanup EXIT

cat > "$TMPD/flood.lua" <<'LUA'
-- Queue far more than a socket buffer holds, so a stop finds a real backlog.
function on_message(msg) end
function on_client_message(client_id, msg)
    local chunk = string.rep("x", 65536)
    for i = 1, 100 do self.send(client_id, chunk) end   -- 6.4 MB
end
LUA

cat > "$TMPD/probe.py" <<'PY'
import socket, sys, time
port, hold = int(sys.argv[1]), float(sys.argv[2])
s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
s.sendall(b"go\n")
time.sleep(hold)          # not reading on purpose: let the queue back up
s.settimeout(8)
total = 0
try:
    while True:
        b = s.recv(1 << 20)
        if not b: break
        total += len(b)
except socket.timeout:
    pass
print(total)
PY

# Queue, stop, then read whatever survived the stop.
measure() {  # name port extra_flags -> bytes on stdout
    local name=$1 port=$2 extra=${3:-}
    "$BIN" create server "$name" -p "$port" --mode in --lua "$TMPD/flood.lua" $extra -s \
        >/dev/null 2>&1 || { echo 0; return; }
    sleep 1
    ( python3 "$TMPD/probe.py" "$port" 2 > "$TMPD/$name.bytes" 2>/dev/null ) &
    local p=$!
    sleep 1.5                       # the trigger is sent and the queue is filling
    "$BIN" stop "$name" >/dev/null 2>&1 || true
    wait "$p" 2>/dev/null || true
    cat "$TMPD/$name.bytes" 2>/dev/null || echo 0
}

echo "=== Integration: --drain flushes the queue a stop would otherwise drop ==="

daemon_start "$BIN"

W_ON=$(measure  dw_on  $((SL_PORT_BASE+320)) "--drain")
W_OFF=$(measure dw_off $((SL_PORT_BASE+321)) "")

echo "  --drain $W_ON B   without $W_OFF B"

# ── Controls ────────────────────────────────────────────────────────────────
#
# Without these, "drain sent more than no-drain" is satisfied by a fixture that
# sent nothing at all in the second arm — including one where the runtime never
# started, the script never loaded, or the probe never connected.
for pair in "worker:$W_OFF"; do
    if [ "${pair#*:}" -gt 500000 ]; then ok
    else bad "control: the ${pair%%:*} fixture floods at all" \
             "the no-drain arm received ${pair#*:} B; a stop drops the queue but the socket buffer alone is more than this, so the flood did not happen"; fi
done

# ── What the flag promises ──────────────────────────────────────────────────
if [ "$W_ON" -gt $((W_OFF * 3 / 2)) ]; then ok
else bad "worker: --drain delivers more than a bare stop" \
         "with $W_ON B against $W_OFF B, the flag changed nothing a stop would not have done anyway"; fi

echo ""
echo "  passed: $PASS / $TOTAL"
[ "$FAIL" -eq 0 ]
