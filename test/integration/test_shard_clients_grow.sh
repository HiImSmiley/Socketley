#!/usr/bin/env bash
# Integration test: self.clients() on every shard after the shard count grew.
#
# ─── THE DEFECT ────────────────────────────────────────────────────────────
#
# The client list the shards of one server share is a region whose width is
# the shard count, fixed when it is made.  `edit --shards` is refused while the
# runtime runs, and `stop` takes every shard down before it answers, so a new
# count always meets a fresh set and a fresh region.  One stop did not: a
# script running in the daemon -- a runtime a worker's script made with
# socketley.create -- calling socketley.stop only marked the placeholder
# stopped, and the shards went on serving until the next health tick.  An
# `edit --shards 3` and a `start` inside that window found two live shards,
# kept them, forked a third and gave it a NEW region, which the two survivors
# never saw.
#
#     without the fix   clients() said 27 on the two survivors and 3 on the
#                       new shard, for 30 connections
#     with it           30 on every shard
#
# ─── WHAT EACH ASSERTION WOULD CATCH ───────────────────────────────────────
#
#   two shards agree     The control: the script and the counting work before
#   before the grow      anything changes.
#
#   the port is free     The in-daemon stop took the shards down before the
#   after the stop       script got its answer, as the CLI's and a worker
#                        script's stop do.  Without it the survivors serve the
#                        port for up to a tick.
#
#   three shards agree   The one this file exists for, asserted as the SET of
#   after the grow       counts the shards answered with, so one shard short
#                        of the others shows up as a second number.
#
# It is red without the fix unless the daemon's own two-second tick happens to
# reconcile between the script's stop and the start, a window of about a tenth
# of a second.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ [[ "$2" == "$3" ]] && ok "$1 ($2)" || bad "$1: expected '$3', got '$2'"; }

daemon_isolate shardgrow
daemon_start "$BIN"

P_SRV=$((SL_PORT_BASE+790))
P_STOP=$((SL_PORT_BASE+791))
P_CTL=$((SL_PORT_BASE+792))
WORK=$(mktemp -d)

cleanup() {
    "$BIN" stop  grow ctl >/dev/null 2>&1 || true
    sleep 0.2
    "$BIN" remove grow ctl >/dev/null 2>&1 || true
    rm -rf "$WORK"
    daemon_stop
}
trap cleanup EXIT

cat > "$WORK/count.lua" <<'LUA'
function on_message(msg)
    if msg:find("COUNT") then
        self.broadcast("N:" .. tostring(#self.clients()) .. "\n")
    end
end
LUA

# Runs in the daemon, because a runtime a script creates does.
cat > "$WORK/stopper.lua" <<'LUA'
function on_message(msg)
    if msg:find("STOP") then
        self.broadcast("STOPPED:" .. tostring(socketley.stop("grow")) .. "\n")
    end
end
LUA

cat > "$WORK/ctl.lua" <<LUA
function on_start()
    socketley.create("server", "stopper", { port = $P_STOP, lua = "$WORK/stopper.lua", start = true })
end
LUA

# Every connection asks its own shard, so each shard's clients() answers.
cat > "$WORK/count.py" <<'PY'
import socket, sys, time
port = int(sys.argv[1]); n = int(sys.argv[2])
socks = [socket.create_connection(('127.0.0.1', port), timeout=5) for _ in range(n)]
time.sleep(1.0)                       # every shard has accepted its share
for s in socks:
    s.sendall(b"COUNT\n")
time.sleep(1.2)
counts = set()
for s in socks:
    s.settimeout(0.3)
    buf = b""
    try:
        while True:
            d = s.recv(65536)
            if not d: break
            buf += d
    except Exception:
        pass
    for line in buf.split(b"\n"):
        if line.startswith(b"N:"): counts.add(int(line[2:]))
print(",".join(str(c) for c in sorted(counts)) or "none")
PY

cat > "$WORK/stop.py" <<'PY'
import socket, sys
s = socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=5)
s.sendall(b"STOP\n")
s.settimeout(5)
buf = b""
while b"\n" not in buf:
    d = s.recv(4096)
    if not d: break
    buf += d
print(buf.decode().strip() or "none")
PY

shard_count() { "$BIN" stats grow 2>/dev/null | grep -c '^\[shard'; }

N=30

echo "== a scripted server on two shards =="
"$BIN" create server grow -p $P_SRV --lua "$WORK/count.lua" --shards 2 -s >/dev/null 2>&1
check "the sharded server starts" "$?" "0"
"$BIN" create server ctl -p $P_CTL --lua "$WORK/ctl.lua" -s >/dev/null 2>&1
check "the server whose script makes the stopper starts" "$?" "0"
ready_tcp 127.0.0.1 "$P_STOP" 10 || echo "  NOTE: the stopper never accepted"
sleep 0.5
check "two shards" "$(shard_count)" "2"
COUNTS=$(python3 "$WORK/count.py" "$P_SRV" "$N")
check "two shards agree on the clients before the grow" "$COUNTS" "$N"

echo "== stopped by a script in the daemon, grown, started =="
check "the script's stop succeeds" "$(python3 "$WORK/stop.py" "$P_STOP")" "STOPPED:true"
# Once and at once, because every moment spent here widens the window the
# daemon's own tick can close for a build without the fix.
free=no
nc -z 127.0.0.1 "$P_SRV" 2>/dev/null || free=yes
check "the port is free after the script's stop" "$free" "yes"
"$BIN" edit grow --shards 3 >/dev/null 2>&1
check "the shard count is editable once stopped" "$?" "0"
"$BIN" start grow >/dev/null 2>&1
check "it starts again" "$?" "0"
sleep 0.8
check "three shards" "$(shard_count)" "3"

COUNTS=$(python3 "$WORK/count.py" "$P_SRV" "$N")
echo "  observed: the shards' clients() said [$COUNTS] for $N connections"
check "every shard sees every client after the grow" "$COUNTS" "$N"

echo
echo "shard clients grow: PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]]
