#!/usr/bin/env bash
# Integration test: self.broadcast on a runtime that is N processes.
#
# ─── THIS FILE COULD NOT RUN UNTIL THE REFUSAL CAME OFF ────────────────────
#
# The only runtime that can exercise this is a scripted server with --shards,
# and that was refused while the mechanism was being built.  So it lived
# outside run_all.sh's test_*.sh glob as pending_, carrying the numbers below
# from a scratch build with the one refusal line disabled and nothing else
# changed.  It runs for real from the commit that removed the refusal; the
# figures are kept because they are the red this was watched failing at.
#
#     without the fan-out   15 of 40 sockets reached, 15 deliveries
#     with the fan-out      40 of 40 sockets reached, 40 deliveries
#     one-shard control     40 of 40 in both, which is what says the test is
#                           about sharding and not about broadcasting
#
# ─── THE DEFECT ────────────────────────────────────────────────────────────
#
# `self.broadcast(msg)` wrote to this PROCESS's connection table.  On four
# shards that is a quarter of the runtime's clients — delivered, reported as
# done, and wrong by nothing.  It is the failure the server's --shards refusal
# names in its own text: "a message from a client on one shard never reaches a
# client on another, and nothing reports it."
#
# ─── HOW THIS IS ASSERTED ──────────────────────────────────────────────────
#
# N clients connect and are spread across the shards by SO_REUSEPORT.  ONE of
# them sends a word.  The script's on_message broadcasts a marker, and the test
# counts how many of the N sockets carry that marker.
#
# The count is the assertion, and it has to be: an assertion that the sender got
# an answer passes on the broken build, because the sender is on the shard that
# handled the message and is the one client guaranteed to be reached.
#
#   broken build   the shard holding the sender reaches its own clients only,
#                  which for 40 over 4 shards is about 10.
#   this build     40.
#   double build   also caught.  A fan-out that echoes the frame back to the
#                  shard that sent it up delivers to those ~10 twice, so the
#                  test counts the DELIVERIES per socket, not the sockets that
#                  got at least one.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ [[ "$2" == "$3" ]] && ok "$1 ($2)" || bad "$1: expected '$3', got '$2'"; }

daemon_isolate shardfan
daemon_start "$BIN"

P_SRV=$((SL_PORT_BASE+760))
P_SRV1=$((SL_PORT_BASE+761))
WORK=$(mktemp -d)

cleanup() {
    "$BIN" stop  fan4 >/dev/null 2>&1 || true
    "$BIN" stop  fan1 >/dev/null 2>&1 || true
    sleep 0.2
    "$BIN" remove fan4 >/dev/null 2>&1 || true
    "$BIN" remove fan1 >/dev/null 2>&1 || true
    rm -rf "$WORK"
    daemon_stop
}
trap cleanup EXIT

cat > "$WORK/fan.lua" <<'LUA'
function on_message(msg)
    if msg:find("SHOUT") then
        self.broadcast("ALL:" .. tostring(self.connections()) .. "\n")
    end
end
LUA

# Counts DELIVERIES, not sockets that got at least one.  A fan-out that echoes
# the frame back to the shard that sent it up would reach that shard's clients
# twice, and a count of sockets would read that as success.
cat > "$WORK/fan.py" <<'PY'
import socket, sys, time
port = int(sys.argv[1]); n = int(sys.argv[2])
socks = []
for _ in range(n):
    s = socket.create_connection(('127.0.0.1', port), timeout=5)
    socks.append(s)
time.sleep(0.8)                      # every shard has accepted its share
socks[0].sendall(b"SHOUT\n")
time.sleep(1.2)                      # the fan-out is one daemon hop, not two
deliveries = 0
reached = 0
for s in socks:
    s.settimeout(0.4)
    buf = b""
    try:
        while True:
            d = s.recv(4096)
            if not d: break
            buf += d
    except Exception:
        pass
    c = buf.count(b"ALL:")
    deliveries += c
    if c: reached += 1
print("%d %d" % (reached, deliveries))
PY

N=40

echo "== a scripted server on four shards =="
"$BIN" create server fan4 -p $P_SRV --lua "$WORK/fan.lua" --shards 4 >/dev/null 2>&1
check "a sharded scripted server is accepted" "$?" "0"
"$BIN" start fan4 >/dev/null 2>&1
sleep 0.8

read -r REACHED DELIVERED < <(python3 "$WORK/fan.py" "$P_SRV" "$N")
echo "  observed: $REACHED of $N sockets reached, $DELIVERED deliveries in total"
check "every client of the runtime is reached" "$REACHED"   "$N"
check "and each of them exactly once"          "$DELIVERED" "$N"

# The sibling half goes over the shards' own links: with the daemon stopped, a
# half that still went through it would reach this shard's quarter and no more.
kill -STOP "$SOCKETLEY_DPID"
read -r REACHEDM DELIVEREDM < <(python3 "$WORK/fan.py" "$P_SRV" "$N")
kill -CONT "$SOCKETLEY_DPID"
echo "  observed with the daemon stopped: $REACHEDM of $N reached, $DELIVEREDM deliveries"
check "the fan-out reaches every client without the daemon" "$REACHEDM"   "$N"
check "and each of them exactly once without it"            "$DELIVEREDM" "$N"

echo "== the control: the same script on ONE shard =="
"$BIN" create server fan1 -p $P_SRV1 --lua "$WORK/fan.lua" --shards 1 >/dev/null 2>&1
"$BIN" start fan1 >/dev/null 2>&1
sleep 0.8

read -r REACHED1 DELIVERED1 < <(python3 "$WORK/fan.py" "$P_SRV1" "$N")
echo "  observed: $REACHED1 of $N sockets reached, $DELIVERED1 deliveries in total"
check "one shard reaches its own clients" "$REACHED1"   "$N"
check "and does not double-deliver"       "$DELIVERED1" "$N"

echo
echo "shard fanout: PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]]
