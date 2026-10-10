#!/usr/bin/env bash
# Integration test: self.clients() and self.send(id) across a shard boundary.
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
#     without this change   clients() said 10; 10 of 40 sockets pinged
#     with it               clients() said 40; 40 of 40, each exactly once
#     one-shard control     40 either way, which is what says the test is about
#                           sharding and not about sending
#
# ─── THE DEFECT ────────────────────────────────────────────────────────────
#
# `self.clients()` returned this PROCESS's descriptors.  On four shards that is
# a quarter of the runtime's clients, and the ids are descriptors — so two
# shards both have a client 12 and they are different sockets.  A script that
# took an id from one shard and handed it to another would not have been
# routed anywhere; it would have written into a stranger's connection, which
# is the defect conn_identity.h exists to have fixed.
#
# So `clients()` now returns this shard's descriptors plus a HANDLE for each
# client a sibling holds, out of the reserved range no descriptor can occupy,
# and `send(handle)` routes to the shard that owns it — one hop, because a
# conn_ref carries its minting shard in the top six bits of its serial.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ───────────────────────────────────────
#
#   clients() is 40      Broken build: about 10.  Asserted as a NUMBER: a
#                        script that got a non-empty list back would pass any
#                        weaker check on the broken build.
#
#   every socket gets    The list is only worth having if the ids in it work.
#   exactly one ping     Broken build: about 10 sockets pinged.  A build that
#                        routes to every shard instead of the owning one is
#                        caught by "exactly one" rather than "at least one".
#
#   the same client is   A script that calls clients() twice and compares must
#   the same number      get the same handle for the same client, or every id
#                        it stores between calls is worthless.
#
#                        This one PASSES on the broken build, and it was watched
#                        doing so: a build that mints no handles has nothing to
#                        be unstable about, so the assertion reports true over
#                        an empty set.  It bites only once the list contains
#                        handles, which is why it is asserted ALONGSIDE the
#                        count and would prove nothing on its own.  What it
#                        catches is a later build that mints a fresh handle per
#                        call — m_forwarded_by_ref not being consulted, or being
#                        pruned too eagerly.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ [[ "$2" == "$3" ]] && ok "$1 ($2)" || bad "$1: expected '$3', got '$2'"; }

daemon_isolate shardroute
daemon_start "$BIN"

P_SRV=$((SL_PORT_BASE+780))
P_SRV1=$((SL_PORT_BASE+781))
WORK=$(mktemp -d)

cleanup() {
    "$BIN" stop  rt4 >/dev/null 2>&1 || true
    "$BIN" stop  rt1 >/dev/null 2>&1 || true
    sleep 0.2
    "$BIN" remove rt4 >/dev/null 2>&1 || true
    "$BIN" remove rt1 >/dev/null 2>&1 || true
    rm -rf "$WORK"
    daemon_stop
}
trap cleanup EXIT

cat > "$WORK/route.lua" <<'LUA'
function on_message(msg)
    if msg:find("COUNT") then
        self.broadcast("N:" .. tostring(#self.clients()))
    elseif msg:find("PINGALL") then
        -- One message per client, addressed individually.  This is the whole
        -- point: broadcast already reaches everybody, and what is being tested
        -- is that an id out of clients() can be sent to on its own.
        for _, id in ipairs(self.clients()) do
            self.send(id, "P")
        end
    elseif msg:find("STABLE") then
        local a, b = self.clients(), self.clients()
        local sa, sb = {}, {}
        for _, v in ipairs(a) do sa[#sa+1] = tostring(v) end
        for _, v in ipairs(b) do sb[#sb+1] = tostring(v) end
        table.sort(sa); table.sort(sb)
        self.broadcast("STABLE:" .. tostring(table.concat(sa, ",") == table.concat(sb, ",")))
    end
end
LUA

# Three phases, each drained before the next, so a count is never contaminated
# by the phase before it.
cat > "$WORK/route.py" <<'PY'
import socket, sys, time
port = int(sys.argv[1]); n = int(sys.argv[2])
socks = [socket.create_connection(('127.0.0.1', port), timeout=5) for _ in range(n)]
time.sleep(1.0)                       # every shard has accepted its share

def drain(secs=1.2):
    time.sleep(secs)
    out = []
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
        out.append(buf)
    return out

# From every socket, so each shard's own clients() answers and one that disagrees adds a second count.
for s in socks:
    s.sendall(b"COUNT\n")
counts = set()
for b in drain():
    for line in b.split(b"\n"):
        if line.startswith(b"N:"): counts.add(int(line[2:]))

socks[0].sendall(b"PINGALL\n")
pings = [b.count(b"P") for b in drain()]

socks[0].sendall(b"STABLE\n")
stable = set()
for b in drain():
    for line in b.split(b"\n"):
        if line.startswith(b"STABLE:"): stable.add(line[7:].decode())

reached = sum(1 for c in pings if c >= 1)
exactly = sum(1 for c in pings if c == 1)
print("%s %d %d %s" % (
    ",".join(str(c) for c in sorted(counts)) or "none",
    reached, exactly,
    ",".join(sorted(stable)) or "none"))
PY

N=40

run_arm() {                     # $1 = runtime name, $2 = port, $3 = shards
    "$BIN" create server "$1" -p "$2" --lua "$WORK/route.lua" --shards "$3" >/dev/null 2>&1
    local rc=$?
    "$BIN" start "$1" >/dev/null 2>&1
    sleep 0.8
    python3 "$WORK/route.py" "$2" "$N"
    return $rc
}

echo "== a scripted server on four shards =="
read -r COUNTS REACHED EXACTLY STABLE < <(run_arm rt4 $P_SRV 4)
echo "  observed: clients() said [$COUNTS]; $REACHED of $N sockets pinged, $EXACTLY exactly once; stable=$STABLE"
check "every shard's clients() sees the whole runtime" "$COUNTS"  "$N"
check "every client can be sent to by id"              "$REACHED" "$N"
check "and exactly once"                               "$EXACTLY" "$N"
check "a client is the same id on two calls"           "$STABLE"  "true"

echo "== the control: the same script on ONE shard =="
read -r COUNTS1 REACHED1 EXACTLY1 STABLE1 < <(run_arm rt1 $P_SRV1 1)
echo "  observed: clients() said [$COUNTS1]; $REACHED1 pinged, $EXACTLY1 exactly once; stable=$STABLE1"
check "one shard lists its own clients"   "$COUNTS1"  "$N"
check "and can send to each of them once" "$EXACTLY1" "$N"
check "and its ids are stable too"        "$STABLE1"  "true"

echo
echo "shard route: PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]]
