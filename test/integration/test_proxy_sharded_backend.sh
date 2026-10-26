#!/usr/bin/env bash
# suite: quiet -- a health check with a threshold of one takes a shard out on
# the first probe that load makes slow.
# Integration test: what a proxy owes a sharded backend, beyond reaching it.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# test_companion_node.sh 6d proves a sharded server binds one node per shard
# and a proxy naming it spreads over all N.  That is the happy path, and it was
# the only path measured.  A name backend with N dial targets inside one
# m_backends entry is a NEW shape, and everything the old shape got for free
# from "one backend is one address" has to be shown again, once each:
#
#   a breaker takes out one NODE, not the backend.  If it takes the backend,
#   one dead shard of four costs the whole runtime; if it takes nothing, every
#   request keeps paying a connect to a path nobody serves.  Both read as
#   "still works" on a green box, which is why this is measured with a node
#   removed rather than argued about.
#
#   the lua index still means the BACKEND.  --strategy lua returns a number,
#   and that number used to be an index into the backend list.  If N nodes
#   moved into that list, `return 1` silently starts meaning "shard 1 of
#   backend 0" and every lua router in the wild reroutes without a word.
#
#   --health-check still probes something real.  A sharded name has no single
#   address to probe, and a probe that quietly does nothing leaves the flag as
#   a promise the operator paid attention to.
#
#   the ADDRESS form gets the nodes too.  `--backend 127.0.0.1:PORT` of a
#   sharded runtime resolves to the same runtime as `--backend name`, and if
#   only the name form takes the nodes, the two spellings of one backend have
#   different transports and nothing says so.
#
#   a sharded runtime inside a @group is N members, not one.  A group is a set
#   of equals; a shard is one of those equals.
#
# Every assertion below is about a shape that reads as working when it is
# wrong, which is the only reason to spend a test file on it.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: a proxy in front of a sharded backend ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

SP=$((SL_PORT_BASE+1360))     # the sharded server
PLAIN=$((SL_PORT_BASE+1361))  # an unsharded server, to tell the lua index apart
PX_NAME=$((SL_PORT_BASE+1362))
PX_LUA=$((SL_PORT_BASE+1363))
PX_HC=$((SL_PORT_BASE+1364))
PX_ADDR=$((SL_PORT_BASE+1365))
PX_GRP=$((SL_PORT_BASE+1366))
GSRV=$((SL_PORT_BASE+1367))   # the sharded server that is a group member

daemon_isolate shardedbackend
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

RTDIR="$SOCKETLEY_SOCKET.rt"
WWW="$SOCKETLEY_TMPD/www";   mkdir -p "$WWW"
WWWP="$SOCKETLEY_TMPD/wwwp"; mkdir -p "$WWWP"
printf '<h1>SHARDED</h1>\n' > "$WWW/index.html"
printf '<h1>PLAIN</h1>\n'   > "$WWWP/index.html"

"$BIN" create server sb_srv   -p "$SP"    --shards 4 --http "$WWW"  -s >/dev/null 2>&1
"$BIN" create server sb_plain -p "$PLAIN"            --http "$WWWP" -s >/dev/null 2>&1
sleep 2

NODES=$(ls "$RTDIR"/sb_srv#*.sock 2>/dev/null | wc -l)
if [ "$NODES" -eq 4 ]; then ok "the sharded server bound 4 nodes"
else bad "the sharded server bound 4 nodes" "found $NODES; every assertion below needs them"; fi

# One request, through the proxy's own path prefix, reporting which backend
# answered rather than just that something did.
via() {   # via PORT PROXYNAME -> SHARDED | PLAIN | <status line> | ERROR:...
    python3 -c "
import socket
try:
    s=socket.create_connection(('127.0.0.1',$1),timeout=5)
    s.sendall(b'GET /$2/ HTTP/1.1\r\nHost: p\r\nConnection: close\r\n\r\n')
    d=b''
    while True:
        c=s.recv(4096)
        if not c: break
        d+=c
    s.close()
    print('SHARDED' if b'SHARDED' in d else ('PLAIN' if b'PLAIN' in d else (d.split(b'\r\n')[0].decode('latin1') or 'NOTHING')))
except Exception as e: print('ERROR:'+type(e).__name__)" 2>/dev/null
}
# ─── Why the spread is measured through a TCP proxy ────────────────────────
#
# shard_total_connections counts ACCEPTED CONNECTIONS, not requests, and an
# HTTP proxy pools its backend legs and prefers the one it just released -- on
# purpose, measured, because this guest has no cpuidle driver and waking a cold
# shard costs more than the node saves.  So a burst of 32 requests through an
# HTTP proxy legitimately opens two legs and moves two counters, and a test
# reading those counters is measuring the pool rather than the spread.  It read
# `1 1 0 0` for 32 requests here, and `3 2 2 2` for 24 on the run before: the
# figure is not a function of what the test does.
#
# A TCP proxy has no pool and takes one leg per connection, which is why
# test_companion_node.sh 6d uses one to count per-shard accepts.  Every
# assertion below that is about WHICH SHARD went through a TCP proxy for that
# reason; the ones about semantics (the 502, the lua index) stay on HTTP where
# they belong.
tvia() {  # tvia PORT -> SHARDED | PLAIN | <status line> | ERROR:...   (tcp proxy)
    python3 -c "
import socket
try:
    s=socket.create_connection(('127.0.0.1',$1),timeout=5)
    s.sendall(b'GET / HTTP/1.0\r\nHost: p\r\n\r\n')
    d=s.recv(4096); s.close()
    print('SHARDED' if b'SHARDED' in d else ('PLAIN' if b'PLAIN' in d else (d.split(b'\r\n')[0].decode('latin1') or 'NOTHING')))
except Exception as e: print('ERROR:'+type(e).__name__)" 2>/dev/null
}
many() {  # many PORT N -> how many of N connections answered SHARDED (tcp proxy)
    python3 -c "
import socket
n=0
for i in range($2):
    try:
        s=socket.create_connection(('127.0.0.1',$1),timeout=5)
        s.sendall(b'GET / HTTP/1.0\r\nHost: p\r\n\r\n')
        d=s.recv(4096); s.close()
        n += 1 if b'SHARDED' in d else 0
    except Exception: pass
print(n)" 2>/dev/null
}
# Per-shard accepted counts as a space-separated list, the same figure test 6d
# reads -- it is cumulative, so every check below is a DIFFERENCE.
per_shard() { "$BIN" stats "$1" 2>/dev/null | sed -n 's/^shard_total_connections:\([0-9][0-9]*\)$/\1/p' | tr '\n' ' '; }
busy_since() {  # busy_since "before" "after" -> how many shards took new work
    python3 -c "
import sys
a=[int(x) for x in '''$1'''.split()]; b=[int(x) for x in '''$2'''.split()]
print(sum(1 for i in range(min(len(a),len(b))) if b[i]-a[i] > 0))"
}
delta_of() {    # delta_of IDX "before" "after" -> new work on one shard
    python3 -c "
a=[int(x) for x in '''$2'''.split()]; b=[int(x) for x in '''$3'''.split()]
print(b[$1]-a[$1] if len(a) > $1 and len(b) > $1 else -1)"
}

# ── 1. Four live nodes: concurrency spreads over all four ──────────────────
#
# The control for everything below, and the reason it is separate: if the
# spread is not there while all four nodes are up, the node-removed assertion
# would pass for the wrong reason.
"$BIN" create proxy sb_px -p "$PX_NAME" --backend sb_srv --protocol tcp -s >/dev/null 2>&1
sleep 1.5
WARM_BEFORE=$(per_shard sb_srv)
WARM=$(many "$PX_NAME" 32)
sleep 0.5
WARM_AFTER=$(per_shard sb_srv)
WARM_BUSY=$(busy_since "$WARM_BEFORE" "$WARM_AFTER")
if [ "$WARM" -eq 32 ] && [ "$WARM_BUSY" -eq 4 ]; then
    ok "32 connections through a tcp proxy spread over 4 of 4 shards ($WARM_AFTER)"
else
    bad "concurrency spreads over every node" \
        "answered $WARM of 32 over $WARM_BUSY of 4 shards; per-shard '$WARM_BEFORE' -> '$WARM_AFTER';" \
        "a tcp proxy takes one leg per connection, so 32 connections owe every node work"
fi
"$BIN" stop sb_px >/dev/null 2>&1; "$BIN" remove sb_px >/dev/null 2>&1

# ── 2. A breaker takes out one node, and the other three carry it ──────────
#
# Removing the path is how one node dies while its shard stays healthy: the
# listener keeps the descriptor it already has, so the port and the other three
# nodes are untouched and exactly one dial target becomes a refused connect.
#
# The proxy is created AFTER the removal, and that is the whole trick: an
# unlinked path does not disturb a leg that is already established, so a proxy
# that had pooled a leg to #0 would keep answering over it and this assertion
# would pass on a build with no breaker at all.  A fresh proxy has to dial.
rm -f "$RTDIR/sb_srv#0.sock"
"$BIN" create proxy sb_bk -p "$PX_NAME" --backend sb_srv --protocol tcp -s >/dev/null 2>&1
sleep 1.5

# The first batch is the breaker opening -- some of these are entitled to fail,
# because a breaker learns from failures and this one has had none.
OPENING=$(many "$PX_NAME" 16)
sleep 1.0
BEFORE=$(per_shard sb_srv)
SETTLED=$(many "$PX_NAME" 24)
sleep 0.5
AFTER=$(per_shard sb_srv)
D0=$(delta_of 0 "$BEFORE" "$AFTER")
BUSY=$(busy_since "$BEFORE" "$AFTER")

# Not 24 of 24: a breaker that has opened re-probes, and the trial request it
# sends to a node that is still gone is entitled to fail.  Asserting a clean
# sweep here would be asserting that the breaker never tries again, which is the
# opposite of what one is for.  What must hold is that the dead node takes no
# work and the loss is a probe rather than a share of the traffic.
if [ "$SETTLED" -ge 22 ] && [ "$D0" -eq 0 ] && [ "$BUSY" -eq 3 ]; then
    ok "one node removed: $SETTLED of 24 answered over the other 3 shards, 0 new on the dead one"
else
    bad "a breaker takes out one node, not the backend" \
        "the batch that opens the breaker answered $OPENING of 16," \
        "the settled batch answered $SETTLED of 24 over $BUSY shard(s), new work on the dead shard: $D0;" \
        "per-shard before '$BEFORE' after '$AFTER';" \
        "0 of 24 means the breaker took the whole backend, work on shard 0 means it took nothing," \
        "and fewer than 22 means the dead node is still taking a share rather than a probe"
fi
"$BIN" stop sb_bk >/dev/null 2>&1; "$BIN" remove sb_bk >/dev/null 2>&1

# ── 3. Every node gone: the backend is down, and says so ───────────────────
#
# The other half of the same claim.  is_backend_available() reports the backend
# down only when EVERY node is, so with all four removed the proxy owes a
# status line rather than a hang -- and it must still be alive afterwards.
# A fresh proxy again, for the reason given above.
rm -f "$RTDIR"/sb_srv#*.sock
"$BIN" create proxy sb_dead -p "$PX_NAME" --backend sb_srv -s >/dev/null 2>&1
sleep 1.5
DOWN=$(via "$PX_NAME" sb_dead)
ALIVE=$("$BIN" ls 2>/dev/null | grep -c "sb_dead")
case "$DOWN" in
    NOTHING|SHARDED|PLAIN) DOWN_OK=no ;;
    ERROR:*)               DOWN_OK=no ;;
    HTTP/1*)               DOWN_OK=yes ;;
    *)                     DOWN_OK=no ;;
esac
if [ "$DOWN_OK" = "yes" ] && [ "$ALIVE" -ge 1 ]; then
    ok "with every node gone the proxy answers '$DOWN' and stays up"
else
    bad "every node gone means the backend is down, not the proxy" \
        "the proxy said '$DOWN' (a status line was expected, not a body and not a dropped connection)," \
        "and socketley ls found it $ALIVE time(s)"
fi
"$BIN" stop sb_dead >/dev/null 2>&1; "$BIN" remove sb_dead >/dev/null 2>&1
# Back to four bound nodes for everything below.
"$BIN" stop sb_srv >/dev/null 2>&1; "$BIN" start sb_srv >/dev/null 2>&1
sleep 2

# ── 4. --strategy lua: the index still means the backend ───────────────────
IDX_FILE="$SOCKETLEY_TMPD/idx"
echo 0 > "$IDX_FILE"
ROUTE_LUA="$SOCKETLEY_TMPD/route.lua"
cat > "$ROUTE_LUA" <<LUAEOF
local IDX_FILE = "$IDX_FILE"
LUAEOF
cat >> "$ROUTE_LUA" <<'LUAEOF'
function on_route()
    local f = io.open(IDX_FILE, "r")
    if not f then return 0 end
    local n = tonumber(f:read("*l"))
    f:close()
    return n or 0
end
LUAEOF
"$BIN" create proxy sb_lua -p "$PX_LUA" --protocol tcp --strategy lua \
    --backend sb_srv --backend "127.0.0.1:$PLAIN" --lua "$ROUTE_LUA" -s >/dev/null 2>&1
sleep 1.5
echo 0 > "$IDX_FILE"; L0=$(tvia "$PX_LUA"); L0b=$(tvia "$PX_LUA")
echo 1 > "$IDX_FILE"; L1=$(tvia "$PX_LUA"); L1b=$(tvia "$PX_LUA")
if [ "$L0" = "SHARDED" ] && [ "$L0b" = "SHARDED" ] && [ "$L1" = "PLAIN" ] && [ "$L1b" = "PLAIN" ]; then
    ok "--strategy lua: index 0 is the sharded backend and 1 is the plain one, not shard 1 of backend 0"
else
    bad "the lua index still means the backend" \
        "return 0 gave '$L0','$L0b' (expected SHARDED), return 1 gave '$L1','$L1b' (expected PLAIN);" \
        "PLAIN for 0 or SHARDED for 1 means the N nodes joined the backend list and every" \
        "lua router in the wild reroutes without a word"
fi
"$BIN" stop sb_lua >/dev/null 2>&1; "$BIN" remove sb_lua >/dev/null 2>&1

# ── 5. --health-check on a sharded name keeps it in rotation ───────────────
"$BIN" create proxy sb_hc -p "$PX_HC" --backend sb_srv --protocol tcp \
    --health-check tcp --health-interval 1 --health-threshold 1 -s >/dev/null 2>&1
sleep 3   # several probe intervals, so a probe that takes the backend out has
HC_BEFORE=$(per_shard sb_srv)
HC=$(many "$PX_HC" 24)
sleep 0.5
HC_AFTER=$(per_shard sb_srv)
HC_BUSY=$(busy_since "$HC_BEFORE" "$HC_AFTER")
# The spread is asserted at >= 2 and not at 4: which nodes a burst of 24 needs
# is the pool's decision and it does not owe every node one.  The failures this
# is here to catch are a probe that was believed (0 answered) and a probe that
# collapsed the name to a single address (1 shard).
if [ "$HC" -eq 24 ] && [ "$HC_BUSY" -ge 2 ]; then
    ok "--health-check tcp on a sharded name: 24 of 24 answered over $HC_BUSY of 4 shards after 3 probe rounds"
else
    bad "a health check does not take a healthy sharded backend out" \
        "answered $HC of 24 over $HC_BUSY of 4 shards; per-shard '$HC_BEFORE' -> '$HC_AFTER';" \
        "0 of 24 is a probe that failed and was believed, and a probe against a name with no" \
        "single address is exactly where that happens"
fi
"$BIN" stop sb_hc >/dev/null 2>&1; "$BIN" remove sb_hc >/dev/null 2>&1

# ── 6. The address form of a sharded runtime takes the nodes too ───────────
#
# Held connections rather than counts: the question is which TRANSPORT the legs
# are on, and only the open sockets say that.
"$BIN" create proxy sb_addr -p "$PX_ADDR" --backend "127.0.0.1:$SP" --protocol tcp -s >/dev/null 2>&1
sleep 1.5
held() {   # held PORT NAME N HOLD OUTFILE -- N concurrent requests kept open
    python3 - "$1" "$2" "$3" "$4" > "$5" 2>/dev/null <<'PY' &
import socket, sys, threading, time
port, name, n, hold = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
got = [0]*n
def one(i):
    try:
        s = socket.create_connection(('127.0.0.1', port), timeout=5)
        # 1.1 and no Connection: close, because the leg is what is being
        # counted and an HTTP/1.0 server closes it the moment it has answered.
        s.sendall(b'GET / HTTP/1.1\r\nHost: p\r\n\r\n')
        d = s.recv(4096)
        got[i] = 1 if b'SHARDED' in d else 0
        time.sleep(hold); s.close()
    except Exception:
        pass
ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
for t in ts: t.start()
for t in ts: t.join()
print(sum(got))
PY
    HELD_PID=$!
}
held "$PX_ADDR" sb_addr 16 2.5 "$SOCKETLEY_TMPD/addr.txt"
sleep 1.2
ADDR_NODE_LEGS=$(ss -xn state established 2>/dev/null | grep -cF "$RTDIR/sb_srv#")
ADDR_PORT_LEGS=$(ss -Htn state established "( dport = :$SP )" 2>/dev/null | wc -l)
wait "$HELD_PID"
ADDR_ANSWERED=$(cat "$SOCKETLEY_TMPD/addr.txt" 2>/dev/null || echo 0)
# A tcp proxy holds one leg per connection, so 16 held connections owe 16 rows
# on the nodes and none on the port -- which is the whole question here, since
# the two spellings of one backend must not have two transports.
if [ "$ADDR_ANSWERED" = "16" ] && [ "$ADDR_NODE_LEGS" -ge 16 ] && [ "$ADDR_PORT_LEGS" -eq 0 ]; then
    ok "--backend 127.0.0.1:PORT of a sharded runtime is on its nodes ($ADDR_NODE_LEGS rows, 0 TCP legs)"
else
    bad "the address form resolves to the same runtime, and to the same transport" \
        "answered $ADDR_ANSWERED of 16, rows on sb_srv#*.sock: $ADDR_NODE_LEGS, TCP legs to :$SP: $ADDR_PORT_LEGS;" \
        "legs on the port mean the two spellings of one backend have two transports"
fi
"$BIN" stop sb_addr >/dev/null 2>&1; "$BIN" remove sb_addr >/dev/null 2>&1

# ── 7. A sharded server inside a @group is N members, not one ──────────────
"$BIN" create server sb_gs -p "$GSRV" --shards 4 --group sb_g --http "$WWW" -s >/dev/null 2>&1
sleep 2
"$BIN" create proxy sb_gp -p "$PX_GRP" --backend @sb_g --protocol tcp -s >/dev/null 2>&1
sleep 1.5
G_BEFORE=$(per_shard sb_gs)
GRP=$(many "$PX_GRP" 24)
sleep 0.5
G_AFTER=$(per_shard sb_gs)
G_BUSY=$(busy_since "$G_BEFORE" "$G_AFTER")
G_NODES=$(ls "$RTDIR"/sb_gs#*.sock 2>/dev/null | wc -l)
if [ "$GRP" -eq 24 ] && [ "$G_BUSY" -eq 4 ] && [ "$G_NODES" -eq 4 ]; then
    ok "a sharded member behind @group: 24 of 24 answered over 4 of 4 shards ($G_AFTER)"
else
    bad "a sharded runtime in a group expands into its shards" \
        "answered $GRP of 24 over $G_BUSY of 4 shards, nodes bound: $G_NODES;" \
        "per-shard '$G_BEFORE' -> '$G_AFTER';" \
        "1 of 4 busy means the group took the member as one address and collapsed --shards to 1/N"
fi

"$BIN" stop sb_gp >/dev/null 2>&1; "$BIN" remove sb_gp >/dev/null 2>&1
"$BIN" stop sb_gs >/dev/null 2>&1; "$BIN" remove sb_gs >/dev/null 2>&1
"$BIN" stop sb_plain >/dev/null 2>&1; "$BIN" remove sb_plain >/dev/null 2>&1
"$BIN" stop sb_srv >/dev/null 2>&1; "$BIN" remove sb_srv >/dev/null 2>&1
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
