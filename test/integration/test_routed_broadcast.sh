#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# A broadcast reaching clients routed in from another runtime: every one of them
# gets it once, in the order it was sent, and a broadcast between two writes to
# one of them arrives between them -- the broadcast is carried once per path to
# the origin, beside the refs it is for, and each ref's share goes the way its
# own writes go, whether that is the direct link or the daemon's leg -- and with
# a sharded origin, the daemon's leg takes it to the shard holding the client.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

ORIGIN_PORT=$((SL_PORT_BASE+790))
TARGET_PORT=$((SL_PORT_BASE+791))
CLIENTS=120

cleanup() {
    "$BIN" stop   rb_origin rb_target 2>/dev/null || true
    "$BIN" remove rb_origin rb_target 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a broadcast to clients routed in from another runtime ==="

daemon_isolate routedbcast
daemon_start "$BIN"

TARGET_LUA="$SOCKETLEY_TMPD/target.lua"
cat > "$TARGET_LUA" <<'LUAEOF'
function on_connect(client_id)
    if client_id >= 16777216 then
        -- The first write to a ref pins its path: the first clients' go up
        -- through the daemon, before the link exists, and the others' over it.
        self.send(client_id, "hi")
        socketley.log("RB_GOT " .. tostring(client_id))
    end
end
function on_client_message(client_id, msg)
    -- A write, a broadcast and a write, so the broadcast has a place to be.
    if msg:sub(1, 4) == "abc " then
        local tag = msg:sub(5)
        self.send(client_id, "A" .. tag)
        self.broadcast("B" .. tag)
        self.send(client_id, "C" .. tag)
    elseif msg:sub(1, 3) == "go " then
        for i = 1, tonumber(msg:sub(4)) do
            self.broadcast("m" .. i)
        end
    end
end
LUAEOF

ORIGIN_LUA="$SOCKETLEY_TMPD/origin.lua"
cat > "$ORIGIN_LUA" <<'LUAEOF'
function on_connect(client_id)
    self.route(client_id, "rb_target")
end
LUAEOF

create_ok "target created" "$BIN" create server rb_target -p "$TARGET_PORT" --lua "$TARGET_LUA" -s

for OSHARDS in 1 4; do
echo "-- an origin of $OSHARDS shard(s)"
"$BIN" stop rb_origin >/dev/null 2>&1; "$BIN" remove rb_origin >/dev/null 2>&1
create_ok "origin created" "$BIN" create server rb_origin -p "$ORIGIN_PORT" --lua "$ORIGIN_LUA" --shards "$OSHARDS" -s
sleep 0.5
MARK=$(wc -c < "$SOCKETLEY_DLOG")

# The clients, eight connected before the peer link exists and the rest after
# it, so some refs are pinned to the daemon's leg, at four shards each shard's
# first one most of all, and some to the link: each one says
# `abc <i>` in turn, then the target broadcasts m1..m50, and every client
# checks what it read.
OUT=$(python3 - "$ORIGIN_PORT" "$TARGET_PORT" "$CLIENTS" "$SOCKETLEY_DLOG" "$MARK" <<'PY'
import socket, sys, time, selectors
oport, tport, n, dlog, mark = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], int(sys.argv[5])
def routed():
    try:
        with open(dlog, 'rb') as f:
            f.seek(mark); return f.read().decode(errors='replace').count('RB_GOT ')
    except OSError: return 0
def wait_routed(k):
    for _ in range(200):
        if routed() >= k: return True
        time.sleep(0.05)
    return False
socks = []
for i in range(n):
    socks.append(socket.create_connection(('127.0.0.1', oport), timeout=5))
    if i == 7:
        # The first routed connections' frames go up through the daemon, which then links the two workers.
        wait_routed(8); time.sleep(1.0)
if not wait_routed(n):
    print('ROUTED', routed()); sys.exit(0)
bufs = [b''] * n
sel = selectors.DefaultSelector()
for i, s in enumerate(socks):
    s.setblocking(False); sel.register(s, selectors.EVENT_READ, i)
def pump(until, deadline):
    while time.time() < deadline and not until():
        for key, _ in sel.select(0.05):
            try: d = key.fileobj.recv(65536)
            except BlockingIOError: continue
            if d: bufs[key.data] += d
def lines(i): return bufs[i].decode(errors='replace').split('\n')[:-1]
for i, s in enumerate(socks):
    s.sendall(b'abc %d\n' % i)
    pump(lambda: ('C%d' % i) in lines(i), time.time() + 5)
pump(lambda: all(sum(1 for l in lines(i) if l.startswith('B')) >= n for i in range(n)), time.time() + 10)
ctl = socket.create_connection(('127.0.0.1', tport), timeout=5)
ctl.sendall(b'go 50\n')
pump(lambda: all(lines(i) and lines(i)[-1] == 'm50' for i in range(n)), time.time() + 10)
order = btotal = mtotal = mordered = 0
for i in range(n):
    ls = lines(i)
    try:
        a, b, c = ls.index('A%d' % i), ls.index('B%d' % i), ls.index('C%d' % i)
        order += a < b < c
    except ValueError: pass
    bs = [l for l in ls if l.startswith('B')]
    btotal += len(bs) == n and len(set(bs)) == n
    ms = [l for l in ls if l.startswith('m')]
    mtotal += len(ms) == 50
    mordered += ms == ['m%d' % k for k in range(1, 51)]
print('ROUTED', n, 'ORDER', order, 'BALL', btotal, 'MALL', mtotal, 'MORDER', mordered)
PY
)
read -r _ routed _ order _ ball _ mall _ morder <<<"$OUT"
echo "  ($OUT)"
if [ "${routed:-0}" -eq "$CLIENTS" ]; then pass "all $CLIENTS clients routed to the target"
else fail "routed" "$routed of $CLIENTS clients reached the target; nothing below means anything"; fi
LINKS=$("$BIN" stats rb_target 2>/dev/null | awk -F: '/^peer_links:/ {s+=$2} END{print s+0}')
if [ "$LINKS" -ge 1 ]; then pass "control: the target holds a link to the origin"
else fail "control: link" "peer_links is $LINKS; without one every frame takes the daemon and the paths never differ"; fi
if [ "${order:-0}" -eq "$CLIENTS" ]; then pass "a broadcast between two writes arrived between them at every client"
else fail "order" "${order:-0} of $CLIENTS clients read their write, broadcast, write in that order"; fi
if [ "${ball:-0}" -eq "$CLIENTS" ]; then pass "every client read each of the $CLIENTS broadcasts once"
else fail "broadcasts" "${ball:-0} of $CLIENTS clients read each broadcast exactly once"; fi
if [ "${mall:-0}" -eq "$CLIENTS" ] && [ "${morder:-0}" -eq "$CLIENTS" ]; then
    pass "every client read the 50 broadcasts of one call once each, in order"
else
    fail "a run of broadcasts" "${mall:-0} of $CLIENTS clients read all 50, ${morder:-0} in order"
fi
done

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
