#!/usr/bin/env bash
# Integration test: the node beside the port.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# A runtime with a port gets a second listener on a node, and a proxy naming
# that runtime uses it.  Two ways this can be wrong and nothing else would say
# so:
#
#   the port stops working.  The whole point is that the node is ADDITIONAL --
#   a runtime that traded its port for a node is unreachable from anywhere but
#   this machine, and every other test here connects over the port, so they
#   would all still pass on a build that also broke nothing else.
#
#   the daemon publishes a node nobody bound.  Then a proxy dials a path that
#   is not there and the backend is simply down.  The rule that decides this is
#   wants_companion(), asked on both sides, and the assertions below are what
#   check the two sides agree: no node under TLS, none for a runtime already on
#   a path, one otherwise.
#
# And the mode, because a node is a file: 0600 in a 0700 directory is what
# makes this at least as closed as the port it sits beside, and a port on
# 127.0.0.1 is open to every user on the box.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: the node beside the port ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

# True as soon as the condition holds, false if it never did within 5 s.
wait_for() { local _; for _ in $(seq 1 100); do eval "$1" && return 0; sleep 0.05; done; return 1; }

PORT=$((SL_PORT_BASE+1340))
daemon_isolate companionnode

# A trap and not a line at the bottom: an assertion that exits early would
# otherwise leave a daemon holding this file's ports for the rest of the suite,
# which is how this test left two behind the first time it ran.
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

# Named after the daemon socket, not a sibling called "rt": the default
# socket is /tmp/socketley.sock, and every user on the machine shares /tmp.
RTDIR="$SOCKETLEY_SOCKET.rt"
NODE="$RTDIR/cn_srv.sock"
WWW="$SOCKETLEY_TMPD/www"; mkdir -p "$WWW"
printf '<h1>over-either</h1>\n' > "$WWW/index.html"

"$BIN" create server cn_srv -p "$PORT" --http "$WWW" -s >/dev/null 2>&1
wait_for '[ -S "$NODE" ]'

# ── 1. It exists, and it is as closed as the port it sits beside ───────────
if [ -S "$NODE" ]; then ok "the node is there ($NODE)"
else bad "the node is there" "$NODE is not a socket"; fi

MODE=$(stat -c '%a' "$NODE" 2>/dev/null || echo "?")
DMODE=$(stat -c '%a' "$RTDIR" 2>/dev/null || echo "?")
if [ "$MODE" = "600" ] && [ "$DMODE" = "700" ]; then
    ok "node 0600 in a 0700 directory"
else
    bad "node 0600 in a 0700 directory" \
        "node is $MODE, directory is $DMODE;" \
        "a port on 127.0.0.1 is open to every user on this box, and the whole" \
        "security argument for the node is that it is not"
fi

# ── 2. The port did not go anywhere ────────────────────────────────────────
get_tcp() {
    python3 -c "
import socket,sys
try:
    s=socket.create_connection(('127.0.0.1',$1),timeout=5)
    s.sendall(b'GET / HTTP/1.0\r\n\r\n'); d=s.recv(400)
    print('yes' if b'over-either' in d else (d.split(b'\r\n')[0].decode('latin1') or 'NOTHING'))
except Exception as e: print('ERROR:'+type(e).__name__)" 2>/dev/null
}
get_unix() {
    python3 -c "
import socket,sys
try:
    s=socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect('$1')
    s.sendall(b'GET / HTTP/1.0\r\n\r\n'); d=s.recv(400)
    print('yes' if b'over-either' in d else (d.split(b'\r\n')[0].decode('latin1') or 'NOTHING'))
except Exception as e: print('ERROR:'+type(e).__name__)" 2>/dev/null
}

BYPORT=$(get_tcp "$PORT")
BYNODE=$(get_unix "$NODE")
if [ "$BYPORT" = "yes" ]; then ok "the port still answers"
else bad "the port still answers" "got '$BYPORT' -- the node is additional, not a replacement"; fi
if [ "$BYNODE" = "yes" ]; then ok "and so does the node"
else bad "and so does the node" "got '$BYNODE'"; fi

# ── 3. A proxy naming the runtime takes the node ───────────────────────────
"$BIN" create proxy cn_name -p $((PORT+1)) --backend cn_srv           -s >/dev/null 2>&1
"$BIN" create proxy cn_addr -p $((PORT+2)) --backend "127.0.0.1:$PORT" -s >/dev/null 2>&1
wait_for '[ "$(grep -c "is reached over $NODE" "$SOCKETLEY_DLOG" 2>/dev/null)" -ge 2 ]'

proxied() {
    python3 -c "
import socket,sys
try:
    s=socket.create_connection(('127.0.0.1',$1),timeout=5)
    s.sendall(b'GET /$2/ HTTP/1.1\r\nHost: p\r\n\r\n'); d=s.recv(600)
    print('yes' if b'over-either' in d else (d.split(b'\r\n')[0].decode('latin1') or 'NOTHING'))
except Exception as e: print('ERROR:'+type(e).__name__)" 2>/dev/null
}
BY_NAME=$(proxied $((PORT+1)) cn_name)
BY_ADDR=$(proxied $((PORT+2)) cn_addr)
if [ "$BY_NAME" = "yes" ]; then ok "a proxy naming the runtime reaches it"
else bad "a proxy naming the runtime reaches it" "got '$BY_NAME'"; fi
if [ "$BY_ADDR" = "yes" ]; then ok "a proxy naming the address reaches it"
else bad "a proxy naming the address reaches it" "got '$BY_ADDR'"; fi

# The route, not just the answer: both forms should say which way they went,
# because a backend that quietly stayed on TCP answers identically.
SAID=$(grep -c "is reached over $NODE" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "${SAID:-0}" -ge 2 ]; then
    ok "both proxies said they took the node ($SAID lines)"
else
    bad "both proxies said they took the node" \
        "$SAID lines in the log, expected 2 (one per proxy);" \
        "an answer is the same over either transport, so the log is the only" \
        "evidence that the node was used at all"
fi

# ── 4. An address that is NOT a runtime stays TCP ──────────────────────────
# The backend is resolved during startup, which -s waits for, so the log is complete once create returns.
if "$BIN" create proxy cn_else -p $((PORT+3)) --backend "127.0.0.1:$((PORT+9))" -s >/dev/null 2>&1; then
    ok "a proxy on an address no runtime publishes starts"
else
    bad "a proxy on an address no runtime publishes starts" "create failed, so the check below would read an empty log"
fi
ELSE_SAID=$(grep -c "127.0.0.1:$((PORT+9))\" is reached over" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "${ELSE_SAID:-0}" -eq 0 ]; then
    ok "an address no runtime publishes stays an address"
else
    bad "an address no runtime publishes stays an address" \
        "the proxy substituted a node for an address that names nothing;" \
        "the address form means what it says or it means nothing"
fi

"$BIN" stop cn_name >/dev/null 2>&1; "$BIN" remove cn_name >/dev/null 2>&1
"$BIN" stop cn_addr >/dev/null 2>&1; "$BIN" remove cn_addr >/dev/null 2>&1
"$BIN" stop cn_else >/dev/null 2>&1; "$BIN" remove cn_else >/dev/null 2>&1

# ── 5. Stopping takes the node with it ─────────────────────────────────────
"$BIN" stop cn_srv >/dev/null 2>&1
wait_for '[ ! -e "$NODE" ]'
if [ ! -e "$NODE" ]; then ok "stopping removes the node"
else bad "stopping removes the node" "$NODE is still there; closing a descriptor does not unlink a path"; fi
"$BIN" remove cn_srv >/dev/null 2>&1

# ── 6. The two runtimes that get none ──────────────────────────────────────
OWNSOCK="$SOCKETLEY_TMPD/own.sock"
"$BIN" create server cn_own --listen "unix:$OWNSOCK" --http "$WWW" -s >/dev/null 2>&1
# Its own path bound is the runtime up, which is when a second one would have been.
wait_for '[ -S "$OWNSOCK" ]'
if [ -S "$OWNSOCK" ] && [ ! -e "$RTDIR/cn_own.sock" ]; then
    ok "a runtime already on a path gets no second one"
else
    bad "a runtime already on a path gets no second one" \
        "own path bound: $([ -S "$OWNSOCK" ] && echo yes || echo no), $RTDIR/cn_own.sock exists: $([ -e "$RTDIR/cn_own.sock" ] && echo yes || echo no);" \
        "there is no port for it to be beside"
fi

# ── 6b. A cache gets a node too, and its proxy takes it ────────────────────
#
# This section used to assert the opposite -- "a cache gets no node" -- and
# it was right to, because the daemon published one and the cache bound
# nothing, so a proxy naming a cache dialled a path nobody was on and every
# request went unanswered.  The cache binds one now, so both halves are
# asserted together: the node is there, the proxy said it took it, and a
# write and a read through the proxy agree -- which a build that publishes
# without binding cannot pass.
"$BIN" create cache  cn_kv -p $((PORT+7)) -s >/dev/null 2>&1
"$BIN" create proxy  cn_kvpx -p $((PORT+8)) --backend cn_kv --protocol tcp -s >/dev/null 2>&1
wait_for '[ -S "$RTDIR/cn_kv.sock" ] && grep -q "cn_kv\" is reached over $RTDIR/cn_kv.sock" "$SOCKETLEY_DLOG" 2>/dev/null'
KV_NODE=$([ -S "$RTDIR/cn_kv.sock" ] && echo yes || echo no)
KV_SAID=$(grep -c "cn_kv\" is reached over $RTDIR/cn_kv.sock" "$SOCKETLEY_DLOG" 2>/dev/null || true)
KV_ANSWERED=$(printf 'set nodek nodev\nget nodek\n' | timeout 5 nc -q1 127.0.0.1 $((PORT+8)) 2>/dev/null | tr -d '\r' | sed -n 2p)
if [ "$KV_NODE" = "yes" ] && [ "${KV_SAID:-0}" -ge 1 ] && [ "$KV_ANSWERED" = "nodev" ]; then
    ok "a cache gets a node, and a proxy in front of it takes it and answers"
else
    bad "a cache gets a node, and a proxy in front of it takes it and answers" \
        "node present: $KV_NODE, log said it $KV_SAID time(s)," \
        "the proxy read back '${KV_ANSWERED:-<nothing>}' for nodek;" \
        "a path published for a type that binds none is a backend that is simply down"
fi
KV_MODE=$(stat -c '%a' "$RTDIR/cn_kv.sock" 2>/dev/null || echo "?")
if [ "$KV_MODE" = "600" ]; then ok "the cache's node is 0600 like the server's"
else bad "the cache's node is 0600 like the server's" "node is $KV_MODE"; fi
"$BIN" stop cn_kvpx >/dev/null 2>&1; "$BIN" remove cn_kvpx >/dev/null 2>&1
"$BIN" stop cn_kv   >/dev/null 2>&1
wait_for '[ ! -e "$RTDIR/cn_kv.sock" ]'
if [ ! -e "$RTDIR/cn_kv.sock" ]; then ok "stopping the cache removes its node"
else bad "stopping the cache removes its node" "$RTDIR/cn_kv.sock is still there"; fi
"$BIN" remove cn_kv   >/dev/null 2>&1

# ── 6c. A sharded cache gets none ──────────────────────────────────────────
#
# A path is one node and N processes would unlink each other's, the way
# --listen is refused for shards, so the shards stay on the port they share
# -- and the proxy in front of them has to stay on TCP for the same reason
# 6b exists: a node published for a set that binds none is a backend down.
"$BIN" create cache  cn_kvs -p $((PORT+10)) --shards 2 -s >/dev/null 2>&1
"$BIN" create proxy  cn_kvspx -p $((PORT+11)) --backend cn_kvs --protocol tcp -s >/dev/null 2>&1
# The proxy answering is both shards up, and its backend was resolved and logged before -s returned.
for _ in 1 2 3 4 5; do
    KVS_ANSWERED=$(printf 'set shk shv\nget shk\n' | timeout 5 nc -q1 127.0.0.1 $((PORT+11)) 2>/dev/null | tr -d '\r' | sed -n 2p)
    [ "$KVS_ANSWERED" = "shv" ] && break
    sleep 0.3
done
KVS_NODE_GONE=$([ -e "$RTDIR/cn_kvs.sock" ] && echo no || echo yes)
KVS_SAID=$(grep -c "cn_kvs\" is reached over" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "$KVS_NODE_GONE" = "yes" ] && [ "${KVS_SAID:-0}" -eq 0 ] && [ "$KVS_ANSWERED" = "shv" ]; then
    ok "a sharded cache gets no node, and a proxy in front of it still answers"
else
    bad "a sharded cache gets no node, and a proxy in front of it still answers" \
        "node absent: $KVS_NODE_GONE, log said it $KVS_SAID time(s)," \
        "the proxy read back '${KVS_ANSWERED:-<nothing>}' for shk;" \
        "two processes on one path would unlink each other's node"
fi
"$BIN" stop cn_kvspx >/dev/null 2>&1; "$BIN" remove cn_kvspx >/dev/null 2>&1
"$BIN" stop cn_kvs   >/dev/null 2>&1; "$BIN" remove cn_kvs   >/dev/null 2>&1

# ── 6d. A sharded server gets one node per shard, and its proxy spreads over them ─
#
# One path per shard, because a path is one listener: when all four asked
# for cn_srvs.sock the first to bind it won, the other three logged a refusal
# and served the port alone, and a proxy on that node reached one shard of
# four -- measured as every accepted socket on one pid.  Two numbers here:
# the daemon's own per-shard count after 64 connections through a TCP proxy,
# which relays each client connection to one backend connection of its own,
# so a shard nobody reaches reads 0 -- and, with 16 more held open, what ss
# sees on the server side, because over the port SO_REUSEPORT would spread
# them just as well and only the transport says which way they went.
"$BIN" create server cn_srvs -p $((PORT+12)) --shards 4 --http "$WWW" -s >/dev/null 2>&1
"$BIN" create proxy  cn_srvspx -p $((PORT+13)) --backend cn_srvs --protocol tcp -s >/dev/null 2>&1
wait_for '[ "$(ls "$RTDIR"/cn_srvs#*.sock 2>/dev/null | wc -l)" -eq 4 ] && [ "$(grep -c "\"cn_srvs\" is reached over $RTDIR/cn_srvs#" "$SOCKETLEY_DLOG" 2>/dev/null)" -ge 4 ]'
SRVS_NODES=$(ls "$RTDIR"/cn_srvs#*.sock 2>/dev/null | wc -l)
SRVS_ONE_GONE=$([ -e "$RTDIR/cn_srvs.sock" ] && echo no || echo yes)
SRVS_REFUSED=$(grep -c "companion node $RTDIR/cn_srvs" "$SOCKETLEY_DLOG" 2>/dev/null || true)
SRVS_SAID=$(grep -c "\"cn_srvs\" is reached over $RTDIR/cn_srvs#" "$SOCKETLEY_DLOG" 2>/dev/null || true)
# N connections through PORT, each held open HOLD seconds after its answer so
# the backend leg is there for ss to see; prints how many answered.  HTTP/1.1,
# because a 1.0 answer closes the leg before ss looks.
srvs_held() {   # srvs_held PORT N HOLD OUTFILE
    python3 - "$1" "$2" "$3" >"$4" <<'PY' &
import socket, sys, threading, time
port, n, hold = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
got = [0] * n
def one(i):
    try:
        s = socket.create_connection(('127.0.0.1', port), timeout=5)
        s.sendall(b'GET / HTTP/1.1\r\nHost: p\r\n\r\n')
        d = s.recv(4096)
        got[i] = 1 if b'over-either' in d else 0
        time.sleep(hold)
        s.close()
    except Exception:
        pass
ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
for t in ts: t.start()
for t in ts: t.join()
print(sum(got))
PY
    SRVS_HELD_PID=$!
}
srvs_run() {   # srvs_run PORT N -> how many answered, each connection closed as it finishes
    python3 -c "
import socket
n=0
for i in range($2):
    try:
        s=socket.create_connection(('127.0.0.1',$1),timeout=3)
        s.sendall(b'GET / HTTP/1.0\r\nHost: p\r\n\r\n')
        d=s.recv(4096); s.close()
        n+= 1 if b'over-either' in d else 0
    except Exception: pass
print(n)" 2>/dev/null
}
SRVS_ANSWERED=$(srvs_run $((PORT+13)) 64)
sleep 0.5
SRVS_PER_SHARD=$("$BIN" stats cn_srvs 2>/dev/null | sed -n 's/^shard_total_connections:\([0-9][0-9]*\)$/\1/p' | tr '\n' ' ')
SRVS_BUSY=$(printf '%s\n' $SRVS_PER_SHARD | awk '$1 > 0 { n++ } END { print n+0 }')
if [ "$SRVS_NODES" -eq 4 ] && [ "$SRVS_ONE_GONE" = "yes" ] && [ "${SRVS_REFUSED:-0}" -eq 0 ] \
   && [ "${SRVS_SAID:-0}" -eq 4 ] && [ "$SRVS_ANSWERED" = "64" ] && [ "$SRVS_BUSY" -eq 4 ]; then
    ok "a sharded server binds 4 nodes, its proxy names all 4, and 64 connections reached 4 of 4 shards ($SRVS_PER_SHARD)"
else
    bad "a sharded server binds one node per shard, and its proxy spreads over every shard" \
        "nodes cn_srvs#*.sock: $SRVS_NODES of 4, the unsharded cn_srvs.sock absent: $SRVS_ONE_GONE," \
        "shards refused a node $SRVS_REFUSED time(s), the proxy named a node $SRVS_SAID time(s) (expected 4)," \
        "answered $SRVS_ANSWERED of 64, per-shard connections: ${SRVS_PER_SHARD:-<none>} -- $SRVS_BUSY shard(s) saw any;" \
        "one node is one shard, and a proxy on it collapses --shards to 1/N"
fi
srvs_held $((PORT+13)) 16 2.5 "$SOCKETLEY_TMPD/srvs_held.txt"
sleep 1.2
SRVS_NODE_LEGS=$(ss -xn state established 2>/dev/null | grep -cF "$RTDIR/cn_srvs#")
SRVS_PORT_LEGS=$(ss -Htn state established "( dport = :$((PORT+12)) )" 2>/dev/null | wc -l)
wait "$SRVS_HELD_PID"
SRVS_HELD_ANSWERED=$(cat "$SOCKETLEY_TMPD/srvs_held.txt")
if [ "$SRVS_HELD_ANSWERED" = "16" ] && [ "$SRVS_NODE_LEGS" -ge 16 ] && [ "$SRVS_PORT_LEGS" -eq 0 ]; then
    ok "16 held connections through the proxy are all on nodes ($SRVS_NODE_LEGS rows on cn_srvs#*.sock, 0 TCP legs to the port)"
else
    bad "every leg to a sharded backend is a node" \
        "answered $SRVS_HELD_ANSWERED of 16, ss rows on cn_srvs#*.sock: $SRVS_NODE_LEGS, TCP legs to :$((PORT+12)): $SRVS_PORT_LEGS;" \
        "a leg over the port is the 17.93 us path the node exists to replace"
fi

# And the count following the runtime: two shards after an edit bind #0 and
# #1, the proxy has to stop dialling #2 and #3 -- paths nobody serves -- and
# the log has to say it took the new set.
"$BIN" stop cn_srvs >/dev/null 2>&1
"$BIN" edit cn_srvs --shards 2 >/dev/null 2>&1
"$BIN" start cn_srvs >/dev/null 2>&1
# The proxy saying it took #0 and #1 again is it having followed the restart.
wait_for '[ "$(ls "$RTDIR"/cn_srvs#*.sock 2>/dev/null | wc -l)" -eq 2 ] && [ "$(grep -c "\"cn_srvs\" is reached over $RTDIR/cn_srvs#[01].sock" "$SOCKETLEY_DLOG" 2>/dev/null)" -ge 4 ]'
SRVS2_NODES=$(ls "$RTDIR"/cn_srvs#*.sock 2>/dev/null | wc -l)
SRVS2_STALE=$( { [ -e "$RTDIR/cn_srvs#2.sock" ] || [ -e "$RTDIR/cn_srvs#3.sock" ]; } && echo yes || echo no)
SRVS2_ANSWERED=$(srvs_run $((PORT+13)) 16)
sleep 0.5
SRVS2_PER_SHARD=$("$BIN" stats cn_srvs 2>/dev/null | sed -n 's/^shard_total_connections:\([0-9][0-9]*\)$/\1/p' | tr '\n' ' ')
SRVS2_BUSY=$(printf '%s\n' $SRVS2_PER_SHARD | awk '$1 > 0 { n++ } END { print n+0 }')
SRVS2_SAID=$(grep -c "\"cn_srvs\" is reached over $RTDIR/cn_srvs#[01].sock" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "$SRVS2_NODES" -eq 2 ] && [ "$SRVS2_STALE" = "no" ] && [ "$SRVS2_ANSWERED" = "16" ] \
   && [ "$SRVS2_BUSY" -eq 2 ] && [ "${SRVS2_SAID:-0}" -ge 4 ]; then
    ok "after edit --shards 2 and a restart the proxy follows: 2 nodes, 16 of 16 answered over 2 of 2 shards ($SRVS2_PER_SHARD)"
else
    bad "the proxy follows a changed shard count" \
        "nodes after the restart: $SRVS2_NODES (expected 2), a stale #2/#3 left: $SRVS2_STALE," \
        "answered $SRVS2_ANSWERED of 16, per-shard: ${SRVS2_PER_SHARD:-<none>} -- $SRVS2_BUSY shard(s) saw any," \
        "log named #0/#1 $SRVS2_SAID time(s) (expected 2 at first, 2 more after);" \
        "a path nobody binds is the refused connect unix_listener.h describes"
fi
"$BIN" stop cn_srvspx >/dev/null 2>&1; "$BIN" remove cn_srvspx >/dev/null 2>&1
"$BIN" stop cn_srvs   >/dev/null 2>&1
wait_for '[ "$(ls "$RTDIR"/cn_srvs#*.sock 2>/dev/null | wc -l)" -eq 0 ]'
SRVS_LEFT=$(ls "$RTDIR"/cn_srvs#*.sock 2>/dev/null | wc -l)
if [ "$SRVS_LEFT" -eq 0 ]; then ok "stopping the sharded server removes every node"
else bad "stopping the sharded server removes every node" "$SRVS_LEFT of them are still there; each shard unlinks its own"; fi
"$BIN" remove cn_srvs   >/dev/null 2>&1

"$BIN" stop cn_own >/dev/null 2>&1; "$BIN" remove cn_own >/dev/null 2>&1

"$BIN" stop cn_own >/dev/null 2>&1 || true
daemon_stop
trap - EXIT

# ── 7. A directory this daemon does not own gets no nodes at all ───────────
#
# mkdir answering EEXIST says a directory is there and nothing about whose it
# is.  A directory anybody can write to is where a stranger holds a live node
# at a path the daemon is about to publish -- and a live node is one the bind
# refuses to take, which would leave the path published and served by them.
daemon_isolate companionnodedir
# A fresh isolate is a fresh temporary directory, so the document root has to
# be made again -- the one above went with the daemon that owned it.
WWW="$SOCKETLEY_TMPD/www"; mkdir -p "$WWW"
printf '<h1>over-either</h1>\n' > "$WWW/index.html"
mkdir -p "$SOCKETLEY_SOCKET.rt"
chmod 0777 "$SOCKETLEY_SOCKET.rt"
daemon_start "$BIN"
"$BIN" create server cn_open -p $((PORT+6)) --http "$WWW" -s >/dev/null 2>&1
wait_for 'grep -q "companion nodes are off" "$SOCKETLEY_DLOG" 2>/dev/null'
OPEN_NODE="$SOCKETLEY_SOCKET.rt/cn_open.sock"
OPEN_SAID=$(grep -c "companion nodes are off" "$SOCKETLEY_DLOG" 2>/dev/null || true)
OPEN_PORT=$(get_tcp $((PORT+6)))
if [ ! -e "$OPEN_NODE" ] && [ "${OPEN_SAID:-0}" -ge 1 ] && [ "$OPEN_PORT" = "yes" ]; then
    ok "a world-writable node directory is refused out loud, and the port still serves"
else
    bad "a world-writable node directory is refused out loud" \
        "node exists: $([ -e "$OPEN_NODE" ] && echo yes || echo no)," \
        "log said it $OPEN_SAID time(s), the port answered '$OPEN_PORT';" \
        "a daemon that binds into a directory it does not own publishes a path" \
        "a stranger can be serving"
fi
"$BIN" stop cn_open >/dev/null 2>&1; "$BIN" remove cn_open >/dev/null 2>&1
daemon_stop

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
