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
sleep 1.5

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
sleep 1.5

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
"$BIN" create proxy cn_else -p $((PORT+3)) --backend "127.0.0.1:$((PORT+9))" -s >/dev/null 2>&1
sleep 0.8
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
sleep 0.8
if [ ! -e "$NODE" ]; then ok "stopping removes the node"
else bad "stopping removes the node" "$NODE is still there; closing a descriptor does not unlink a path"; fi
"$BIN" remove cn_srv >/dev/null 2>&1

# ── 6. The two runtimes that get none ──────────────────────────────────────
OWNSOCK="$SOCKETLEY_TMPD/own.sock"
"$BIN" create server cn_own --listen "unix:$OWNSOCK" --http "$WWW" -s >/dev/null 2>&1
sleep 1
if [ ! -e "$RTDIR/cn_own.sock" ]; then
    ok "a runtime already on a path gets no second one"
else
    bad "a runtime already on a path gets no second one" \
        "$RTDIR/cn_own.sock exists; there is no port for it to be beside"
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
sleep 1.5
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
sleep 0.8
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
sleep 1.5
KVS_NODE_GONE=$([ -e "$RTDIR/cn_kvs.sock" ] && echo no || echo yes)
KVS_SAID=$(grep -c "cn_kvs\" is reached over" "$SOCKETLEY_DLOG" 2>/dev/null || true)
KVS_ANSWERED=$(printf 'set shk shv\nget shk\n' | timeout 5 nc -q1 127.0.0.1 $((PORT+11)) 2>/dev/null | tr -d '\r' | sed -n 2p)
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
sleep 1.5
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
