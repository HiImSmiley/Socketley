#!/bin/bash
# =============================================================================
# sharded-server.sh - One server, N worker processes
# =============================================================================
#
# A runtime is one process and therefore one event loop on one core.  --shards
# gives a single server N processes that share its listening socket through
# SO_REUSEPORT, and the kernel hands each incoming connection to one of them.
# It is the only way one runtime uses more than one core.
#
# USAGE:
#   ./sharded-server.sh
#
# FLAGS DEMONSTRATED:
#   --shards N       Serve this server from N worker processes
#
# THE ONE RULE: NO --lua.
#   Sharding declares that nothing is shared between connections, and nothing
#   can detect whether that is true -- a Lua table at file scope is the same
#   object whether the operator meant it as per-connection scratch or as the
#   room every connection publishes into.  For a proxy the declaration is about
#   code in this tree.  For a server it would be about the operator's own
#   script, where cross-connection state is the common case rather than the
#   exception: a chat room, a presence table, a counter.  Sharded, a message
#   from a client on shard 1 never reaches a client on shard 2 and nothing
#   reports it -- self.broadcast, owner_broadcast and upstream_broadcast are all
#   per-process.  So a server carrying --lua refuses --shards, in either flag
#   order, and refuses it through edit, through import and at start-up from a
#   state file as well.
#
# WHAT IT COSTS:
#   Throughput bought with cores, not with efficiency.  Measured on this tree,
#   one --http server with --http-cache over 64 keep-alive connections, seven
#   interleaved passes, cores from the server processes' own /proc/<pid>/stat:
#
#       1 shard   126,497 req/s   0.99 cores   127,775 req/s per core
#       8 shards  451,097 req/s   4.78 cores    94,372 req/s per core
#
#   3.57x total for roughly a quarter of the per-core rate given up.  That is a
#   good trade on a machine with idle cores and a bad one on a machine without.
#   And --http-cache is held once PER SHARD, so eight shards is eight copies of
#   the file cache in memory.
#
#   One shard is 0.99 cores with fifteen more idle, which is the whole case for
#   the flag: a server does not run out of machine, it runs out of the single
#   event loop it is allowed.
#
#   Drive it with enough connections to feed the shards.  The same eight over
#   only 16 connections read 294,917 req/s and 2.54x -- starved rather than
#   slow (4.12 cores against 4.78), because SO_REUSEPORT hands out whole
#   connections and the slowest of eight gates the pass.
#
# =============================================================================

set -e

echo "=== Sharded Server Example ==="
echo ""

echo "[1/4] Creating a server with four shards..."
socketley create server shard-srv \
    -p 9110 \
    --shards 4 \
    -s

echo ""
echo "[2/4] What the shards look like from outside:"
echo ""
echo "  \$ socketley ls          -- ONE line.  A shard is an implementation"
echo "                             detail of a runtime, not a runtime."
socketley ls | grep -E 'NAME|shard-srv' || true
echo ""
echo "  \$ ss -ltn | grep 9110   -- four listeners sharing the port"
ss -ltn 2>/dev/null | grep ':9110 ' || true
echo ""
echo "  \$ socketley stats shard-srv"
echo "     connections is the SUM across the shards, and each shard's detail"
echo "     text is labelled so two shards' connection tables are not read as"
echo "     one runtime listing the same connection twice.  shard_pids names"
echo "     every process, because 'pid' can only name one of four."
socketley stats shard-srv 2>/dev/null | grep -E '^shards:|^shard_pids:' || true

echo ""
echo "[3/4] The rule, demonstrated.  A script and shards together are refused,"
echo "      and it does not matter which order the flags are typed in:"
echo ""
cat > /tmp/sharded-server-demo.lua <<'LUA'
-- Cross-connection state: the ordinary case, and the reason for the rule.
local room = {}
function on_connect(conn) room[#room + 1] = conn end
LUA
echo "  \$ socketley create server chat -p 9111 --lua demo.lua --shards 4"
socketley create server chat -p 9111 --lua /tmp/sharded-server-demo.lua --shards 4 || true
echo ""
echo "  \$ socketley create server chat -p 9111 --shards 4 --lua demo.lua"
socketley create server chat -p 9111 --shards 4 --lua /tmp/sharded-server-demo.lua || true

echo ""
echo "[4/4] Two more combinations that are refused rather than ignored:"
echo ""
echo "  \$ socketley create server s -p 9112 --shards 4 --daemon-process"
socketley create server s -p 9112 --shards 4 --daemon-process || true
echo "     (a shard IS a worker process, so a runtime asked to stay in the"
echo "      daemon has exactly one however many it declares)"
echo ""
echo "  \$ socketley create server s --shards 4 --listen unix:/tmp/s.sock"
socketley create server s --shards 4 --listen unix:/tmp/s.sock || true
echo "     (SO_REUSEPORT shares a port; a unix socket is a path, and N"
echo "      processes would unlink each other's node)"

rm -f /tmp/sharded-server-demo.lua

echo ""
echo "NOTE: SO_REUSEPORT balances per CONNECTION, not per request.  A shard is"
echo "      chosen when the connection is accepted and never revisited, so one"
echo "      heavy long-lived connection makes one shard hot while the others"
echo "      idle.  Sharding helps a server carrying many comparable connections."
echo ""
echo "      The count is persisted, so a daemon restart brings back the number"
echo "      that was asked for.  It can be changed with 'edit' only while the"
echo "      runtime is stopped, for the same reason -p can."
echo ""
echo "Cleanup:"
echo "  socketley remove shard-srv"
