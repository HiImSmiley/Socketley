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
# WITH --lua TOO, AND WHAT THAT DOES AND DOES NOT GIVE YOU.
#   A scripted server used to refuse this flag.  Everything a script could ask
#   about its clients was answered per PROCESS: on four shards
#   self.connections() reported a quarter of them, self.broadcast reached a
#   quarter of them, and self.clients() listed a quarter -- as descriptors, so
#   an id from one shard named a different socket on another.  None of it was
#   reported.
#
#   All four now cross a shard boundary.  connections() sums every shard's own
#   figure out of a shared mapping with no round trip; broadcast reaches every
#   shard's clients once each; clients() lists the whole runtime, this shard's
#   descriptors plus a stable handle per sibling's client; and send(id) on one
#   of those handles reaches the shard that owns it.
#
#   WHAT DOES NOT CROSS, and this is what sharding means rather than a gap in
#   it: per-connection state is PER SHARD.  A connection belongs to one shard,
#   so on_connect and on_message for it run there and nowhere else.  A script
#   holds no state for the ids clients() hands it from elsewhere -- it can name
#   them, count them and send to them, and it never saw them arrive.  So keep
#   cross-connection state in a cache runtime, which every shard reaches, and
#   not in a Lua table at file scope, which each shard has its own copy of.
#   Step [3/4] below shows both halves.
#
#   self.route is still refused in a worker, sharded or not: it hands a live
#   client to another runtime and runs that runtime's on_connect on this
#   thread's stack, and there is no channel for that between two processes.
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
#   the file cache in memory.  Plain --http now keeps its responses in memory
#   too -- revalidated by one statx per request, so it still picks up edits --
#   and that is per shard as well, though it is capped at 64 MiB each where
#   --http-cache is however large the directory happens to be.
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
echo "[3/4] A script and shards together, and the one thing to know about it."
echo ""
cat > /tmp/sharded-server-demo.lua <<'LUA'
-- self.connections() is the WHOLE runtime's count, not this process's, and
-- self.broadcast reaches every shard's clients.  Both are summed and fanned
-- out for you.
function on_message(msg)
    if msg:find("WHO") then
        self.broadcast("clients: " .. tostring(#self.clients()))
    end
end

-- But `room` is per SHARD: each of the four processes has its own copy, and
-- on_connect for a client fires only in the shard that accepted it.  This is
-- the table to move into a cache runtime if every shard has to see it.
local room = {}
function on_connect(conn) room[#room + 1] = conn end
LUA
echo "  \$ socketley create server chat -p 9111 --lua demo.lua --shards 4"
socketley create server chat -p 9111 --lua /tmp/sharded-server-demo.lua --shards 4 && \
  echo "     accepted -- and in the other flag order too" || true
socketley remove chat >/dev/null 2>&1 || true
echo ""
echo "  \$ socketley create server chat -p 9111 --shards 4 --lua demo.lua"
socketley create server chat -p 9111 --shards 4 --lua /tmp/sharded-server-demo.lua && \
  echo "     accepted" || true
socketley remove chat >/dev/null 2>&1 || true

echo ""
echo "[4/4] Three combinations that are refused rather than ignored:"
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
echo ""
echo "  \$ socketley create cache c -p 9113 --shards 4"
socketley create cache c -p 9113 --shards 4 || true
echo "     (N shards would be N separate stores behind one port, so a SET"
echo "      lands in one process and a later GET asks another)"

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
