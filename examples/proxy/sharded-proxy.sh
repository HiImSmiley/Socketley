#!/bin/bash
# =============================================================================
# sharded-proxy.sh - One proxy, N worker processes
# =============================================================================
#
# A runtime is one process and therefore one event loop on one core.  --shards
# gives a single proxy N processes that share its listening socket through
# SO_REUSEPORT, and the kernel hands each incoming connection to one of them.
# It is the only way one runtime uses more than one core.
#
# USAGE:
#   ./sharded-proxy.sh
#
# FLAGS DEMONSTRATED:
#   --shards N       Serve this proxy from N worker processes (proxy only)
#
# WHEN TO REACH FOR IT:
#   Only when a proxy is saturated -- one worker pinned at 100% of a core with
#   the rest of the machine idle.  Below saturation a single connection is
#   bound by the cost of a cross-core wakeup, and a second process cannot help
#   with that; it only adds another process to supervise.
#
# WHAT IT IS NOT:
#   It is not automatic and it is not offered on the other three runtime types.
#   Sharding is correct exactly when nothing is shared between connections, and
#   nothing can detect that -- so the operator declares it and owns it.  A cache
#   would become N separate stores behind one port; a server whose Lua holds
#   state across connections would have that state split N ways.  Both fail
#   silently, which is why both refuse the flag rather than accepting it.
#
# =============================================================================

set -e

echo "=== Sharded Proxy Example ==="
echo ""

# Backend for the proxy to forward to.
echo "[1/3] Creating backend server..."
socketley create server shard-backend \
    -p 9101 \
    --mode echo \
    -s

# Four worker processes, one runtime.
echo "[2/3] Creating a proxy with four shards..."
socketley create proxy shard-gw \
    -p 9100 \
    --protocol tcp \
    --backend 127.0.0.1:9101 \
    --shards 4 \
    -s

echo ""
echo "[3/3] What the shards look like from outside:"
echo ""
echo "  \$ socketley ls          -- ONE line.  A shard is an implementation"
echo "                             detail of a runtime, not a runtime."
socketley ls | grep -E 'NAME|shard-gw' || true
echo ""
echo "  \$ ss -ltn | grep 9100   -- four listeners sharing the port"
ss -ltn 2>/dev/null | grep ':9100 ' || true
echo ""
echo "  \$ socketley stats shard-gw"
echo "     connections is the SUM across the shards, and each shard's detail"
echo "     text is labelled so two shards' connection tables are not read as"
echo "     one runtime listing the same connection twice.  shard_pids names"
echo "     every process, because 'pid' can only name one of four."
socketley stats shard-gw 2>/dev/null | grep -E '^shards:|^shard_pids:' || true
echo ""
echo "NOTE: SO_REUSEPORT balances per CONNECTION, not per request.  A shard is"
echo "      chosen when the connection is accepted and never revisited, so one"
echo "      heavy long-lived connection makes one shard hot while the others"
echo "      idle.  Sharding helps a proxy carrying many comparable connections."
echo ""
echo "Cleanup:"
echo "  socketley remove shard-gw shard-backend"
