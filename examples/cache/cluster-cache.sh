#!/bin/bash
# =============================================================================
# cluster-cache.sh - Letting the client pick the shard, with no client of ours
# =============================================================================
#
# THE NUMBER THIS EXISTS FOR
#   A sharded cache costs more CPU per request than the same work with no
#   crossings.  Measured on this tree, 8 client processes x 50 connections,
#   three interleaved passes per arm, medians, rps per SERVER core:
#
#       four shards, clients on the shared port       63,849   15.66 us/req
#       the same runtime, clients routed to the
#         per-shard ports (zero crossings)            87,401   11.44 us/req
#       four independent single-shard caches          87,663   11.40 us/req
#
#   +36.9%, and the routed arm lands within 0.3% of four separate caches.  The
#   crossing is already as cheap as it can be made -- it is on the io_uring
#   ring, it makes zero blocking syscalls, the daemon is not in the path -- so
#   the only way left to remove the cost was to remove the crossing.
#
#   And a crossing happens because the CLIENT could not choose.  All N shards
#   share one port through SO_REUSEPORT and the kernel assigns connections by
#   four-tuple hash, so with N shards a random key is foreign (N-1)/N of the
#   time.
#
# WHY IT IS A FLAG AND NOT AUTOMATIC
#   A routing client connects to every shard DIRECTLY, and the address this
#   cache advertises is the one the ASKING connection arrived on.  Behind a
#   proxy that is the PROXY's address: either the client can reach it too, and
#   the proxy's rules have been bypassed by a map the cache handed out, or it
#   cannot, and the client burns its retries on a connection refused.  Neither
#   logs anything.  That is what client-side routing IS -- Redis Cluster has
#   the same property -- so a --cluster cache CANNOT SIT BEHIND A PROXY used
#   for access control, and the operator makes that call, not the cache.
#
#   Off by default.  Without it, --shards N is the shared-port cache it always
#   was: nothing extra bound, no redirects, crossings over the mesh.
#
# WHAT CHANGED
#   Two things, and neither of them is a client library:
#
#     1. Which shard owns a key is CRC16 of the key modulo 16384, Redis's own
#        hash slot function, `{hash tag}` rule included.  Not because it mixes
#        better -- our FNV-1a mixed better -- but because redis-cli, redis-py,
#        go-redis, lettuce and node-redis can all compute it WITHOUT ASKING US.
#
#     2. With --cluster, shard i binds port+1+i in addition to the shared
#        port, and a key that arrives on the wrong one is answered
#        `-MOVED slot host:port`.
#
#   Between them, an off-the-shelf cluster client bootstraps from CLUSTER SLOTS
#   and thereafter sends every key straight to the process that holds it.
#
# WHAT DID NOT CHANGE
#   The shared port.  A client that has never heard of a slot map connects to
#   it and is served exactly as before, over the mesh.  One runtime serves both
#   kinds of client at once.
#
# USAGE:
#   ./cluster-cache.sh
#
# REQUIRES:
#   redis-cli.  The whole point is that the client is not ours.
# =============================================================================
set -euo pipefail

PORT="${PORT:-9500}"
NAME="${NAME:-clustercache}"
SHARDS="${SHARDS:-4}"

command -v redis-cli >/dev/null || { echo "redis-cli is required"; exit 1; }

cleanup() { socketley stop "$NAME" 2>/dev/null || true
            sleep 0.3
            socketley remove "$NAME" 2>/dev/null || true; }
trap cleanup EXIT

# port+1 .. port+SHARDS must be free as well: the address a client is sent to
# is a formula, so a shard that could not bind its own port would be advertised
# anyway.  The start refuses instead, naming the port.
echo "== a cache in $SHARDS processes on $PORT, plus $((PORT+1))..$((PORT+SHARDS)) =="
socketley create cache "$NAME" -p "$PORT" --shards "$SHARDS" --resp --cluster -s

for _ in $(seq 1 80); do
    redis-cli -p "$PORT" PING 2>/dev/null | grep -q PONG && break
    sleep 0.25
done

echo
echo "== the map a cluster client bootstraps from =="
redis-cli -p "$PORT" CLUSTER SLOTS | sed 's/^/  /'

echo
echo "== the slots are Redis's, so a client can compute them itself =="
for k in foo bar hello key1; do
    printf "  CLUSTER KEYSLOT %-6s -> %s   (redis says 12182 / 5061 / 866 / 9189)\n" \
        "$k" "$(redis-cli -p "$PORT" CLUSTER KEYSLOT $k)"
done
echo "  {hash tag}: both of these are the slot of 'user1000'"
printf "    {user1000}.following -> %s\n" "$(redis-cli -p "$PORT" CLUSTER KEYSLOT '{user1000}.following')"
printf "    {user1000}.followers -> %s\n" "$(redis-cli -p "$PORT" CLUSTER KEYSLOT '{user1000}.followers')"

echo
echo "== asking the wrong shard directly: a redirect, not a crossing =="
SLOT=$(redis-cli -p "$PORT" CLUSTER KEYSLOT foo)
OWNER=$(( SLOT * SHARDS / 16384 ))
redis-cli -p $((PORT + 1 + OWNER)) SET foo hello >/dev/null
WRONG=$(( PORT + 1 + ((OWNER + 1) % SHARDS) ))
echo "  foo is slot $SLOT, owned by shard $OWNER on port $((PORT+1+OWNER))"
echo "  GET foo on $WRONG    -> $(redis-cli -p "$WRONG" GET foo 2>&1)"
echo "  GET foo on $((PORT+1+OWNER))    -> $(redis-cli -p $((PORT+1+OWNER)) GET foo)"

echo
echo "== redis-cli -c follows the map and never crosses =="
for i in 1 2 3 4 5 6 7 8; do
    redis-cli -c -p $((PORT+1)) SET "ck$i" "v$i" >/dev/null
done
for i in 1 4 8; do
    printf "  ck%d -> %s\n" "$i" "$(redis-cli -c -p $((PORT+1)) GET "ck$i")"
done

echo
echo "== count the crossings, because throughput would not have told you =="
echo "   (a build where the client is NOT routing still answers every key,"
echo "    over the mesh, and looks identical from the outside)"
sleep 2
socketley stats "$NAME" | grep -E 'mesh_direct|mesh_relayed' | sed 's/^/  /'

echo
echo "== and the shared port is untouched: no redirect, the value =="
echo "  GET foo on $PORT  -> $(redis-cli -p "$PORT" GET foo)"
echo "  DBSIZE on $PORT   -> $(redis-cli -p "$PORT" DBSIZE)   (every shard, summed)"
echo "  DBSIZE on $((PORT+1))  -> $(redis-cli -p $((PORT+1)) DBSIZE)   (that shard alone, as Redis answers it)"

echo
echo "Done."
