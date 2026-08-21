#!/bin/bash
# =============================================================================
# sharded-cache.sh - One cache, N worker processes, one keyspace
# =============================================================================
#
# A runtime is one process and therefore one event loop on one core.  --shards
# gives a cache N processes sharing its listening socket through SO_REUSEPORT.
#
# THE THING THAT MAKES THIS DIFFERENT FROM A SHARDED SERVER
#   A server's shards share nothing: a connection lands on one of them and is
#   served there.  A cache's shards share a KEYSPACE, and a client that writes
#   on one connection reads on another.  So --shards on a cache was refused for
#   a long time, with a reason worth repeating: N shards would be N separate
#   stores behind one port, a SET would land in one process and a later GET ask
#   another, and the answer would be a miss for data that was stored -- 1/N of
#   the time, with no error anywhere.
#
#   What removes that is OWNERSHIP BY KEY HASH.  Each shard owns the keys whose
#   hash falls to it and is the only reader and only writer of that slice; a
#   command naming somebody else's key is answered by them.  The cache is still
#   ONE store as far as a client is concerned.
#
# USAGE:
#   ./sharded-cache.sh
#
# FLAGS DEMONSTRATED:
#   --shards N       Serve this cache from N worker processes
#   --persistent     A dump per shard, which survives a changed shard count
#
# WHAT SCALES, MEASURED
#   Four clients driving one runtime at pipeline depth 1:
#
#       1 shard    172,000 ops/s
#       4 shards   289,000 ops/s      1.68x
#
#   Drive it with more than one client.  A single redis-benchmark process tops
#   out near 90-110k ops/s on an ordinary box, and a series measured with one
#   client is a series about the client: the same 8-shard cache answered 89,888
#   to one client, 185,609 to two and 338,912 to four.
#
# WHAT IS REFUSED, AND WHY
#   replicate.  A follower arrives as ONE connection and SO_REUSEPORT gives it
#   to one shard; that shard must be the only writer its socket ever has, and
#   the others have no socket to it at all.  Promoting it would send the
#   follower one shard's writes and report success, so it is refused by name.
#   A sharded cache may still BE a follower of an unsharded leader.
# =============================================================================
set -euo pipefail

PORT="${PORT:-9400}"
NAME="${NAME:-shardedcache}"
SHARDS="${SHARDS:-4}"
DUMP="${DUMP:-/tmp/$NAME.rdb}"

cleanup() { socketley stop "$NAME" 2>/dev/null || true
            sleep 0.3
            socketley remove "$NAME" 2>/dev/null || true; }
trap cleanup EXIT

echo "== a cache in $SHARDS processes, on one port =="
socketley create cache "$NAME" -p "$PORT" --shards "$SHARDS" \
          --persistent "$DUMP" -s

# The shards fork, exec and build their rings; ask rather than sleep.
for _ in $(seq 1 60); do
    printf 'set __ready 1\n' | nc -q1 127.0.0.1 "$PORT" 2>/dev/null | grep -q ok && break
    sleep 0.25
done

echo
echo "== it is one keyspace: written on one connection, read on another =="
for i in $(seq 1 12); do
    printf "set k%d v%d\n" "$i" "$i" | nc -q1 127.0.0.1 "$PORT" >/dev/null
done
for i in 1 5 12; do
    printf "get k%d -> %s\n" "$i" "$(printf "get k%d\n" "$i" | nc -q1 127.0.0.1 "$PORT")"
done

echo
echo "== keyspace-wide commands answer for the runtime, not for one shard =="
printf 'size\n'   | nc -q1 127.0.0.1 "$PORT" | sed 's/^/  size:  /'
printf 'keys k*\n' | nc -q1 127.0.0.1 "$PORT" | tr '\n' ' ' | sed 's/^/  keys:  /'
echo

echo
echo "== and stats shows where the keys actually live =="
socketley stats "$NAME" | grep -E '^\[shard|^keys:'

echo
echo "== the dump is one file per shard, and survives a changed shard count =="
socketley stop "$NAME" >/dev/null; sleep 1
ls -1 "$DUMP".shard* 2>/dev/null | sed 's/^/  /'
socketley remove "$NAME" >/dev/null 2>&1 || true

echo "  restarting the same data at 2 shards instead of $SHARDS..."
socketley create cache "$NAME" -p "$PORT" --shards 2 --persistent "$DUMP" -s
for _ in $(seq 1 60); do
    printf 'size\n' | nc -q1 127.0.0.1 "$PORT" 2>/dev/null | grep -qE '^[0-9]+$' && break
    sleep 0.25
done
printf 'size\n' | nc -q1 127.0.0.1 "$PORT" | sed 's/^/  size after 4 -> 2:  /'
for i in 1 5 12; do
    printf "  k%d -> %s\n" "$i" "$(printf "get k%d\n" "$i" | nc -q1 127.0.0.1 "$PORT")"
done

echo
echo "Done.  Every key is still there: each dump records the split it was"
echo "written under, and a set whose split does not match this run is"
echo "redistributed rather than loaded into the wrong slices."
