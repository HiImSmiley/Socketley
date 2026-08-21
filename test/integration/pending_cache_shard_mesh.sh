#!/usr/bin/env bash
# Integration test: shard-to-shard links, and the two ways they can be absent.
#
# ─── WHY pending_ ──────────────────────────────────────────────────────────
#
# `--shards` on a cache is still refused; build with
# -DSOCKETLEY_SCRATCH_CACHE_SHARDS to run this.  It skips without it.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# The mesh has a fallback: a crossing with no usable link relays through the
# daemon, which is what keeps a dead link from being an outage.  That fallback
# is also what would let a mesh that never connects go unnoticed — it would
# serve every key correctly, pass every other test in this directory, and report
# the throughput of the build without it.
#
# "The mesh made no difference" and "the mesh was never used" have to be
# distinguishable or a measurement of it means nothing.  So the assertions here
# are about the ROUTE, not about the answers:
#
#   direct > 0        crossings really went shard-to-shard.  Asserting that the
#                     keys read back passes on a build with no mesh at all.
#   relayed == 0      and none of them fell back.  A mesh that connects and then
#                     quietly relays half its traffic reports direct > 0.
#   off: correct      with the mesh disabled the same keys still read back, over
#                     the daemon.  This is the arm every measurement compares
#                     against, so it has to be known-good.
#   the cap           N shards need N(N-1) descriptors at once while the set is
#                     forked.  RLIMIT_NOFILE here is 1,048,576, so the cap can
#                     never fire on this box and its branch would ship never
#                     having run.  The test lowers the limit in its own shell
#                     and watches the daemon refuse, say so, and relay.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate cacheshardmesh

PORT=$((SL_PORT_BASE+1270))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line; for line in "${@:3}"; do echo "        $line"; done
}

cleanup() { "$BIN" stop meshc >/dev/null 2>&1 || true; sleep 0.3
            "$BIN" remove meshc >/dev/null 2>&1 || true; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: shard-to-shard links ==="

command -v redis-cli >/dev/null 2>&1 || { echo "  SKIP: redis-cli required"; exit 0; }

daemon_start "$BIN"
if ! "$BIN" create cache meshc -p "$PORT" --shards 4 --resp -s >/dev/null 2>&1; then
    echo "  SKIP: this build refuses --shards on a cache."
    exit 0
fi
for i in $(seq 1 80); do
    redis-cli -p "$PORT" PING 2>/dev/null | grep -q PONG && break; sleep 0.25
done

# Enough keys that every shard both owns some and asks for others.
for i in $(seq 1 40); do redis-cli -p "$PORT" SET "x$i" "v$i" >/dev/null 2>&1; done
MISS=0
for i in $(seq 1 40); do
    [ "$(redis-cli -p "$PORT" GET "x$i" 2>/dev/null)" = "v$i" ] || MISS=$((MISS+1))
done
[ "$MISS" -eq 0 ] && ok "every key reads back over the mesh (40/40)" \
    || bad "every key reads back over the mesh" "$MISS of 40 missing"

sleep 3
ST=$("$BIN" stats meshc 2>&1 || true)
DIRECT=$(printf '%s\n' "$ST" | awk -F: '/^mesh_direct:/  {s+=$2} END{print s+0}')
RELAY=$( printf '%s\n' "$ST" | awk -F: '/^mesh_relayed:/ {s+=$2} END{print s+0}')

if [ "$DIRECT" -gt 0 ]; then
    ok "crossings went shard-to-shard ($DIRECT direct)"
else
    bad "crossings went shard-to-shard" \
        "mesh_direct is $DIRECT — every crossing relayed through the daemon," \
        "which answers correctly and measures as the build without a mesh"
fi
if [ "$RELAY" -eq 0 ]; then
    ok "none of them fell back to the daemon (relayed $RELAY)"
else
    bad "none of them fell back to the daemon" \
        "$RELAY of $((DIRECT+RELAY)) relayed; a link that connects and then" \
        "quietly gives up still reports direct > 0"
fi

"$BIN" stop meshc >/dev/null 2>&1; sleep 0.3; "$BIN" remove meshc >/dev/null 2>&1
daemon_stop

# ── the arm every measurement compares against ─────────────────────────────
daemon_isolate cacheshardmeshoff
export SOCKETLEY_NO_SHARD_MESH=1
daemon_start "$BIN"
"$BIN" create cache meshc -p "$PORT" --shards 4 --resp -s >/dev/null 2>&1
for i in $(seq 1 80); do
    redis-cli -p "$PORT" PING 2>/dev/null | grep -q PONG && break; sleep 0.25
done
for i in $(seq 1 20); do redis-cli -p "$PORT" SET "y$i" "w$i" >/dev/null 2>&1; done
MISS=0
for i in $(seq 1 20); do
    [ "$(redis-cli -p "$PORT" GET "y$i" 2>/dev/null)" = "w$i" ] || MISS=$((MISS+1))
done
if [ "$MISS" -eq 0 ] && grep -q "shard mesh disabled" "$SOCKETLEY_DLOG" 2>/dev/null; then
    ok "with the mesh disabled the daemon says so and still answers (20/20)"
else
    bad "with the mesh disabled the daemon says so and still answers" \
        "$MISS of 20 missing; log says: $(grep -c 'shard mesh disabled' "$SOCKETLEY_DLOG" 2>/dev/null || echo 0)"
fi
unset SOCKETLEY_NO_SHARD_MESH
"$BIN" stop meshc >/dev/null 2>&1; sleep 0.3; "$BIN" remove meshc >/dev/null 2>&1
daemon_stop

# ── the descriptor cap, which cannot fire at this box's real limit ─────────
#
# Lowered in a subshell so nothing after it inherits the limit.  8 shards need
# 8*7 = 56 descriptors held at once; at a soft limit of 512 the budget is half
# of that less headroom, so the mesh is refused and the runtime relays.
(
    ulimit -n 512 2>/dev/null || exit 0
    daemon_isolate cacheshardcap
    daemon_start "$BIN"
    "$BIN" create cache capc -p $((PORT+1)) --shards 8 --resp -s >/dev/null 2>&1
    for i in $(seq 1 80); do
        redis-cli -p $((PORT+1)) PING 2>/dev/null | grep -q PONG && break; sleep 0.25
    done
    for i in $(seq 1 20); do redis-cli -p $((PORT+1)) SET "z$i" "u$i" >/dev/null 2>&1; done
    m=0
    for i in $(seq 1 20); do
        [ "$(redis-cli -p $((PORT+1)) GET "z$i" 2>/dev/null)" = "u$i" ] || m=$((m+1))
    done
    said=$(grep -c "open-file limit leaves room" "$SOCKETLEY_DLOG" 2>/dev/null || echo 0)
    "$BIN" stop capc >/dev/null 2>&1; sleep 0.3; "$BIN" remove capc >/dev/null 2>&1
    printf '%s %s\n' "$m" "$said" > /tmp/skl-cap-result.$$
    daemon_stop
)
if [ -f /tmp/skl-cap-result.$$ ]; then
    read -r CAPMISS CAPSAID < /tmp/skl-cap-result.$$
    rm -f /tmp/skl-cap-result.$$
    if [ "${CAPSAID:-0}" -gt 0 ] && [ "${CAPMISS:-1}" -eq 0 ]; then
        ok "under a low descriptor limit the mesh is refused out loud and the cache still answers"
    else
        bad "under a low descriptor limit the mesh is refused out loud" \
            "log said it $CAPSAID time(s), $CAPMISS of 20 keys missing" \
            "a runtime that quietly stops meshing is indistinguishable from one" \
            "whose mesh did not help"
    fi
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
