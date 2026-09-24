#!/usr/bin/env bash
# Integration test: the text protocol does not rename a key into the wrong shard
#
# ─── WHAT THIS REPLACES ─────────────────────────────────────────────────────
# RENAME, COPY, SMOVE and the set algebra name more than one key and cannot be
# split across shards.  The RESP path has routed them since
# route_all_keys_one_shard(); the text path never did, because cache_classify()
# does not name them and an unnamed command reads `unknown` -- which is served
# locally, out of whichever shard the client happened to reach.
#
# Measured on two shards with --cluster, `rename k2 k1` sent as text to the
# shard owning k2 while k1 belongs to the other:
#
#     the command answered           ok
#     the owning shard, get k1       (nothing)
#     the shard it landed on         MOVED ... :26602
#
# So the value was written under a name every router sends somewhere else, and
# was reachable from no port at all -- with the client told it had happened.
#
# ─── THE CONTROL IS THE HALF THAT MUST STILL WORK ───────────────────────────
# A fix that refused every RENAME would pass the first assertion.  The second
# pair is two keys the same shard owns, which must still rename.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate textmultikey
P=$((SL_PORT_BASE+580))
PASS=0; FAIL=0; TOTAL=0

cleanup() { "$BIN" stop tmk 2>/dev/null || true; "$BIN" remove tmk 2>/dev/null || true; daemon_stop; }
trap cleanup EXIT

ok() {
    TOTAL=$((TOTAL+1))
    if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
    else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi
}
command -v redis-cli >/dev/null 2>&1 || { echo "  SKIP: redis-cli not available"; exit 0; }
command -v nc >/dev/null 2>&1        || { echo "  SKIP: nc not available"; exit 0; }

txt() { printf '%s\n' "$1" | timeout 10 nc -q 2 127.0.0.1 "$2" 2>/dev/null | tr -d '\r' | head -1; }

"$BIN" create cache tmk -p "$P" --shards 2 --cluster -s >/dev/null
for _ in $(seq 1 100); do
    redis-cli -p $((P+1)) ping >/dev/null 2>&1 && redis-cli -p $((P+2)) ping >/dev/null 2>&1 && break
    sleep 0.2
done

# Two keys on shard 0 and one on shard 1, taken from the cache's own slot map
# rather than assumed -- the mapping is slot*shards/16384 and a test that
# hard-coded a name would rot with the hash.
A=""; B=""; A2=""
for k in k1 k2 k3 k4 k5 k6 k7 k8 k9 k10; do
    s=$(redis-cli -p $((P+1)) cluster keyslot "$k" 2>/dev/null)
    own=$(( s * 2 / 16384 ))
    if [ "$own" = "0" ]; then [ -z "$A" ] && A=$k || { [ -z "$A2" ] && A2=$k; }
    else [ -z "$B" ] && B=$k; fi
done
echo "  shard0 owns '$A' and '$A2', shard1 owns '$B'"
# The hash is fixed and ten names always split, so a map that does not is a
# cache that stopped answering KEYSLOT rather than a reason to skip.
[ -n "$A" ] && [ -n "$A2" ] && [ -n "$B" ] || { echo "  FAIL: the slot map did not split ten keys across two shards"; exit 1; }

redis-cli -p $((P+1)) set "$A" wert >/dev/null

# The half that must be refused.
R=$(txt "rename $A $B" $((P+1)))
ok "$(echo "$R" | grep -c '^error:')" "1" "a rename whose target belongs elsewhere is refused, not answered ok"
ok "$(redis-cli -p $((P+1)) get "$A")" "wert" "and the source key is still here, untouched"
ok "$(redis-cli -p $((P+2)) get "$B")" ""     "and nothing was written where the target belongs"

# The half that must still work: both keys on this shard.
R2=$(txt "rename $A $A2" $((P+1)))
ok "$(echo "$R2" | grep -c 'ok')" "1"            "a rename within one shard still succeeds"
ok "$(redis-cli -p $((P+1)) get "$A2")" "wert"   "and the value moved to the new name"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
