#!/usr/bin/env bash
# Integration test: RENAME, RENAMENX, COPY, RANDOMKEY, EXPIRETIME, PEXPIRETIME.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
#   THE DEADLINE THAT DOES OR DOES NOT TRAVEL.  RENAME carries the key's expiry
#   with it -- renaming is not a way to make an expiring key permanent -- and
#   COPY carries it too.  The second of those was written the other way round
#   here, from a confident reading of the documentation, and the comparison
#   against a live redis-server is what caught it: the copy came back with
#   TTL -1 here and 500 there.  A copy that outlives its original is a key
#   nothing ever removes.
#
#   THE FIVE CONTAINERS.  A key lives in exactly one of strings, lists, sets,
#   hashes or sorted sets, so moving one has to look in all five.  This file
#   has already lost a container twice -- dump_commands walked four of five and
#   started followers without their sorted sets, and holds_other_type the same
#   -- so the move is written once as a template and every type is renamed and
#   copied here.
#
#   THE ANSWER SHAPES, WHICH DIFFER ON PURPOSE.  A missing source is an ERROR
#   for RENAME and a plain 0 for COPY, because one asks to move a thing that is
#   not there and the other asks whether it copied.  A client tests them
#   differently and Redis distinguishes them.
#
#   AND A KEY CANNOT BE HALF-MOVED.  On a sharded cache both keys must belong
#   to one shard; keys that do not are refused with -CROSSSLOT rather than
#   leaving the source deleted and the destination missing.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: renaming, copying and expiry times ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local l; for l in "${@:3}"; do echo "        $l"; done; }
eq()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$3'" "got      '$2'"; fi; }

P=$((SL_PORT_BASE+1484))
PS=$((SL_PORT_BASE+1490))
daemon_isolate cachekeymove
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"
"$BIN" create cache km_c -p "$P" -s >/dev/null 2>&1
sleep 1.5

r()      { redis-cli -p "${2:-$P}" $1 2>&1 | head -20; }
sorted() { redis-cli -p "${2:-$P}" $1 2>&1 | sort | tr '\n' ' ' | sed 's/ *$//'; }

echo "--- 1. RENAME across every container ---"
redis-cli -p "$P" flushall >/dev/null 2>&1
redis-cli -p "$P" set  s v      >/dev/null 2>&1
redis-cli -p "$P" rpush l a b   >/dev/null 2>&1
redis-cli -p "$P" sadd  t x y   >/dev/null 2>&1
redis-cli -p "$P" hset  h f v   >/dev/null 2>&1
redis-cli -p "$P" zadd  z 1 m   >/dev/null 2>&1
for pair in "s:string" "l:list" "t:set" "h:hash" "z:zset"; do
    k=${pair%%:*}; want=${pair##*:}
    eq "RENAME moves a $want"        "$(r "rename $k ${k}2")" "OK"
    eq "  and the type came with it" "$(r "type ${k}2")"      "$want"
    eq "  and the old name is gone"  "$(r "exists $k")"       "0"
done

echo "--- 2. what RENAME does with the deadline and the destination ---"
redis-cli -p "$P" set e v >/dev/null 2>&1; redis-cli -p "$P" expire e 500 >/dev/null 2>&1
eq "RENAME onto a live key replaces it" "$(r 'rename e s2')" "OK"
eq "  and carries the expiry over"      "$(r 'ttl s2')"      "500"
eq "a missing source is an ERROR, not a zero" \
   "$(r 'rename nosuch x' | cut -d' ' -f1)" "ERR"
eq "renaming a key onto itself is accepted" "$(r 'rename s2 s2')" "OK"
eq "  and it is still there"                "$(r 'exists s2')"    "1"

echo "--- 3. RENAMENX will not overwrite ---"
redis-cli -p "$P" set n1 a >/dev/null 2>&1; redis-cli -p "$P" set n2 b >/dev/null 2>&1
eq "refuses an occupied destination" "$(r 'renamenx n1 n2')" "0"
eq "  and left the source alone"     "$(r 'get n1')"         "a"
eq "  and the destination alone"     "$(r 'get n2')"         "b"
eq "takes a free one"                "$(r 'renamenx n1 n3')" "1"
eq "  and moved it"                  "$(r 'get n3')"         "a"

echo "--- 4. COPY ---"
redis-cli -p "$P" set c1 v1 >/dev/null 2>&1
eq "copies a value"                  "$(r 'copy c1 c2')" "1"
eq "  and both exist afterwards"     "$(r 'exists c1 c2')" "2"
eq "will not overwrite by default"   "$(r 'copy c1 c2')" "0"
eq "REPLACE says otherwise"          "$(r 'copy c1 c2 replace')" "1"
eq "a missing source is 0, not an error" "$(r 'copy nosuch x')" "0"
# The one this test was written for.
redis-cli -p "$P" set c3 v >/dev/null 2>&1; redis-cli -p "$P" expire c3 500 >/dev/null 2>&1
r 'copy c3 c4' >/dev/null
eq "the copy carries the deadline"   "$(r 'ttl c4')" "500"
eq "  and the original keeps its own" "$(r 'ttl c3')" "500"
redis-cli -p "$P" rpush cl a b c >/dev/null 2>&1
eq "copies a list whole"             "$(r 'copy cl cl2')" "1"
eq "  with its members"              "$(sorted 'lrange cl2 0 -1')" "a b c"

echo "--- 5. EXPIRETIME and PEXPIRETIME ---"
eq "a key with no expiry is -1"  "$(r 'expiretime c1')"      "-1"
eq "a key that is not there, -2" "$(r 'expiretime nosuch')"  "-2"
eq "and PEXPIRETIME the same"    "$(r 'pexpiretime nosuch')" "-2"
# An absolute time, so it must sit ahead of now by about the TTL.
NOW=$(date +%s); AT=$(r 'expiretime c3'); D=$(( AT - NOW ))
if [ "$D" -gt 480 ] && [ "$D" -lt 520 ]; then ok "an absolute time about 500s ahead"
else bad "expiretime" "expected now+~500, got now+$D" "expiretime=$AT now=$NOW"; fi
PAT=$(r 'pexpiretime c3')
if [ "$PAT" -gt $(( AT * 1000 - 2000 )) ] && [ "$PAT" -lt $(( AT * 1000 + 2000 )) ]; then
    ok "and the millisecond form agrees with it"
else bad "pexpiretime" "ms form disagrees" "expiretime=$AT pexpiretime=$PAT"; fi

echo "--- 6. RANDOMKEY ---"
K=$(r 'randomkey')
eq "returns a key that exists" "$(redis-cli -p "$P" exists "$K" 2>/dev/null)" "1"
# FLUSHALL was missing entirely until this test asked for it: the flush did
# nothing and RANDOMKEY kept answering, which is how it was found.
eq "FLUSHALL is accepted"      "$(r 'flushall')"   "OK"
eq "and empties the store"     "$(r 'dbsize')"     "0"
eq "and nil on an empty cache" "$(r 'randomkey')"  ""

echo "--- 7. against a live redis-server ---"
RP=$((SL_PORT_BASE+1496))
RDIR=$SOCKETLEY_TMPD/redis-km
if command -v redis-server >/dev/null 2>&1; then
    mkdir -p "$RDIR"
    redis-server --port "$RP" --dir "$RDIR" --daemonize yes --save '' --appendonly no >/dev/null 2>&1
    for _ in $(seq 1 20); do [ "$(redis-cli -p "$RP" ping 2>/dev/null)" = "PONG" ] && break; sleep 0.3; done
fi
if [ "$(redis-cli -p "$RP" ping 2>/dev/null)" = "PONG" ]; then
    for p in "$P" "$RP"; do
        redis-cli -p "$p" flushall >/dev/null 2>&1
        redis-cli -p "$p" set a 1 >/dev/null 2>&1; redis-cli -p "$p" set b 2 >/dev/null 2>&1
        redis-cli -p "$p" rpush ll x y >/dev/null 2>&1
        redis-cli -p "$p" expire a 500 >/dev/null 2>&1
    done
    for q in 'rename a a2' 'ttl a2' 'renamenx a2 b' 'copy b bb' 'copy b bb' \
             'copy b bb replace' 'copy ll ll2' 'ttl bb' 'copy a2 ac' 'ttl ac' \
             'expiretime b' 'expiretime gone' 'pexpiretime gone' 'rename gone x'; do
        eq "same as redis-server: $q" "$(r "$q" "$P")" "$(r "$q" "$RP")"
    done
    redis-cli -p "$RP" shutdown nosave >/dev/null 2>&1
else
    echo "  (redis-server absent — the comparison arm did not run)"
fi

echo "--- 8. sharded: a key cannot be half-moved ---"
"$BIN" create cache km_s -p "$PS" --shards 4 --cluster -s >/dev/null 2>&1
for _ in $(seq 1 80); do
    [ "$(ss -ltn 2>/dev/null | awk -v a=$((PS+1)) -v d=$((PS+4)) -F: '{n=$NF+0; if(n>=a&&n<=d) c++} END{print c+0}')" -ge 4 ] && break
    sleep 0.2
done
redis-cli -p "$PS" set '{x}a' 1 >/dev/null 2>&1
eq "under one tag it renames"  "$(r 'rename {x}a {x}b' "$PS")" "OK"
case "$(r 'rename {x}b {y}c' "$PS")" in CROSSSLOT*) ok "across shards it is refused" ;;
    *) bad "crossslot" "expected CROSSSLOT" "got: $(r 'rename {x}b {y}c' "$PS")" ;; esac
eq "and the source survived the refusal" "$(r 'exists {x}b' "$PS")" "1"
case "$(r 'copy {x}b {y}c' "$PS")" in CROSSSLOT*) ok "COPY across shards too" ;;
    *) bad "crossslot" "expected CROSSSLOT" ;; esac

echo ""
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && { echo "  OK"; exit 0; } || exit 1
