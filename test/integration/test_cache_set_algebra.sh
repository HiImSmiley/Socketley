#!/usr/bin/env bash
# Integration test: SINTER, SUNION, SDIFF, their STORE forms, and SMOVE.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
#   THE DESTINATION THAT IS ALSO A SOURCE.  SINTERSTORE a a b is legal and
#   common -- narrowing a set in place -- and it is the case that breaks an
#   implementation which writes the result while still reading from it.  The
#   result is therefore materialised as owned strings before the destination is
#   touched, and this test names that case on purpose.
#
#   THE EMPTY RESULT.  Redis does not keep empty sets: a STORE whose result is
#   empty DELETES the destination rather than leaving a zero-member key behind.
#   An implementation that leaves the key makes EXISTS disagree with SMEMBERS,
#   and nothing else in the suite would notice.
#
#   THE KEY THAT IS NOT A SET.  Every key is checked before any work, so a
#   WRONGTYPE never arrives after a partial answer -- which for a STORE form
#   would mean the destination had already been replaced.
#
#   AND THE SPLIT THAT CANNOT BE MADE.  An intersection computed on two shards
#   separately is not an intersection, so unlike MGET or DEL these cannot be
#   exploded per key.  Every key must belong to one shard, and the answer for
#   keys that do not is -CROSSSLOT, which is what Redis Cluster answers and for
#   the same reason.
#
#   The results are compared against a live redis-server where one is
#   available, because "what Redis does" is the specification here and a
#   hand-written expectation is a second opinion about it.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: set algebra ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local l; for l in "${@:3}"; do echo "        $l"; done; }
eq()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$3'" "got      '$2'"; fi; }

P=$((SL_PORT_BASE+1463))
PS=$((SL_PORT_BASE+1470))
daemon_isolate cachesetalg
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"
"$BIN" create cache sa_c -p "$P" -s >/dev/null 2>&1
sleep 1.5

r() { redis-cli -p "${2:-$P}" $1 2>&1 | head -20; }
sorted() { redis-cli -p "${2:-$P}" $1 2>&1 | sort | tr '\n' ' ' | sed 's/ *$//'; }

redis-cli -p "$P" flushall >/dev/null 2>&1
redis-cli -p "$P" sadd a x y z >/dev/null 2>&1
redis-cli -p "$P" sadd b y z w >/dev/null 2>&1
redis-cli -p "$P" sadd c z     >/dev/null 2>&1
redis-cli -p "$P" set str v    >/dev/null 2>&1

echo "--- 1. the three readers ---"
eq "SINTER of two sets"   "$(sorted 'sinter a b')"     "y z"
eq "SUNION of three"      "$(sorted 'sunion a b c')"   "w x y z"
eq "SDIFF keeps only the first's own" "$(sorted 'sdiff a b')" "x"
eq "an absent key empties an intersection" "$(sorted 'sinter a nosuch')" ""
eq "and is simply skipped by a union"      "$(sorted 'sunion a nosuch')" "x y z"

echo "--- 2. the STORE forms ---"
eq "SINTERSTORE answers the cardinality" "$(r 'sinterstore d a b')" "2"
eq "and the destination holds it"        "$(sorted 'smembers d')"   "y z"
# The case that breaks a naive implementation: writing the answer into a set it
# is still reading from.
eq "a destination that is also a source"  "$(r 'sinterstore a a b')" "2"
eq "and it narrowed in place"             "$(sorted 'smembers a')"   "y z"
# Redis keeps no empty sets, so this must remove the key, not empty it.
eq "an empty result answers 0"            "$(r 'sinterstore e c nosuch')" "0"
eq "and leaves NO key behind"             "$(r 'exists e')"              "0"
# Two and not three: the assertion above narrowed `a` to {y,z} in place, so
# this also checks that the in-place STORE really took effect rather than
# leaving the old members behind.
eq "SUNIONSTORE over the narrowed set" "$(r 'sunionstore u a c')" "2"
eq "SDIFFSTORE"   "$(r 'sdiffstore f b a')"  "1"

echo "--- 3. SMOVE ---"
eq "moves a member"            "$(r 'smove b d y')" "1"
eq "and it left the source"    "$(sorted 'smembers b')" "w z"
eq "and arrived at the target" "$(sorted 'smembers d')" "y z"
eq "a member that is not there moves nothing" "$(r 'smove b d nope')" "0"

echo "--- 4. a key that is not a set stops the command ---"
case "$(r 'sinter a str')"      in WRONGTYPE*) ok "SINTER refuses a string" ;;
    *) bad "wrongtype" "not a WRONGTYPE" "got: $(r 'sinter a str')" ;; esac
case "$(r 'sunionstore g a str')" in WRONGTYPE*) ok "and so does a STORE form" ;;
    *) bad "wrongtype" "not a WRONGTYPE" ;; esac
eq "and the destination was NOT replaced first" "$(r 'exists g')" "0"
case "$(r 'smove str d x')"     in WRONGTYPE*) ok "SMOVE refuses one too" ;;
    *) bad "wrongtype" "not a WRONGTYPE" ;; esac

echo "--- 5. against a live redis-server, where the answers are defined ---"
RP=$((SL_PORT_BASE+1477))
RDIR=$SOCKETLEY_TMPD/redis-sa
if command -v redis-server >/dev/null 2>&1; then
    mkdir -p "$RDIR"
    redis-server --port "$RP" --dir "$RDIR" --daemonize yes --save '' --appendonly no >/dev/null 2>&1
    for _ in $(seq 1 20); do [ "$(redis-cli -p "$RP" ping 2>/dev/null)" = "PONG" ] && break; sleep 0.3; done
fi
if [ "$(redis-cli -p "$RP" ping 2>/dev/null)" = "PONG" ]; then
    for p in "$P" "$RP"; do
        redis-cli -p "$p" flushall >/dev/null 2>&1
        redis-cli -p "$p" sadd s1 a b c d >/dev/null 2>&1
        redis-cli -p "$p" sadd s2 c d e   >/dev/null 2>&1
        redis-cli -p "$p" sadd s3 d       >/dev/null 2>&1
    done
    for q in 'sinter s1 s2 s3' 'sunion s1 s2 s3' 'sdiff s1 s2' 'sdiff s2 s1' \
             'sinter s1 gone' 'sunion gone' 'sdiff gone s1'; do
        eq "same as redis-server: $q" "$(sorted "$q" "$P")" "$(sorted "$q" "$RP")"
    done
    for q in 'sinterstore t s1 s2' 'sunionstore t s1 s3' 'sdiffstore t s1 s2' \
             'sinterstore s1 s1 s2' 'smove s2 s3 e'; do
        eq "same as redis-server: $q" "$(r "$q" "$P")" "$(r "$q" "$RP")"
    done
    redis-cli -p "$RP" shutdown nosave >/dev/null 2>&1
elif command -v redis-server >/dev/null 2>&1; then
    bad "redis-server comes up for the comparison arm" "nothing answered PING on $RP"
else
    echo "  (redis-server absent — the comparison arm did not run)"
fi

echo "--- 6. sharded: one shard owns all of it, or nothing does ---"
"$BIN" create cache sa_s -p "$PS" --shards 4 --cluster -s >/dev/null 2>&1
for _ in $(seq 1 80); do
    [ "$(ss -ltn 2>/dev/null | awk -v a=$((PS+1)) -v d=$((PS+4)) -F: '{n=$NF+0; if(n>=a&&n<=d) c++} END{print c+0}')" -ge 4 ] && break
    sleep 0.2
done
redis-cli -p "$PS" sadd '{x}p' 1 2 3 >/dev/null 2>&1
redis-cli -p "$PS" sadd '{x}q' 2 3 4 >/dev/null 2>&1
eq "two keys under one tag intersect" "$(sorted 'sinter {x}p {x}q' "$PS")" "2 3"
case "$(r 'sinter {x}p {y}q' "$PS")" in CROSSSLOT*) ok "keys on two shards are refused, not half-answered" ;;
    *) bad "crossslot" "expected CROSSSLOT" "got: $(r 'sinter {x}p {y}q' "$PS")" ;; esac
case "$(r 'sinterstore {x}r {x}p {y}q' "$PS")" in CROSSSLOT*) ok "and a STORE form the same" ;;
    *) bad "crossslot" "expected CROSSSLOT" ;; esac
case "$(r 'smove {x}p {y}q 1' "$PS")" in CROSSSLOT*) ok "SMOVE across shards is refused" ;;
    *) bad "crossslot" "expected CROSSSLOT" ;; esac
eq "and nothing was moved" "$(sorted 'smembers {x}p' "$PS")" "1 2 3"

echo ""
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && { echo "  OK"; exit 0; } || exit 1
