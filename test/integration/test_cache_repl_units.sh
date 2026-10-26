#!/usr/bin/env bash
# Integration test: a multi-argument write reaches a follower as what it was.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# repl() joins argv with spaces, and everything that reads those records back --
# a follower and this cache's own journal, which share one chokepoint in
# replicate_command() -- splits a text command with extract_key, which takes
# the whole remainder as the LAST field.  So seven commands were replicated as
# something else entirely:
#
#     RPUSH q a b c      one element "a b c"      where the leader has three
#     SADD  s x y z      one member  "x y z"
#     HSET  h f1 v1 f2 v2   f1 valued "v1 f2 v2", and no f2 at all
#     ZREM  z m1 m2      removes nothing
#     SREM / HDEL        the same
#
# No flag, no configuration, and on every correct call.  DEL's comment has
# named this exact trap since it was written -- "the text interpreter's `del`
# takes the whole remainder as one key, so `DEL p1 p2` deleted a key literally
# named p1 p2" -- MSET emits one record per pair, dump_commands emits one per
# element, and ZADD was fixed the same way one commit earlier.  These seven had
# not caught up.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# A seed written with a single-argument command first, and confirmed on the
# follower, for every structure.  Without it a build that replicated nothing at
# all would read as agreement on two empty answers.  And the negative
# assertions -- SISMEMBER for the invented member, HGET for the swallowed value
# -- because a count alone does not say what is wrong, only that something is.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate replunits

LP=$((SL_PORT_BASE+1524)); FP=$((SL_PORT_BASE+1525))
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    for n in rul ruf; do "$BIN" stop $n >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in rul ruf; do "$BIN" remove $n >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

ok() {   # ok GOT WANT LABEL
    TOTAL=$((TOTAL+1))
    if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
    else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi
}

echo "=== Integration: a multi-argument write replicates as what it was ==="

if ! command -v redis-cli >/dev/null 2>&1; then
    echo "  SKIP: redis-cli not available"
    exit 0
fi

daemon_start "$BIN"
create_ok "leader created" "$BIN" create cache rul -p "$LP" -s
for _ in $(seq 1 100); do redis-cli -p "$LP" ping >/dev/null 2>&1 && break; sleep 0.2; done
create_ok "follower created" "$BIN" create cache ruf -p "$FP" --replicate "127.0.0.1:$LP" -s
for _ in $(seq 1 100); do redis-cli -p "$FP" ping >/dev/null 2>&1 && break; sleep 0.2; done
sleep 2

r()  { redis-cli -p "$1" "${@:2}" 2>/dev/null; }
rl() { redis-cli -p "$1" "${@:2}" 2>/dev/null | tr '\n' ' '; }

# Bounded, so a link that is merely slow does not read as a divergence -- and
# one that is diverged still ends red, because the comparison is made after.
settle() {   # settle PORT WANT CMD...
    local port=$1 want=$2; shift 2
    for _ in $(seq 1 30); do
        [ "$(rl "$port" "$@")" = "$want" ] && return 0
        sleep 0.2
    done
    return 1
}

# ─── The seeds: one unit each, written one argument at a time ───────────────
r "$LP" rpush q seed   >/dev/null
r "$LP" sadd  s seed   >/dev/null
r "$LP" hset  h fs vs  >/dev/null
r "$LP" zadd  z 1 mseed >/dev/null
settle "$FP" "seed " lrange q 0 -1 || true
ok "$(rl "$FP" lrange q 0 -1)" "seed "  "the seeded list reached the follower"
ok "$(r  "$FP" scard s)"       "1"      "the seeded set reached the follower"
ok "$(r  "$FP" hget h fs)"     "vs"     "the seeded hash reached the follower"
ok "$(r  "$FP" zcard z)"       "1"      "the seeded sorted set reached the follower"

# ─── RPUSH / LPUSH ──────────────────────────────────────────────────────────
ok "$(r "$LP" rpush q a b c)" "4" "the leader took three elements"
settle "$FP" "seed a b c " lrange q 0 -1 || true
ok "$(rl "$FP" lrange q 0 -1)" "seed a b c " "RPUSH replicates element by element"

ok "$(r "$LP" lpush l x y z)" "3" "the leader took three elements at the head"
settle "$FP" "z y x " lrange l 0 -1 || true
ok "$(rl "$FP" lrange l 0 -1)" "z y x " "LPUSH keeps its order on the follower"

# ─── SADD, and the member it used to invent ─────────────────────────────────
ok "$(r "$LP" sadd s x y z)" "3" "the leader took three members"
settle "$FP" "4" scard s || true
ok "$(r "$FP" scard s)"            "4" "SADD replicates member by member"
ok "$(r "$FP" sismember s x)"      "1" "and each member is itself"
ok "$(r "$FP" sismember s 'x y z')" "0" "and no member was invented out of the split"

# ─── HSET, and the value that used to swallow the rest ──────────────────────
ok "$(r "$LP" hset h f1 v1 f2 v2)" "2" "the leader took two pairs"
settle "$FP" "3" hlen h || true
ok "$(r "$FP" hlen h)"     "3"  "HSET replicates pair by pair"
ok "$(r "$FP" hget h f1)"  "v1" "and the first value stops where it should"
ok "$(r "$FP" hget h f2)"  "v2" "and the second pair exists at all"

# ─── The removers, which used to remove nothing ─────────────────────────────
ok "$(r "$LP" srem s x y)" "2" "the leader removed two members"
settle "$FP" "2" scard s || true
ok "$(r "$FP" scard s)" "2" "SREM replicates member by member"

ok "$(r "$LP" hdel h f1 f2)" "2" "the leader removed two fields"
settle "$FP" "1" hlen h || true
ok "$(r "$FP" hlen h)" "1" "HDEL replicates field by field"

r "$LP" zadd z 2 m1 >/dev/null; r "$LP" zadd z 3 m2 >/dev/null
settle "$FP" "3" zcard z || true
ok "$(r "$LP" zrem z m1 m2)" "2" "the leader removed two members"
settle "$FP" "1" zcard z || true
ok "$(r "$FP" zcard z)" "1" "ZREM replicates member by member"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
