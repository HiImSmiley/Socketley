#!/usr/bin/env bash
# Integration test: ZADD is all-or-nothing, and every pair reaches the follower.
#
# ─── TWO DEFECTS ON ONE LINE ────────────────────────────────────────────────
#
# The RESP ZADD parsed each score INSIDE the loop that applied it, so a bad
# score in a later pair returned after the earlier pairs were already in the
# store -- and that `return` jumped over the repl() below it.  The leader kept
# those members, the follower never heard of them, and nothing later repairs
# it:
#
#     ZADD lb 1 alpha notanumber beta   -> -ERR value is not a valid float
#     leader   ZRANGE lb 0 -1            alpha, seed
#     follower ZRANGE lb 0 -1            seed
#
# The second is the same line's other half.  repl() joins argv with spaces and
# the follower splits a text `zadd` with extract_key twice, so the member is
# the whole remainder: a live `ZADD mp 1 m1 2 m2` arrived as the single member
# "m1 2 m2" scored 1.  repl_set_effect carries that sentence for SET and
# dump_commands has spelled a zset as one zadd per member since it was written;
# the live RESP path had not caught up.
#
# ─── WHAT KEEPS THIS FROM BEING VACUOUS ─────────────────────────────────────
#
# The seed member, written and confirmed on both sides before anything else, so
# "leader and follower agree" cannot pass on two empty answers.  And the
# leader-side reads, so a build that replicated nothing at all would fail here
# rather than looking like agreement.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate zaddpartial

LP=$((SL_PORT_BASE+1520)); FP=$((SL_PORT_BASE+1521))
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    for n in zpl zpf; do "$BIN" stop $n >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in zpl zpf; do "$BIN" remove $n >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

ok() {   # ok GOT WANT LABEL
    TOTAL=$((TOTAL+1))
    if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
    else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi
}

echo "=== Integration: a refused ZADD leaves no member behind ==="

if ! command -v redis-cli >/dev/null 2>&1; then
    echo "  SKIP: redis-cli not available"
    exit 0
fi

daemon_start "$BIN"
create_ok "leader created" "$BIN" create cache zpl -p "$LP" -s
for _ in $(seq 1 100); do redis-cli -p "$LP" ping >/dev/null 2>&1 && break; sleep 0.2; done
create_ok "follower created" "$BIN" create cache zpf -p "$FP" --replicate "127.0.0.1:$LP" -s
for _ in $(seq 1 100); do redis-cli -p "$FP" ping >/dev/null 2>&1 && break; sleep 0.2; done
sleep 2

zr() { redis-cli -p "$1" zrange "$2" 0 -1 withscores 2>/dev/null | tr '\n' ' '; }

# Bounded, so a link that is merely slow does not read as a divergence -- and
# one that is diverged still ends red, because the comparison is made after.
settle() {   # settle PORT KEY WANT
    for _ in $(seq 1 30); do
        [ "$(zr "$1" "$2")" = "$3" ] && return 0
        sleep 0.2
    done
    return 1
}

# ─── The control: the link carries a sorted-set write at all ────────────────
ok "$(redis-cli -p "$LP" zadd lb 5 seed 2>/dev/null)" "1" "the leader took the seed member"
settle "$FP" lb "seed 5 " || true
ok "$(zr "$FP" lb)" "seed 5 " "the seed member reached the follower"

# ─── The refusal, with the bad score in the SECOND pair ─────────────────────
ok "$(redis-cli -p "$LP" zadd lb 1 alpha notanumber beta 2>&1)" \
   "ERR value is not a valid float" "the unparsable score is refused"

L=$(zr "$LP" lb)
ok "$L" "seed 5 " "the refused ZADD applied none of its pairs on the leader"

settle "$FP" lb "$L" || true
ok "$(zr "$FP" lb)" "$L" "leader and follower agree after the refusal"
ok "$(redis-cli -p "$FP" zscore lb alpha 2>/dev/null)" "" \
   "the follower has no member the leader dropped"

# ─── The other half: a live multi-pair ZADD ─────────────────────────────────
ok "$(redis-cli -p "$LP" zadd mp 1 m1 2 m2 2>/dev/null)" "2" "the leader took both pairs"
L2=$(zr "$LP" mp)
ok "$L2" "m1 1 m2 2 " "the leader holds two members and not one"

settle "$FP" mp "$L2" || true
ok "$(zr "$FP" mp)" "$L2" "a live multi-pair ZADD reaches the follower pair by pair"
ok "$(redis-cli -p "$FP" zscore mp 'm1 2 m2' 2>/dev/null)" "" \
   "the follower did not invent a member out of the split"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
