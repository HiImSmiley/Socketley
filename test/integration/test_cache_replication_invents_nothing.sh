#!/usr/bin/env bash
# Integration test: a follower may lack a key, but it must not invent one
#
# ─── WHAT THIS REPLACES ─────────────────────────────────────────────────────
# A replicated record is a text line, and both consumers of one -- a follower's
# link and this cache's own journal replay -- hand it to the text interpreter,
# which splits on spaces and lets the LAST field absorb the rest.  The RESP
# path builds that line by joining arguments with a space, so `SET "a b" v`
# went out as `set a b v` and came back as the key "a" holding "b v".
#
#     before            leader            follower
#     GET 'a b'         v                 (nothing)
#     GET 'a'           (nothing)         "b v"
#     DBSIZE            4                 4
#
# The follower had not lost a key.  It had invented one, under a name no client
# ever wrote, holding bytes no client ever put there -- and the two counts
# agreed, so nothing looked wrong from outside.  A read of `a` against that
# follower answers and is believed.
#
# ─── WHAT IT ASSERTS, AND WHY IT IS NOT "THEY MATCH" ────────────────────────
# The repair does not make the key replicate; it stops the record being written
# at all, so the leader keeps the key and the follower does not have it.  That
# is a visible divergence -- DBSIZE differs -- and the assertions are written
# for exactly that, because a test demanding both sides match would fail on the
# fix as loudly as on the defect.  Completing this wants a record that carries
# its own field lengths, which is a wire format between builds.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate replinvent
LP=$((SL_PORT_BASE+550)); FP=$((SL_PORT_BASE+231))
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    for n in rleader rfollower; do "$BIN" stop $n 2>/dev/null || true; "$BIN" remove $n 2>/dev/null || true; done
    daemon_stop
}
trap cleanup EXIT

ok() {
    TOTAL=$((TOTAL+1))
    if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
    else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi
}

if ! command -v redis-cli >/dev/null 2>&1; then
    echo "  SKIP: redis-cli not available (needed to send a key with a space)"
    exit 0
fi

"$BIN" create cache rleader -p "$LP" -s >/dev/null
for _ in $(seq 1 100); do redis-cli -p "$LP" ping >/dev/null 2>&1 && break; sleep 0.2; done
"$BIN" create cache rfollower -p "$FP" --replicate "127.0.0.1:$LP" -s >/dev/null
for _ in $(seq 1 100); do redis-cli -p "$FP" ping >/dev/null 2>&1 && break; sleep 0.2; done
sleep 2

# One key the wire cannot carry, and two it can, so a fix that simply stopped
# replicating everything would be caught by the second pair.
redis-cli -p "$LP" set "a b" "v"   >/dev/null
redis-cli -p "$LP" set plain "w"   >/dev/null
redis-cli -p "$LP" set "" "leer"   >/dev/null
sleep 2

ok "$(redis-cli -p "$LP" get 'a b')" "v"    "the leader holds the key it was given"
ok "$(redis-cli -p "$FP" get 'a')"  ""      "the follower did NOT invent 'a' out of the split"
ok "$(redis-cli -p "$FP" get plain)" "w"    "an ordinary key still replicates"
ok "$(redis-cli -p "$FP" get '')"   "leer"  "an empty key still replicates"

# The divergence has to be countable, or "the follower does not have it" is
# indistinguishable from "nobody looked".
L=$(redis-cli -p "$LP" dbsize); F=$(redis-cli -p "$FP" dbsize)
echo "  dbsize: leader $L, follower $F"
ok "$([ "$L" -gt "$F" ] && echo yes || echo no)" "yes" \
   "the divergence shows in dbsize rather than hiding behind equal counts"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
