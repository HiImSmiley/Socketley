#!/usr/bin/env bash
# Integration test: nothing past the parser's last slot is dropped in silence.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# parsed_args::parse stopped at MAX_ARGS and never looked at the rest of the
# line.  rest_from() spans to the end of the LAST argument, so everything past
# the limit was gone.  Measured, a cache SET with a forty-word value:
#
#     socketley c1 set k1 w0 w1 ... w39     exit 0
#     socketley c1 get k1 | wc -w           28
#
# Twelve words dropped, reported as success.  For a cache that is the worst
# property it could have: the loss shows up when the value is read back, long
# after whatever produced it is gone.
#
# Two halves, because one fix does not cover both shapes of command:
#
#   * a command whose last argument is FREE TEXT — send, action, import — has
#     no business having a word limit, and the last slot now carries the whole
#     remainder so rest_from() covers the line.
#   * a command whose arguments are a LIST — start, stop, create — cannot be
#     repaired that way: the merged tail is one impossible name, or a create
#     missing its flags.  Those are refused.
#
# Both are asserted, and the refusal is paired with an ordinary command of the
# same shape that must still work.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate argoverflow
PASS=0; FAIL=0; TOTAL=0

cleanup() { daemon_stop; }
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: arguments past the parser's last slot ==="

daemon_start "$BIN"
P=$((SL_PORT_BASE + 890))

"$BIN" create cache ov_cache -p "$P" -s >/dev/null 2>&1 || true

# ─── Free text: a long value arrives entire ─────────────────────────────────
LONG=$(python3 -c "print(' '.join('w%d' % i for i in range(40)))")
"$BIN" ov_cache set k_long $LONG >/dev/null 2>&1 || true
GOT=$("$BIN" ov_cache get k_long 2>/dev/null | wc -w)
if [ "$GOT" -eq 40 ]; then pass
else fail "a forty-word value is stored whole" \
          "stored $GOT of 40 words" \
          "everything past the parser's last slot used to be dropped, with exit 0."; fi

# The words at the END are the ones that used to go.  A count alone would pass
# on a value that kept forty words of the wrong thing.
if "$BIN" ov_cache get k_long 2>/dev/null | grep -qw "w39"; then pass
else fail "the last word of the value survived" "w39 is not in the stored value"; fi

# A short value is unaffected — the ordinary path has to keep working.
"$BIN" ov_cache set k_short hello world >/dev/null 2>&1 || true
if [ "$("$BIN" ov_cache get k_short 2>/dev/null)" = "hello world" ]; then pass
else fail "an ordinary two-word value still round trips" \
          "got '$("$BIN" ov_cache get k_short 2>/dev/null)'"; fi

# ─── Lists: refused rather than half-applied ────────────────────────────────
#
# The names are REAL and repeated, not made up.  Written with forty invented
# names this assertion passed on the broken build too — `stop n0 n1 ...` exits 1
# there because none of them resolve, which is a different refusal for a
# different reason, and the test would have been green on both sides.  Forty
# copies of a runtime that exists gives the broken build every reason to exit 0.
"$BIN" create server ov_a -p $((P + 2)) >/dev/null 2>&1 || true
"$BIN" create server ov_b -p $((P + 3)) >/dev/null 2>&1 || true

MANY=$(python3 -c "print(' '.join('ov_a' for _ in range(40)))")
RC=0
OUT=$("$BIN" stop $MANY 2>&1) || RC=$?
if [ "$RC" -ne 0 ]; then pass
else fail "a list command with too many arguments is refused" \
          "stop exited 0 and silently ignored everything past the limit"; fi

# The discriminating half: WHICH refusal it was.
if grep -qi "too many arguments" <<<"$OUT"; then pass
else fail "the refusal says what happened" \
          "said: ${OUT:-<nothing>}" \
          "some other refusal fired; this assertion is about the overflow."; fi

# create is the one where a dropped argument builds the wrong runtime.  Same
# reasoning: the message is what tells the two refusals apart, because an
# unreadable trailing token is also an "unknown flag" on the broken build.
RC=0
OUT=$("$BIN" create server ov_srv -p $((P + 1)) $MANY 2>&1) || RC=$?
if [ "$RC" -ne 0 ] && grep -qi "too many arguments" <<<"$OUT"; then pass
else fail "create with too many arguments is refused as an overflow" \
          "exit $RC, said: ${OUT:-<nothing>}"; fi

if [ -z "$("$BIN" ls --name 2>/dev/null | grep -x ov_srv || true)" ]; then pass
else fail "the refused create left nothing behind" "ov_srv exists"; fi

# ─── Control: a list command of ordinary length still works ─────────────────
#
# Load-bearing.  A build that refused every list command would pass all four
# refusals above.  (ov_a and ov_b were created before the refusals, so that the
# names in them resolve.)
RC=0
OUT=$("$BIN" stop ov_a ov_b 2>&1) || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "an ordinary two-name list still works" "stop exited $RC: ${OUT:-<nothing>}"; fi

# And exactly at the limit is not an overflow: the last slot then holds one
# token and there is nothing merged into it.
AT_LIMIT=$(python3 -c "print(' '.join('ov_a' for _ in range(30)))")
RC=0
OUT=$("$BIN" stop $AT_LIMIT 2>&1) || RC=$?
if [ "$RC" -eq 0 ]; then pass
else fail "a list that just fits is not treated as an overflow" \
          "stop exited $RC: ${OUT:-<nothing>}"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
