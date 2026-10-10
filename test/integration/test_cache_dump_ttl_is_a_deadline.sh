#!/usr/bin/env bash
# Integration test: a TTL restored from a dump is the deadline it was, not the
# time that was left when the dump was written.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# The dump stored each key's remaining milliseconds and the loader added them
# to the moment of loading, so a stop and a start granted every TTL again in
# full: a session key with ten seconds left at a clean stop, restored a week
# later, lived another ten seconds.  The journal already wrote pexpireat for
# exactly this reason; the dump, which is what a clean stop leaves, did not.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# A string and a list both expire while the runtime is stopped, because the
# collection types had their own copy of the rule.  A key with a long TTL must
# come back with it -- a build that dropped every TTL, or every key carrying
# one, would pass the first two rows -- and a key with no TTL must come back
# with none.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate dumpttl

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
         local l; for l in "${@:3}"; do echo "        $l"; done; }
WORK=$(mktemp -d)
cleanup() { rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: a dumped TTL is a deadline ==="
command -v redis-cli >/dev/null 2>&1 || { echo "  FAIL: redis-cli required"; exit 1; }
daemon_start "$BIN"
P=$((SL_PORT_BASE + 1720))
R() { redis-cli -p "$P" "$@" 2>/dev/null; }
up() { local i; for i in $(seq 1 100); do R ping | grep -q PONG && return 0; sleep 0.1; done; return 1; }

"$BIN" create cache dt -p "$P" --persistent "$WORK/dt.rdb" -s >/dev/null 2>&1
up || { echo "  FAIL: the cache never answered"; exit 1; }

R set short v px 2000 >/dev/null
R rpush shortlist a b >/dev/null
R pexpire shortlist 2000 >/dev/null
R set long v ex 300 >/dev/null
R set forever v >/dev/null
# What the two gone-checks below mean only if both keys were there to begin with: an empty answer after the restart
# reads the same for a deadline honoured and for a write that never landed.
[ "$(R get short) $(R llen shortlist)" = "v 2" ] || fail "the premise" \
    "before the stop, GET short = '$(R get short)' and LLEN shortlist = '$(R llen shortlist)', wanted v and 2"

"$BIN" stop dt >/dev/null 2>&1
# The worker writes the dump on its way out, after `stop` has answered.
for _ in $(seq 1 50); do [ -s "$WORK/dt.rdb" ] && break; sleep 0.1; done
[ -s "$WORK/dt.rdb" ] || fail "the premise" "the stop left no dump at $WORK/dt.rdb"
sleep 4                       # both short deadlines pass while stopped
"$BIN" start dt >/dev/null 2>&1
up || { echo "  FAIL: the cache never came back"; exit 1; }

V=$(R get short)
if [ -z "$V" ]; then pass "a string whose deadline passed while stopped is gone"
else fail "string deadline" "GET short = '$V', PTTL $(R pttl short)" \
          "the dump's remaining time was granted again at the load"; fi

L=$(R llen shortlist)
if [ "$L" = "0" ]; then pass "a list whose deadline passed while stopped is gone"
else fail "list deadline" "LLEN shortlist = $L, PTTL $(R pttl shortlist)"; fi

T=$(R ttl long)
if [ -n "$T" ] && [ "$T" -gt 250 ] && [ "$T" -le 297 ]; then
    pass "a long TTL comes back as its deadline (${T}s of 300)"
else fail "long ttl" "TTL long = '$T', want 251..297 after 4 s stopped"; fi

T=$(R ttl forever)
if [ "$T" = "-1" ]; then pass "a key with no TTL comes back with none"
else fail "no ttl" "TTL forever = '$T'"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
