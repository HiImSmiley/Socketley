#!/usr/bin/env bash
# Integration test: sorted sets, on both protocols and across a restart.
#
# The cache had four types and a leaderboard was the thing you could not keep
# in it: a score per member, read back in score order.  What that cost was a
# fifth map in the store, which is why this file checks the places a fifth type
# leaks into rather than only the new verbs --
#
#   type()          answers `zset` and not `none`
#   the type is exclusive, so zadd refuses a key that is a string
#   keys/size       count it
#   SCAN            walks it, which needed a bit taken from the cursor's
#                   bucket-count field for the map index to fit
#   the dump        carries it, or a restart is a silent loss
#
# Ordering is asserted through zrange rather than through zrank alone, because
# a rank that is merely consistent with itself would pass on a wrong order.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate zsets
PORT=$((SL_PORT_BASE+1410))
DUMP="$SOCKETLEY_TMPD/z.rdb"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
eq()  { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', wanted '$3'"; fi; }

cleanup() { "$BIN" stop zc >/dev/null 2>&1; sleep 0.3
            "$BIN" remove zc >/dev/null 2>&1; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: sorted sets ==="
command -v nc >/dev/null 2>&1 || { echo "  SKIP: nc is required"; exit 0; }

daemon_start "$BIN"
"$BIN" create cache zc -p "$PORT" --persistent "$DUMP" --mode admin -s >/dev/null 2>&1

pt() { printf '%s\n' "$1" | timeout 3 nc -q1 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\r' | tr '\n' '|'; }
for i in $(seq 1 60); do [ -n "$(pt 'size')" ] && break; sleep 0.2; done
if [ -n "$(pt 'size')" ]; then ok; else
    bad "the cache answers" "nothing on $PORT"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit 1
fi

# ── The text protocol ───────────────────────────────────────────────────────
pt 'zadd lb 100 ada' >/dev/null
pt 'zadd lb 250 bob' >/dev/null
eq "a new member is 1"        "$(pt 'zadd lb 50 cyd')"  "1|"
eq "an existing member is 0"  "$(pt 'zadd lb 100 ada')" "0|"
eq "zcard counts them"        "$(pt 'zcard lb')"        "3|"
eq "zscore reads one back"    "$(pt 'zscore lb bob')"   "250|"

# Order, stated as the whole sequence: a rank alone can be self-consistent and
# still describe the wrong order.
eq "zrange is in score order"   "$(pt 'zrange lb 0 -1')"    "cyd|ada|bob|end|"
eq "zrevrange is the reverse"   "$(pt 'zrevrange lb 0 -1')" "bob|ada|cyd|end|"
eq "withscores pairs them"      "$(pt 'zrange lb 0 -1 withscores')" "cyd 50|ada 100|bob 250|end|"
eq "a slice is inclusive"       "$(pt 'zrange lb 0 1')"     "cyd|ada|end|"
eq "zrank counts from the low"  "$(pt 'zrank lb bob')"      "2|"
eq "zrevrank counts from the high" "$(pt 'zrevrank lb bob')" "0|"

# A score that moves has to move in the ordered view too, or the member is in
# it twice and the order is wrong afterwards.
pt 'zadd lb 10 bob' >/dev/null
eq "a re-scored member moves"   "$(pt 'zrange lb 0 -1')"  "bob|cyd|ada|end|"
eq "and is not there twice"     "$(pt 'zcard lb')"        "3|"
pt 'zadd lb 250 bob' >/dev/null

eq "zincrby answers the new score" "$(pt 'zincrby lb 25 cyd')" "75|"
eq "zrem takes one out"            "$(pt 'zrem lb ada')"       "ok|"
eq "zrem of a stranger is nil"     "$(pt 'zrem lb ada')"       "nil|"
eq "zscore of a stranger is nil"   "$(pt 'zscore lb weg')"     "nil|"

# ── The type, and its exclusivity ───────────────────────────────────────────
eq "type says zset"             "$(pt 'type lb')"        "zset|"
pt 'set plain v' >/dev/null
eq "zadd refuses a string key"  "$(pt 'zadd plain 1 m')" "error: type conflict|"
eq "set refuses a zset key"     "$(pt 'set lb v')"       "error: type conflict|"

# A malformed score is refused whole, like every number in this protocol.
eq "a malformed score is refused" "$(pt 'zadd lb 1x m')" "error: invalid score|"
eq "a fractional score is kept"   "$(pt 'zadd f 1.5 m')" "1|"
eq "and reads back fractional"    "$(pt 'zscore f m')"   "1.5|"

# ── The keyspace notices it ─────────────────────────────────────────────────
case "$(pt 'keys')" in *lb*) ok ;; *) bad "keys lists a zset" "got $(pt 'keys')" ;; esac
# scan walks five maps now; the zset key has to come out of it.
FOUND=0; CUR=0
for i in $(seq 1 40); do
    OUT=$(pt "scan $CUR")
    case "$OUT" in *lb*) FOUND=1 ;; esac
    CUR=$(printf '%s' "$OUT" | tr '|' '\n' | tail -2 | head -1)
    [ "$CUR" = "0" ] || [ -z "$CUR" ] && break
done
if [ "$FOUND" = 1 ]; then ok; else bad "scan reaches the fifth map" "no zset key in any scan page"; fi

# ── RESP ────────────────────────────────────────────────────────────────────
if command -v redis-cli >/dev/null 2>&1; then
    r() { redis-cli -p "$PORT" $1 2>&1 | tr '\n' '|'; }
    eq "ZADD takes score/member pairs" "$(r 'ZADD rl 3 c 1 a 2 b')" "3|"
    eq "ZRANGE over RESP"              "$(r 'ZRANGE rl 0 -1')"      "a|b|c|"
    eq "WITHSCORES over RESP"          "$(r 'ZRANGE rl 0 -1 WITHSCORES')" "a|1|b|2|c|3|"
    eq "ZSCORE over RESP"              "$(r 'ZSCORE rl b')"         "2|"
    eq "ZRANK over RESP"               "$(r 'ZRANK rl c')"          "2|"
    eq "ZINCRBY over RESP"             "$(r 'ZINCRBY rl 5 a')"      "6|"
    eq "ZREM counts what it removed"   "$(r 'ZREM rl a b')"         "2|"
    case "$(r "ZADD rl 1")" in *"wrong number of arguments"*) ok ;; *) bad "an odd ZADD arity is refused" "$(r "ZADD rl 1")" ;; esac
    case "$(r 'ZADD rl 1x m')" in *"not a valid float"*) ok ;; *) bad "a bad RESP score is refused" "$(r 'ZADD rl 1x m')" ;; esac
else
    echo "  (redis-cli absent — the RESP arm did not run)"
fi

# ── The dump carries it ─────────────────────────────────────────────────────
pt 'flush' >/dev/null
sleep 0.4
"$BIN" stop zc >/dev/null 2>&1; sleep 1
"$BIN" start zc >/dev/null 2>&1
for i in $(seq 1 60); do [ -n "$(pt 'size')" ] && break; sleep 0.2; done
eq "a zset survives a restart"        "$(pt 'zrange lb 0 -1 withscores')" "cyd 75|bob 250|end|"
eq "and its type came back with it"   "$(pt 'type lb')"                   "zset|"
eq "a fractional score survives too"  "$(pt 'zscore f m')"                "1.5|"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
