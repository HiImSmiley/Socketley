#!/usr/bin/env bash
# Integration test: a number flag reads the whole value or refuses it.
#
# std::from_chars reports success for a PREFIX, so a site that does not compare
# the end pointer takes the number in front of the typo and says nothing.  The
# unit tests cover the four helpers in flag_handlers.h; this covers the sites
# that never called them, measured on the parent commit through the CLI:
#
#     --retry 2x               -> retry_count 2
#     --health-threshold 3x    -> 3
#     --circuit-threshold 4x   -> 4
#     attach server a 8080x    -> port 8080, runtime created
#     <cache> expire k 5x      -> ttl 5
#
# The cache's own arm moved when CLI cache commands started running in the
# worker: `expire 5x` is now refused by the cache's parser rather than by the
# daemon's, and it is still refused, which is what this asserts.  The daemon's
# copy stays for a runtime that is attached rather than forked.
#
# Each of these is a plausible typo -- 5m for a threshold, a stray character
# from a shell history -- and every one of them configured something other than
# what was typed, at exit 0.
#
# The valid arm is here because refusing everything would pass the typo arm on
# its own, and these five are the only proof that a working command still
# works.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate numtypo

PORT_PROXY=$((SL_PORT_BASE+1390))
PORT_BACK=$((SL_PORT_BASE+1391))
PORT_CACHE=$((SL_PORT_BASE+1392))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

cleanup() {
    "$BIN" stop cch 2>/dev/null >/dev/null
    sleep 0.3
    "$BIN" remove cch 2>/dev/null >/dev/null
    for n in 1 2 3 9 ""; do "$BIN" remove "pxy$n" >/dev/null 2>&1; done
    "$BIN" remove pxybig >/dev/null 2>&1
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a number flag reads the whole value or refuses it ==="

# Refused means exit 1 and a message, never exit 0 with the prefix stored.
refuses() {
    local what=$1; shift
    local out rc
    out=$("$@" 2>&1); rc=$?
    if [ "$rc" -eq 1 ] && [ -n "$out" ]; then ok; else
        bad "$what is refused" "expected exit 1 with a message, got exit $rc: '${out:-<silence>}'"
    fi
}

# A name and a port per arm, because on the parent commit the first create
# SUCCEEDED and the two after it were refused with "runtime already exists" --
# exit 1 and a message, which is what this test looks for.  Sharing a name made
# two of the three arms pass against the defect they exist to catch.
N=0
for pair in "retry:2x" "health-threshold:3x" "circuit-threshold:4x"; do
    N=$((N+1))
    refuses "--${pair%%:*} ${pair##*:}" \
        "$BIN" create proxy "pxy$N" -p $((PORT_PROXY+N)) --backend "127.0.0.1:$PORT_BACK" \
               "--${pair%%:*}" "${pair##*:}"
    "$BIN" remove "pxy$N" >/dev/null 2>&1
done

# A value past the type is refused rather than wrapped, and says so differently.
OUT=$("$BIN" create proxy pxybig -p $((PORT_PROXY+9)) --backend "127.0.0.1:$PORT_BACK" \
             --retry 99999999999 2>&1)
"$BIN" remove pxybig >/dev/null 2>&1
case "$OUT" in
    *"out of range"*) ok ;;
    *) bad "--retry past int is out of range" "got '${OUT:-<silence>}'" ;;
esac

# The valid arm: the same three flags, spelled right, still land their values.
if "$BIN" create proxy pxy -p "$PORT_PROXY" --backend "127.0.0.1:$PORT_BACK" \
        --retry 2 --health-threshold 5 --circuit-threshold 4 >/dev/null 2>&1
then ok; else bad "valid counts are accepted" "create refused a correct command line"; fi

SHOW=$("$BIN" show pxy 2>/dev/null)
if grep -q '"retry_count": 2' <<<"$SHOW" && grep -q '"circuit_threshold": 4' <<<"$SHOW" \
        && grep -q '"health_threshold": 5' <<<"$SHOW"
then ok; else bad "valid counts are stored" "show reports something else"; fi

# The edit arm is a second copy of all three cases in flag_handlers.cpp, so a
# fix applied to create alone would pass everything above this line.
refuses "edit --retry 9x" "$BIN" edit pxy --retry 9x

# Not a flag: the attach port and the cache TTL were the same defect elsewhere.
refuses "attach port 8080x" "$BIN" attach server att "8080x" --pid $$

"$BIN" create cache cch -p "$PORT_CACHE" -s >/dev/null 2>&1
for i in $(seq 1 40); do
    "$BIN" cch set k v >/dev/null 2>&1 && break
    sleep 0.1
done
if "$BIN" cch set k v >/dev/null 2>&1; then ok; else
    bad "the cache answers" "no reply on $PORT_CACHE after 4s"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; echo "  FAILED"; exit 1
fi

refuses "expire 5x" "$BIN" cch expire k 5x

# And the TTL it does take is the one asked for, not a prefix of it -- read
# back over the PORT, not over the CLI.  When this was written both routes
# ended in the daemon's placeholder, so the pair agreed with each other and
# said nothing about the cache; they cross processes now and the read is put
# where it proves that.
"$BIN" cch expire k 30 >/dev/null 2>&1
if command -v nc >/dev/null 2>&1; then
    TTL=$(printf 'ttl k\n' | timeout 3 nc -q1 127.0.0.1 "$PORT_CACHE" 2>/dev/null | tr -dc '0-9')
else
    TTL=$("$BIN" cch ttl k 2>/dev/null | tr -dc '0-9')
fi
if [ -n "$TTL" ] && [ "$TTL" -ge 28 ] && [ "$TTL" -le 30 ]; then ok; else
    bad "a valid expire is stored" "ttl reported '${TTL:-<nothing>}', wanted 28..30"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
