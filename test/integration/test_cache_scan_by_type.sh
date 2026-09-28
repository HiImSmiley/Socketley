#!/usr/bin/env bash
# Integration test: SCAN filtering on the VALUE a key holds
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# "Give me every hash" cost one TYPE round trip per key, and TYPE itself probes
# up to five maps to answer.  SCAN ... TYPE <t> answers it in the walk, and it
# is nearly free for a structural reason: the type of a key IS the map it lives
# in, and the scan already walks the five maps in a fixed order with the map
# index packed into its cursor.  Restricting to a type is walking one map.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the option being ignored, which is what an older build does with it: an
#     unknown token in SCAN's option list is skipped, so the answer is every key
#     of every type and reads like a filter that matched everything
#   * a restriction that returns the right COUNT of keys out of the wrong map
#   * a type name no type has, answered with the whole keyspace instead of with
#     nothing
#   * TYPE and VALUEMATCH asking for incompatible things.  A value predicate can
#     only be answered from the string map, so TYPE hash with one can match
#     nothing -- and saying so without walking is the difference between an
#     empty answer and a pointless full walk
#   * the case of the name, which a client should not have to guess
#   * and the plain SCAN they all share a function with, unchanged
#   * a per-type COUNT that disagrees with a walk of the same type, or five
#     counts that do not add up to the keyspace -- the two ways an O(1) answer
#     can drift away from the O(n) one it stands in for
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: SCAN restricted to one type of key ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0
fi

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local line; for line in "${@:3}"; do echo "        $line"; done; }

P=$((SL_PORT_BASE+1483))
PS=$((SL_PORT_BASE+1484))

daemon_isolate cachescantype
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

"$BIN" create cache st_c  -p "$P"  --resp -s >/dev/null 2>&1
"$BIN" create cache st_cs -p "$PS" --shards 4 --resp -s >/dev/null 2>&1
for _ in $(seq 1 150); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done
for _ in $(seq 1 150); do ss -ltn 2>/dev/null | grep -q ":$PS " && break; sleep 0.1; done
if ! ss -ltn 2>/dev/null | grep -q ":$P "; then
    echo "  FATAL: the cache never bound $P"; echo "  Results: 0/0 passed (0 failed)"; exit 2
fi

# A RESP client that runs the SCAN cursor loop to the end and prints the keys it
# collected, sorted, plus the number of pages it took.  In python because the
# loop is the point: one page proves nothing about a cursor.
SCAN_PY="$SOCKETLEY_TMPD/scanloop.py"
cat > "$SCAN_PY" <<'PY'
import socket, sys

def read_reply(f):
    line = f.readline()
    if not line:
        raise EOFError("connection closed")
    t, body = line[0:1], line[1:-2]
    if t in (b'+', b'-', b':'):
        return body
    if t == b'$':
        n = int(body)
        if n < 0:
            return None
        d = f.read(n + 2)
        return d[:-2]
    if t == b'*':
        n = int(body)
        if n < 0:
            return None
        return [read_reply(f) for _ in range(n)]
    raise ValueError("unknown reply type %r" % t)

def send(f, s, args):
    p = ('*%d\r\n' % len(args)).encode()
    for a in args:
        b = a.encode('latin1')
        p += b'$%d\r\n' % len(b) + b + b'\r\n'
    s.sendall(p)

port = int(sys.argv[1])
mode = sys.argv[2]                 # "setup" or "scan"
rest = sys.argv[3:]
s = socket.create_connection(('127.0.0.1', port), timeout=10)
f = s.makefile('rb')
if mode == 'setup':
    for spec in rest:
        send(f, s, spec.split('\x1f'))
        read_reply(f)
    print("ok")
elif mode == 'cmd':
    # One command, one reply, printed flat -- for the counting rows, which are
    # not walks and must not be run through the cursor loop.
    send(f, s, rest)
    r = read_reply(f)
    print(r.decode('latin1') if isinstance(r, bytes) else r)
elif mode == 'resume':
    # A cursor from a plain scan that has moved past the string map: its top
    # bits name another map, and its bucket index is that map's, not m_data's.
    vp = rest[0]
    cursor, foreign = '0', None
    while True:
        send(f, s, ['SCAN', cursor, 'COUNT', '1'])
        r = read_reply(f)
        cursor = r[0].decode()
        if cursor == '0':
            break
        if (int(cursor) >> 55) & 0x7:
            foreign = cursor
            break
    if foreign is None:
        print("ERR no cursor ever named another map")
    else:
        keys, cur = [], foreign
        while True:
            send(f, s, ['SCAN', cur, 'COUNT', '10000', 'VALUEMATCH', vp])
            r = read_reply(f)
            cur = r[0].decode()
            keys += [k.decode('latin1') for k in r[1]]
            if cur == '0':
                break
        print("%s %d" % (foreign, len(keys)))
else:
    cursor, pages, keys = '0', 0, []
    while True:
        send(f, s, ['SCAN', cursor] + rest)
        r = read_reply(f)
        pages += 1
        if not isinstance(r, list):
            print("ERR " + repr(r)); sys.exit(0)
        cursor = r[0].decode()
        keys += [k.decode('latin1') for k in r[1]]
        if cursor == '0':
            break
        if pages > 5000:
            print("ERR runaway cursor"); sys.exit(0)
    print("%d %s" % (pages, ' '.join(sorted(keys))))
s.close()
PY

seed() {   # port
    python3 "$SCAN_PY" "$1" setup \
      $'SET\x1fu:1\x1f{"city":"berlin","age":30}' \
      $'SET\x1fu:2\x1f{"city":"hamburg","age":41}' \
      $'SET\x1fu:3\x1f{"city":"berlin","age":22}' \
      $'SET\x1fother:1\x1fberlin but another prefix' \
      $'SET\x1fempty:1\x1f' \
      $'RPUSH\x1fl:1\x1fberlin' \
      $'SADD\x1fs:1\x1fberlin' \
      $'HSET\x1fh:1\x1fcity\x1fberlin' \
      $'ZADD\x1fz:1\x1f1\x1fberlin' \
      $'XADD\x1fx:1\x1f*\x1fcity\x1fberlin' >/dev/null
}
scan() {   # port args...
    local port=$1; shift
    python3 "$SCAN_PY" "$port" scan "$@" 2>/dev/null
}
keys_of() { echo "$1" | cut -d' ' -f2-; }
pages_of(){ echo "$1" | cut -d' ' -f1; }

seed "$P"

echo "--- 1. one restriction, one map ---"
FAILED_ROW=0
check() {  # label  args...  -> expected in $EXP
    local label=$1; shift
    local R; R=$(scan "$P" COUNT 10000 "$@")
    if [ "$(keys_of "$R")" = "$EXP" ]; then ok "$label"
    else bad "$label" "got '$(keys_of "$R")', wanted '$EXP'"; fi
}
EXP="empty:1 other:1 u:1 u:2 u:3"; check "TYPE string returns the string keys"  TYPE string
EXP="l:1";                          check "TYPE list returns the list keys"      TYPE list
EXP="s:1";                          check "TYPE set returns the set keys"        TYPE set
EXP="h:1";                          check "TYPE hash returns the hash keys"      TYPE hash
EXP="z:1";                          check "TYPE zset returns the zset keys"      TYPE zset
EXP="x:1";                          check "TYPE stream returns the stream keys"  TYPE stream

echo "--- 2. the name is not the client's to spell exactly ---"
EXP="h:1"; check "TYPE HASH is TYPE hash"  TYPE HASH

echo "--- 3. a name no type has matches nothing, not everything ---"
R=$(scan "$P" COUNT 10000 TYPE nosuchtype)
if [ -z "$(keys_of "$R")" ]; then ok "TYPE nosuchtype returns nothing"
else bad "a type name no type has returns nothing" \
        "got '$(keys_of "$R")'" \
        "-- the whole keyspace here means the name fell through to no filter"; fi

echo "--- 4. TYPE and MATCH are both required ---"
EXP="u:1 u:2 u:3"; check "the key pattern and the type are ANDed"  TYPE string MATCH 'u:*'

echo "--- 5. TYPE and VALUEMATCH, agreeing and disagreeing ---"
EXP="other:1 u:1 u:3"; check "TYPE string with a value predicate is the value walk" \
                            TYPE string VALUEMATCH '*berlin*'
R=$(scan "$P" COUNT 10000 TYPE hash VALUEMATCH '*berlin*')
if [ -z "$(keys_of "$R")" ]; then ok "TYPE hash with a value predicate matches nothing"
else bad "TYPE hash with a value predicate matches nothing" \
        "got '$(keys_of "$R")'" \
        "-- h:1 does hold berlin, as a field value; a value predicate asks what" \
        "   the KEY holds, and a hash holds no single value"; fi

echo "--- 6. the plain scan it shares a function with ---"
EXP="empty:1 h:1 l:1 other:1 s:1 u:1 u:2 u:3 x:1 z:1"; check "SCAN without the option is unchanged"

echo "--- 7. paging inside one restriction ---"
R=$(CNT=1 scan "$P" COUNT 1 TYPE string)
PG=$(pages_of "$R")
if [ "$(keys_of "$R")" = "empty:1 other:1 u:1 u:2 u:3" ] && [ "${PG:-0}" -gt 1 ]; then
    ok "a tiny COUNT pages ($PG pages) and still returns every key of the type"
else
    bad "a tiny COUNT pages and still returns every key of the type" \
        "$PG pages, keys '$(keys_of "$R")'"; fi

echo "--- 8. and the same answer from a sharded cache ---"
if ss -ltn 2>/dev/null | grep -q ":$PS "; then
    seed "$PS"
    R=$(scan "$PS" COUNT 10000 TYPE hash)
    if [ "$(keys_of "$R")" = "h:1" ]; then
        ok "four shards walked by one cursor give the same set"
    else
        bad "four shards walked by one cursor give the same set" \
            "got '$(keys_of "$R")', wanted 'h:1'" \
            "-- the cursor carries the shard index beside the map index, and a" \
            "   restriction dropped on the hand-off shows up only here"; fi
else
    bad "the sharded cache bound its port" "nothing listening on $PS"
fi

echo "--- 9. counting a type, which the maps answer by existing ---"
cmd() { python3 "$SCAN_PY" "$1" cmd "${@:2}" 2>/dev/null; }
COUNT_OK=1
for pair in "string 5" "list 1" "set 1" "hash 1" "zset 1" "stream 1"; do
    set -- $pair
    GOT=$(cmd "$P" DBSIZE TYPE "$1")
    [ "$GOT" = "$2" ] || { bad "DBSIZE TYPE $1 counts its own map" "got '$GOT', wanted $2"; COUNT_OK=0; }
done
[ "$COUNT_OK" = 1 ] && ok "DBSIZE TYPE counts each of the six maps"

echo "--- 10. a name no type has counts nothing, not everything ---"
GOT=$(cmd "$P" DBSIZE TYPE nosuchtype)
if [ "$GOT" = 0 ]; then ok "DBSIZE TYPE nosuchtype is 0"
else bad "a type name no type has counts nothing" "got '$GOT'" \
        "-- the whole keyspace here means the name fell through to no filter"; fi

echo "--- 11. the O(1) answer and the O(n) one have to agree ---"
TOTAL_KEYS=$(cmd "$P" DBSIZE)
SUM=0
AGREE=1
for t in string list set hash zset stream; do
    C=$(cmd "$P" DBSIZE TYPE "$t")
    SUM=$(( SUM + C ))
    W=$(scan "$P" COUNT 10000 TYPE "$t")
    N=$(keys_of "$W"); N=$([ -z "$N" ] && echo 0 || echo "$N" | wc -w)
    [ "$C" = "$N" ] || { bad "the count of $t agrees with a walk of it" "count $C, walk $N"; AGREE=0; }
done
if [ "$AGREE" = 1 ] && [ "$SUM" = "$TOTAL_KEYS" ]; then
    ok "the six counts sum to DBSIZE ($SUM) and each agrees with its own walk"
else
    bad "the six counts sum to DBSIZE and each agrees with its own walk" \
        "sum $SUM against DBSIZE $TOTAL_KEYS" \
        "-- a map counted twice or missed entirely shows up here and nowhere else"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ] || exit 1
