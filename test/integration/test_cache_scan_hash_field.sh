#!/usr/bin/env bash
# Integration test: SCAN filtering on the VALUE a key holds
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# "Which records have city = berlin" is the database question, and records are
# usually hashes.  A value predicate on its own cannot answer it: it asks what a
# KEY holds, and a hash holds no single value.  SCAN ... FIELD <f> asks what a
# named field of each hash holds, which from outside is an HGET per hash key --
# measured at 15.8 ms against 1.5 ms over 5,000 hashes, and that against a client
# that already pipelines AND already uses the type filter.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the option being ignored, which is what an older build does with it: an
#     unknown token in SCAN's option list is skipped, so the answer is the whole
#     keyspace and reads like a filter that matched everything
#   * a hash WITHOUT the field counted as one whose field is empty.  Those are
#     different answers to "city = ''" and a store that confuses them answers a
#     query wrongly rather than slowly
#   * the predicate matched against the key's own value instead of the field's,
#     which a string holding the same word would then answer
#   * FIELD and a TYPE that cannot hold one, which can match nothing
#   * the value returned by WITHVALUES being the key's rather than the field's
#   * and the plain SCAN it shares a function with, unchanged
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: SCAN filtering on a hash field ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0
fi

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local line; for line in "${@:3}"; do echo "        $line"; done; }

P=$((SL_PORT_BASE+1485))
PS=$((SL_PORT_BASE+1486))

daemon_isolate cachescanfield
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

"$BIN" create cache sf_c  -p "$P"  --resp -s >/dev/null 2>&1
"$BIN" create cache sf_cs -p "$PS" --shards 4 --resp -s >/dev/null 2>&1
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
elif mode == 'pairs':
    cursor, prs, pages = '0', {}, 0
    while True:
        send(f, s, ['SCAN', cursor, 'COUNT', '10000'] + rest)
        r = read_reply(f)
        pages += 1
        cursor = r[0].decode()
        e = r[1]
        if len(e) % 2:
            print("ERR odd page of %d elements" % len(e)); sys.exit(0)
        for i in range(0, len(e), 2):
            prs[e[i].decode('latin1')] = e[i+1].decode('latin1')
        if cursor == '0':
            break
        if pages > 5000:
            print("ERR runaway cursor"); sys.exit(0)
    print("%d %s" % (pages, ' '.join('%s=%s' % kv for kv in sorted(prs.items()))))
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
      $'ZADD\x1fz:1\x1f1\x1fberlin' >/dev/null
}
scan() {   # port args...
    local port=$1; shift
    python3 "$SCAN_PY" "$port" scan "$@" 2>/dev/null
}
keys_of() { echo "$1" | cut -d' ' -f2-; }
pages_of(){ echo "$1" | cut -d' ' -f1; }
pairs() { local port=$1; shift; python3 "$SCAN_PY" "$port" pairs "$@" 2>/dev/null; }

# Records as hashes, which is the layout this file is about.
seedf() {   # port
    python3 "$SCAN_PY" "$1" setup \
      $'HSET\x1fu:1\x1fcity\x1fberlin\x1fage\x1f30' \
      $'HSET\x1fu:2\x1fcity\x1fhamburg\x1fage\x1f41' \
      $'HSET\x1fu:3\x1fcity\x1fberlin\x1fage\x1f22' \
      $'HSET\x1fu:4\x1fname\x1fno city at all' \
      $'HSET\x1fu:5\x1fcity\x1f' \
      $'SET\x1fplain\x1fberlin' \
      $'RPUSH\x1fl:1\x1fberlin' >/dev/null
}
seedf "$P"

EXP=""
check() {  # label  args...
    local label=$1; shift
    local R; R=$(scan "$P" COUNT 10000 "$@")
    if [ "$(keys_of "$R")" = "$EXP" ]; then ok "$label"
    else bad "$label" "got '$(keys_of "$R")', wanted '$EXP'"; fi
}

echo "--- 1. the query itself ---"
EXP="u:1 u:3"
check "FIELD city VALUEMATCH berlin returns the hashes whose city is berlin" \
      FIELD city VALUEMATCH berlin

echo "--- 2. having the field is not the field being empty ---"
EXP="u:1 u:2 u:3 u:5"
check "FIELD city alone returns the hashes that HAVE a city"  FIELD city
EXP="u:5"
check "and the empty value is asked for by name"  FIELD city VALUEMATCH ''

echo "--- 3. the predicate is the field's, not the key's ---"
R=$(scan "$P" COUNT 10000 FIELD city VALUEMATCH berlin)
case " $(keys_of "$R") " in
    *" plain "*|*" l:1 "*)
        bad "a string or list holding the same word is not an answer" \
            "got '$(keys_of "$R")'" \
            "-- plain and l:1 both hold berlin, and neither is a hash with a city" ;;
    *) ok "a string or list holding the same word is not an answer" ;;
esac

echo "--- 4. the key pattern still applies ---"
EXP="u:1"
check "FIELD and MATCH are ANDed"  FIELD city VALUEMATCH berlin MATCH 'u:1*'

echo "--- 5. WITHVALUES returns the field's value ---"
R=$(pairs "$P" FIELD city WITHVALUES)
EXPP='u:1=berlin u:2=hamburg u:3=berlin u:5='
if [ "$(keys_of "$R")" = "$EXPP" ]; then
    ok "WITHVALUES with a field returns that field's value, the empty one included"
else
    bad "WITHVALUES with a field returns that field's value" \
        "got '$(keys_of "$R")'" "wanted '$EXPP'"
fi

echo "--- 6. a type that holds no fields ---"
R=$(scan "$P" COUNT 10000 FIELD city TYPE string)
if [ -z "$(keys_of "$R")" ]; then ok "FIELD with TYPE string matches nothing"
else bad "FIELD with TYPE string matches nothing" "got '$(keys_of "$R")'"; fi

echo "--- 7. a field no hash has ---"
R=$(scan "$P" COUNT 10000 FIELD nosuchfield)
if [ -z "$(keys_of "$R")" ]; then ok "a field no hash has returns nothing"
else bad "a field no hash has returns nothing" "got '$(keys_of "$R")'" \
        "-- the whole keyspace here means the option fell through"; fi

echo "--- 8. paging ---"
R=$(scan "$P" COUNT 1 FIELD city)
PG=$(pages_of "$R")
if [ "$(keys_of "$R")" = "u:1 u:2 u:3 u:5" ] && [ "${PG:-0}" -gt 1 ]; then
    ok "a tiny COUNT pages ($PG pages) and still returns every match"
else
    bad "a tiny COUNT pages and still returns every match" \
        "$PG pages, keys '$(keys_of "$R")'"; fi

echo "--- 9. the plain scan it shares a function with ---"
EXP="l:1 plain u:1 u:2 u:3 u:4 u:5"
check "SCAN without the option is unchanged"

echo "--- 10. and the same answer from a sharded cache ---"
if ss -ltn 2>/dev/null | grep -q ":$PS "; then
    seedf "$PS"
    R=$(scan "$PS" COUNT 10000 FIELD city VALUEMATCH berlin)
    if [ "$(keys_of "$R")" = "u:1 u:3" ]; then
        ok "four shards walked by one cursor give the same set"
    else
        bad "four shards walked by one cursor give the same set" \
            "got '$(keys_of "$R")', wanted 'u:1 u:3'"; fi
else
    bad "the sharded cache bound its port" "nothing listening on $PS"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ] || exit 1
