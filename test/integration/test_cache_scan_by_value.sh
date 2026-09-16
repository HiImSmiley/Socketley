#!/usr/bin/env bash
# Integration test: SCAN filtering on the VALUE a key holds
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# "Which keys hold this value" is a database question, and answering it from the
# client means dragging the whole keyspace over the wire to throw almost all of
# it away.  SCAN ... VALUEMATCH <glob> does the throwing away at the shard, on
# the same glob_match() the key MATCH already uses.
#
# It is a scan and not an index, and the name says so on purpose: it costs one
# glob per key examined, measured at about 130 ns, and nothing is maintained on
# the write path.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the option being ignored, which is what an older build does with it -- an
#     unknown token in SCAN's option list is skipped, so the reply is the WHOLE
#     keyspace and reads like a filter that matched everything
#   * a value predicate answered from the wrong maps.  Only a string key holds a
#     single value; a list, set, hash or zset that CONTAINS the pattern as a
#     member must not match, or "keys whose value is X" quietly means four
#     different things
#   * VALUEMATCH "" taken as "no predicate".  Absent and empty are different
#     requests -- the empty string is a value a key can hold -- and the same
#     distinction MATCH "" already makes
#   * the page bounded by keys RETURNED rather than keys EXAMINED.  A value
#     predicate is selective, so under the other contract one call walks the
#     whole map: 74 ms over 632,331 keys with the shard answering nobody.  A
#     tiny COUNT therefore has to produce many pages and still the same set
#   * and the plain SCAN it shares a function with, unchanged
#   * a cursor that names one of the other four maps.  The cursor packs the map
#     index beside the bucket index, so a cursor handed over from a plain scan
#     carries a bucket number that means nothing to a walk of the string map --
#     taken at face value it starts partway in and SKIPS everything before it,
#     which is the one thing a scan may never do
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: SCAN filtering on the value a key holds ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0
fi

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local line; for line in "${@:3}"; do echo "        $line"; done; }

P=$((SL_PORT_BASE+1481))
PS=$((SL_PORT_BASE+1482))

daemon_isolate cachescanval
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

"$BIN" create cache sv_c  -p "$P"  --resp -s >/dev/null 2>&1
"$BIN" create cache sv_cs -p "$PS" --shards 4 --resp -s >/dev/null 2>&1
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
    send(f, s, rest)
    r = read_reply(f)
    print(r.decode('latin1') if isinstance(r, bytes) else r)
elif mode == 'hpairs':
    # The same cursor loop for HSCAN, whose reply is field and value
    # interleaved.  rest[0] is the key; the rest are the options.
    key, opts = rest[0], rest[1:]
    cursor, prs, pages = '0', {}, 0
    while True:
        send(f, s, ['HSCAN', key, cursor, 'COUNT', '10000'] + opts)
        r = read_reply(f)
        pages += 1
        if not isinstance(r, list):
            print("ERR " + repr(r)); sys.exit(0)
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
elif mode == 'pairs':
    # The reply is key and value interleaved, so it is read two at a time and
    # printed as one token per pair: a helper that sorted the flat list would
    # scramble exactly the property this is here to check.
    cursor, pairs, pages = '0', {}, 0
    while True:
        send(f, s, ['SCAN', cursor, 'COUNT', '10000'] + rest)
        r = read_reply(f)
        pages += 1
        cursor = r[0].decode()
        e = r[1]
        if len(e) % 2:
            print("ERR odd page of %d elements" % len(e)); sys.exit(0)
        for i in range(0, len(e), 2):
            pairs[e[i].decode('latin1')] = e[i+1].decode('latin1')
        if cursor == '0':
            break
        if pages > 5000:
            print("ERR runaway cursor"); sys.exit(0)
    print("%d %s" % (pages, ' '.join('%s=%s' % kv for kv in sorted(pairs.items()))))
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
# A failing pair row can otherwise print two hundred pairs into the log.
cut_long(){ if [ ${#1} -gt 220 ]; then echo "${1:0:220}... (${#1} Zeichen)"; else echo "$1"; fi; }
pages_of(){ echo "$1" | cut -d' ' -f1; }

seed "$P"

echo "--- 1. the predicate itself ---"
R=$(scan "$P" COUNT 10000 VALUEMATCH '*berlin*')
if [ "$(keys_of "$R")" = "other:1 u:1 u:3" ]; then
    ok "VALUEMATCH returns exactly the string keys whose value matches"
else
    bad "VALUEMATCH returns exactly the string keys whose value matches" \
        "got '$(keys_of "$R")', wanted 'other:1 u:1 u:3'" \
        "-- the whole keyspace here means the option was skipped as unknown," \
        "   which is what a build without it does"
fi

echo "--- 2. only a string key holds a value ---"
R=$(scan "$P" COUNT 10000 VALUEMATCH '*')
if [ "$(keys_of "$R")" = "empty:1 other:1 u:1 u:2 u:3" ]; then
    ok "a list, set, hash or zset holding the pattern never matches"
else
    bad "a list, set, hash or zset holding the pattern never matches" \
        "got '$(keys_of "$R")', wanted the five string keys" \
        "-- l:1, s:1, h:1 and z:1 all CONTAIN 'berlin' as a member"
fi

echo "--- 3. absent is not empty ---"
R=$(scan "$P" COUNT 10000 VALUEMATCH '')
if [ "$(keys_of "$R")" = "empty:1" ]; then
    ok "VALUEMATCH '' asks for the empty value, not for no filter"
else
    bad "VALUEMATCH '' asks for the empty value, not for no filter" \
        "got '$(keys_of "$R")', wanted 'empty:1'"
fi

echo "--- 4. MATCH and VALUEMATCH are both required ---"
R=$(scan "$P" COUNT 10000 MATCH 'u:*' VALUEMATCH '*berlin*')
if [ "$(keys_of "$R")" = "u:1 u:3" ]; then
    ok "the key pattern and the value pattern are ANDed"
else
    bad "the key pattern and the value pattern are ANDed" \
        "got '$(keys_of "$R")', wanted 'u:1 u:3'"
fi

echo "--- 5. COUNT bounds the keys examined, not the keys returned ---"
R=$(scan "$P" COUNT 1 VALUEMATCH '*berlin*')
PG=$(pages_of "$R")
if [ "$(keys_of "$R")" = "other:1 u:1 u:3" ] && [ "${PG:-0}" -gt 1 ]; then
    ok "a tiny COUNT pages ($PG pages) and still returns every match"
else
    bad "a tiny COUNT pages and still returns every match" \
        "$PG pages, keys '$(keys_of "$R")'" \
        "-- one page for a selective predicate means the walk ran to the end of" \
        "   the map in a single call, which is the shard answering nobody"
fi

echo "--- 6. the plain scan it shares a function with ---"
R=$(scan "$P" COUNT 10000)
if [ "$(keys_of "$R")" = "empty:1 h:1 l:1 other:1 s:1 u:1 u:2 u:3 z:1" ]; then
    ok "SCAN without the option still returns every key of every type"
else
    bad "SCAN without the option still returns every key of every type" \
        "got '$(keys_of "$R")'"
fi

echo "--- 7. and the same answer from a sharded cache ---"
if ss -ltn 2>/dev/null | grep -q ":$PS "; then
    seed "$PS"
    R=$(scan "$PS" COUNT 10000 VALUEMATCH '*berlin*')
    if [ "$(keys_of "$R")" = "other:1 u:1 u:3" ]; then
        ok "four shards walked by one cursor give the same set"
    else
        bad "four shards walked by one cursor give the same set" \
            "got '$(keys_of "$R")', wanted 'other:1 u:1 u:3'" \
            "-- the cursor carries the shard index, so a predicate dropped on the" \
            "   hand-off would show up as a short answer here and nowhere else"
    fi
else
    bad "the sharded cache bound its port" "nothing listening on $PS"
fi

echo "--- 8. the value beside the key, so the client needs no second trip ---"
pairs() { local port=$1; shift; python3 "$SCAN_PY" "$port" pairs "$@" 2>/dev/null; }
R=$(pairs "$P" WITHVALUES)
EXPP='empty:1= other:1=berlin but another prefix u:1={"city":"berlin","age":30} u:2={"city":"hamburg","age":41} u:3={"city":"berlin","age":22}'
if [ "$(keys_of "$R")" = "$EXPP" ]; then
    ok "WITHVALUES returns every string key with its value, the empty one included"
else
    bad "WITHVALUES returns every string key with its value" \
        "got '$(cut_long "$(keys_of "$R")")'" \
        "wanted '$EXPP'" \
        "-- a key returned without its value means the option was skipped as" \
        "   unknown; empty:1 missing means an empty value was taken for absent"
fi

echo "--- 9. and together with the predicate, which is the whole use ---"
R=$(pairs "$P" VALUEMATCH '*"city":"berlin"*' WITHVALUES)
EXPP='u:1={"city":"berlin","age":30} u:3={"city":"berlin","age":22}'
if [ "$(keys_of "$R")" = "$EXPP" ]; then
    ok "the matches come back with their values in one walk"
else
    bad "the matches come back with their values in one walk" \
        "got '$(cut_long "$(keys_of "$R")")', wanted '$EXPP'"
fi

echo "--- 10. and a type that holds no single value returns nothing ---"
R=$(pairs "$P" TYPE hash WITHVALUES)
if [ "$(keys_of "$R")" = "" ]; then
    ok "TYPE hash with WITHVALUES matches nothing"
else
    bad "TYPE hash with WITHVALUES matches nothing" "got '$(cut_long "$(keys_of "$R")")'"
fi

echo "--- 11. a cursor that names another map restarts rather than skipping ---"
# Enough string keys that skipping any bucket loses some of them: with five the
# miss depends on where the hash puts them, which is a test that passes by luck.
python3 - "$SCAN_PY" "$P" <<'SEED'
import subprocess, sys
scanpy, port = sys.argv[1], sys.argv[2]
cmds = ['SET\x1fv:%d\x1f{"city":"berlin","n":%d}' % (i, i) for i in range(200)]
subprocess.run(['python3', scanpy, port, 'setup'] + cmds,
               stdout=subprocess.DEVNULL, check=True)
SEED
R=$(python3 "$SCAN_PY" "$P" resume '*"city":"berlin"*' 2>/dev/null)
CUR=$(echo "$R" | cut -d' ' -f1)
GOT=$(echo "$R" | cut -d' ' -f2)
# 200 seeded plus u:1 and u:3.  Not other:1: it holds the word berlin but not
# the quoted city field this pattern asks for, which is the point of using a
# pattern narrower than the one the rows above use.
if [ "$GOT" = 202 ]; then
    ok "resuming a value scan on a foreign cursor ($CUR) returns all 202"
else
    bad "resuming a value scan on a foreign cursor returns everything" \
        "got $GOT of 202 from cursor '$CUR'" \
        "-- the cursor's bucket index belongs to another map; used as this one's" \
        "   the walk starts partway into the string map and the keys before that" \
        "   point are never returned by any call of the iteration"
fi

echo "--- 12. the same predicate one level in, on a hash's fields ---"
hp() { local port=$1; shift; python3 "$SCAN_PY" "$port" hpairs "$@" 2>/dev/null; }
python3 "$SCAN_PY" "$P" setup \
  $'HSET\x1ftbl\x1ff1\x1fberlin\x1ff2\x1fhamburg\x1ff3\x1fberlin\x1ff4\x1f' >/dev/null
R=$(hp "$P" tbl VALUEMATCH berlin)
if [ "$(keys_of "$R")" = "f1=berlin f3=berlin" ]; then
    ok "HSCAN VALUEMATCH returns the fields holding that value"
else
    bad "HSCAN VALUEMATCH returns the fields holding that value" \
        "got '$(cut_long "$(keys_of "$R")")'" \
        "-- every field back means the option was not applied; hscan's own MATCH" \
        "   asks what a field is CALLED and this asks what it holds"
fi
R=$(hp "$P" tbl VALUEMATCH '')
if [ "$(keys_of "$R")" = "f4=" ]; then ok "and the empty value is asked for by name"
else bad "the empty value is asked for by name" "got '$(keys_of "$R")'"; fi
R=$(hp "$P" tbl MATCH 'f[13]' VALUEMATCH berlin)
if [ "$(keys_of "$R")" = "f1=berlin f3=berlin" ]; then ok "the two patterns are ANDed"
else bad "the two patterns are ANDed" "got '$(keys_of "$R")'"; fi

echo "--- 13. and a collection with no values to match refuses ---"
# sscan's members and zscan's scores are not values in this sense, and answering
# as if they were would make one option mean three things.
python3 "$SCAN_PY" "$P" setup $'SADD\x1fst\x1fa' $'ZADD\x1fzt\x1f1\x1fa' >/dev/null
BAD_S=$(python3 "$SCAN_PY" "$P" cmd SSCAN st 0 VALUEMATCH a 2>/dev/null)
BAD_Z=$(python3 "$SCAN_PY" "$P" cmd ZSCAN zt 0 VALUEMATCH a 2>/dev/null)
case "$BAD_S$BAD_Z" in
    *syntax*syntax*) ok "SSCAN and ZSCAN refuse VALUEMATCH as a syntax error" ;;
    *) bad "SSCAN and ZSCAN refuse VALUEMATCH" "sscan said '$BAD_S', zscan said '$BAD_Z'" ;;
esac

echo "--- 14. the question a glob cannot ask ---"
python3 "$SCAN_PY" "$P" setup \
  $'SET\x1fr:10\x1f10' $'SET\x1fr:20\x1f20' $'SET\x1fr:30\x1f30' \
  $'SET\x1fr:f\x1f25.5' $'SET\x1fr:na\x1f30kg' >/dev/null
R=$(scan "$P" COUNT 10000 MATCH 'r:*' VALUERANGE 20 30)
if [ "$(keys_of "$R")" = "r:20 r:30 r:f" ]; then
    ok "VALUERANGE takes the values between its bounds, inclusive"
else
    bad "VALUERANGE takes the values between its bounds" \
        "got '$(cut_long "$(keys_of "$R")")', wanted 'r:20 r:30 r:f'"
fi
R=$(scan "$P" COUNT 10000 MATCH 'r:*' VALUERANGE '(20' '(30')
if [ "$(keys_of "$R")" = "r:f" ]; then ok "and a leading ( makes a bound exclusive"
else bad "a leading ( makes a bound exclusive" "got '$(keys_of "$R")'"; fi

echo "--- 15. and a value that is not a number is in no range at all ---"
# Not even -inf..+inf.  from_chars would read the 30 out of "30kg" and stop, so
# the whole of the value has to be the number or it is not one.
R=$(scan "$P" COUNT 10000 MATCH 'r:*' VALUERANGE -inf +inf)
if [ "$(keys_of "$R")" = "r:10 r:20 r:30 r:f" ]; then
    ok "'30kg' matches no range, not even the one every number matches"
else
    bad "'30kg' matches no range" "got '$(cut_long "$(keys_of "$R")")'" \
        "-- r:na in the answer means the value was read as far as it parsed"
fi
BADR=$(python3 "$SCAN_PY" "$P" cmd SCAN 0 VALUERANGE abc 40 2>/dev/null)
case "$BADR" in *float*) ok "a bound that is not a float is an error, not a filter" ;;
                *) bad "a bound that is not a float is an error" "got '$BADR'" ;; esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ] || exit 1
