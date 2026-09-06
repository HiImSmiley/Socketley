#!/usr/bin/env bash
# Integration test: the RESP commands the cache gained, and two answers it was
# getting wrong before they were added.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
#   EXISTS COUNTED ONE KEY.  `EXISTS a b c` answered 1 where Redis answers 3,
#   because the implementation read args[1] and stopped -- unsharded as well as
#   sharded.  The matrix never saw it: it measures EXISTS with one key.  A
#   client using the count as "how many of these are cached" got 1 or 0 for any
#   number of keys and cached nothing it should have.
#
#   A FOLLOWER STARTED WITHOUT EVERY SORTED SET.  dump_commands() walked
#   m_data, m_lists, m_sets and m_hashes and stopped, so the initial dump
#   carried four of the five containers.  The live stream then carried the
#   zadds that came AFTER the follower attached, which is what made it
#   invisible: a follower attached to an idle leader looked complete, and one
#   attached to a busy leader looked complete too, minus whatever was already
#   there.  Same shape as the expiry walk in test_cache_redis_disagreements.sh
#   and as the type-conflict probe: four containers handled, the fifth missed.
#
#   HELLO WAS AN UNKNOWN COMMAND.  A client asking for RESP3 got
#   "-ERR unknown command", which is not a protocol negotiation failure and
#   need not be handled as one.  -NOPROTO is what a Redis before 6 answers and
#   what every client falls back from.
#
# The rest is coverage: each new command answered over RESP, over the text
# protocol, and -- for the ones that mutate -- reaching a follower, because a
# command the text interpreter does not know replicates as nothing at all.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: the RESP commands the cache gained ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

P=$((SL_PORT_BASE+1496))
PL=$((SL_PORT_BASE+1497))
PF=$((SL_PORT_BASE+1498))

daemon_isolate cacheresp
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

"$BIN" create cache rc_c -p "$P" -s >/dev/null 2>&1
sleep 1.5

# One connection, commands in, replies as one line -- redis-cli is not on every
# box this runs on.
RESP_PY="$SOCKETLEY_TMPD/rcresp.py"
cat > "$RESP_PY" <<'PY'
import socket, sys, json
port = int(sys.argv[1])
cmds = json.loads(sys.argv[2])
out = b''
try:
    s = socket.create_connection(('127.0.0.1', port), timeout=5)
    payload = b''
    for c in cmds:
        if isinstance(c, str):
            payload += c.encode()
        else:
            payload += ('*%d\r\n' % len(c)).encode()
            for a in c:
                payload += ('$%d\r\n%s\r\n' % (len(a), a)).encode()
    s.sendall(payload)
    s.settimeout(2.0)
    while True:
        try:
            b = s.recv(65536)
        except socket.timeout:
            break
        if not b:
            break
        out += b
        if len(out) > 0 and b.endswith(b'\r\n'):
            break
    s.close()
except Exception as e:
    print('ERROR:' + type(e).__name__)
sys.stdout.write(out.decode('latin1').replace('\r\n', ' | '))
PY
resp() { python3 "$RESP_PY" "${2:-$P}" "$1" 2>/dev/null; }

want() {   # want LABEL EXPECTED_SUBSTRING JSON [PORT]
    local label=$1 expect=$2 cmds=$3 port=${4:-$P} got
    got=$(resp "$cmds" "$port")
    case "$got" in
        *"$expect"*) ok "$label" ;;
        *) bad "$label" "reply did not contain '$expect'" "got: $got" ;;
    esac
}

echo "--- 1. EXISTS counts every key it is given ---"
want "exists over three keys" ":2 |" \
  '[["MSET","ex1","a","ex2","b"],["EXISTS","ex1","ex2","nosuch"]]'
# Redis counts a repeated key once per mention, which is what makes the count a
# count and not a set size.
want "exists counts repeats" ":3 |" '[["EXISTS","ex1","ex1","ex1"]]'
want "touch counts like exists" ":2 |" '[["TOUCH","ex1","ex2","nosuch"]]'

echo "--- 2. HELLO negotiates instead of failing ---"
want "hello 3 is refused with NOPROTO" "-NOPROTO" '[["HELLO","3"]]'
want "hello 2 answers a map"           "socketley" '[["HELLO","2"]]'
want "hello with no argument answers"  "proto"     '[["HELLO"]]'

echo "--- 3. the handshake set a client library sends ---"
want "echo"            'hallo'  '[["ECHO","hallo"]]'
want "select 0"        '+OK'    '[["SELECT","0"]]'
want "select 1 refused" '-ERR'  '[["SELECT","1"]]'
want "client setname"  '+OK'    '[["CLIENT","SETNAME","x"]]'
want "client id"       ':'      '[["CLIENT","ID"]]'
want "config get maxmemory" 'maxmemory' '[["CONFIG","GET","maxmemory"]]'
want "info reports a role"  'role:master' '[["INFO"]]'

echo "--- 4. strings: the range and float spellings ---"
want "getrange"     'Hello' '[["SET","gs","Hello World"],["GETRANGE","gs","0","4"]]'
want "getrange negative" 'World' '[["GETRANGE","gs","-5","-1"]]'
want "setrange"     ':11'   '[["SETRANGE","gs","6","Redis"]]'
want "setrange took" 'Hello Redis' '[["GET","gs"]]'
want "incrbyfloat"  '10.5'  '[["SET","fn","10"],["INCRBYFLOAT","fn","0.5"]]'
want "getdel gives the value" 'x' '[["SET","gd","x"],["GETDEL","gd"]]'
want "getdel took it"  ':0' '[["EXISTS","gd"]]'

echo "--- 5. lists: the positional spellings ---"
want "linsert"  ':4' '[["DEL","ll"],["RPUSH","ll","a","b","c"],["LINSERT","ll","BEFORE","b","Z"]]'
want "lset"     '+OK' '[["LSET","ll","0","head"]]'
want "lrem"     ':1'  '[["LREM","ll","1","Z"]]'
want "ltrim"    '+OK' '[["LTRIM","ll","0","1"]]'
want "list is what those left" 'head' '[["LRANGE","ll","0","-1"]]'

echo "--- 6. hashes: the field spellings ---"
want "hincrby"  ':8'  '[["DEL","hh"],["HSET","hh","f","5"],["HINCRBY","hh","f","3"]]'
want "hexists"  ':1'  '[["HEXISTS","hh","f"]]'
want "hexists absent" ':0' '[["HEXISTS","hh","nope"]]'
want "hsetnx does not overwrite" ':0' '[["HSETNX","hh","f","zzz"]]'
want "hsetnx sets what is absent" ':1' '[["HSETNX","hh","g","new"]]'
want "hmget"    '8'   '[["HMGET","hh","f","nope"]]'
want "hstrlen"  ':1'  '[["HSTRLEN","hh","f"]]'

echo "--- 7. sorted sets by score, which is what a sorted set is for ---"
Z='["DEL","zz"],["ZADD","zz","1","a","2","b","3","c"]'
want "zcount inclusive"  ':3' "[$Z,[\"ZCOUNT\",\"zz\",\"1\",\"3\"]]"
want "zcount exclusive"  ':2' "[$Z,[\"ZCOUNT\",\"zz\",\"(1\",\"3\"]]"
want "zcount infinities" ':3' "[$Z,[\"ZCOUNT\",\"zz\",\"-inf\",\"+inf\"]]"
want "zrangebyscore"     'b'  "[$Z,[\"ZRANGEBYSCORE\",\"zz\",\"(1\",\"+inf\"]]"
want "zrangebyscore withscores" '2' "[$Z,[\"ZRANGEBYSCORE\",\"zz\",\"2\",\"2\",\"WITHSCORES\"]]"
want "zrevrangebyscore reverses" 'c' "[$Z,[\"ZREVRANGEBYSCORE\",\"zz\",\"+inf\",\"-inf\"]]"
want "zpopmin takes the lowest" 'a' "[$Z,[\"ZPOPMIN\",\"zz\"]]"
want "zremrangebyscore" ':2' "[$Z,[\"ZREMRANGEBYSCORE\",\"zz\",\"2\",\"3\"]]"
want "zremrangebyrank"  ':1' "[$Z,[\"ZREMRANGEBYRANK\",\"zz\",\"0\",\"0\"]]"

echo "--- 8. sets: the sampling spellings ---"
want "spop returns the member" 'm1' '[["DEL","ss"],["SADD","ss","m1"],["SPOP","ss"]]'
want "spop emptied the key"    ':0' '[["EXISTS","ss"]]'
want "smismember"              ':1' '[["SADD","ss2","m"],["SMISMEMBER","ss2","m","nope"]]'

echo "--- 9. the same commands over the text protocol, which replication uses ---"
TXT_PY="$SOCKETLEY_TMPD/rctxt.py"
cat > "$TXT_PY" <<'PY'
import socket, sys
port = int(sys.argv[1])
out = b''
try:
    s = socket.create_connection(('127.0.0.1', port), timeout=5)
    s.sendall(sys.argv[2].encode())
    s.settimeout(1.5)
    while True:
        try: b = s.recv(65536)
        except socket.timeout: break
        if not b: break
        out += b
    s.close()
except Exception as e:
    print('ERROR:' + type(e).__name__)
sys.stdout.write(out.decode('latin1').replace('\n', ' | '))
PY
txt() { python3 "$TXT_PY" "${2:-$P}" "$1" 2>/dev/null; }
twant() {  # twant LABEL EXPECTED LINES
    local label=$1 expect=$2 lines=$3 got
    got=$(txt "$lines")
    case "$got" in
        *"$expect"*) ok "$label" ;;
        *) bad "$label" "reply did not contain '$expect'" "got: $got" ;;
    esac
}
twant "text getrange"    'Hello' 'set ts HelloWorld
getrange ts 0 4
'
twant "text hincrby"     '8'     'hset th f 5
hincrby th f 3
'
twant "text zrangebyscore" 'b'   'zadd tz 1 a
zadd tz 2 b
zrangebyscore tz (1 +inf
'
twant "text ltrim"       'ok'    'rpush tl a
rpush tl b
ltrim tl 0 0
'
twant "text spop"        'm'     'sadd tst m
spop tst
'

echo "--- 10. a follower gets every container, sorted sets included ---"
"$BIN" create cache rc_l -p "$PL" -s >/dev/null 2>&1
sleep 1.2
resp '[["SET","rs","v"],["RPUSH","rl","a"],["SADD","rst","m"],["HSET","rh","f","v"],["ZADD","rz","1","a","2.5","b","-3","c"]]' "$PL" >/dev/null
"$BIN" create cache rc_f -p "$PF" --replicate "127.0.0.1:$PL" -s >/dev/null 2>&1
for _ in $(seq 1 60); do
    [ "$(resp '[["DBSIZE"]]' "$PF")" = "$(resp '[["DBSIZE"]]' "$PL")" ] && break
    sleep 0.2
done
L=$(resp '[["DBSIZE"]]' "$PL"); F=$(resp '[["DBSIZE"]]' "$PF")
if [ "$L" = "$F" ]; then ok "follower holds as many keys as the leader ($L)"
else bad "dump" "follower short of the leader" "leader=$L follower=$F"; fi
want "the sorted set survived the dump, scores and all" '2.5' \
  '[["ZRANGE","rz","0","-1","WITHSCORES"]]' "$PF"
want "a negative score survived too" '-3' '[["ZSCORE","rz","c"]]' "$PF"

echo "--- 11. a mutation only the new path knows reaches the follower ---"
resp '[["SETRANGE","rs","0","XX"],["HINCRBY","rh","n","7"],["LSET","rl","0","Q"]]' "$PL" >/dev/null
for _ in $(seq 1 40); do
    [ "$(resp '[["HGET","rh","n"]]' "$PF")" != "" ] && break
    sleep 0.2
done
# Against the leader rather than against a literal: the assertion is that the
# two agree, and a literal here only tests whether I did the arithmetic right.
same() {   # same LABEL JSON
    local label=$1 cmds=$2 a b
    a=$(resp "$cmds" "$PL"); b=$(resp "$cmds" "$PF")
    if [ "$a" = "$b" ]; then ok "$label ($a)"
    else bad "$label" "leader and follower disagree" "leader=$a" "follower=$b"; fi
}
same "setrange reached the follower" '[["GET","rs"]]'
same "hincrby reached the follower"  '[["HGET","rh","n"]]'
same "lset reached the follower"     '[["LRANGE","rl","0","-1"]]' 

echo ""
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && { echo "  OK"; exit 0; } || exit 1
