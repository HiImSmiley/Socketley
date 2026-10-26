#!/usr/bin/env bash
# Integration test: the commands a job queue and a big collection need.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
#   THE ELEMENT IN NEITHER LIST.  RPOPLPUSH and LMOVE are the reliable-queue
#   move: a job leaves the pending list and arrives in the processing one, and
#   a worker that dies between the two is the reason the pattern exists.  Every
#   refusal therefore has to happen BEFORE the pop -- a wrong-typed destination,
#   a memory limit, a destination on another shard.  The store charges memory
#   and checks the destination's type first for exactly that reason, and the
#   assertions below check the source is intact after each refusal rather than
#   only that an error came back.
#
#   THE SCAN THAT MISSES ELEMENTS.  HSCAN/SSCAN/ZSCAN walk buckets, and a
#   rehash between two calls moves elements between them.  The bucket count
#   rides in the cursor so a resume can tell it is not the table it left; a
#   full round over 300 fields is walked here and every field counted, because
#   a scan that returns 280 of 300 looks like a working scan.
#
#   AND THE OPTIONS THAT CHANGE WHAT SET MEANS.  KEEPTTL is what a session
#   refresh needs -- the value changes and the hour it has left does not -- and
#   it is the difference between a session that survives and one that logs the
#   user out on every write.  GET answers the replaced value, including when NX
#   refused the write, which is the case that reads wrong on a first reading.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: the queue move, the collection scan, and SET's options ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line; for line in "${@:3}"; do echo "        $line"; done
}

P=$((SL_PORT_BASE+1471))
PS=$((SL_PORT_BASE+1475))

daemon_isolate cachequeue
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

"$BIN" create cache qs_c -p "$P" -s >/dev/null 2>&1
sleep 1.5

RESP_PY="$SOCKETLEY_TMPD/q.py"
cat > "$RESP_PY" <<'PY'
import socket, sys, json
port = int(sys.argv[1]); cmds = json.loads(sys.argv[2])
out = b''
try:
    s = socket.create_connection(('127.0.0.1', port), timeout=5)
    payload = b''
    for c in cmds:
        payload += ('*%d\r\n' % len(c)).encode()
        for a in c: payload += ('$%d\r\n%s\r\n' % (len(a), a)).encode()
    s.sendall(payload); s.settimeout(2.0)
    while True:
        try: b = s.recv(65536)
        except socket.timeout: break
        if not b: break
        out += b
        if out.endswith(b'\r\n'): break
    s.close()
except Exception as e: print('ERROR:' + type(e).__name__)
sys.stdout.write(out.decode('latin1').replace('\r\n', ' | '))
PY
resp() { python3 "$RESP_PY" "${2:-$P}" "$1" 2>/dev/null; }
want() {  # want LABEL EXPECTED JSON [PORT]
    local label=$1 expect=$2 cmds=$3 port=${4:-$P} got
    got=$(resp "$cmds" "$port")
    case "$got" in *"$expect"*) ok "$label" ;;
                   *) bad "$label" "reply did not contain '$expect'" "got: $got" ;; esac
}
want_is() {  # want_is LABEL EXPECTED-WHOLE-REPLY JSON [PORT]
    local label=$1 expect=$2 cmds=$3 port=${4:-$P} got
    got=$(resp "$cmds" "$port")
    [ "$got" = "$expect" ] && ok "$label" || bad "$label" "reply was not '$expect'" "got: $got"
}

echo "--- 1. the reliable-queue move ---"
want "rpoplpush takes from the tail" "c" \
  '[["DEL","q","proc"],["RPUSH","q","a","b","c"],["RPOPLPUSH","q","proc"]]'
want_is "and the source lost exactly it" '*2 | $1 | a | $1 | b | ' '[["LRANGE","q","0","-1"]]'
want "lmove LEFT RIGHT takes from the head" "a" '[["LMOVE","q","proc","LEFT","RIGHT"]]'
want "src == dst rotates rather than emptying" "b" '[["LMOVE","q","q","RIGHT","LEFT"]]'
want "an empty source is nil, not an error" '$-1' \
  '[["DEL","empty"],["RPOPLPUSH","empty","proc"]]'

echo "--- 2. every refusal happens BEFORE the pop ---"
resp '[["DEL","q2","str"],["RPUSH","q2","job"],["SET","str","v"]]' >/dev/null
want "a wrong-typed destination is refused" "WRONGTYPE" '[["RPOPLPUSH","q2","str"]]'
# The point of the test: the job must still be in the queue.
want "and the job is still in the queue" "job" '[["LRANGE","q2","0","-1"]]'
want "the destination is untouched too" "v" '[["GET","str"]]'
want "a wrong-typed source is refused" "WRONGTYPE" '[["RPOPLPUSH","str","q2"]]'
want "bad directions are a syntax error" "syntax" '[["LMOVE","q2","proc","UP","DOWN"]]'
want "and the job survived that too" "job" '[["LRANGE","q2","0","-1"]]'

echo "--- 3. a full scan round returns every element exactly once ---"
BIG=$SOCKETLEY_TMPD/big.json
python3 - "$BIG" <<'PY'
import json, sys
cmds = [["DEL","big"]] + [["HSET","big","f%d" % i,"v%d" % i] for i in range(300)]
json.dump(cmds, open(sys.argv[1],'w'))
PY
resp "$(cat "$BIG")" >/dev/null
n=$(resp '[["HLEN","big"]]')
case "$n" in *300*) ok "300 fields loaded" ;; *) bad "load" "HLEN said $n" ;; esac

SCAN_PY="$SOCKETLEY_TMPD/scan.py"
cat > "$SCAN_PY" <<'PY'
# Walks HSCAN to completion and reports how many DISTINCT fields it saw, how
# many times in total, and how many calls it took.  A scan that repeats is as
# wrong as one that skips, and only the distinct/total pair shows both.
import socket, sys, re
port = int(sys.argv[1])
s = socket.create_connection(('127.0.0.1', port), timeout=5)
def call(cur):
    cmd = ['HSCAN', 'big', str(cur), 'COUNT', '20']
    p = ('*%d\r\n' % len(cmd)).encode()
    for a in cmd: p += ('$%d\r\n%s\r\n' % (len(a), a)).encode()
    s.sendall(p)
    buf = b''
    while True:
        b = s.recv(65536)
        if not b: break
        buf += b
        # cursor line plus a complete array is enough when the last byte is CRLF
        if buf.endswith(b'\r\n') and buf.count(b'\r\n') >= 3: break
    return buf.decode('latin1')
seen, total, calls, cur = set(), 0, 0, 0
while True:
    r = call(cur); calls += 1
    m = re.match(r'\*2\r\n\$\d+\r\n(\d+)\r\n', r)
    if not m: print('PARSE', repr(r[:80])); break
    cur = int(m.group(1))
    for f in re.findall(r'\$\d+\r\n(f\d+)\r\n', r):
        seen.add(f); total += 1
    if cur == 0 or calls > 400: break
s.close()
print(f'{len(seen)} {total} {calls}')
PY
read -r distinct total calls <<<"$(python3 "$SCAN_PY" "$P" 2>/dev/null)"
[ "${distinct:-0}" = "300" ] && ok "the round saw all 300 fields ($calls calls)" \
    || bad "scan" "saw $distinct distinct fields of 300 in $calls calls"
[ "${total:-0}" = "300" ] && ok "and none of them twice" \
    || bad "scan" "300 fields came back $total times"

want "MATCH filters"        "f7 | " '[["HSCAN","big","0","MATCH","f7","COUNT","500"]]'
want "sscan on a small set" "m1"    '[["DEL","s1"],["SADD","s1","m1"],["SSCAN","s1","0"]]'
want "zscan carries scores" '$1 | m | $1 | 2 | ' '[["DEL","z1"],["ZADD","z1","2","m"],["ZSCAN","z1","0"]]'
want_is "a missing key is cursor 0" '*2 | $1 | 0 | *0 | ' '[["HSCAN","nosuchkey","0"]]'

echo "--- 4. SET KEEPTTL and SET GET ---"
want "GET answers the replaced value" "alt" \
  '[["SET","sk","alt"],["SET","sk","neu","GET"]]'
want "and the write took"              "neu"  '[["GET","sk"]]'
want "GET on an absent key is nil"     '$-1'  '[["DEL","weg"],["SET","weg","x","GET"]]'
# The case that reads wrong at first: NX refused the write, and GET still
# answers what is there.
want "GET answers even when NX refuses" "neu" '[["SET","sk","dritt","NX","GET"]]'
want "and NX really did refuse"         "neu" '[["GET","sk"]]'
want "KEEPTTL leaves the deadline"      ":100" \
  '[["SET","tk","v"],["EXPIRE","tk","100"],["SET","tk","v2","KEEPTTL"],["TTL","tk"]]'
want "a plain SET clears it"            ":-1"  '[["SET","tk","v3"],["TTL","tk"]]'
want "KEEPTTL with EX is a contradiction" "syntax" '[["SET","tk","v","KEEPTTL","EX","10"]]'
want "SET GET on a list is WRONGTYPE"   "WRONGTYPE" \
  '[["DEL","lk"],["RPUSH","lk","e"],["SET","lk","v","GET"]]'
want "and the list is intact"           ":1"   '[["LLEN","lk"]]'

echo "--- 5. sharded: the move refuses a destination it does not own ---"
"$BIN" create cache qs_s -p "$PS" --shards 4 --cluster -s >/dev/null 2>&1
for _ in $(seq 1 80); do
    [ "$(ss -ltn 2>/dev/null | awk -v a=$((PS+1)) -v d=$((PS+4)) -F: '{n=$NF+0; if(n>=a&&n<=d) c++} END{print c+0}')" -ge 4 ] && break
    sleep 0.2
done
resp '[["RPUSH","{a}q","job"]]' "$PS" >/dev/null
want "a move across shards is -CROSSSLOT" "CROSSSLOT" \
  '[["RPOPLPUSH","{a}q","{b}p"]]' "$PS"
# And the refusal did not eat the job, which is the whole point.
want "the job is still there afterwards" "job" '[["LRANGE","{a}q","0","-1"]]' "$PS"
want "a move inside one shard works"      "job" \
  '[["RPOPLPUSH","{a}q","{a}p"]]' "$PS"
want "hscan routes to the key's owner"    "f1" \
  '[["HSET","{c}h","f1","v1"],["HSCAN","{c}h","0"]]' "$PS"

echo ""
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && { echo "  OK"; exit 0; } || exit 1
