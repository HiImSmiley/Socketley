#!/usr/bin/env bash
# Integration test: a read of a key held as another type.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# GET on a list answered nil.  So did STRLEN with 0, LLEN with 0, HGETALL with
# an empty array, ZCARD with 0 -- twenty of twenty-four reads gave "not there"
# for a key that was very much there as something else.
#
# That is worse than an error, because a caller believes it: a cache client
# reads GET session:7, is told nil, and goes to the database for something it
# already has under another type.  Redis answers WRONGTYPE, and a client
# switching on the error code can tell the two apart.
#
# The fix costs nothing on a hit -- the probe is in the MISS branch, which is
# the only place the two answers are confusable -- and the second half of this
# file is about that: every genuine hit and every genuine miss has to keep
# answering exactly what it answered before.  A change that makes the wrong
# case right and the right case wrong is not an improvement.
#
# MGET is deliberately not here: Redis answers nil per key for a wrong-typed
# one, and matching that is matching Redis.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: reading a key that is there as something else ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local l; for l in "${@:3}"; do echo "        $l"; done; }

P=$((SL_PORT_BASE+1451))
daemon_isolate cachewt
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"
"$BIN" create cache wt_c -p "$P" -s >/dev/null 2>&1
sleep 1.5

RESP_PY="$SOCKETLEY_TMPD/w.py"
cat > "$RESP_PY" <<'PY'
import socket, sys, json
port = int(sys.argv[1]); cmds = json.loads(sys.argv[2])
out = b''
try:
    s = socket.create_connection(('127.0.0.1', port), timeout=5)
    p = b''
    for c in cmds:
        p += ('*%d\r\n' % len(c)).encode()
        for a in c: p += ('$%d\r\n%s\r\n' % (len(a), a)).encode()
    s.sendall(p); s.settimeout(2.0)
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
resp() { python3 "$RESP_PY" "$P" "$1" 2>/dev/null; }
wantx() { local l=$1 e=$2 c=$3 got; got=$(resp "$c")
          [ "$got" = "$e" ] && ok "$l" || bad "$l" "wanted '$e'" "got: $got"; }
want() { local l=$1 e=$2 c=$3 got; got=$(resp "$c")
         case "$got" in *"$e"*) ok "$l" ;; *) bad "$l" "wanted '$e'" "got: $got" ;; esac; }

resp '[["DEL","s","l","t","h","z"],["SET","s","v"],["RPUSH","l","e"],["SADD","t","m"],["HSET","h","f","v"],["ZADD","z","1","m"]]' >/dev/null

echo "--- 1. every read of a wrong-typed key says so ---"
# One per (command family, holder type), because the probe skips its OWN
# container and a mistake there shows as one family answering nil for one
# other type -- which a spot check of a single pair cannot see.
for holder in l t h z; do
    want "GET on $holder"      "WRONGTYPE" "[[\"GET\",\"$holder\"]]"
    want "STRLEN on $holder"   "WRONGTYPE" "[[\"STRLEN\",\"$holder\"]]"
    want "GETRANGE on $holder" "WRONGTYPE" "[[\"GETRANGE\",\"$holder\",\"0\",\"2\"]]"
done
for holder in s t h z; do
    want "LLEN on $holder"   "WRONGTYPE" "[[\"LLEN\",\"$holder\"]]"
    want "LRANGE on $holder" "WRONGTYPE" "[[\"LRANGE\",\"$holder\",\"0\",\"-1\"]]"
    want "LINDEX on $holder" "WRONGTYPE" "[[\"LINDEX\",\"$holder\",\"0\"]]"
done
for holder in s l h z; do
    want "SCARD on $holder"     "WRONGTYPE" "[[\"SCARD\",\"$holder\"]]"
    want "SMEMBERS on $holder"  "WRONGTYPE" "[[\"SMEMBERS\",\"$holder\"]]"
    want "SISMEMBER on $holder" "WRONGTYPE" "[[\"SISMEMBER\",\"$holder\",\"m\"]]"
done
for holder in s l t z; do
    want "HLEN on $holder"    "WRONGTYPE" "[[\"HLEN\",\"$holder\"]]"
    want "HGETALL on $holder" "WRONGTYPE" "[[\"HGETALL\",\"$holder\"]]"
    want "HGET on $holder"    "WRONGTYPE" "[[\"HGET\",\"$holder\",\"f\"]]"
done
for holder in s l t h; do
    want "ZCARD on $holder"  "WRONGTYPE" "[[\"ZCARD\",\"$holder\"]]"
    want "ZSCORE on $holder" "WRONGTYPE" "[[\"ZSCORE\",\"$holder\",\"m\"]]"
done

echo "--- 2. and nothing else changed ---"
# The half that matters as much: a hit is still a hit and a miss is still nil.
wantx "GET on its own string"  '$1 | v | ' '[["GET","s"]]'
want "STRLEN on its own"       ":1"   '[["STRLEN","s"]]'
want "LLEN on its own list"    ":1"   '[["LLEN","l"]]'
want "LRANGE on its own"       "e"    '[["LRANGE","l","0","-1"]]'
want "SCARD on its own set"    ":1"   '[["SCARD","t"]]'
want "SMEMBERS on its own"     "m"    '[["SMEMBERS","t"]]'
want "HLEN on its own hash"    ":1"   '[["HLEN","h"]]'
want "HGET on its own"         "v"    '[["HGET","h","f"]]'
want "ZCARD on its own zset"   ":1"   '[["ZCARD","z"]]'
wantx "ZSCORE on its own"      '$1 | 1 | ' '[["ZSCORE","z","m"]]'
want "GET on nothing is nil"   '$-1'  '[["GET","weder"]]'
want "LLEN on nothing is 0"    ":0"   '[["LLEN","weder"]]'
want "HLEN on nothing is 0"    ":0"   '[["HLEN","weder"]]'
want "ZCARD on nothing is 0"   ":0"   '[["ZCARD","weder"]]'
want "SCARD on nothing is 0"   ":0"   '[["SCARD","weder"]]'
want "HGETALL on nothing is empty" "*0" '[["HGETALL","weder"]]'
# An empty hash that exists is not the same as no hash, and neither is an error.
want "SMEMBERS on nothing is empty" "*0" '[["SMEMBERS","weder"]]'

echo "--- 3. MGET keeps Redis's exception ---"
want "MGET answers nil per wrong-typed key" '$-1' '[["MGET","l"]]'

echo ""
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && { echo "  OK"; exit 0; } || exit 1
