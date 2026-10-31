#!/usr/bin/env bash
# Integration test: three places the cache answered differently from Redis.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# All three are answers a client believes, which is what makes them worse than
# an error.
#
#   MORE THAN 64 ARGUMENTS was "-ERR protocol error".  The parser promises
#   RESP_MAX_ARRAY_SIZE = 1024 and the caller handed it an array of 64, so
#   `MSET` with 32 pairs, `DEL` or `MGET` with 65 keys and `ZADD` with 32 pairs
#   -- all ordinary Redis -- were refused.  And the refusal did the damage:
#   partial.clear() threw away whatever the client had already pipelined behind
#   the bad command, so it got fewer replies than commands and waited for ever
#   on a connection that stayed open.  Redis closes on a protocol error for
#   exactly this reason, and now so does this.
#
#   AN EXPIRED SORTED SET OUTLIVED ITS EXPIRY.  Two of the three expiry paths
#   walked m_data, m_lists, m_sets and m_hashes and stopped -- del() knew about
#   m_zsets and they did not.  So a read reaching the key between its deadline
#   and the 500 ms sweep erased the DEADLINE and kept the DATA, and the key was
#   then persistent for ever.  The sweep is turned down to a minute here so the
#   window is the whole test rather than a race the test would usually lose.
#
#   TTL TRUNCATED.  duration_cast goes towards zero, so `SET k v EX 1` answered
#   0 immediately and `EX 10` read as 9 after one millisecond.  A client that
#   treats TTL == 0 as "expiring now" acted a second early, every time.
#
# Not covered here, and said rather than skipped: the read-submit fallback.
# Its branches are only reachable when two io_uring submissions fail in one
# turn, and nothing on this box can make that happen on demand -- there is no
# ring-size knob.  It is a dead-branch removal proven by reading, not by this
# file.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: where the cache disagreed with Redis ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

P=$((SL_PORT_BASE+1402))

daemon_isolate cachedisagree
trap 'daemon_stop 2>/dev/null || true' EXIT
# A sweep of a minute, so the expiry assertions are about the lazy path and not
# about which of two timers ran first.
SOCKETLEY_CACHE_TTL_SWEEP_MS=60000 daemon_start "$BIN"

"$BIN" create cache cd_c -p "$P" -s >/dev/null 2>&1
sleep 1.5

# One connection, a list of commands, the replies as lines.  Written out rather
# than shelling to redis-cli, which is not on every box this runs on.
RESP_PY="$SOCKETLEY_TMPD/resp.py"
cat > "$RESP_PY" <<'PY'
import socket, sys, json
port = int(sys.argv[1])
cmds = json.loads(sys.argv[2])
hold = len(sys.argv) > 3 and sys.argv[3] == 'hold'
out = b''
try:
    s = socket.create_connection(('127.0.0.1', port), timeout=5)
    payload = b''
    for c in cmds:
        if isinstance(c, str):          # a raw frame, sent as written
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
            print('TIMEOUT'); break
        if not b:
            print('CLOSED'); break
        out += b
        if not hold:
            break
    s.close()
except Exception as e:
    print('ERROR:' + type(e).__name__)
sys.stdout.write(out.decode('latin1').replace('\r\n', ' | '))
PY
resp() { python3 "$RESP_PY" "$P" "$1" "${2:-}" 2>/dev/null; }

# ── 1. Sixty-five keys is an ordinary DEL ──────────────────────────────────
KEYS=$(python3 -c "import json;print(json.dumps([['DEL']+['k%d'%i for i in range(65)]]))")
OUT1=$(resp "$KEYS")
case "$OUT1" in
    *"protocol error"*) bad "a DEL with 65 keys is answered, not refused" \
                            "said: $OUT1;" \
                            "the parser's own limit is 1024 and the caller passed 64" ;;
    :*)                 ok "DEL with 65 keys answered '$(printf '%s' "$OUT1" | head -c 20)'" ;;
    *)                  bad "a DEL with 65 keys is answered, not refused" "said: ${OUT1:-<nothing>}" ;;
esac

MSET=$(python3 -c "
import json
c=['MSET']
for i in range(32): c += ['m%d'%i, 'v%d'%i]
print(json.dumps([c]))")
OUT2=$(resp "$MSET")
case "$OUT2" in
    *OK*) ok "MSET with 32 pairs is accepted" ;;
    *)    bad "MSET with 32 pairs is accepted" "said: ${OUT2:-<nothing>}" ;;
esac

# ── 2. A real protocol error closes, so a pipeline cannot be stranded ──────
#
# The malformed frame claims three arguments and supplies a non-bulk second
# one; two ordinary commands are pipelined behind it.  Before, the reply was
# one error, the rest of the buffer was dropped and the connection stayed open
# -- a client waiting for three replies waited for ever.
STRANDED=$(python3 -c "import json;print(json.dumps(['*2\r\n\$3\r\nGET\r\nNOTBULK\r\n', ['PING'], ['PING']]))")
OUT3=$(resp "$STRANDED" hold)
case "$OUT3" in
    *CLOSED*"-ERR"*) ok "a protocol error is answered and the connection closes" ;;
    *CLOSED*) bad "a protocol error is answered before the connection closes" \
                   "the connection closed with no error reply: $OUT3" ;;
    *TIMEOUT*) bad "a protocol error closes the connection" \
                   "the connection stayed open: $OUT3;" \
                   "Redis closes here because the stream is no longer framed, and a client" \
                   "that pipelined behind the bad command is otherwise waiting for replies" \
                   "that were silently discarded" ;;
    *) bad "a protocol error closes the connection" "said: ${OUT3:-<nothing>}" ;;
esac

# ── 3. An expired sorted set is gone, deadline and data together ───────────
resp "$(python3 -c "import json;print(json.dumps([['ZADD','zz','1','a']]))")" >/dev/null
resp "$(python3 -c "import json;print(json.dumps([['PEXPIRE','zz','100']]))")" >/dev/null
sleep 0.4
ZC=$(resp "$(python3 -c "import json;print(json.dumps([['ZCARD','zz']]))")")
ZT=$(resp "$(python3 -c "import json;print(json.dumps([['TTL','zz']]))")")
if [ "$(printf '%s' "$ZC" | tr -d ' |')" = ":0" ] && [ "$(printf '%s' "$ZT" | tr -d ' |')" = ":-2" ]; then
    ok "an expired sorted set is gone: ZCARD $ZC, TTL $ZT"
else
    bad "an expired sorted set takes its data with it" \
        "ZCARD said '$ZC' (want :0) and TTL said '$ZT' (want :-2);" \
        "ZCARD 1 with TTL -1 is the shape of it: the deadline erased, the members" \
        "kept, and the key persistent from then on -- two of three expiry paths" \
        "walked every container except m_zsets"
fi

# The control: a plain string with the same treatment still expires, so a build
# that broke expiry altogether would not pass the assertion above.
resp "$(python3 -c "import json;print(json.dumps([['SET','ss','v']]))")" >/dev/null
resp "$(python3 -c "import json;print(json.dumps([['PEXPIRE','ss','100']]))")" >/dev/null
sleep 0.4
SG=$(resp "$(python3 -c "import json;print(json.dumps([['GET','ss']]))")")
case "$SG" in
    *'$-1'*) ok "and a plain key with the same treatment still expires" ;;
    *)       bad "expiry itself still works" "GET said '$SG', want a nil bulk" ;;
esac

# ── 4. TTL rounds the way Redis rounds ─────────────────────────────────────
# Set and read in one pipeline, so no half second of a busy box passes between them.
T10=$(resp "$(python3 -c "import json;print(json.dumps([['SETEX','t10','10','v'],['TTL','t10']]))")" hold | grep -o ':[0-9-]*' | tail -1)
T1=$(resp "$(python3 -c "import json;print(json.dumps([['SET','t1','v','EX','1'],['TTL','t1']]))")" hold | grep -o ':[0-9-]*' | tail -1)
if [ "$T10" = ":10" ] && [ "$T1" = ":1" ]; then
    ok "TTL rounds: EX 10 reads 10 and EX 1 reads 1"
else
    bad "TTL rounds rather than truncating" \
        "EX 10 read '$T10' (want :10) and EX 1 read '$T1' (want :1);" \
        "9 and 0 are duration_cast truncating towards zero after a millisecond has passed," \
        "and a client treating TTL == 0 as 'expiring now' then acts a second early"
fi

# ── 5. A blank line between commands is nothing, as Redis reads it ─────────
# redis-cli --pipe ends its stream with "\r\n*2\r\n$4\r\nECHO\r\n$20\r\n<mark>\r\n" and waits for the mark; a
# blank line answered as a protocol error closed the connection, so every --pipe import ended in "ERR protocol error".
BL=$(resp "$(python3 -c "import json;print(json.dumps(['*1\r\n\$4\r\nPING\r\n\r\n  \r\n*2\r\n\$4\r\nECHO\r\n\$4\r\nmark\r\n']))")" hold)
case "$BL" in
    *'+PONG | $4 | mark'*) ok "blank lines between commands are skipped, as redis-cli --pipe needs" ;;
    *) bad "a blank line between commands is skipped" "said: ${BL:-<nothing>}" ;;
esac

"$BIN" stop cd_c >/dev/null 2>&1; "$BIN" remove cd_c >/dev/null 2>&1
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
