#!/usr/bin/env bash
# Integration test: answers a Redis client library depends on, where the cache
# gave a different one.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
#   UNSUBSCRIBE   with no argument means "all of them" and is how Jedis ends a
#                 subscribe loop and how ioredis leaves subscriber mode; it was
#                 refused with a wrong-number-of-arguments error
#   the count     every SUBSCRIBE reply carried one more than the last, even
#                 for a channel already held, so a client counting down to
#                 zero never got there
#   HSET          answered the number of fields written, not the number added
#   HMSET         ignored a refusal and answered +OK over a key of another type
#   READONLY      and READWRITE and ASKING, sent by cluster clients on every
#                 connection they open, were unknown commands
#   OOM           went out as -ERR OOM, so a client mapping the first word to
#                 an exception saw a generic error
#   EVAL          loaded precompiled chunks, and LuaJIT runs bytecode unverified
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# Each refusal has the ordinary case beside it: a named UNSUBSCRIBE, an HSET of
# a new field, an HMSET on a hash, a text EVAL -- so a build that refused or
# zeroed everything fails as loudly as the one this replaces.  The bytecode is
# real, dumped by a socketley Lua runtime, so the refusal is about its kind and
# not about it being malformed.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate cachecompat

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1))
        if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
        else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi; }
cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: cache answers a client library depends on ==="
command -v redis-cli >/dev/null 2>&1 || { echo "  FAIL: redis-cli required"; exit 1; }
daemon_start "$BIN"
P=$((SL_PORT_BASE + 1760))
"$BIN" create cache cc -p "$P" --maxmemory 2M -s >/dev/null 2>&1
for _ in $(seq 1 100); do redis-cli -p "$P" ping 2>/dev/null | grep -q PONG && break; sleep 0.1; done

# Raw RESP in, the reply bytes out with CR removed and lines joined by '|'.
resp() {
    python3 - "$P" "$@" <<'PYEOF'
import socket, sys, time
port, cmds = int(sys.argv[1]), sys.argv[2:]
s = socket.create_connection(("127.0.0.1", port)); s.settimeout(2)
out = b""
for c in cmds:
    parts = c.split(" ") if c else []
    s.sendall(b"*%d\r\n" % len(parts) + b"".join(b"$%d\r\n%s\r\n" % (len(p), p.encode()) for p in parts))
    time.sleep(0.1)
try:
    while True:
        b = s.recv(65536)
        if not b: break
        out += b
except socket.timeout:
    pass
print(out.decode("latin1").replace("\r\n", "|"))
PYEOF
}

# ── pub/sub counts ──────────────────────────────────────────────────────────
R=$(resp "SUBSCRIBE a" "SUBSCRIBE a" "SUBSCRIBE b")
ok "$R" '*3|$9|subscribe|$1|a|:1|*3|$9|subscribe|$1|a|:1|*3|$9|subscribe|$1|b|:2|' \
   "a repeated SUBSCRIBE does not raise the count"

R=$(resp "SUBSCRIBE a" "SUBSCRIBE b" "UNSUBSCRIBE")
case "$R" in
    *'unsubscribe|$1|a|:1|'*'unsubscribe|$1|b|:0|'*|*'unsubscribe|$1|b|:1|'*'unsubscribe|$1|a|:0|'*)
        ok yes yes "a bare UNSUBSCRIBE leaves every channel and counts down to 0" ;;
    *) ok "$R" "two unsubscribe replies ending at :0" "bare UNSUBSCRIBE" ;;
esac

R=$(resp "UNSUBSCRIBE")
ok "$R" '*3|$11|unsubscribe|$-1|:0|' "a bare UNSUBSCRIBE holding nothing is still answered"

R=$(resp "SUBSCRIBE a" "UNSUBSCRIBE zz" "UNSUBSCRIBE a")
ok "$R" '*3|$9|subscribe|$1|a|:1|*3|$11|unsubscribe|$2|zz|:1|*3|$11|unsubscribe|$1|a|:0|' \
   "leaving a channel never joined does not lower the count"

R=$(resp "PSUBSCRIBE p*" "PUNSUBSCRIBE")
ok "$R" '*3|$10|psubscribe|$2|p*|:1|*3|$12|punsubscribe|$2|p*|:0|' \
   "a bare PUNSUBSCRIBE leaves every pattern"

# ── hashes ──────────────────────────────────────────────────────────────────
ok "$(resp "HSET h f v")" ':1|' "HSET of a new field counts it"
ok "$(resp "HSET h f w")" ':0|' "HSET of an existing field counts nothing"
ok "$(resp "HSET h f x g y")" ':1|' "HSET of one old and one new field counts one"
ok "$(resp "HMSET h2 f v")" '+OK|' "HMSET on a new hash answers OK"
resp "SET str v" >/dev/null
case "$(resp "HMSET str f v")" in
    -WRONGTYPE*) ok yes yes "HMSET over a string is refused WRONGTYPE" ;;
    *) ok "$(resp "HMSET str f v")" "-WRONGTYPE ..." "HMSET over a string" ;;
esac
ok "$(redis-cli -p "$P" get str 2>/dev/null)" "v" "and the string is untouched"

# ── cluster handshake ───────────────────────────────────────────────────────
ok "$(resp "READONLY")"  '+OK|' "READONLY is answered"
ok "$(resp "READWRITE")" '+OK|' "READWRITE is answered"
ok "$(resp "ASKING")"    '+OK|' "ASKING is answered"

# ── error codes ─────────────────────────────────────────────────────────────
BIGV=$(head -c 400000 /dev/zero | tr '\0' v)
R=""
for i in 1 2 3 4 5 6 7 8; do
    R=$(printf '%s' "$BIGV" | redis-cli -p "$P" -x set "big$i" 2>&1)
    case "$R" in *OOM*) break ;; esac
done
case "$R" in
    OOM*) ok yes yes "a write past maxmemory is refused with the OOM code" ;;
    *) ok "$R" "OOM command not allowed ..." "the OOM code" ;;
esac
redis-cli -p "$P" flushall >/dev/null 2>&1

# ── EVAL and bytecode ───────────────────────────────────────────────────────
ok "$(redis-cli -p "$P" eval 'return 7' 0 2>&1)" "7" "a text script still runs"

cat > "$SOCKETLEY_TMPD/dump.lua" <<EOF
local f = io.open("$SOCKETLEY_TMPD/chunk.bin", "wb")
f:write(string.dump(function() return 42 end))
f:close()
EOF
"$BIN" create server dumper -p $((P + 1)) --lua "$SOCKETLEY_TMPD/dump.lua" -s >/dev/null 2>&1
for _ in $(seq 1 50); do [ -s "$SOCKETLEY_TMPD/chunk.bin" ] && break; sleep 0.1; done
if [ -s "$SOCKETLEY_TMPD/chunk.bin" ]; then
    R=$(python3 - "$P" "$SOCKETLEY_TMPD/chunk.bin" <<'PYEOF'
import socket, sys
port, path = int(sys.argv[1]), sys.argv[2]
body = open(path, "rb").read()
s = socket.create_connection(("127.0.0.1", port)); s.settimeout(3)
parts = [b"EVAL", body, b"0"]
s.sendall(b"*3\r\n" + b"".join(b"$%d\r\n%s\r\n" % (len(p), p) for p in parts))
print(s.recv(4096).decode("latin1").split("\r\n")[0])
PYEOF
)
    case "$R" in
        -*) ok yes yes "a precompiled chunk is refused ($R)" ;;
        *)  ok "$R" "an error" "EVAL of LuaJIT bytecode" ;;
    esac
else
    ok "no chunk" "a dumped chunk" "the premise: a Lua runtime dumped a function"
fi

# ── a sharded cache: FLUSHALL and transactions ──────────────────────────────
SP=$((P + 5))
"$BIN" create cache ccs -p "$SP" --shards 2 -s >/dev/null 2>&1
for _ in $(seq 1 100); do redis-cli -p "$SP" ping 2>/dev/null | grep -q PONG && break; sleep 0.1; done
for i in $(seq 1 20); do redis-cli -p "$SP" set "k$i" v >/dev/null 2>&1; done
ok "$(redis-cli -p "$SP" dbsize 2>/dev/null)" "20" "the premise: twenty keys across two shards"
ok "$(redis-cli -p "$SP" flushall 2>/dev/null)" "OK" "FLUSHALL on a sharded cache answers OK"
ok "$(redis-cli -p "$SP" dbsize 2>/dev/null)" "0" "and empties every shard, not the one it landed on"

TX=$(python3 - "$SP" <<'PYEOF'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1]))); s.settimeout(2)
def cmd(*a):
    return b"*%d\r\n" % len(a) + b"".join(b"$%d\r\n%s\r\n" % (len(x), x) for x in a)
s.sendall(cmd(b"MULTI") + b"".join(cmd(b"SET", b"k%d" % i, b"v") for i in range(1, 21)) + cmd(b"EXEC"))
time.sleep(0.5)
out = b""
try:
    while True:
        b = s.recv(65536)
        if not b: break
        out += b
except socket.timeout:
    pass
lines = out.split(b"\r\n")
print(lines[-2].decode("latin1") if len(lines) >= 2 else "nothing")
PYEOF
)
case "$TX" in
    -EXECABORT*) ok yes yes "a transaction naming another shard's keys is aborted whole" ;;
    *) ok "$TX" "-EXECABORT ..." "a cross-shard transaction" ;;
esac
ok "$(redis-cli -p "$SP" dbsize 2>/dev/null)" "0" "and none of its writes ran outside it"
ok "$(printf 'MULTI\nPING\nEXEC\n' | redis-cli -p "$SP" 2>/dev/null | tr '\n' ' ')" "OK QUEUED PONG " \
   "a transaction naming no key still runs on a sharded cache"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
