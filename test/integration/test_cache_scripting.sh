#!/usr/bin/env bash
# Integration test: EVAL, and the two things that make it safe to offer.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
#   THE SANDBOX.  shared/lua/lua_context.h says of itself, in its own comment:
#   "This is not a sandbox and says so: `io`, `package` and `base` are open, so
#   a Lua handler runs with the daemon's full privileges."  That is the right
#   trade for a script the operator wrote and pointed --lua at, and the wrong
#   one for EVAL, where the script is whatever a client sent.  So EVAL has a
#   state of its own, opened by name, and under LuaJIT the one that matters
#   most is `ffi`: require("ffi") is arbitrary memory access, which is a shell
#   on this machine.  Every door is probed here BY NAME, because a sandbox that
#   is tested by "it works for a normal script" is not tested at all.
#
#   THE DEADLINE.  One event loop per shard, so a script that loops holds every
#   other client on that shard for ever.  `while true do end` is run here and
#   the cache is asked to answer afterwards -- the assertion is not that the
#   script fails, it is that the cache is still there.
#
#   AND THE ONE-LINE ERROR.  A RESP error is one line.  A Lua error carries a
#   traceback, and a traceback carries newlines: the reply ended early and
#   everything after it was read as the next reply.  Measured as exactly that
#   before it was fixed -- redis-cli answered "Bad simple string value" to a
#   script whose redis.call had failed.  The test drives two commands down one
#   connection and checks the second one's answer arrives intact.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: EVAL, its sandbox and its deadline ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line; for line in "${@:3}"; do echo "        $line"; done
}

P=$((SL_PORT_BASE+1461))
PS=$((SL_PORT_BASE+1465))

daemon_isolate cachescript
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"
"$BIN" create cache sc_c -p "$P" -s >/dev/null 2>&1
sleep 1.5

RESP_PY="$SOCKETLEY_TMPD/s.py"
cat > "$RESP_PY" <<'PY'
import socket, sys, json
port = int(sys.argv[1]); cmds = json.loads(sys.argv[2])
def skip(b, i):
    e = b.find(b'\r\n', i)
    if e < 0: return None
    t = b[i:i+1]; line = b[i+1:e]; e += 2
    if t in (b'+', b'-', b':', b'_'): return e
    n = int(line)
    if t == b'$':
        if n < 0: return e
        return e + n + 2 if e + n + 2 <= len(b) else None
    if n < 0: return e
    for _ in range(n):
        e = skip(b, e)
        if e is None: return None
    return e
def replies(b):
    n = 0; i = 0
    while i < len(b):
        i = skip(b, i)
        if i is None: break
        n += 1
    return n
out = b''
try:
    s = socket.create_connection(('127.0.0.1', port), timeout=20)
    payload = b''
    for c in cmds:
        payload += ('*%d\r\n' % len(c)).encode()
        for a in c: payload += ('$%d\r\n%s\r\n' % (len(a.encode()), a)).encode()
    s.sendall(payload); s.settimeout(20.0)
    while True:
        try: b = s.recv(65536)
        except socket.timeout: break
        if not b: break
        out += b
        if replies(out) >= len(cmds): break
    s.close()
except Exception as e: print('ERROR:' + type(e).__name__)
sys.stdout.write(out.decode('latin1').replace('\r\n', ' | '))
PY
resp() { python3 "$RESP_PY" "${2:-$P}" "$1" 2>/dev/null; }
want() {
    local label=$1 expect=$2 cmds=$3 port=${4:-$P} got
    got=$(resp "$cmds" "$port")
    case "$got" in *"$expect"*) ok "$label" ;;
                   *) bad "$label" "reply did not contain '$expect'" "got: $got" ;; esac
}
deny() {   # the reply must NOT contain this, and must start as expected so no reply is not a pass
    local label=$1 forbidden=$2 start=$3 cmds=$4 got
    got=$(resp "$cmds")
    case "$got" in *"$forbidden"*) bad "$label" "reply contained '$forbidden'" "got: $got" ;;
                   "$start"*) ok "$label" ;;
                   *) bad "$label" "reply did not start with '$start'" "got: ${got:-<nothing>}" ;; esac
}

echo "--- 1. the sandbox, door by door ---"
# Each of these is a way out of the interpreter, and `nil` is the only
# acceptable answer.  ffi is last because it is the one that matters most.
for lib in io os package debug require load loadstring dofile loadfile getfenv setfenv; do
    want "$lib is not there" '$3 | nil | ' "[[\"EVAL\",\"return type($lib)\",\"0\"]]"
done
# require is gone, so this is belt and braces: if some path to it survives,
# the script says so rather than the test assuming it cannot.
want "ffi cannot be reached" "nein" \
  '[["EVAL","local ok = pcall(function() return require(\"ffi\") end); if ok then return \"JA\" end return \"nein\"","0"]]'
deny "and no script sees the operator's globals" "socketley" '$3 | nil' \
  '[["EVAL","return type(socketley)","0"]]'

echo "--- 2. the deadline, and what survives it ---"
START=$(date +%s)
got=$(resp '[["EVAL","while true do end","0"]]')
ELAPSED=$(( $(date +%s) - START ))
case "$got" in *deadline*) ok "a runaway script is stopped (${ELAPSED}s)" ;;
               *) bad "deadline" "no deadline error" "got: $got" ;; esac
[ "$ELAPSED" -lt 30 ] && ok "and stopped in time, not left running" \
                      || bad "deadline" "took ${ELAPSED}s"
want "the cache answers afterwards" "PONG" '[["PING"]]'

echo "--- 3. an error is one line, and the next reply survives it ---"
# Two commands down one connection: if the error reply ends early, the PING's
# answer is read as part of it and this sees the wrong thing.
got=$(resp '[["SET","es","v"],["EVAL","return redis.call(\"incr\", KEYS[1])","1","es"],["PING"]]')
case "$got" in *PONG*) ok "the reply after a script error is intact" ;;
               *) bad "framing" "PONG did not survive the error reply" "got: $got" ;; esac
deny "and the traceback is not in it" "traceback" "-" \
  '[["EVAL","return redis.call(\"incr\", \"es\")","0"]]'

echo "--- 4. what a script returns, converted ---"
want "a number is an integer"      ":1"      '[["EVAL","return 1","0"]]'
want "a float is truncated"        ":3"      '[["EVAL","return 3.7","0"]]'
want "a string is a bulk"          "hallo"   '[["EVAL","return \"hallo\"","0"]]'
want "true is 1"                   ":1"      '[["EVAL","return true","0"]]'
want "false is nil"                '$-1'     '[["EVAL","return false","0"]]'
want "a table is an array"         "*3"      '[["EVAL","return {1,2,3}","0"]]'
# Lua's own rule, and Redis follows it: the array ends at the first hole.
want "and it ends at the first hole" "*2"    '[["EVAL","return {1,2,nil,4}","0"]]'
want "status_reply is a status"    "+FERTIG" '[["EVAL","return redis.status_reply(\"FERTIG\")","0"]]'
want "error_reply is an error"     "-MEINS"  '[["EVAL","return redis.error_reply(\"MEINS kaputt\")","0"]]'
want "KEYS arrives"                "mykey"   '[["EVAL","return KEYS[1]","1","mykey"]]'
want "ARGV arrives"                "zwei"    '[["EVAL","return ARGV[2]","0","eins","zwei"]]'
want "sha1hex of the empty string" "da39a3ee5e6b4b0d3255bfef95601890afd80709" \
  '[["EVAL","return redis.sha1hex(\"\")","0"]]'

echo "--- 5. redis.call reaches the cache, and pcall catches ---"
want "call writes"        "+OK"   '[["EVAL","return redis.call(\"set\", KEYS[1], ARGV[1])","1","sk","wert"]]'
want "and the write took" "wert"  '[["GET","sk"]]'
want "call reads"         "wert"  '[["EVAL","return redis.call(\"get\", KEYS[1])","1","sk"]]'
want "a missing key is false" '$-1' '[["EVAL","if redis.call(\"get\",\"nosuch\") == false then return nil end return 1","0"]]'
# An integer argument must not be sent as "60.0", which no command parses.
want "a number argument is an integer" ":1" \
  '[["EVAL","return redis.call(\"expire\", KEYS[1], 60)","1","sk"]]'
want "and the ttl really is 60"        ":60"  '[["TTL","sk"]]'
want "pcall hands the error back"      "gefangen" \
  '[["EVAL","local r = redis.pcall(\"incr\", KEYS[1]); if r.err then return \"gefangen\" end return \"nein\"","1","sk"]]'
# The code a client switches on has to survive the trip out of the script.
# LPUSH onto a string, not GET on a list: a read of a wrong-typed key answers
# nil here rather than WRONGTYPE, which is a gap on the read path older than
# scripting and belongs to its own change.
want "and an error code is passed through" "WRONGTYPE" \
  '[["SET","strk","v"],["EVAL","return redis.call(\"lpush\", KEYS[1], \"x\")","1","strk"]]'

echo "--- 6. the script cache ---"
want "script load answers a sha" "a5260dd66ce02462c5b5231c727b3f7772c0bcc5" \
  '[["SCRIPT","LOAD","return redis.call(\"get\", KEYS[1])"]]'
want "script exists says 1" ":1" \
  '[["SCRIPT","EXISTS","a5260dd66ce02462c5b5231c727b3f7772c0bcc5"]]'
want "evalsha runs it" "wert" \
  '[["EVALSHA","a5260dd66ce02462c5b5231c727b3f7772c0bcc5","1","sk"]]'
# A body that does not compile has no SHA, by SCRIPT LOAD or by EVAL, as on Redis.
want "script load of a body that does not compile is an error" "-ERR" '[["SCRIPT","LOAD","return ("]]'
want "and neither it nor an EVAL of it is kept" ":0" \
  '[["EVAL","return (","0"],["SCRIPT","EXISTS","728acb63e2aaef0ee859ece5db586bff5d800d1e"]]'
want "an unknown sha is NOSCRIPT" "NOSCRIPT" \
  '[["EVALSHA","0000000000000000000000000000000000000000","1","sk"]]'
want "script flush empties it" "+OK" '[["SCRIPT","FLUSH"]]'
want "and then it is gone" ":0" \
  '[["SCRIPT","EXISTS","a5260dd66ce02462c5b5231c727b3f7772c0bcc5"]]'

# EVAL keeps what it ran, but not without end: a client that sends a new body each time grew the cache for ever. The
# least recently run of EVAL's own goes past 500, as Redis 7.4 has it, and SCRIPT LOAD's stays until a flush.
EVALS=$(python3 -c '
import json, hashlib
cmds = [["SCRIPT", "LOAD", "return 7 -- kept by name"]] + [["EVAL", "return 1 -- %d" % i, "0"] for i in range(600)]
first = hashlib.sha1(b"return 1 -- 0").hexdigest(); last = hashlib.sha1(b"return 1 -- 599").hexdigest()
kept = hashlib.sha1(b"return 7 -- kept by name").hexdigest()
cmds.append(["SCRIPT", "EXISTS", first, last, kept])
print(json.dumps(cmds))')
want "EVAL keeps the scripts it ran recently, drops the oldest past 500, and keeps a loaded one" \
    '*3 | :0 | :1 | :1' "$EVALS"
# EVAL loads as it runs, which is what makes the NOSCRIPT fallback work.
want "eval loads as well as runs" "wert" \
  '[["EVAL","return redis.call(\"get\", KEYS[1])","1","sk"]]'
want "so evalsha finds it afterwards" ":1" \
  '[["SCRIPT","EXISTS","a5260dd66ce02462c5b5231c727b3f7772c0bcc5"]]'

echo "--- 7. the globals are sealed, so one script cannot leave state for the next ---"
# One interpreter serves every script on a cache, so its global table is
# shared.  Before this, `leaked = 42` in one client's script was readable by
# every later script on that cache, for the life of the process, and no FLUSH
# cleared it -- a channel between two clients that neither opened.
want "writing a global is refused, and names the variable" "leaked" \
  '[["EVAL","leaked = 42","0"]]'
want "and nothing was left behind" '$3 | nil | ' \
  '[["EVAL","return tostring(leaked)","0"]]'
# The seal must not reach the things a script legitimately uses.
want "locals still work" ":8" \
  '[["EVAL","local a = 7 return a + 1","0"]]'
want "KEYS is still bound" "hello" \
  '[["EVAL","return KEYS[1]","1","hello"]]'
want "ARGV is still bound" "world" \
  '[["EVAL","return ARGV[1]","0","world"]]'
want "and redis.call still reaches the store" "+OK" \
  '[["EVAL","return redis.call(\"set\",KEYS[1],\"v\")","1","sealed:k"]]'
# The metatable alone is NOT the guard: rawset walks straight past __newindex,
# and it did -- rawset(_G,"sneak",1) stored and the next script read it back.
# table.insert(_G, x) is the same hole by number.  Every route needs a
# REFERENCE to the globals table, so the name is taken away as well, and these
# now fail on the argument rather than on the permission -- rawset on its own
# name, since the sandbox that locks the library tables took it away too.
want "rawset cannot reach the globals" "nil value" \
  '[["EVAL","rawset(_G, \"sneak\", 1) return 1","0"]]'
want "nor can table.insert" "table expected" \
  '[["EVAL","table.insert(_G, \"x\") return 1","0"]]'
want "nor setmetatable" "table expected" \
  '[["EVAL","setmetatable(_G, {}) return 1","0"]]'
want "and no value survived any of them" "nil" \
  '[["EVAL","return tostring(sneak)","0"]]'
# KEYS and ARGV are the two tables every script shares by name, so a metatable
# one script set on them answered the next script's reads from its upvalue.
want "a metatable on KEYS is refused" "protected metatable" \
  '[["EVAL","setmetatable(KEYS, {}) return 1","0"]]'
resp '[["EVAL","local s = {} pcall(setmetatable, KEYS, {__index = function(_, k) return s[k] end, __newindex = function(_, k, v) s[k] = v end}) KEYS.secret = ARGV[1] return 1","0","planted"]]' >/dev/null
want "and nothing one script put in KEYS reaches the next" '$3 | nil | ' \
  '[["EVAL","return tostring(KEYS.secret)","0"]]'
resp '[["EVAL","pcall(setmetatable, ARGV, {__index = function() return \"planted\" end}) return 1","0"]]' >/dev/null
want "nor does an __index planted on ARGV" '$6 | absent | ' \
  '[["EVAL","return ARGV[9] or \"absent\"","0"]]'

echo "--- 8. sharded: a script is routed by the keys it declares ---"
"$BIN" create cache sc_s -p "$PS" --shards 4 --cluster -s >/dev/null 2>&1
for _ in $(seq 1 80); do
    [ "$(ss -ltn 2>/dev/null | awk -v a=$((PS+1)) -v d=$((PS+4)) -F: '{n=$NF+0; if(n>=a&&n<=d) c++} END{print c+0}')" -ge 4 ] && break
    sleep 0.2
done
want "two keys on one shard run together" "ab" \
  '[["EVAL","redis.call(\"set\",KEYS[1],\"a\"); redis.call(\"set\",KEYS[2],\"b\"); return redis.call(\"get\",KEYS[1])..redis.call(\"get\",KEYS[2])","2","{x}k1","{x}k2"]]' "$PS"
# Not a crossing: a script is one atomic stretch and cannot be half here.
want "keys on two shards are -CROSSSLOT" "CROSSSLOT" \
  '[["EVAL","return 1","2","{x}k1","{y}k2"]]' "$PS"
want "a script with no keys runs where asked" "+ok" \
  '[["EVAL","return redis.status_reply(\"ok\")","0"]]' "$PS"

# A script reaches the cache through the same door a client does -- redis.call
# hands its arguments to the dispatch -- so every option scan has
# is a script's too.  That follows from the structure and would stop following
# it the day somebody gives scripts a dispatch of their own, which is what these
# rows are for.
echo ""
echo "--- scan's filters are reachable from a script ---"
resp '[["FLUSHDB"],["SET","u:1","{\"city\":\"berlin\"}"],["SET","u:2","{\"city\":\"hamburg\"}"],["HSET","h:1","city","berlin"],["HSET","h:2","city","hamburg"]]' >/dev/null
# The COUNT and not a key name: four keys are seeded and every one of them comes
# back on a build that skips the option, so a row looking for "u:1" in the reply
# passes there too and measures nothing.
want "a script can filter on the value" ":1" \
  '[["EVAL","local r = redis.call(\"scan\",0,\"count\",10000,\"valuematch\",\"*berlin*\"); return #r[2]","0"]]'
want "a script can restrict to a type" ":2" \
  '[["EVAL","local r = redis.call(\"scan\",0,\"count\",10000,\"type\",\"hash\"); return #r[2]","0"]]'
want "a script can ask what a field holds" ":1" \
  '[["EVAL","local r = redis.call(\"scan\",0,\"count\",10000,\"field\",\"city\",\"valuematch\",\"berlin\"); return #r[2]","0"]]'
want "a script can count a type without walking it" ":2" \
  '[["EVAL","return redis.call(\"dbsize\",\"type\",\"hash\")","0"]]'
# The whole loop inside one script, which is what a client would otherwise do
# over the wire: one answer instead of a page at a time.
want "a script can run the cursor loop itself" ":1" \
  '[["EVAL","local c,n = \"0\",0; repeat local r = redis.call(\"scan\",c,\"count\",1000,\"field\",\"city\",\"valuematch\",\"berlin\"); c = r[1]; n = n + #r[2]; until c == \"0\"; return n","0"]]'

echo ""
echo "--- 9. a script cannot take the worker, or its own connection, with it ---"
# MULTI and SUBSCRIBE would outlive the script on the caller's connection.
want "MULTI from a script leaves nothing queueing" '$1 | v |' \
  '[["SET","mk","v"],["EVAL","return redis.pcall(\"multi\")","0"],["GET","mk"]]'
want "SUBSCRIBE from a script is refused" "not allowed from script" \
  '[["EVAL","return redis.pcall(\"subscribe\",\"ch\")","0"]]'
# Redis answers a blocking pop in a script as its non-blocking twin.
want "a blocking pop in a script answers at once" "+PONG" \
  '[["EVAL","return redis.call(\"blpop\",\"nolist\",0)","0"],["PING"]]'
# The arguments reach the dispatch as they are, so the parser's limit is kept.
want "a call with more arguments than a command takes is refused" "too many arguments" \
  '[["EVAL","local t = {\"del\"} for i = 1, 1100 do t[#t+1] = \"k\" .. i end return redis.call(unpack(t))","0"]]'
want "an error caught in the script is the cache's own text" '$29 | ERR wrong number of arguments' \
  '[["EVAL","local ok, e = pcall(redis.call, \"set\", \"k\") return e","0"]]'
# What a script returns is read after its pcall has ended, so an error raised
# there had nothing to catch it: one EVAL ended the worker, for every client.
resp '[["EVAL","return setmetatable({}, {__index = function() error(\"boom\") end})","0"]]' >/dev/null
want "a returned table whose __index raises leaves the cache up" "+PONG" '[["PING"]]'
# EVAL from inside EVAL recursed until the worker died; on a cache of its own,
# so the row above cannot decide this one.
PR=$((SL_PORT_BASE+1463))
"$BIN" create cache sc_r -p "$PR" -s >/dev/null 2>&1
for _ in $(seq 1 50); do ss -ltn 2>/dev/null | grep -q ":$PR " && break; sleep 0.1; done
REC='return redis.call(\"eval\", ARGV[1], 0, ARGV[1])'
want "a script cannot run a script" "not allowed from script" \
  "[[\"EVAL\",\"$REC\",\"0\",\"$REC\"]]" "$PR"
want "and the cache is still there" "+PONG" '[["PING"]]' "$PR"

echo ""
echo "--- 10. a pattern match answers to the deadline, and still matches as Lua 5.1 does ---"
# LuaJIT's matcher backtracks inside one C call where the count hook never fires: this held the shard for hours.
START=$(date +%s)
got=$(resp '[["EVAL","return string.find(string.rep(\"a\", 100000), \"a*a*b\")","0"]]')
ELAPSED=$(( $(date +%s) - START ))
case "$got" in *deadline*) ok "a backtracking pattern is stopped (${ELAPSED}s)" ;;
               *) bad "pattern deadline" "no deadline error" "got: ${got:-<nothing>}" ;; esac
[ "$ELAPSED" -lt 30 ] && ok "and stopped in time" || bad "pattern deadline" "took ${ELAPSED}s"
want "the cache answers after it" "PONG" '[["PING"]]'
want "the method form is the same matcher" "deadline" \
  '[["EVAL","return (\"a\"):rep(100000):match(\"a*a*b\")","0"]]'
want "a plain find"            '*2 | :5 | :7 |' '[["EVAL","return {string.find(\"hello world\", \"o w\")}","0"]]'
want "find with captures"      '*4 | :1 | :7 | $3 | key | $3 | val |' \
  '[["EVAL","return {string.find(\"key=val\", \"(%w+)=(%w+)\")}","0"]]'
want "an anchored miss"        '$3 | nil |' '[["EVAL","return tostring(string.find(\"abc\", \"^b\"))","0"]]'
want "a balanced match"        '$7 | (a(b)c) |' '[["EVAL","return string.match(\"f(a(b)c) d\", \"%b()\")","0"]]'
want "a frontier from an init" ':6 |' '[["EVAL","return string.find(\"THE (quick) fox\", \"%f[%a]%a+\", 5)","0"]]'
want "a position capture"      ':3 |' '[["EVAL","return string.match(\"hello\", \"()ll()\")","0"]]'
want "a back reference"        '$3 | abc |' '[["EVAL","return string.match(\"xabcabcx\", \"(abc)%1\")","0"]]'
want "a lazy repetition"       '$3 | <a> |' '[["EVAL","return string.match(\"<a><b>\", \"<.->\")","0"]]'
want "gsub with a template"    '$15 | <hello> <world> |' \
  '[["EVAL","return (string.gsub(\"hello world\", \"(%w+)\", \"<%1>\"))","0"]]'
want "gsub with a function"    '$3 | ABC |' \
  '[["EVAL","return (string.gsub(\"abc\", \"%w\", function(c) return c:upper() end))","0"]]'
want "gsub with a table"       '$3 | 1b2 |' \
  '[["EVAL","return (string.gsub(\"abc\", \"%w\", {a = \"1\", c = 2}))","0"]]'
want "gsub counts"             ':3 |' '[["EVAL","return select(2, string.gsub(\"aaa\", \"a\", \"b\"))","0"]]'
want "gsub stops at its limit" '$3 | bba |' '[["EVAL","return (string.gsub(\"aaa\", \"a\", \"b\", 2))","0"]]'
want "gmatch walks the subject" '$5 | a1,b2 |' \
  '[["EVAL","local t = {} for k, v in string.gmatch(\"a=1, b=2\", \"(%w+)=(%w+)\") do t[#t+1] = k .. v end return table.concat(t, \",\")","0"]]'
want "a malformed pattern is an error" "missing" '[["EVAL","return string.find(\"a\", \"[a\")","0"]]'
want "a pattern nested past 200 is refused, not a C stack overflow" "too complex" \
  '[["EVAL","return string.match(string.rep(\"a\", 300), string.rep(\"a?\", 300))","0"]]'

echo ""
echo "--- 11. what a script may hold and return is bounded ---"
# A string grown in C is built before any hook could fire, and its reply was a second copy of the same size.
want "a string.rep past the script's heap is refused before it is built" "string.rep would make more than the 128 MiB" \
  '[["EVAL","return #string.rep(\"a\", 200000000)","0"]]'
want "a string doubled past the script's heap is out of memory" "OOM the script asked for more than the 128 MiB" \
  '[["EVAL","local s = \"a\" for i = 1, 28 do s = s .. s end return #s","0"]]'
want "a reply naming one string many times is refused at 64 MiB" "longer than the 64 MiB" \
  '[["EVAL","local s = string.rep(\"a\", 1048576) local t = {} for i = 1, 80 do t[i] = s end return t","0"]]'
want "and a script after them has its whole heap again" ":50000000 |" \
  '[["EVAL","return #string.rep(\"a\", 50000000)","0"]]'
want "a rep of nothing is nothing" '$0 |' '[["EVAL","return string.rep(\"\", 2000000000)","0"]]'
want "the cache answers after them" "PONG" '[["PING"]]'

echo ""
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && { echo "  OK"; exit 0; } || exit 1
