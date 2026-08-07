#!/usr/bin/env bash
# Integration test: a cache runtime with --lua.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# No test in this suite had ever created a cache with a script.  That one gap
# accounted for twenty-one self.* methods and four callbacks — on_miss, on_write,
# on_delete, on_expire — none of which was executed by anything, ever.
#
# ─── HOW THE METHODS ARE REACHED ────────────────────────────────────────────
#
# on_miss is used as the entry point: a GET of `ops:<name>` runs a battery of
# self.* calls and RETURNS the result, which the cache then serves to the client
# as the value of that key.  So every figure below is asserted off the RESP
# wire, as an exact string, by an ordinary client — rather than off a log line
# the script wrote about itself.  A binding that returns the wrong thing changes
# the reply.
#
# ─── THE THREE CLAIMS WORTH SPELLING OUT ────────────────────────────────────
#
# 1. on_miss's return is written into the store AND served as a hit.  Both
#    halves matter, and the second GET is what separates them: it must return
#    the same value WITHOUT on_miss running again.  The script counts its own
#    invocations into a file, so "again" is a number rather than an impression.
#
#    Then the third GET, after the TTL has passed, must miss — and that clause
#    is the only thing in this file that pins the second element of on_miss's
#    return tuple.  Drop the ttl and the first two assertions still pass: the
#    key simply never expires, the count stays 1, and nothing says so.
#
# 2. on_write's third argument is the TTL the command carried, not a flag that
#    one was present.  `SETEX k 5 v` delivers 5 and a plain `SET` delivers 0,
#    and the pair is what makes the assertion about the value rather than about
#    the argument existing.
#
# 3. self.set and self.get reach the SAME store the RESP client does.  Asserted
#    in both directions, because one direction is satisfied by a script with a
#    table of its own that happens to be seeded at startup.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_create.sh"

daemon_isolate luacache

PB=${SOCKETLEY_PORT_BASE:-19140}
PORT=$((PB + 0))

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
assert_eq() {
    local label=$1 want=$2 got=$3; shift 3
    if [ "$got" = "$want" ]; then pass; else
        fail "$label" "got '$got', wanted '$want'" "$@"
    fi
}

cleanup() {
    "$BIN" stop lc_cache 2>/dev/null || true
    sleep 0.3
    "$BIN" remove lc_cache 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a cache runtime with --lua ==="

daemon_start "$BIN"

MISSES="$SOCKETLEY_TMPD/miss.count"
: > "$MISSES"

# A tiny RESP client.  Sends each command on ONE connection and prints one line
# per reply, so the assertions can name the reply they mean.
cat > "$SOCKETLEY_TMPD/resp.py" <<'PYEOF'
import socket, sys

def enc(*parts):
    out = b"*%d\r\n" % len(parts)
    for p in parts:
        b = p.encode()
        out += b"$%d\r\n%s\r\n" % (len(b), b)
    return out

def decode(sock):
    # One reply, in the three shapes this file provokes: simple string, error,
    # integer, and bulk (including the null bulk).
    buf = b""
    def line():
        nonlocal buf
        while b"\r\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                raise EOFError("connection closed mid-reply")
            buf += chunk
        i = buf.index(b"\r\n")
        out, buf = buf[:i], buf[i+2:]
        return out
    head = line()
    kind, rest = head[:1], head[1:]
    if kind in (b"+", b"-", b":"):
        return rest.decode("latin-1")
    if kind == b"$":
        n = int(rest)
        if n < 0:
            return "<nil>"
        while len(buf) < n + 2:
            chunk = sock.recv(65536)
            if not chunk:
                raise EOFError("connection closed mid-bulk")
            buf += chunk
        out, buf = buf[:n], buf[n+2:]
        return out.decode("latin-1")
    return "<unparsed:%s>" % head.decode("latin-1")

port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), 5)
s.settimeout(5)
for cmd in sys.argv[2:]:
    s.sendall(enc(*cmd.split(" ")))
    try:
        print(decode(s), flush=True)
    except Exception as e:
        print("<error:%s>" % e, flush=True)
s.close()
PYEOF

# resp CMD... — one reply per command, one per line.
resp() { python3 "$SOCKETLEY_TMPD/resp.py" "$PORT" "$@"; }
# reply N CMD... — just the Nth reply.
reply() { local n=$1; shift; resp "$@" | sed -n "${n}p"; }

LUA="$SOCKETLEY_TMPD/cache.lua"
cat > "$LUA" <<LUAEOF
local MISS_FILE = "$MISSES"
local CACHE_NAME = "lc_cache"
LUAEOF
cat >> "$LUA" <<'LUAEOF'

-- One line per on_miss for the key the ttl assertions use.  A file rather than
-- a Lua counter because the assertion that needs it is "it did NOT run again",
-- and a number this side of the process boundary is one the shell can read
-- without asking the script anything.
local function note_miss(key)
    local f = io.open(MISS_FILE, "a")
    if f then f:write(key .. "\n"); f:close() end
end

local function j(t) return table.concat(t, " ") end

-- Every self.* method the cache table binds, grouped by what it is for.  The
-- return value of each call is in the answer, so a binding that returns the
-- wrong type or the wrong value changes the string the client reads.
local ops = {}

ops["strings"] = function()
    local r = {}
    r[#r+1] = "set=" .. tostring(self.set("st", "v1"))
    r[#r+1] = "get=" .. self.get("st")
    r[#r+1] = "del=" .. tostring(self.del("st"))
    r[#r+1] = "getgone=[" .. self.get("st") .. "]"
    r[#r+1] = "delgone=" .. tostring(self.del("st"))
    return j(r)
end

ops["lists"] = function()
    local r = {}
    r[#r+1] = "rpush=" .. tostring(self.rpush("li", "b"))
    self.rpush("li", "c")
    r[#r+1] = "lpush=" .. tostring(self.lpush("li", "a"))
    r[#r+1] = "llen=" .. tostring(self.llen("li"))
    r[#r+1] = "lpop=" .. self.lpop("li")
    r[#r+1] = "rpop=" .. self.rpop("li")
    r[#r+1] = "llen2=" .. tostring(self.llen("li"))
    return j(r)
end

ops["sets"] = function()
    local r = {}
    r[#r+1] = "sadd=" .. tostring(self.sadd("se", "x"))
    r[#r+1] = "saddagain=" .. tostring(self.sadd("se", "x"))
    self.sadd("se", "y")
    r[#r+1] = "scard=" .. tostring(self.scard("se"))
    r[#r+1] = "ismem=" .. tostring(self.sismember("se", "x"))
    r[#r+1] = "srem=" .. tostring(self.srem("se", "x"))
    r[#r+1] = "ismem2=" .. tostring(self.sismember("se", "x"))
    r[#r+1] = "sremgone=" .. tostring(self.srem("se", "zzz"))
    r[#r+1] = "scard2=" .. tostring(self.scard("se"))
    return j(r)
end

ops["hashes"] = function()
    local r = {}
    r[#r+1] = "hset=" .. tostring(self.hset("ha", "f1", "v1"))
    self.hset("ha", "f2", "v2")
    r[#r+1] = "hget=" .. self.hget("ha", "f1")
    r[#r+1] = "hlen=" .. tostring(self.hlen("ha"))
    r[#r+1] = "hdel=" .. tostring(self.hdel("ha", "f1"))
    r[#r+1] = "hgetgone=[" .. self.hget("ha", "f1") .. "]"
    r[#r+1] = "hlen2=" .. tostring(self.hlen("ha"))
    r[#r+1] = "hdelgone=" .. tostring(self.hdel("ha", "nope"))
    return j(r)
end

ops["ttl"] = function()
    local r = {}
    self.set("tk", "v")
    r[#r+1] = "ttlnone=" .. tostring(self.ttl("tk"))
    r[#r+1] = "expire=" .. tostring(self.expire("tk", 100))
    -- The one figure here that is a clock rather than a value.  It is 100 the
    -- instant the expiry is set and 99 a microsecond later, so the exact
    -- number would make this file fail for the machine's speed; anything
    -- outside the pair is a real answer and is printed as itself.
    local t = self.ttl("tk")
    r[#r+1] = "ttl=" .. ((t == 100 or t == 99) and "ok" or tostring(t))
    r[#r+1] = "persist=" .. tostring(self.persist("tk"))
    r[#r+1] = "ttlafter=" .. tostring(self.ttl("tk"))
    r[#r+1] = "ttlmissing=" .. tostring(self.ttl("nosuchkey"))
    r[#r+1] = "expiremissing=" .. tostring(self.expire("nosuchkey", 5))
    r[#r+1] = "persistmissing=" .. tostring(self.persist("nosuchkey"))
    return j(r)
end

ops["publish"] = function()
    return "publish=" .. tostring(self.publish("chan", "from-lua"))
end

ops["identity"] = function()
    return "alias=" .. tostring(rawequal(cache, self)) ..
           " aliasget=" .. tostring(cache.get("from_resp")) ..
           " conns=" .. tostring(self.connections()) ..
           " name=" .. self.name ..
           " type=" .. self.type ..
           " state=" .. tostring(self.state) ..
           " port=" .. tostring(self.port)
end

-- Both directions across the store, in one answer: what the RESP client wrote
-- read from Lua, and what Lua writes left for the RESP client to read.
ops["shared"] = function()
    self.set("from_lua", "written-in-lua")
    return "ext=[" .. self.get("from_resp") .. "]"
end

-- `ops:<name>` optionally followed by `@<anything>`.
--
-- The suffix is not decoration.  on_miss's return is WRITTEN INTO THE STORE as
-- well as served, which is the behaviour asserted at the top of this file — so
-- a second GET of the same ops key is an ordinary hit and never reaches this
-- function.  Any battery that has to be run twice therefore has to be asked
-- for under two names, and one of them is: `ops:publish` before a subscriber
-- exists and `ops:publish@2` after.  Diagnosed the hard way, as "publish
-- reports 0 with a subscriber attached".
function on_miss(key)
    local name = key:match("^ops:([^@]+)")
    if name and ops[name] then return ops[name](), 0 end
    if key == "fillme" then
        note_miss(key)
        -- Two seconds, so the third GET below can be made after it has passed
        -- without making this file slow.
        return "filled-by-on_miss", 2
    end
    -- Everything else misses for real: on_miss returning nil must leave the
    -- key absent, not write an empty string into the store.
    return nil
end

-- Defined for one reason, written down because it is not obvious: self.state
-- is only ever updated from inside invoke_on_start / invoke_on_stop, and both
-- return early when the script has not defined the callback —
--
--     if (!m_lua || !m_lua->has_on_start()) return;
--     m_lua->update_self_state("running");
--
-- so a script with no on_start reads self.state as "created" for the whole life
-- of a running runtime.  Measured, two identical servers, both Up in `ls`:
-- with on_start defined, self.state=running; without it, self.state=created.
-- Reported as a defect rather than worked around; this file asserts the field
-- on the path where it does work, and says so here so the assertion is not
-- mistaken for evidence that it works on the other one.
function on_start()
    socketley.log("CSTART " .. tostring(self.state))
end

function on_write(key, value, ttl)
    socketley.log("CW " .. key .. " " .. tostring(value) .. " " .. tostring(ttl))
end

function on_delete(key)
    socketley.log("CD " .. key)
end

function on_expire(key)
    socketley.log("CE " .. key)
end

socketley.subscribe(CACHE_NAME, "chan", function(channel, message)
    socketley.log("CS " .. tostring(channel) .. " " .. tostring(message))
end)
LUAEOF

create_ok "cache created with a script" "$BIN" create cache lc_cache -p "$PORT" --lua "$LUA" -s
ready_tcp 127.0.0.1 "$PORT" 10 || echo "  NOTE: the cache never accepted a connection"

# said PATTERN — wait for a daemon log line.
said() {
    local pattern=$1 deadline=$(( $(date +%s) + ${2:-8} ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        grep -qaE "$pattern" "$SOCKETLEY_DLOG" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}
hits() { grep -ac "$1" "$2" 2>/dev/null || true; }

# ── 1. on_miss fills the store, and the fill is a hit next time ─────────────
FIRST=$(reply 1 "GET fillme")
assert_eq "on_miss's return is served to the client" "filled-by-on_miss" "$FIRST"
assert_eq "on_miss ran once" "1" "$(hits fillme "$MISSES")"

SECOND=$(reply 1 "GET fillme")
assert_eq "the second GET returns the same value" "filled-by-on_miss" "$SECOND"
assert_eq "the second GET did NOT run on_miss again" "1" "$(hits fillme "$MISSES")" \
    "on_miss's return is written into the store as well as served, so the" \
    "next GET is an ordinary hit — a build that only served it would fetch" \
    "again on every request and this count would be 2"

# ── 2. ...and the fill expires, which is the ttl half of the return tuple ───
said 'CE fillme' 8 || true
assert_eq "on_expire fired for the key on_miss filled" "1" "$(hits 'CE fillme' "$SOCKETLEY_DLOG")"

THIRD=$(reply 1 "GET fillme")
assert_eq "after the TTL the value is fetched again" "filled-by-on_miss" "$THIRD"
assert_eq "on_miss ran a second time once the TTL had passed" \
          "2" "$(hits fillme "$MISSES")" \
    "this is the ONLY assertion in this file that pins the second element of" \
    "on_miss's return tuple: drop the ttl and the key never expires, the" \
    "count stays 1, and the two assertions above still pass"

# ── 3. on_miss returning nil leaves the key absent ──────────────────────────
assert_eq "a key on_miss declines is a miss" "<nil>" "$(reply 1 "GET neverfilled")"
assert_eq "and declining wrote nothing into the store" "<nil>" "$(reply 1 "GET neverfilled")" \
    "a build that wrote on_miss's nil as an empty string would answer with a" \
    "zero-length bulk here, which is a hit"

# ── 4. on_write's third argument is the TTL the command carried ─────────────
OUT=$(resp "SETEX wk 5 wv" "SET wk2 wv2" "MSET wk3 wv3 wk4 wv4")
assert_eq "SETEX is accepted" "OK" "$(sed -n 1p <<<"$OUT")"
said 'CW wk4 wv4 0' 8 || true

assert_eq "on_write is told the TTL a SETEX carried" \
          "1" "$(hits 'CW wk wv 5' "$SOCKETLEY_DLOG")" \
    "the third argument is the seconds, not a flag saying there were some"
assert_eq "on_write is told 0 for a SET with no TTL" \
          "1" "$(hits 'CW wk2 wv2 0' "$SOCKETLEY_DLOG")" \
    "paired with the SETEX above on purpose: either one alone is satisfied" \
    "by a build that passes a constant"
assert_eq "on_write fires once per pair of an MSET" \
          "1" "$(hits 'CW wk3 wv3 0' "$SOCKETLEY_DLOG")"
assert_eq "...for the second pair too" \
          "1" "$(hits 'CW wk4 wv4 0' "$SOCKETLEY_DLOG")"

# ── 5. on_delete fires for a key that was there, and not for one that was not ─
DEL_OUT=$(resp "DEL wk2" "DEL nosuchkey")
assert_eq "DEL of an existing key reports one" "1" "$(sed -n 1p <<<"$DEL_OUT")"
assert_eq "DEL of an absent key reports none" "0" "$(sed -n 2p <<<"$DEL_OUT")"
said 'CD wk2' 8 || true
assert_eq "on_delete fired for the key that was deleted" \
          "1" "$(hits 'CD wk2' "$SOCKETLEY_DLOG")"
assert_eq "on_delete did not fire for the key that was not there" \
          "0" "$(hits 'CD nosuchkey' "$SOCKETLEY_DLOG")" \
    "del() succeeds on a key that is merely expired, so a hook fired on the" \
    "attempt rather than on the deletion is a plausible mistake"

# ── 6. One store, not two ──────────────────────────────────────────────────
resp "SET from_resp written-in-resp" >/dev/null
assert_eq "self.get() reads what a RESP client wrote" \
          "ext=[written-in-resp]" "$(reply 1 "GET ops:shared")"
assert_eq "a RESP client reads what self.set() wrote" \
          "written-in-lua" "$(reply 1 "GET from_lua")"
assert_eq "and reading it did not go through on_miss" \
          "2" "$(hits fillme "$MISSES")" \
    "a value self.set() wrote must be an ordinary hit; if the read fell" \
    "through to on_miss the store the script writes is not the store the" \
    "client reads"

# ── 7. The twenty-one methods, by their return values ──────────────────────
assert_eq "strings: set, get, del" \
          "set=true get=v1 del=true getgone=[] delgone=false" \
          "$(reply 1 "GET ops:strings")"
assert_eq "lists: lpush, rpush, lpop, rpop, llen" \
          "rpush=true lpush=true llen=3 lpop=a rpop=c llen2=1" \
          "$(reply 1 "GET ops:lists")"
assert_eq "sets: sadd, srem, sismember, scard" \
          "sadd=1 saddagain=0 scard=2 ismem=true srem=true ismem2=false sremgone=false scard2=1" \
          "$(reply 1 "GET ops:sets")"
assert_eq "hashes: hset, hget, hdel, hlen" \
          "hset=true hget=v1 hlen=2 hdel=true hgetgone=[] hlen2=1 hdelgone=false" \
          "$(reply 1 "GET ops:hashes")"
assert_eq "ttl: expire, ttl, persist" \
          "ttlnone=-1 expire=true ttl=ok persist=true ttlafter=-1 ttlmissing=-2 expiremissing=false persistmissing=false" \
          "$(reply 1 "GET ops:ttl")"

# self.connections() is asked while exactly one client is connected — this one.
# The wait is for the previous probes' connections to be reaped, so the figure
# is a fact about the runtime rather than about how fast the last close was.
for _ in $(seq 1 100); do
    [ "$("$BIN" stats lc_cache 2>/dev/null | awk -F: '$1=="connections"{print $2}')" = "0" ] && break
    sleep 0.1
done
# self.state is written by update_self_state as the runtime changes state, so
# it is a field that can go stale rather than a constant — asked here while the
# runtime is up, which is the only value it should ever have on this path.
assert_eq "self.connections(), self.name, self.type, self.state, self.port" \
          "alias=true aliasget=written-in-resp conns=1 name=lc_cache type=cache state=running port=$PORT" \
          "$(reply 1 "GET ops:identity")"

# ── 8. publish, counted and delivered ──────────────────────────────────────
assert_eq "self.publish() with nobody subscribed reports none" \
          "publish=0" "$(reply 1 "GET ops:publish")"

# A RESP subscriber, then the same call again.
SUB_OUT="$SOCKETLEY_TMPD/sub.out"
(echo "subscribe chan"; sleep 4) | timeout 6 nc -q 5 127.0.0.1 "$PORT" > "$SUB_OUT" 2>/dev/null &
SUB_PID=$!
# The subscriber counts once the cache has accepted it AND registered the
# subscription, and the cache's own connection count is the first of those.  The
# "ok" nc gets back is the second, so both are waited for.
for _ in $(seq 1 100); do
    [ "$("$BIN" stats lc_cache 2>/dev/null | awk -F: '$1=="connections"{print $2}')" != "0" ] \
        && [ -s "$SUB_OUT" ] && break
    sleep 0.05
done
assert_eq "self.publish() counts the subscriber that is there" \
          "publish=1" "$(reply 1 "GET ops:publish@2")"
wait "$SUB_PID" 2>/dev/null || true
assert_eq "and the subscriber received the message self.publish() sent" \
          "1" "$(hits 'from-lua' "$SUB_OUT")"

# socketley.subscribe's own callback, with both of its arguments.
said 'CS chan from-lua' 8 || true
if [ "$(hits 'CS chan from-lua' "$SOCKETLEY_DLOG")" -ge 1 ]; then pass; else
    fail "socketley.subscribe's callback is given the channel and the message" \
         "no 'CS chan from-lua' line" \
         "fn(channel, message) is the documented signature; a callback handed" \
         "only one of them logs 'CS chan nil' and fails here"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
