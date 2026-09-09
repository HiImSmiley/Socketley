#!/usr/bin/env bash
# Integration test: a readonly cache, seen from its own Lua script.
#
# ─── THE ONE THAT WAS A LIE, NOT MERELY QUIET ───────────────────────────────
#
# Twelve mutating self.* calls on a cache refuse when --mode readonly, and every
# one of them refuses by answering exactly what it answers when there was simply
# nothing to do: `false` for nine, "" for lpop and rpop.  Quiet, and arguably
# defensible.  self.sadd was the exception and the wrong way round -- it returns
# an int, and the refusal was -1:
#
#     if (m_mode == cache_mode_readonly)
#         return -1;
#
# In Lua every number is true, so
#
#     if self.sadd(key, member) then   -- taken on a readonly cache
#         ...                          -- where nothing was added
#
# ran its success branch on the one path that had failed.  Measured, the same
# script against two caches differing only in --mode: readwrite reported
# `sadd=1`, readonly reported `sadd=-1`, and the truth test was taken in both.
#
# It is now nil, which is false in Lua.  1 and 0 still mean added and
# already-present, as they do over the wire, so a script comparing numbers is
# untouched -- and the second case is why this is not just made a boolean.
#
# ─── AND THE REASON THE OTHER ELEVEN WERE INVISIBLE ─────────────────────────
#
# A script had no way to ask.  self.name, self.port, self.type and self.state
# were on the table; the mode was not, and the same runtime answering a RESP
# client says "denied: readonly mode" in as many words.  So the wire had a
# diagnosis and the script it runs did not.
#
# self.cache_mode() closes that, and is a CALL rather than a field on purpose:
# --mode is editable, and a field written when the table was built would go
# stale exactly the way self.state did before b9912b3a.
#
# Both caches below run the SAME script file.  A difference between them is
# therefore the mode and cannot be anything else.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate cachero
P_RW=$((SL_PORT_BASE+1502))
P_RO=$((SL_PORT_BASE+1503))
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    for n in cro_rw cro_ro; do "$BIN" stop "$n" 2>/dev/null || true; done
    sleep 0.3
    for n in cro_rw cro_ro; do "$BIN" remove "$n" 2>/dev/null || true; done
    daemon_stop
}
trap cleanup EXIT

check() {   # label expected actual
    TOTAL=$((TOTAL+1))
    if [ "$2" = "$3" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$1]: expected '$2', got '$3'"
    fi
}

cat > "$SOCKETLEY_TMPD/resp.py" <<'PYEOF'
import socket, sys
def enc(*a):
    out = ("*%d\r\n" % len(a)).encode()
    for x in a:
        b = x.encode()
        out += b"$%d\r\n" % len(b) + b + b"\r\n"
    return out
def decode(sock):
    buf = b""
    def line():
        nonlocal buf
        while b"\r\n" not in buf:
            c = sock.recv(65536)
            if not c: raise EOFError("closed mid-reply")
            buf += c
        i = buf.index(b"\r\n"); out, buf = buf[:i], buf[i+2:]
        return out
    head = line(); kind, rest = head[:1], head[1:]
    if kind in (b"+", b"-", b":"): return rest.decode("latin-1")
    if kind == b"$":
        n = int(rest)
        if n < 0: return "<nil>"
        while len(buf) < n + 2:
            c = sock.recv(65536)
            if not c: raise EOFError("closed mid-bulk")
            buf += c
        out, buf = buf[:n], buf[n+2:]
        return out.decode("latin-1")
    return "<unparsed:%s>" % head.decode("latin-1")
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(5)
for cmd in sys.argv[2:]:
    s.sendall(enc(*cmd.split(" ")))
    try:    print(decode(s), flush=True)
    except Exception as e: print("<error:%s>" % e, flush=True)
s.close()
PYEOF

# One script, both caches.  on_miss is the way in, because a GET that misses is
# the only thing a readonly cache will run for us.
LUA="$SOCKETLEY_TMPD/ro.lua"
cat > "$LUA" <<'LUAEOF'
local ops = {}

-- The truth test, which is the whole point: a script asking "did that work?"
-- the way anybody writes it in Lua.
ops["truthtest"] = function()
    local taken = "NOT-TAKEN"
    if self.sadd("s:probe", "m1") then taken = "TAKEN" end
    return "branch=" .. taken .. " value=" .. tostring(self.sadd("s:probe2", "m1"))
end

-- 1 and 0 are still the two normal answers, and they are different: a script
-- that compares numbers must keep working.
ops["addtwice"] = function()
    local first  = self.sadd("s:twice", "m")
    local second = self.sadd("s:twice", "m")
    return "first=" .. tostring(first) .. " second=" .. tostring(second)
end

-- What a script can ask, and what its neighbours answer on the same cache.
ops["mode"] = function()
    return "mode=" .. self.cache_mode() ..
           " set=" .. tostring(self.set("k", "v")) ..
           " del=" .. tostring(self.del("k"))
end

function on_miss(key)
    local name = key:match("^ops:([^@]+)")
    if name and ops[name] then return ops[name](), 0 end
    return nil
end
LUAEOF

echo "=== Integration: a readonly cache, from its own script ==="

daemon_start "$BIN"

create_ok "a readwrite cache" \
    "$BIN" create cache cro_rw -p "$P_RW" --lua "$LUA" -s
create_ok "the same script, readonly" \
    "$BIN" create cache cro_ro -p "$P_RO" --lua "$LUA" --mode readonly -s

ready_tcp 127.0.0.1 "$P_RW" || echo "  WARN: nothing listening on $P_RW"
ready_tcp 127.0.0.1 "$P_RO" || echo "  WARN: nothing listening on $P_RO"
sleep 0.5

ask() { python3 "$SOCKETLEY_TMPD/resp.py" "$1" "GET ops:$2" | head -1; }

# ── the truth test, both ways round ────────────────────────────────────────
#
# The control comes first: on a writable cache the branch MUST be taken, or the
# assertion below would also pass against a build where sadd never succeeds.
check "readwrite: the branch is taken, and sadd answers 1" \
      "branch=TAKEN value=1" "$(ask "$P_RW" truthtest)"

check "readonly: the branch is NOT taken, and sadd answers nil" \
      "branch=NOT-TAKEN value=nil" "$(ask "$P_RO" truthtest)"

# ── 1 and 0 both survive ───────────────────────────────────────────────────
# nil is only for the refusal: "already a member" is still 0, and 0 is still a
# number, so a script comparing == 1 keeps working.
check "readwrite: added then already-present" \
      "first=1 second=0" "$(ask "$P_RW" addtwice)"

# ── the mode is askable, and its neighbours are not ────────────────────────
check "readwrite: mode and the neighbours that succeed" \
      "mode=readwrite set=true del=true" "$(ask "$P_RW" mode)"

# `set` and `del` answer false here for a reason the script cannot see from the
# value alone -- it is the same false they give for a key that was not there.
# self.cache_mode() is what makes that readable, and it is the assertion.
check "readonly: false from set and del, with the reason askable" \
      "mode=readonly set=false del=false" "$(ask "$P_RO" mode)"

# ── and the wire still says it in as many words ────────────────────────────
# The asymmetry that made this worth fixing: this diagnosis was always here for
# a client and never for the script running inside the same runtime.
WIRE=$(python3 "$SOCKETLEY_TMPD/resp.py" "$P_RO" "SET direct v" | head -1)
TOTAL=$((TOTAL+1))
if grep -qi "readonly" <<<"$WIRE"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [the wire still names readonly]: SET answered '$WIRE'"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
