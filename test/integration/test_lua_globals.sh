#!/usr/bin/env bash
# Integration test: the socketley.* globals — JSON, timers, the management
# calls, and the HTTP client.
#
# ─── THE JSON EDGES ─────────────────────────────────────────────────────────
#
# Three of them, all of them the kind that is discovered by a consumer rather
# than by a test:
#
#   * {1,2,3} is an ARRAY and {[1]=1,[3]=3} is an OBJECT.  One Lua type, two
#     JSON types, decided by whether the integer keys run 1..n without a hole.
#     A change to that rule turns a config file into a different config file
#     and nothing in the encoder is wrong afterwards.
#   * 5 encodes as `5`, not `5.0`.  Every Lua number is a double, so the naive
#     encoder produces the second and every strict consumer downstream — a
#     schema expecting an integer, a Go decoder, anything at all — rejects it.
#   * null decodes to nil, so a key that was present becomes a key that is not.
#
# The sparse-table assertion is deliberately not an exact string: the object's
# keys come out in Lua table order, which is not defined.  What is asserted is
# that it is an object at all and that both pairs are in it — the claim being
# made — rather than a byte order nothing promises.
#
# ─── THE TIMERS ─────────────────────────────────────────────────────────────
#
# Each of the four calls is asserted with the case that separates it from doing
# nothing: a timeout fires ONCE, a cleared timeout fires NEVER, an interval
# fires REPEATEDLY, and a cleared interval STOPS.  "The callback ran" on its own
# says nothing about any of them.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_create.sh"

daemon_isolate luaglobals

PB=${SOCKETLEY_PORT_BASE:-19350}
RPC_PORT=$((PB + 0))    # the script under test, in the daemon
HTTP_PORT=$((PB + 1))   # what socketley.http dials
MADE_PORT=$((PB + 2))   # the runtime the script creates and removes

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
assert_has() {
    local label=$1 needle=$2 hay=$3; shift 3
    if [ "${hay#*"$needle"}" != "$hay" ]; then pass; else
        fail "$label" "'$needle' is not in '$hay'" "$@"
    fi
}

cleanup() {
    touch "${HTTPD_STOP:-/dev/null}" 2>/dev/null || true
    [ -n "${HTTPD_PID:-}" ] && wait "$HTTPD_PID" 2>/dev/null
    "$BIN" stop  glob made 2>/dev/null || true
    sleep 0.3
    "$BIN" remove glob made 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: the socketley.* globals ==="

daemon_start "$BIN"

# ── The HTTP target is NOT a socketley server, and that is a finding ────────
#
# socketley.http sends `GET <path> HTTP/1.0` with `Connection: close` and then
# reads until the peer closes — it does not stop at Content-Length.  socketley's
# own --http file server never closes: measured against it, an HTTP/1.0 request
# carrying `Connection: close` gets its 103 bytes of complete response and the
# socket is still open two seconds later, and so are HTTP/1.1 with and without
# the header.  The two together mean a script cannot fetch from this project's
# own HTTP server: socketley.http returns `ok=false status=0 error=response
# timed out` with an empty body, for a response that arrived in full.  Reported
# separately; it is a product defect and not this file's to work around by
# weakening an assertion.
#
# So the target here is a server that closes, which is what makes the four
# assertions below about socketley.http rather than about that.  It answers 200
# with a known body for /probe.txt and 404 for anything else, one request per
# connection, HTTP/1.0.
cat > "$SOCKETLEY_TMPD/httpd.py" <<'PYEOF'
import os, socket, sys, threading
port, stop_path = int(sys.argv[1]), sys.argv[2]
ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", port))
ls.listen(16)
ls.settimeout(0.2)
BODY = b"HTTP-BODY-FROM-SOCKETLEY"

def serve(c):
    try:
        c.settimeout(2)
        req = c.recv(65536).decode("latin-1")
        path = req.split(" ")[1] if " " in req else "/"
        if path.split("?")[0] == "/probe.txt":
            head = b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(BODY)
            c.sendall(head + BODY)
        else:
            c.sendall(b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass

while not os.path.exists(stop_path):
    try:
        c, _ = ls.accept()
    except socket.timeout:
        continue
    except Exception:
        break
    threading.Thread(target=serve, args=(c,), daemon=True).start()
ls.close()
PYEOF
HTTPD_STOP="$SOCKETLEY_TMPD/httpd.stop"
python3 "$SOCKETLEY_TMPD/httpd.py" "$HTTP_PORT" "$HTTPD_STOP" &
HTTPD_PID=$!

# ask PORT TEXT [BUDGET] — one line in, everything that comes back, flattened.
cat > "$SOCKETLEY_TMPD/ask.py" <<'PYEOF'
import select, socket, sys, time
port, text, budget = int(sys.argv[1]), sys.argv[2], float(sys.argv[3])
s = socket.create_connection(("127.0.0.1", port), 5)
s.sendall((text + "\n").encode())
out, end = b"", time.time() + budget
while time.time() < end:
    r, _, _ = select.select([s], [], [], 0.05)
    if not r:
        continue
    try:
        d = s.recv(65536)
    except Exception:
        break
    if not d:
        break
    out += d
s.close()
print(out.decode("latin-1").replace("\r", "").strip())
PYEOF
ask() { python3 "$SOCKETLEY_TMPD/ask.py" "$1" "$2" "${3:-2.0}"; }

RPC_LUA="$SOCKETLEY_TMPD/glob.lua"
cat > "$RPC_LUA" <<LUAEOF
local HTTP_URL = "http://127.0.0.1:$HTTP_PORT/probe.txt"
local MADE_PORT = $MADE_PORT
LUAEOF
cat >> "$RPC_LUA" <<'LUAEOF'
local function reply(id, s) self.send(id, s) end
local function words(msg)
    local out = {}
    for w in msg:gmatch("%S+") do out[#out+1] = w end
    return out
end

local ticks = 0

function on_client_message(id, msg)
    local a = words(msg)
    local cmd = a[1]
    local e = socketley.json_encode

    if cmd == "encode" then
        reply(id, table.concat({
            "arr=" .. e({1,2,3}),
            "sparse=" .. e({[1]=1,[3]=3}),
            "int=" .. e(5),
            "float=" .. e(2.5),
            "str=" .. e("hi"),
            "bool=" .. e(true),
            "obj=" .. e({a=1}),
            "nested=" .. e({a={1,2},b={c="d"}}),
            "esc=" .. e('a"b'),
        }, " "))

    elseif cmd == "decode" then
        local d = socketley.json_decode(
            '{"n":42,"s":"x","b":true,"a":[1,2,3],"o":{"k":"v"},"z":null}')
        reply(id, table.concat({
            "n=" .. tostring(d.n),
            "s=" .. tostring(d.s),
            "b=" .. tostring(d.b),
            "a1=" .. tostring(d.a[1]),
            "a3=" .. tostring(d.a[3]),
            "alen=" .. tostring(#d.a),
            "ok=" .. tostring(d.o.k),
            "z=" .. tostring(d.z),
            "roundtrip=" .. e(socketley.json_decode('[1,2,3]')),
        }, " "))

    elseif cmd == "timers" then
        -- One that must fire, one that must not, an interval that must repeat
        -- and then stop.  The counters are logged so the shell can read what
        -- happened after the fact rather than being told a summary now.
        socketley.set_timeout(120, function() socketley.log("T fired-once") end)
        local doomed = socketley.set_timeout(120, function()
            socketley.log("T fired-cleared")
        end)
        socketley.clear_timeout(doomed)

        local n = 0
        local iv
        iv = socketley.set_interval(60, function()
            n = n + 1
            socketley.log("T interval=" .. tostring(n))
            if n == 4 then socketley.clear_interval(iv) end
        end)
        reply(id, "scheduled ids_positive=" .. tostring(doomed > 0 and iv > 0))

    elseif cmd == "list" then
        local names = socketley.list()
        local found = false
        for _, n in ipairs(names) do if n == "glob" then found = true end end
        reply(id, "list=" .. tostring(#names) .. " has_self=" .. tostring(found))

    elseif cmd == "getinfo" then
        local i = socketley.get(a[2])
        if not i then reply(id, "get=nil") return end
        reply(id, "name=" .. i.name .. " type=" .. i.type ..
                  " state=" .. i.state .. " port=" .. tostring(i.port))

    elseif cmd == "getmissing" then
        reply(id, "get=" .. tostring(socketley.get("nosuchruntime")))

    elseif cmd == "make" then
        local ok = socketley.create("server", "made", { port = MADE_PORT, start = true })
        reply(id, "create=" .. tostring(ok))

    elseif cmd == "stopmade" then
        local ok = socketley.stop("made")
        local i = socketley.get("made")
        reply(id, "stop=" .. tostring(ok) .. " state=" .. tostring(i and i.state))

    elseif cmd == "startmade" then
        local ok = socketley.start("made")
        local i = socketley.get("made")
        reply(id, "start=" .. tostring(ok) .. " state=" .. tostring(i and i.state))

    elseif cmd == "removemade" then
        local ok = socketley.remove("made")
        reply(id, "remove=" .. tostring(ok) ..
                  " gone=" .. tostring(socketley.get("made") == nil))

    elseif cmd == "http" then
        local r = socketley.http({ url = HTTP_URL, timeout_ms = 3000 })
        reply(id, "ok=" .. tostring(r.ok) ..
                  " status=" .. tostring(r.status) ..
                  " body=[" .. tostring(r.body):gsub("%s+$", "") .. "]")

    elseif cmd == "http404" then
        local r = socketley.http({ url = HTTP_URL .. ".missing", timeout_ms = 3000 })
        reply(id, "ok=" .. tostring(r.ok) .. " status=" .. tostring(r.status))
    end
end
LUAEOF

hits() { grep -ac "$1" "$2" 2>/dev/null || true; }

# In the daemon, not a worker: every management call below reaches for the
# runtime map, and a worker holds none — those calls are refused there by
# design, which test_worker_lua_refusal.sh already covers.
create_ok "RPC server created in the daemon" "$BIN" create server glob \
    -p "$RPC_PORT" --mode in --lua "$RPC_LUA" --daemon-process -s
ready_tcp 127.0.0.1 "$RPC_PORT" 10 || echo "  NOTE: the RPC server never accepted"
ready_http 127.0.0.1 "$HTTP_PORT" /probe.txt 15 || echo "  NOTE: the HTTP target never answered"

# ── 1. json_encode ─────────────────────────────────────────────────────────
ENC=$(ask "$RPC_PORT" encode)
assert_has "a table with keys 1..n encodes as a JSON array" "arr=[1,2,3]" "$ENC" "got: $ENC"
# ─── THIS ASSERTION IS RED ON THE SANITIZE BUILD, AND THE BUILD IS WRONG ────
#
# The man page states the contract: "Tables with consecutive integer keys
# starting at 1 are encoded as JSON arrays; all others as objects."  Release
# honours it and answers {"3":3,"1":1}.  The Sanitize build THROWS:
#
#     [sol2] An exception occurred: caught (...) exception
#
# and the script gets a Lua error instead of a string.  The object branch of
# json_encode_value does
#
#     json_encode_string(out, kv.first.as<std::string>());
#
# on a key that is a NUMBER here.  Release defines NDEBUG, so sol2's safety
# checks are off and as<std::string>() takes LuaJIT's number-to-string
# coercion; Sanitize defines DEBUG, the checks are on, and the same call
# type-checks and throws.  Every other input this file encodes passes on both
# builds — bisected one value at a time.
#
# Left asserting the documented behaviour on purpose.  Relaxing it to match the
# Sanitize build would be writing the bug down as the contract, and the man page
# already says otherwise.
assert_has "a table with a hole encodes as a JSON object" "sparse={" "$ENC" \
    "one Lua type, two JSON types, decided by whether the integer keys run" \
    "1..n without a gap" "got: $ENC"
assert_has "...with the first pair in it"  '"1":1' "$ENC" "got: $ENC"
assert_has "...and the second"             '"3":3' "$ENC" \
    "asserted as two contains rather than one exact string: the key order of" \
    "a Lua table is not defined and nothing promises it" "got: $ENC"
assert_has "an integer-valued number encodes without a decimal point" "int=5 " "$ENC" \
    "every Lua number is a double; 5.0 is what the naive encoder emits and" \
    "what a strict consumer downstream rejects" "got: $ENC"
assert_has "a fractional number keeps its fraction" "float=2.5" "$ENC" "got: $ENC"
assert_has "strings are quoted"      'str="hi"' "$ENC" "got: $ENC"
assert_has "booleans are bare"       "bool=true" "$ENC" "got: $ENC"
assert_has "string keys make an object" 'obj={"a":1}' "$ENC" "got: $ENC"
# Two contains, not one exact string, for the same reason as the sparse table
# above: the outer object's key order is Lua table order.  What is asserted is
# that an array nested in an object stays an array and an object stays an
# object, which is the claim.
assert_has "an array nested in an object stays an array" '"a":[1,2]' "$ENC" "got: $ENC"
assert_has "an object nested in an object stays an object" '"b":{"c":"d"}' "$ENC" "got: $ENC"
assert_has "a quote inside a string is escaped" 'esc="a\"b"' "$ENC" "got: $ENC"

# ── 2. json_decode ─────────────────────────────────────────────────────────
DEC=$(ask "$RPC_PORT" decode)
assert_has "numbers decode"                "n=42" "$DEC" "got: $DEC"
assert_has "strings decode"                "s=x" "$DEC" "got: $DEC"
assert_has "booleans decode"               "b=true" "$DEC" "got: $DEC"
assert_has "arrays decode 1-based"         "a1=1" "$DEC" "got: $DEC"
assert_has "...to the end"                 "a3=3" "$DEC" "got: $DEC"
assert_has "...with the right length"      "alen=3" "$DEC" "got: $DEC"
assert_has "nested objects decode"         "ok=v" "$DEC" "got: $DEC"
assert_has "null decodes to nil"           "z=nil" "$DEC" \
    "a key that was present becomes a key that is not, which is the one" \
    "decode result a caller has to be told about" "got: $DEC"
assert_has "an array survives a round trip" "roundtrip=[1,2,3]" "$DEC" "got: $DEC"

# ── 3. the timers ──────────────────────────────────────────────────────────
TIM=$(ask "$RPC_PORT" timers)
assert_has "set_timeout and set_interval both hand back an id" \
           "ids_positive=true" "$TIM" \
    "0 is the failure return, so an id that is not positive means nothing" \
    "was scheduled" "got: $TIM"
sleep 1.2
assert_eq "set_timeout fires, once" "1" "$(hits 'T fired-once' "$SOCKETLEY_DLOG")" \
    "once and not twice: a timeout that repeats is an interval"
assert_eq "clear_timeout stops one that had not fired yet" \
          "0" "$(hits 'T fired-cleared' "$SOCKETLEY_DLOG")" \
    "the two timeouts were scheduled together with the same delay, so this" \
    "is the same clock and the same turn of the loop — the only difference" \
    "is the clear"
assert_eq "set_interval repeats" "1" "$(hits 'T interval=4' "$SOCKETLEY_DLOG")" \
    "a fourth firing cannot be produced by a one-shot"
sleep 0.8
assert_eq "clear_interval stops it" "0" "$(hits 'T interval=5' "$SOCKETLEY_DLOG")" \
    "asserted after a further second, so 'it had not got there yet' is not" \
    "an explanation"

# ── 4. socketley.list / .get ───────────────────────────────────────────────
LST=$(ask "$RPC_PORT" list)
assert_has "socketley.list() names this runtime among the others" \
           "has_self=true" "$LST" "got: $LST"
assert_eq "socketley.list() counts every runtime the daemon holds" \
          "list=1 has_self=true" "$LST" \
    "one exists at this point, and the count moves below when the script" \
    "creates another — which is what says this is a count and not a constant" \
    "got: $LST"
assert_eq "socketley.get() answers with the runtime's own fields" \
          "name=glob type=server state=running port=$RPC_PORT" \
          "$(ask "$RPC_PORT" "getinfo glob")"
assert_eq "socketley.get() of a name that does not exist is nil" \
          "get=nil" "$(ask "$RPC_PORT" getmissing)"

# ── 5. socketley.create / .stop / .remove ──────────────────────────────────
assert_eq "socketley.create() with start=true brings a runtime up" \
          "create=true" "$(ask "$RPC_PORT" make)"
sleep 0.6
assert_eq "...and the daemon's own inventory has it running" \
          "name=made type=server state=running port=$MADE_PORT" \
          "$(ask "$RPC_PORT" "getinfo made")" \
    "asked of socketley.get rather than of the create's return value, which" \
    "is true for a runtime that was built and never started"
assert_eq "...and socketley.list() counts it too" \
          "list=2 has_self=true" "$(ask "$RPC_PORT" list)" \
    "the count moved with the inventory, which a constant cannot do"
assert_eq "socketley.stop() stops it" \
          "stop=true state=stopped" "$(ask "$RPC_PORT" stopmade)"
assert_eq "socketley.start() brings the stopped runtime back up" \
          "start=true state=running" "$(ask "$RPC_PORT" startmade)" \
    "asked of socketley.get afterwards rather than of the return value, which" \
    "is what stop already returned for a runtime it had not stopped"
assert_eq "socketley.remove() removes it, and it is gone afterwards" \
          "remove=true gone=true" "$(ask "$RPC_PORT" removemade)" \
    "the second half is the assertion: remove returning true is what it" \
    "returned for a runtime it had not removed"
LEFT=$("$BIN" ls 2>/dev/null | grep -c ' made ' || true)
assert_eq "...and the CLI agrees it is gone" "0" "$LEFT"

# ── 6. socketley.http ──────────────────────────────────────────────────────
assert_eq "socketley.http() fetches a body over HTTP" \
          "ok=true status=200 body=[HTTP-BODY-FROM-SOCKETLEY]" \
          "$(ask "$RPC_PORT" http 4.0)"
assert_eq "socketley.http() reports a non-2xx as not ok, with the status" \
          "ok=false status=404" "$(ask "$RPC_PORT" http404 4.0)" \
    "the status is the half that says the request was made and answered;" \
    "ok=false alone is also what a connection failure produces"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
