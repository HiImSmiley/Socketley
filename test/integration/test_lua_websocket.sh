#!/usr/bin/env bash
# Integration test: on_websocket and self.ws_headers.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# test_websocket.sh asserts on the 101 and the response headers;
# test_websocket_data.sh asserts that frame payloads survive.  Neither has ever
# defined a Lua callback, so on_websocket and self.ws_headers — the only way a
# script can see who upgraded and what they said in the upgrade request — were
# executed by nothing.
#
# ─── WHAT IS ASSERTED, AND WHY IT IS THE HEADERS AND NOT THE FIRING ─────────
#
# The upgrade request carries four headers the script is given: Cookie, Origin,
# Sec-WebSocket-Protocol and Authorization.  Each is sent with a distinct value
# and each is asserted by that value, because "on_websocket fired" is satisfied
# by a build that hands the script an empty table — which is exactly what the
# callback does today for every header the request did not carry, so an empty
# table is not distinguishable from a missing one by any weaker check.
#
# Three further claims, each with the case that separates it from a no-op:
#
#   * on_websocket fires AFTER on_connect, which the man page states and nothing
#     checked.  The order is recorded by the script and asserted as a sequence.
#   * self.ws_headers(id) returns the SAME four values when asked later, from a
#     different callback — the table handed to on_websocket could be built once
#     and thrown away, and a script that asks on a later message would then get
#     nothing.
#   * self.ws_headers(id) is NIL for a plain TCP client on the same server.  A
#     build that returned a table for everything satisfies every assertion above
#     it; this is the one that says the answer depends on the connection.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luaws

PB=$((SL_PORT_BASE+360))
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
    "$BIN" stop ws_srv 2>/dev/null || true
    sleep 0.3
    "$BIN" remove ws_srv 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: on_websocket and self.ws_headers ==="

daemon_start "$BIN"

LUA="$SOCKETLEY_TMPD/ws.lua"
cat > "$LUA" <<'LUAEOF'
-- One line per event, carrying every value, so a missing header and an empty
-- one are different strings rather than both being "no line".
local function show(h)
    return "cookie=[" .. tostring(h and h.cookie or "") .. "]" ..
           " origin=[" .. tostring(h and h.origin or "") .. "]" ..
           " protocol=[" .. tostring(h and h.protocol or "") .. "]" ..
           " auth=[" .. tostring(h and h.authorization or "") .. "]"
end

local order = {}

function on_connect(id)
    order[id] = "on_connect"
end

function on_websocket(id, headers)
    order[id] = (order[id] or "none") .. ",on_websocket"
    socketley.log("WS order=" .. order[id])
    socketley.log("WS cb " .. show(headers))
end

function on_client_message(id, msg)
    -- Asked from a later callback, on purpose: the table on_websocket was
    -- handed could have been built for that call alone.
    socketley.log("WS later " .. show(self.ws_headers(id)))
    socketley.log("WS isnil=" .. tostring(self.ws_headers(id) == nil))
end
LUAEOF

cat > "$SOCKETLEY_TMPD/ws.py" <<'PYEOF'
import base64, hashlib, os, socket, struct, sys, time

port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=5)
key = base64.b64encode(os.urandom(16)).decode()
s.sendall((
    "GET / HTTP/1.1\r\n"
    f"Host: 127.0.0.1:{port}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Cookie: sid=COOKIE-VALUE\r\n"
    "Origin: https://ORIGIN-VALUE\r\n"
    "Sec-WebSocket-Protocol: PROTOCOL-VALUE\r\n"
    "Authorization: Bearer AUTH-VALUE\r\n"
    "\r\n"
).encode())
buf = b""
while b"\r\n\r\n" not in buf:
    chunk = s.recv(4096)
    if not chunk:
        sys.exit("server closed during handshake")
    buf += chunk
if b"101" not in buf.split(b"\r\n")[0]:
    sys.exit("upgrade failed: " + buf.split(b"\r\n")[0].decode("latin-1"))
print("upgraded")

def frame(payload, opcode=0x1, fin=True):
    header = bytearray([(0x80 if fin else 0x00) | opcode])
    n = len(payload)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126); header += struct.pack("!H", n)
    else:
        header.append(0x80 | 127); header += struct.pack("!Q", n)
    mask = os.urandom(4)
    header += mask
    return bytes(header) + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

time.sleep(0.3)
s.sendall(frame(b"ask-headers"))
time.sleep(0.5)
s.close()
PYEOF

said() {
    local pattern=$1 deadline=$(( $(date +%s) + ${2:-8} ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        grep -qaE "$pattern" "$SOCKETLEY_DLOG" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}
# -F, and that is load-bearing: every value asserted here is wrapped in square
# brackets so an empty header is visible as [], and a bracket in a basic regex
# is a character class.  Without -F, `cookie=[sid=COOKIE-VALUE]` matches
# "cookie=" followed by any one of those letters — which is to say it matches
# the wrong thing and then does not match the right one.
hits() { grep -acF "$1" "$2" 2>/dev/null || true; }
line() {
    { grep -aoE "$1" "$SOCKETLEY_DLOG" 2>/dev/null || true; } | head -1
}

create_ok "server created with a websocket script" "$BIN" create server ws_srv \
    -p "$PORT" --mode in --lua "$LUA" -s
ready_tcp 127.0.0.1 "$PORT" 10 || echo "  NOTE: the server never accepted"

UP=$(python3 "$SOCKETLEY_TMPD/ws.py" "$PORT" 2>&1 || true)
assert_eq "control: the upgrade succeeded" "upgraded" "$UP" \
    "every assertion below is about a callback that only fires for an" \
    "upgraded connection"

said 'WS cb ' 10 || true
said 'WS later ' 10 || true

WANT="cookie=[sid=COOKIE-VALUE] origin=[https://ORIGIN-VALUE] protocol=[PROTOCOL-VALUE] auth=[Bearer AUTH-VALUE]"

assert_eq "on_websocket is handed every header the upgrade request carried" \
          "1" "$(hits "WS cb $WANT" "$SOCKETLEY_DLOG")" \
    "asserted by the four values, not by the callback firing: the table is" \
    "built with only the headers that were present, so an empty one is what" \
    "a build that reads none of them produces and no weaker check sees it" \
    "got: $(line 'WS cb .*')"

assert_eq "on_websocket fires after on_connect" \
          "1" "$(hits 'WS order=on_connect,on_websocket' "$SOCKETLEY_DLOG")" \
    "the man page states the order and nothing checked it" \
    "got: $(line 'WS order=[a-z_,]*')"

assert_eq "self.ws_headers() answers the same values from a later callback" \
          "1" "$(hits "WS later $WANT" "$SOCKETLEY_DLOG")" \
    "the table on_websocket was handed could have been built for that call" \
    "alone; this is asked from on_client_message, one message later" \
    "got: $(line 'WS later .*')"

assert_eq "...and it is not nil for an upgraded connection" \
          "1" "$(hits 'WS isnil=false' "$SOCKETLEY_DLOG")"

# ── The negative: a plain TCP client on the same server ────────────────────
printf 'ask-headers\n' | timeout 5 nc -q 1 127.0.0.1 "$PORT" >/dev/null 2>&1 || true
said 'WS isnil=true' 10 || true
assert_eq "self.ws_headers() is nil for a plain TCP client" \
          "1" "$(hits 'WS isnil=true' "$SOCKETLEY_DLOG")" \
    "same server, same callback, a connection that never upgraded — without" \
    "this, every assertion above is satisfied by a build that answers with a" \
    "table for anything at all"
assert_eq "...and it reports no headers for it either" \
          "1" "$(hits "WS later cookie=[] origin=[] protocol=[] auth=[]" "$SOCKETLEY_DLOG")"
assert_eq "on_websocket did not fire for the TCP client" \
          "1" "$(hits 'WS cb ' "$SOCKETLEY_DLOG")" \
    "one call in the whole run, from the one connection that upgraded"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
