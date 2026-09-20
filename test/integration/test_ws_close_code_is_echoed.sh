#!/usr/bin/env bash
# Integration test: the close this server sends back says what the client said.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# Every incoming CLOSE was answered with the pre-computed 1000 frame, whatever
# the client had put in it.  A client that said 1001 "going away" was told
# "normal closure"; one that said 1011 "internal error" was told the same; and
# a one-byte payload, which RFC 6455 5.5.1 forbids outright, was answered as if
# it were a polite goodbye.  RFC 6455 5.5.1: "If an endpoint receives a Close
# frame and did not previously send a Close frame, the endpoint MUST send a
# Close frame in response.  (When sending a Close frame in response, the
# endpoint typically echos the status code it received.)"
#
# The cost is not the frame, it is what reads it.  A client library that logs
# the close code, a proxy that counts 1011s, a browser devtools panel -- all of
# them were shown 1000 for connections that ended for six different reasons.
#
# ─── AND THE THREE ECHOES THAT WOULD BE WRONG ──────────────────────────────
#
# A naive echo is worse than none, in three ways this file pins down:
#
#   * a one-byte body is not a status code.  RFC 6455 5.5.1: "If there is a
#     body, the first two bytes of the body MUST be a 2-byte unsigned integer".
#     That is a protocol error and 7.4.1 gives 1002 for it.
#   * 1004, 1005, 1006 and 1015 "MUST NOT be set as a status code in a Close
#     control frame by an endpoint" (RFC 6455 7.4.1).  Echoing one means this
#     end committing the violation the peer just committed, so it is 1002 too.
#   * the reason string is the peer's bytes.  RFC 6455 asks for the status
#     code and says nothing about repeating the text, and sending it back is a
#     reflection path for nothing at all -- so the reply carries the code and
#     stops.
#
# ─── HOW IT IS ASSERTED ────────────────────────────────────────────────────
#
# One connection per case, because a close ends the one it is sent on.  Each
# prints the opcode, the code and the payload LENGTH of what came back, so a
# reply that echoes the reason too is distinguishable from one that does not --
# an assertion on the code alone would pass on the reflection this forbids.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: a CLOSE is answered with the client's own code ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

P=$((SL_PORT_BASE+1452))

daemon_isolate wsclosecode
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

cat > "$SOCKETLEY_TMPD/echo.lua" <<'LUAEOF'
function on_client_message(id, msg) self.send(id, "R:" .. msg) end
LUAEOF

"$BIN" create server wscc -p "$P" --lua "$SOCKETLEY_TMPD/echo.lua" -s >/dev/null 2>&1 \
    || daemon_required "create"
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$P" 2>/dev/null && break; sleep 0.1; done
sleep 0.4

python3 - "$P" > "$SOCKETLEY_TMPD/out.txt" 2>"$SOCKETLEY_TMPD/err.txt" <<'PYEOF' || true
import base64, os, socket, struct, sys

port = int(sys.argv[1])

def handshake():
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall(f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n"
              f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
              f"Sec-WebSocket-Version: 13\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = s.recv(4096)
        if not c: return None, b""
        buf += c
    head, rest = buf.split(b"\r\n\r\n", 1)
    return (s, rest) if b"101" in head.split(b"\r\n")[0] else (None, b"")

def frame(payload, opcode, fin=True):
    h = bytearray([(0x80 if fin else 0x00) | opcode])
    n = len(payload)
    if n < 126: h.append(0x80 | n)
    elif n < 65536: h.append(0x80 | 126); h += struct.pack("!H", n)
    else: h.append(0x80 | 127); h += struct.pack("!Q", n)
    m = os.urandom(4); h += m
    return bytes(h) + bytes(b ^ m[i % 4] for i, b in enumerate(payload))

# One whole server frame out of buf; the server never masks, so no key here.
def take(s, buf):
    while True:
        if len(buf) >= 2:
            op = buf[0] & 0x0F
            ln = buf[1] & 0x7F
            off = 2
            if ln == 126:
                if len(buf) < 4: ln = None
                else: ln = struct.unpack("!H", buf[2:4])[0]; off = 4
            elif ln == 127:
                if len(buf) < 10: ln = None
                else: ln = struct.unpack("!Q", buf[2:10])[0]; off = 10
            if ln is not None and len(buf) >= off + ln:
                return (op, buf[off:off+ln], buf[off+ln:])
        try:
            d = s.recv(65536)
        except Exception:
            return (None, b"", buf)
        if not d: return (None, b"", buf)
        buf += d

out = []

# What came back for one CLOSE payload, on a connection of its own.  Reported
# as opcode, status code and payload LENGTH: the length is what separates an
# echoed code from an echoed code AND the peer's reason bytes behind it.
def probe(name, payload):
    s, buf = handshake()
    if not s:
        out.append("%s handshake_failed" % name); return
    try:
        s.sendall(frame(payload, 0x8))
        op, pay, buf = take(s, buf)
    finally:
        s.close()
    if op is None:
        out.append("%s op=none" % name); return
    code = struct.unpack("!H", pay[:2])[0] if len(pay) >= 2 else -1
    out.append("%s op=%d code=%d len=%d" % (name, op, code, len(pay)))

def be(code): return struct.pack("!H", code)

# ─── the codes an endpoint may put on the wire, which are echoed ───────────
probe("empty",    b"")                 # no code at all to echo
probe("c1000",    be(1000))            # normal closure, the common case
probe("c1001",    be(1001))            # going away
probe("c1002",    be(1002))            # protocol error
probe("c1007",    be(1007))            # invalid frame payload data
probe("c1009",    be(1009))            # message too big
probe("c1011",    be(1011))            # internal error
probe("c3000",    be(3000))            # 7.4.2 library/framework range
probe("c4999",    be(4999))            # 7.4.2 private-use range
probe("reason",   be(1000) + b"bye-now")

# ─── and the ones that may not, which are refused with 1002 ────────────────
probe("onebyte",  b"\x03")             # 5.5.1: a code is two bytes
probe("c1004",    be(1004))            # 7.4.1 reserved, undefined
probe("c1005",    be(1005))            # 7.4.1 MUST NOT be sent
probe("c1006",    be(1006))            # 7.4.1 MUST NOT be sent
probe("c1015",    be(1015))            # 7.4.1 MUST NOT be sent
probe("c999",     be(999))             # 7.4.2: 0-999 are not used
probe("c2000",    be(2000))            # 7.4.2: reserved to the protocol, undefined
probe("badutf8",  be(1000) + b"\xff\xfe")  # 5.5.1: the reason is UTF-8

print("\n".join(out))
PYEOF

OUT=$(cat "$SOCKETLEY_TMPD/out.txt" 2>/dev/null || true)
line() { grep -m1 "^$1 " <<<"$OUT" || true; }

# opcode 8 is CLOSE.  `len=2` is asserted everywhere on purpose: it is the
# assertion that the reason string did not come back with the code.
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$2', got '${3:-<nothing>}'"; fi; }

echo "  -- codes an endpoint may send are echoed back --"
check "a close with no code is answered 1000"  "empty op=8 code=1000 len=2" "$(line empty)"
check "1000 comes back as 1000"                "c1000 op=8 code=1000 len=2" "$(line c1000)"
check "1001 comes back as 1001"                "c1001 op=8 code=1001 len=2" "$(line c1001)"
check "1002 comes back as 1002"                "c1002 op=8 code=1002 len=2" "$(line c1002)"
check "1007 comes back as 1007"                "c1007 op=8 code=1007 len=2" "$(line c1007)"
check "1009 comes back as 1009"                "c1009 op=8 code=1009 len=2" "$(line c1009)"
check "1011 comes back as 1011"                "c1011 op=8 code=1011 len=2" "$(line c1011)"
check "3000 comes back as 3000"                "c3000 op=8 code=3000 len=2" "$(line c3000)"
check "4999 comes back as 4999"                "c4999 op=8 code=4999 len=2" "$(line c4999)"
check "a reason string is not sent back"       "reason op=8 code=1000 len=2" "$(line reason)"

echo "  -- codes an endpoint may not send are refused with 1002 --"
check "a one-byte body is a protocol error"    "onebyte op=8 code=1002 len=2" "$(line onebyte)"
check "reserved 1004 is not echoed"            "c1004 op=8 code=1002 len=2" "$(line c1004)"
check "reserved 1005 is not echoed"            "c1005 op=8 code=1002 len=2" "$(line c1005)"
check "reserved 1006 is not echoed"            "c1006 op=8 code=1002 len=2" "$(line c1006)"
check "reserved 1015 is not echoed"            "c1015 op=8 code=1002 len=2" "$(line c1015)"
check "999 is below the defined range"         "c999 op=8 code=1002 len=2"   "$(line c999)"
check "2000 is undefined in the protocol range" "c2000 op=8 code=1002 len=2" "$(line c2000)"
check "a reason that is not UTF-8 is 1007"     "badutf8 op=8 code=1007 len=2" "$(line badutf8)"

# Eighteen closes in a row must not have cost the runtime anything: a build
# that answered them by falling over would pass every line above.
TOTAL=$((TOTAL+1))
if "$BIN" stats wscc >/dev/null 2>&1; then
    PASS=$((PASS+1)); echo "  PASS: the runtime is still up afterwards"
else
    FAIL=$((FAIL+1)); echo "  FAIL [runtime alive]: the server did not survive eighteen closes"
fi

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || {
    echo "  --- what python reported ---"
    echo "$OUT" | sed 's/^/      /'
    sed 's/^/      /' "$SOCKETLEY_TMPD/err.txt" 2>/dev/null | head -20
    exit 1
}
