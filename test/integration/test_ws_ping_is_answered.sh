#!/usr/bin/env bash
# Integration test: a valid PING is answered with a PONG carrying the same
# bytes, and answering it does not disturb the stream around it.
#
# ─── WHY THIS DID NOT EXIST ────────────────────────────────────────────────
#
# The server has answered PING with PONG since it had websockets, and nothing
# checked it.  The only 0x9 anywhere in the suite was in
# test_ws_malformed_frames.sh, and both times it was an INVALID ping -- a
# fragmented one and a 200-byte one -- so what was covered was the refusal and
# never the answer.  The fuzz corpus reaches the parser and stops there.
#
# RFC 6455 5.5.3: a Pong MUST carry the same Application data as the Ping it
# answers.  A server that replies with an empty pong to a ping with a payload
# is wrong in a way no throughput number would ever show, and a browser that
# uses the payload as a round-trip token would simply stop trusting the link.
#
# ─── AND WHAT IT GUARDS NOW ────────────────────────────────────────────────
#
# The pong used to be built with make_shared + resize -- two allocations per
# ping -- and is now written into the write queue's tail, which means it may
# SHARE an entry with the data frame beside it.  Frames are self-delimiting so
# that is legal, but it is exactly the change that could corrupt a stream if
# the header or the length were written wrong.  Three of the four assertions
# below are about the bytes and not about the pong arriving at all.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: a valid PING is answered with the same bytes ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

P=$((SL_PORT_BASE+1446))

daemon_isolate wsping
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

cat > "$SOCKETLEY_TMPD/echo.lua" <<'LUAEOF'
function on_client_message(id, msg) self.send(id, "R:" .. msg) end
LUAEOF

"$BIN" create server wsp -p "$P" --lua "$SOCKETLEY_TMPD/echo.lua" -s >/dev/null 2>&1
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$P" 2>/dev/null && break; sleep 0.1; done
sleep 0.4

python3 - "$P" > "$SOCKETLEY_TMPD/out.txt" 2>/dev/null <<'PYEOF'
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
                if buf[1] & 0x80: return ("MASKED", b"", buf[off+ln:])
                return (op, buf[off:off+ln], buf[off+ln:])
        d = s.recv(65536)
        if not d: return (None, b"", buf)
        buf += d

out = []

# 1. PING with a payload -- the pong must carry the same bytes (RFC 5.5.3).
s, buf = handshake()
if s:
    token = b"ping-token-1234567890"
    s.sendall(frame(token, 0x9))
    op, pay, buf = take(s, buf)
    out.append("payload_pong op=%s same=%s" % (op, "yes" if pay == token else "no:" + repr(pay[:40])))

    # 2. Empty PING -- the shape a browser keepalive sends, and the one the
    #    two-byte pong takes through the SSO.
    s.sendall(frame(b"", 0x9))
    op, pay, buf = take(s, buf)
    out.append("empty_pong op=%s len=%d" % (op, len(pay)))

    # 3. A PING in the middle of an open fragmented message must be answered
    #    before the message completes -- the code says "process immediately,
    #    even mid-fragment" and nothing checked it.
    s.sendall(frame(b"AA", 0x1, fin=False))
    s.sendall(frame(b"mid", 0x9))
    op, pay, buf = take(s, buf)
    out.append("midfrag_first op=%s pay=%s" % (op, pay.decode("latin1")))
    s.sendall(frame(b"BB", 0x0, fin=True))
    op, pay, buf = take(s, buf)
    out.append("midfrag_then op=%s pay=%s" % (op, pay.decode("latin1")))

    # 4. And the stream is still intact afterwards: a pong may now share a
    #    write-queue entry with a data frame, so a wrong header or length here
    #    would desynchronise everything behind it.
    s.sendall(frame(b"after", 0x1))
    op, pay, buf = take(s, buf)
    out.append("after_op=%s pay=%s" % (op, pay.decode("latin1")))
    s.close()
else:
    out.append("handshake failed")

print("\n".join(out))
PYEOF

OUT=$(cat "$SOCKETLEY_TMPD/out.txt" 2>/dev/null || true)
line() { grep -m1 "^$1" <<<"$OUT" || true; }

# opcode 10 is PONG (0xA).  Each of these would catch a different broken build:
# a pong with the wrong bytes, an empty pong, control frames queued behind
# data, and a frame header written wrong by the _into path.
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$2', got '$3'"; fi; }

check "a ping's pong carries the same bytes" "payload_pong op=10 same=yes" "$(line payload_pong)"
check "an empty ping gets an empty pong"     "empty_pong op=10 len=0"      "$(line empty_pong)"
check "a ping mid-fragment is answered first" "midfrag_first op=10 pay=mid" "$(line midfrag_first)"
check "and the fragmented message still arrives whole" "midfrag_then op=1 pay=R:AABB" "$(line midfrag_then)"
check "and the stream behind it is intact"   "after_op=1 pay=R:after"      "$(line after_op)"

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || { echo "  --- was python reported ---"; echo "$OUT" | sed 's/^/      /'; exit 1; }
