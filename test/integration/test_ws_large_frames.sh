#!/usr/bin/env bash
# Integration test: the 64-bit length form works, and a frame past what this
# runtime buffers is refused with 1009 instead of dropped in silence.
#
# ─── TWO GAPS, ONE FIXTURE ─────────────────────────────────────────────────
#
# FIRST: no test anywhere parsed a VALID 64-bit frame.  test_ws_parser.cpp has
# one row with length 127 and it checks the REFUSAL of a 17 MB declaration;
# test_websocket_data.sh stops at 300 bytes, which is the 16-bit form.  The
# only valid 64-bit frame in the tree is a fuzz seed, and that reaches the
# parser and nothing behind it.  70 KB below exercises the eight-byte length
# end to end.
#
# SECOND, and this one was a defect: the two size limits did not agree and
# nobody was told.  ws_parse_header accepts up to WS_MAX_PAYLOAD, 16 MB; a
# server buffers read_buffer_bytes(), 1 MiB by default.  A frame between them
# hit
#
#     if (conn->partial.size() > read_buffer_bytes()) { conn->closing = true; }
#
# and that was the whole of it: no close frame, no status, no log line.
# Measured before the fix -- 900 KB was echoed, 2 MB got an empty answer and a
# dead socket, and the daemon log said nothing at all.
#
# 1009 (message too big) and not 1002 (protocol error), because the frame was
# well formed and this end simply will not hold it.  A peer told "protocol
# error" concludes its own framing is broken and sends the same message again.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: large WebSocket frames, and the one this runtime refuses ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$2', got '$3'"; fi; }

P=$((SL_PORT_BASE+1450))

daemon_isolate wsbig
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

cat > "$SOCKETLEY_TMPD/len.lua" <<'LUAEOF'
function on_client_message(id, msg) self.send(id, "len=" .. string.len(msg)) end
LUAEOF

"$BIN" create server wsb -p "$P" --lua "$SOCKETLEY_TMPD/len.lua" >/dev/null 2>&1
"$BIN" start wsb >/dev/null 2>&1
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$P" 2>/dev/null && break; sleep 0.1; done
sleep 0.4

python3 - "$P" > "$SOCKETLEY_TMPD/out.txt" 2>/dev/null <<'PYEOF'
import base64, os, socket, struct, sys

port = int(sys.argv[1])

def handshake():
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.settimeout(15)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall(f"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = s.recv(4096)
        if not c:
            return None, b""
        buf += c
    return s, buf.split(b"\r\n\r\n", 1)[1]

def frame(payload):
    n = len(payload)
    h = bytearray([0x81])
    if n < 126:      h.append(0x80 | n)
    elif n < 65536:  h.append(0x80 | 126); h += struct.pack("!H", n)
    else:            h.append(0x80 | 127); h += struct.pack("!Q", n)
    m = os.urandom(4); h += m
    return bytes(h) + bytes(b ^ m[i % 4] for i, b in enumerate(payload))

# Read until one whole server frame is in hand.  Keeping what arrived on a
# timeout rather than discarding it: the first draft cleared the buffer in the
# except branch and reported "nothing" for three replies that were sitting in
# it, which is a fault in the instrument and looks exactly like a fault in the
# server.
def whole_frame(s, buf):
    while True:
        if len(buf) >= 2:
            ln = buf[1] & 0x7F
            off = 2
            if ln == 126 and len(buf) >= 4:
                ln = struct.unpack("!H", buf[2:4])[0]; off = 4
            elif ln == 127 and len(buf) >= 10:
                ln = struct.unpack("!Q", buf[2:10])[0]; off = 10
            if ln < 126 or off > 2:
                if len(buf) >= off + ln:
                    return buf[0], buf[off:off + ln]
        try:
            d = s.recv(65536)
        except socket.timeout:
            return None, b""
        if not d:
            return None, b""
        buf += d

def one(size, label):
    s, buf = handshake()
    if s is None:
        print(f"{label} handshake-failed"); return
    try:
        s.sendall(frame(b"x" * size))
        op, pay = whole_frame(s, buf)
    finally:
        s.close()
    if op is None:
        print(f"{label} nothing")
    elif (op & 0x0F) == 0x8:
        code = struct.unpack("!H", pay[:2])[0] if len(pay) >= 2 else 0
        print(f"{label} close-{code}")
    else:
        print(f"{label} {pay[:16].decode('latin1')}")

# 65535 is the largest 16-bit length; 70000 forces the eight-byte form.
one(300,             "small")
one(70000,           "big64")
one(900 * 1024,      "under")
one(2 * 1024 * 1024, "over")
PYEOF

OUT=$(cat "$SOCKETLEY_TMPD/out.txt" 2>/dev/null || true)
line() { grep -m1 "^$1 " <<<"$OUT" | cut -d' ' -f2- || true; }

check "a 16-bit length frame is echoed"        "len=300"    "$(line small)"
check "and a 64-bit length frame is too"       "len=70000"  "$(line big64)"
check "900 KB, under the buffer, is served"    "len=921600" "$(line under)"
check "2 MB is refused with 1009, not dropped" "close-1009" "$(line over)"

# And the refusal is in the log ONCE, with the limit in it: a read already in
# flight when the first one tripped lands afterwards and used to say the same
# thing twice.
# grep -c prints 0 AND exits 1 when nothing matches, so `|| echo 0` appends a
# second line and the comparison reads "0\n0" -- which fails for the right
# reason and the wrong message.
HITS=$(grep -c 'without a complete message' "$SOCKETLEY_DLOG" 2>/dev/null | head -1)
HITS=${HITS:-0}
check "and said once in the log"               "1"          "$HITS"
if grep -q 'holds at most 1048576' "$SOCKETLEY_DLOG" 2>/dev/null; then
    ok "and the line names the limit it applied"
else
    bad "and the line names the limit it applied" \
        "no limit in: $(grep -m1 'without a complete message' "$SOCKETLEY_DLOG" 2>/dev/null | tail -c 90)"
fi

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || { echo "  --- what python reported ---"; echo "$OUT" | sed 's/^/      /'; exit 1; }
