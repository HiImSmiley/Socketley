#!/usr/bin/env bash
# Integration test: bytes that may not travel in a WebSocket text frame do not.
#
# ─── WHAT WAS ON THE WIRE ───────────────────────────────────────────────────
#
# WS_OP_BINARY was defined and used in exactly one place: the inbound opcode
# check. All three outbound frame builders wrote 0x81 -- FIN | text -- so a
# server could receive a binary frame and never produce one.
#
# That is not a missing feature. RFC 6455 5.6 says a text frame's payload MUST
# be valid UTF-8, and 8.1 says a receiver that finds it is not MUST fail the
# connection. Measured on a relaying server:
#
#     client A sends BINARY  ff fe 00 01 80 81
#     client B receives      opcode 0x1, payload ff fe 00 01 80 81
#
# The payload arrived byte for byte -- only the opcode was wrong -- and a
# conforming B must close on it. socketley put its own clients in the position
# of having to hang up.
#
# ─── WHY THE PAYLOAD DECIDES AND NOT THE SENDER ─────────────────────────────
#
# The obvious fix is to carry the inbound opcode through to the outbound write,
# and the relay path throws it away: process_message() takes the bytes and not
# the frame, and queue_send() knows only that the destination speaks WebSocket.
# Threading a frame kind through the message path reaches the hot-path struct
# and two signatures.
#
# It is also the wrong question. The RFC does not ask what the sender called the
# bytes; it says which frame the bytes are allowed to travel in. So the choice
# is made where the destination is already known, from the payload itself, and
# it needs no plumbing at all:
#
#     valid UTF-8  -> text,   exactly as before
#     anything else -> binary, which is the only conforming option
#
# The third case below is what that reading buys: UTF-8 bytes SENT as binary
# come back as text, because there was never anything wrong with carrying them
# that way.
#
# ─── AND THE HALF THAT MUST NOT MOVE ────────────────────────────────────────
#
# Every relayed line is valid UTF-8, so every existing frame is still 0x81 --
# test_relay_hold_before_classification.sh asserts that on the wire and
# test/benchmark/bench.c rejects any frame that is not 0x1. Both still pass, and
# the second case here is the assertion that says why.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate wsbinary

P=$((SL_PORT_BASE+1952))
NAMES="wb_srv"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

cleanup() {
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: bytes that may not be text are not sent as text ==="
daemon_start "$BIN"

create_ok "a relaying server" "$BIN" create server wb_srv -p "$P" -s
ready_tcp 127.0.0.1 "$P" >/dev/null 2>&1 || true

OUT=$(timeout 60 python3 - "$P" <<'PYEOF' 2>&1
import base64, os, socket, struct, sys, time
port = int(sys.argv[1])

def ws_connect():
    s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(4)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall(("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
               "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
               "Sec-WebSocket-Version: 13\r\n\r\n" % key).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    return s

def frame(op, payload):
    # A client MUST mask; a server MUST NOT.
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    n = len(payload)
    hdr = (struct.pack("!BB", 0x80 | op, 0x80 | n) if n < 126
           else struct.pack("!BBH", 0x80 | op, 0x80 | 126, n))
    return hdr + mask + masked

def read_frame(s):
    h = s.recv(2)
    if len(h) < 2:
        return None, b""
    op, n = h[0] & 0x0F, h[1] & 0x7F
    if n == 126:
        n = struct.unpack("!H", s.recv(2))[0]
    body = b""
    while len(body) < n:
        c = s.recv(n - len(body))
        if not c:
            break
        body += c
    return op, body

a, b = ws_connect(), ws_connect()
time.sleep(0.6)

# 1. bytes that are not valid UTF-8, sent as binary
raw = bytes([0xFF, 0xFE, 0x00, 0x01, 0x80, 0x81])
a.sendall(frame(0x2, raw))
time.sleep(0.8)
op, body = read_frame(b)
print("BIN_OP=0x%x" % (op if op is not None else 0))
print("BIN_PAYLOAD=%s" % body.hex())

# 2. ordinary text, including multibyte UTF-8
a.sendall(frame(0x1, "hello-é-€".encode()))
time.sleep(0.8)
op, body = read_frame(b)
print("TXT_OP=0x%x" % (op if op is not None else 0))
print("TXT_PAYLOAD=%s" % body.decode("utf-8", "replace"))

# 3. valid UTF-8 that the sender called binary
a.sendall(frame(0x2, b"plain-ascii"))
time.sleep(0.8)
op, body = read_frame(b)
print("UTF8_AS_BIN_OP=0x%x" % (op if op is not None else 0))
print("UTF8_AS_BIN_PAYLOAD=%s" % body.decode("utf-8", "replace"))

a.close(); b.close()
PYEOF
)

v() { printf '%s\n' "$OUT" | sed -n "s/^$1=//p" | tail -1; }

# ─── 1. Not valid UTF-8, so not a text frame ────────────────────────────────
check "bytes that are not UTF-8 are relayed as binary" "0x2" "$(v BIN_OP)"
check "with the payload untouched" "fffe00018081" "$(v BIN_PAYLOAD)"

# ─── 2. And everything that was already conforming is unchanged ─────────────
# A build that simply sent everything as binary would satisfy case 1 and break
# every WebSocket client this server has.
check "ordinary text is still a text frame" "0x1" "$(v TXT_OP)"
check "multibyte UTF-8 included"            "hello-é-€" "$(v TXT_PAYLOAD)"

# ─── 3. The payload decides, not the sender ─────────────────────────────────
# There is nothing wrong with carrying UTF-8 in a text frame, whatever the
# sender called it on the way in -- and a build that echoed the inbound opcode
# would answer 0x2 here.
check "UTF-8 sent as binary comes back as text" "0x1" "$(v UTF8_AS_BIN_OP)"
check "and intact"                              "plain-ascii" "$(v UTF8_AS_BIN_PAYLOAD)"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { printf '%s\n' "$OUT" | sed 's/^/    driver: /'; echo "  FAILED"; }
[ "$FAIL" -eq 0 ]
