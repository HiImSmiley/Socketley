#!/usr/bin/env bash
# Integration test: the WebSocket data path.
#
# test_websocket.sh covers only the HTTP upgrade — it asserts on the 101 and the
# response headers and never sends a single frame. So nothing has ever checked
# that a payload arrives intact, which is how a defect corrupting every message
# larger than six bytes survived in the tree.
#
# The server is linked to a cache, which stores each received message under an
# incrementing key. Reading those keys back shows exactly what the server
# understood the payload to be, without needing the server to echo.
#
# Payloads are chosen so that a shift is visible: every byte says where it
# belongs. A repetitive payload such as "AAAA..." survives a shift unnoticed and
# would make this test pass while the defect is present.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate wsdata
SRV_PORT=$((SL_PORT_BASE+701))
CACHE_PORT=$((SL_PORT_BASE+702))
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop wsdata_srv   2>/dev/null || true
    "$BIN" stop wsdata_cache 2>/dev/null || true
    sleep 0.3
    "$BIN" remove wsdata_srv   2>/dev/null || true
    "$BIN" remove wsdata_cache 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

assert_eq() {
    TOTAL=$((TOTAL+1))
    local got="$1" expected="$2" label="$3"
    if [ "$got" = "$expected" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]:"
        echo "        sent: '$expected'"
        echo "        got:  '$got'"
    fi
}

echo "=== Integration: WebSocket data path ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not available (needed for a WebSocket client)"
    exit 0
fi

daemon_start "$BIN"

create_ok "cache created" "$BIN" create cache wsdata_cache -p "$CACHE_PORT" -s
sleep 0.3
create_ok "server created" "$BIN" create server wsdata_srv -p "$SRV_PORT" \
    --cache wsdata_cache -s
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$SRV_PORT" 2>/dev/null && break; sleep 0.1; done
sleep 0.3

# `|| true` on the command line, where a heredoc's guard has to go.  With nothing
# listening — which is what a refused create leaves behind — this python raises
# ConnectionRefusedError, and under `set -e` a bare command that fails is the end
# of the file: the run stopped on a traceback before any of the six payload
# assertions and printed no `Results` line.  Not delivering the frames is the
# reason the reads below come back empty, and assert_eq says that in six lines.
python3 - "$SRV_PORT" <<'PYEOF' || true
import base64, hashlib, os, socket, struct, sys, time

port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=5)
key = base64.b64encode(os.urandom(16)).decode()
s.sendall(f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n"
          f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
          f"Sec-WebSocket-Version: 13\r\n\r\n".encode())
buf = b""
while b"\r\n\r\n" not in buf:
    chunk = s.recv(4096)
    if not chunk:
        sys.exit("server closed during handshake")
    buf += chunk
if b"101" not in buf.split(b"\r\n")[0]:
    sys.exit("upgrade failed")

def frame(payload, opcode, fin):
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

def send_text(sock, payload):
    sock.sendall(frame(payload, 0x1, True))

for payload in (b"012345", b"0123456", b"0123456789",
                b'{"type":"chat","text":"hi"}',
                ("".join(str(i % 10) for i in range(300))).encode()):
    send_text(s, payload)
    time.sleep(0.2)          # one read completion per frame

# Fragmented message (RFC 6455 5.4): text frame with FIN=0, then a continuation
# frame with FIN=1. This is what the in-place compaction exists for, so it has
# to keep working — sent as one write so both frames land in a single read.
s.sendall(frame(b"FIRST-HALF-", 0x1, False) + frame(b"SECOND-HALF", 0x0, True))
time.sleep(0.3)
s.close()
PYEOF

sleep 0.5

read_key() { printf 'get %s\n' "$1" | nc -q 1 127.0.0.1 "$CACHE_PORT" 2>/dev/null | tr -d '\r\n'; }

BIG=$(python3 -c 'print("".join(str(i % 10) for i in range(300)))')

assert_eq "$(read_key 1)" "012345"                      "6 byte payload"
assert_eq "$(read_key 2)" "0123456"                     "7 byte payload"
assert_eq "$(read_key 3)" "0123456789"                  "10 byte payload"
assert_eq "$(read_key 4)" '{"type":"chat","text":"hi"}' "27 byte JSON payload"
assert_eq "$(read_key 5)" "$BIG"                        "300 byte payload"
assert_eq "$(read_key 6)" "FIRST-HALF-SECOND-HALF"      "fragmented message reassembled"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
