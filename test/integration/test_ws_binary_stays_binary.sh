#!/usr/bin/env bash
# Integration test: a relayed WebSocket message keeps its opcode, and bytes that
# may not travel in a text frame never do.
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
# The first fix chose the opcode from the payload: valid UTF-8 went out as
# text, anything else as binary. That made every frame conforming and left the
# second half of the defect in place:
#
#     client A sends BINARY  "plain-ascii"
#     client B receives      opcode 0x1, "plain-ascii"
#
# A browser hands a text frame to onmessage as a string and a binary one as a
# Blob or ArrayBuffer, so the opcode is part of the message and not a detail
# of its encoding. A protocol that sends small binary records -- protobuf, a
# length prefix, anything that happens to stay below 0x80 -- had them arrive
# as strings whenever the bytes happened to be UTF-8, and as ArrayBuffers
# otherwise. Now the no-script relay carries the sender's opcode through; a
# text message is known to be UTF-8, because the server fails any that is not
# (test_ws_text_must_be_utf8.sh).
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   1  bytes that are not UTF-8, relayed as text -- the original defect.
#   2  text relayed as anything else -- a build that sent everything binary,
#      which would satisfy 1 and break every WebSocket client this server has.
#   3  UTF-8 sent as binary, relayed as text -- the payload deciding for the
#      sender; this is the assertion that was the other way round before.
#   4  the same, fragmented -- a build that keeps the opcode of an unfragmented
#      frame and loses it in reassembly, where the continuation frames say 0x0.
#   5  the same, held for a client whose upgrade had not finished when the
#      message was relayed -- the hold kept the bytes and not the opcode.
#   6  the echo server (--send-to sender), which frames one recipient through
#      a different function from the broadcast, in both directions.
#   7  a script's reply still follows its payload: the script API sends strings
#      and says nothing about frames, so what self.send builds is unchanged.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate wsbinary

P=$((SL_PORT_BASE+1952))
PE=$((SL_PORT_BASE+1953))
PL=$((SL_PORT_BASE+1955))
NAMES="wb_srv wb_echo wb_lua"

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

echo "=== Integration: a relayed WebSocket message keeps its opcode ==="
daemon_start "$BIN"

cat > "$SOCKETLEY_TMPD/reply.lua" <<'LUAEOF'
function on_client_message(id, msg) self.send(id, msg) end
LUAEOF

create_ok "a relaying server" "$BIN" create server wb_srv -p "$P" -s
create_ok "an echo server"    "$BIN" create server wb_echo -p "$PE" --send-to sender -s
create_ok "a scripted server" "$BIN" create server wb_lua -p "$PL" --mode in \
    --lua "$SOCKETLEY_TMPD/reply.lua" -s
for p in "$P" "$PE" "$PL"; do ready_tcp 127.0.0.1 "$p" >/dev/null 2>&1 || true; done

OUT=$(timeout 90 python3 - "$P" "$PE" "$PL" "$BIN" <<'PYEOF' 2>&1
import base64, os, socket, struct, subprocess, sys, time
port, port_echo, port_lua, BIN = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]

HEAD = (b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
        b"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n")

def ws_connect(p=port):
    s = socket.create_connection(("127.0.0.1", p), 5); s.settimeout(4)
    key = base64.b64encode(os.urandom(16))
    s.sendall(HEAD + b"Sec-WebSocket-Key: " + key + b"\r\n\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    return s

def frame(op, payload, fin=True):
    # A client MUST mask; a server MUST NOT.
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    n = len(payload)
    b0 = (0x80 if fin else 0) | op
    hdr = (struct.pack("!BB", b0, 0x80 | n) if n < 126
           else struct.pack("!BBH", b0, 0x80 | 126, n))
    return hdr + mask + masked

def recv_n(s, n):
    body = b""
    while len(body) < n:
        c = s.recv(n - len(body))
        if not c:
            break
        body += c
    return body

def read_frame(s):
    try:
        h = recv_n(s, 2)
    except socket.timeout:
        return None, b""
    if len(h) < 2:
        return None, b""
    op, n = h[0] & 0x0F, h[1] & 0x7F
    if n == 126:
        n = struct.unpack("!H", recv_n(s, 2))[0]
    return op, recv_n(s, n)

def report(name, s):
    op, body = read_frame(s)
    print("%s_OP=0x%x" % (name, op if op is not None else 0))
    print("%s_PAYLOAD=%s" % (name, body.hex()))

def stat(key):
    out = subprocess.run([BIN, "stats", "wb_srv"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if line.startswith(key + ":"):
            try:    return int(line.split(":", 1)[1])
            except ValueError: return None
    return None

def wait_until(key, target, deadline=15.0):
    end = time.time() + deadline
    while time.time() < end:
        v = stat(key)
        if v is not None and v >= target:
            return True
        time.sleep(0.05)
    print("TIMEOUT=%s" % key)
    return False

a, b = ws_connect(), ws_connect()
time.sleep(0.6)

# 1. bytes that are not valid UTF-8, sent as binary
a.sendall(frame(0x2, bytes([0xFF, 0xFE, 0x00, 0x01, 0x80, 0x81])))
report("BIN", b)

# 2. ordinary text, including multibyte UTF-8
a.sendall(frame(0x1, "hello-é-€".encode()))
report("TXT", b)

# 3. valid UTF-8 that the sender called binary
a.sendall(frame(0x2, b"plain-ascii"))
report("UTF8_AS_BIN", b)

# 4. the same in three fragments, the last two continuation frames
a.sendall(frame(0x2, b"frag-", fin=False) + frame(0x0, b"ment", fin=False)
          + frame(0x0, b"ed"))
report("FRAG_BIN", b)

# 5. held: a client whose upgrade is half sent is in the relay set and has not
# said what it speaks, so the relay is held for it until the upgrade completes.
base_in = stat("bytes_in") or 0
h = socket.create_connection(("127.0.0.1", port), 5); h.settimeout(4)
h.sendall(HEAD)
wait_until("bytes_in", base_in + len(HEAD))
base_msgs = stat("total_messages") or 0
a.sendall(frame(0x2, b"held-binary"))
wait_until("total_messages", base_msgs + 1)
report("B_SAW_HELD", b)
h.sendall(b"Sec-WebSocket-Key: " + base64.b64encode(os.urandom(16)) + b"\r\n\r\n")
buf = b""
while b"\r\n\r\n" not in buf:
    buf += h.recv(1)
report("HELD", h)
h.close(); a.close(); b.close()

# 6. one recipient, the sender itself
e = ws_connect(port_echo)
e.sendall(frame(0x2, b"echo-binary"))
report("ECHO_BIN", e)
e.sendall(frame(0x1, b"echo-text"))
report("ECHO_TXT", e)
e.close()

# 7. a script's reply is framed by what it sends
l = ws_connect(port_lua)
l.sendall(frame(0x2, b"script-utf8"))
report("LUA_UTF8", l)
l.sendall(frame(0x2, bytes([0xFF, 0x00])))
report("LUA_RAW", l)
l.close()
PYEOF
)

v() { printf '%s\n' "$OUT" | sed -n "s/^$1=//p" | tail -1; }
hex() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }

# ─── 1. Not valid UTF-8, so not a text frame ────────────────────────────────
check "bytes that are not UTF-8 are relayed as binary" "0x2" "$(v BIN_OP)"
check "with the payload untouched" "fffe00018081" "$(v BIN_PAYLOAD)"

# ─── 2. Text stays text ─────────────────────────────────────────────────────
check "ordinary text is still a text frame" "0x1" "$(v TXT_OP)"
check "multibyte UTF-8 included" "$(hex 'hello-é-€')" "$(v TXT_PAYLOAD)"

# ─── 3. Binary stays binary, whatever its bytes happen to be ────────────────
check "UTF-8 sent as binary is relayed as binary" "0x2" "$(v UTF8_AS_BIN_OP)"
check "and intact" "$(hex plain-ascii)" "$(v UTF8_AS_BIN_PAYLOAD)"

# ─── 4. And through reassembly ──────────────────────────────────────────────
check "a fragmented binary message is relayed as binary" "0x2" "$(v FRAG_BIN_OP)"
check "reassembled whole" "$(hex frag-mented)" "$(v FRAG_BIN_PAYLOAD)"

# ─── 5. And through the hold ────────────────────────────────────────────────
check "the relay reached the settled client first" "0x2" "$(v B_SAW_HELD_OP)"
check "a message held across an upgrade is released as binary" "0x2" "$(v HELD_OP)"
check "and intact" "$(hex held-binary)" "$(v HELD_PAYLOAD)"

# ─── 6. The one-recipient echo keeps it too ─────────────────────────────────
check "an echoed binary message is binary" "0x2" "$(v ECHO_BIN_OP)"
check "and intact" "$(hex echo-binary)" "$(v ECHO_BIN_PAYLOAD)"
check "an echoed text message is text" "0x1" "$(v ECHO_TXT_OP)"

# ─── 7. A script's reply is judged by its bytes, as it always was ───────────
check "a script's UTF-8 reply is text" "0x1" "$(v LUA_UTF8_OP)"
check "and intact" "$(hex script-utf8)" "$(v LUA_UTF8_PAYLOAD)"
check "a script's non-UTF-8 reply is binary" "0x2" "$(v LUA_RAW_OP)"
check "and intact" "ff00" "$(v LUA_RAW_PAYLOAD)"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { printf '%s\n' "$OUT" | sed 's/^/    driver: /'; echo "  FAILED"; }
[ "$FAIL" -eq 0 ]
