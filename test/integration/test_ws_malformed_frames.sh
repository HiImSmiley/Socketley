#!/usr/bin/env bash
# Integration test: a WebSocket frame that is not a frame ends the connection.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# `ws_parse_header` answered `false` for two different questions: "not enough
# bytes yet" and "no peer may ever send this".  The server's read loop reads
# `false` as the first one, so a frame RFC 6455 forbids left the connection
# WEDGED -- nothing was delivered, nothing was answered, and nothing was
# closed.  The client waits for a reply that cannot come; the server holds the
# descriptor, the buffer and the connection slot.  `--idle-timeout` is 0 by
# default, so "forever" is literal: no timer exists that would ever collect it.
#
# Three shapes reach it, all fully present in the buffer when they do:
#   * a fragmented control frame (FIN=0 on PING) -- RFC 6455 5.5
#   * a control frame declaring more than 125 bytes -- RFC 6455 5.5
#   * a payload length past WS_MAX_PAYLOAD -- this project's own 16 MB ceiling
#
# The fix gives the parser a third answer and closes on it with 1002, the
# protocol-error code, rather than the 1000 a goodbye uses.
#
# ─── HOW IT IS ASSERTED ────────────────────────────────────────────────────
#
# Each case opens its own connection, sends the bad frame, then sends a
# perfectly good TEXT frame behind it and waits two seconds.  Three outcomes
# are distinguishable and only one is right:
#
#   CLOSE(1002)  the fix: the connection is failed, and it says why
#   echo         the bad frame was ignored and the good one answered -- also
#                wrong, but a different wrongness, and not what was there
#   nothing      the defect: no answer, no close, connection wedged
#
# The echo comes from a Lua script rather than from a mode flag, because what
# must be shown is that a HEALTHY frame on a healthy connection is answered --
# a server that answers nothing would pass a "no answer" assertion for the
# wrong reason.  The sanity case at the top is what makes the three below mean
# anything.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: a malformed WebSocket frame is refused, not awaited ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

P=$((SL_PORT_BASE+1442))

daemon_isolate wsmalformed
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

cat > "$SOCKETLEY_TMPD/echo.lua" <<'LUAEOF'
function on_client_message(id, msg) self.send(id, "R:" .. msg) end
LUAEOF

"$BIN" create server wsmf -p "$P" --lua "$SOCKETLEY_TMPD/echo.lua" -s >/dev/null 2>&1
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$P" 2>/dev/null && break; sleep 0.1; done
sleep 0.4

# One python run for every case, printing one line per case: the shell decides,
# python only reports what came back.
python3 - "$P" > "$SOCKETLEY_TMPD/out.txt" 2>/dev/null <<'PYEOF'
import base64, os, socket, struct, sys, time

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
        if not c:
            return None
        buf += c
    return s if b"101" in buf.split(b"\r\n")[0] else None

# forced_len declares a length the payload does not have, which is the whole
# point of the third case: the bytes never arrive and must not be waited for.
def frame(payload, opcode, fin=True, forced_len=None):
    h = bytearray([(0x80 if fin else 0x00) | opcode])
    n = len(payload) if forced_len is None else forced_len
    if n < 126:
        h.append(0x80 | n)
    elif n < 65536:
        h.append(0x80 | 126); h += struct.pack("!H", n)
    else:
        h.append(0x80 | 127); h += struct.pack("!Q", n)
    m = os.urandom(4); h += m
    return bytes(h) + bytes(b ^ m[i % 4] for i, b in enumerate(payload))

def classify(name, bad_frame):
    s = handshake()
    if s is None:
        print(f"{name} NOUPGRADE"); return
    s.sendall(bad_frame)
    time.sleep(0.3)
    s.sendall(frame(b"after", 0x1))
    s.settimeout(2.0)
    try:
        d = s.recv(256)
    except socket.timeout:
        print(f"{name} WEDGED"); s.close(); return
    s.close()
    if not d:
        print(f"{name} EOF")
    elif d[0] == 0x88 and d[2:4] == b"\x03\xea":
        print(f"{name} CLOSE1002")
    elif d[0] == 0x88:
        print(f"{name} CLOSE-{d[2]*256 + d[3] if len(d) >= 4 else 0}")
    else:
        print(f"{name} ECHO:{d[2:].decode('latin1')}")

# Sanity first: a healthy frame on a healthy connection is answered.  Without
# this line the three below cannot be told from a server that never replies.
s = handshake()
if s is None:
    print("sanity NOUPGRADE")
else:
    s.sendall(frame(b"hi", 0x1)); s.settimeout(2.0)
    try:
        d = s.recv(64)
        print("sanity ECHO:" + d[2:].decode("latin1"))
    except socket.timeout:
        print("sanity WEDGED")
    s.close()

classify("fragmented_ping", frame(b"ab", 0x9, fin=False))
classify("oversize_ping",   frame(b"x" * 200, 0x9))
classify("huge_declared",   frame(b"", 0x1, forced_len=100 * 1024 * 1024))
PYEOF

verdict() { awk -v k="$1" '$1 == k { print $2; exit }' "$SOCKETLEY_TMPD/out.txt"; }

SANITY=$(verdict sanity)
if [ "$SANITY" = "ECHO:R:hi" ]; then
    ok "a healthy frame is answered ($SANITY)"
else
    bad "the instrument works at all" \
        "the sanity connection reported '${SANITY:-<nothing>}';" \
        "nothing below can be told apart if a good frame is not answered"
fi

for case in fragmented_ping oversize_ping huge_declared; do
    GOT=$(verdict "$case")
    case "$GOT" in
        CLOSE1002)
            ok "$case is failed with 1002" ;;
        WEDGED)
            bad "$case ends the connection" \
                "the server neither answered nor closed within 2 s;" \
                "that is the defect: an invalid frame was reported as a short read," \
                "so the loop waits for bytes that would not have helped, and with" \
                "--idle-timeout unset nothing ever collects the connection" ;;
        *)
            bad "$case is failed with 1002" \
                "the connection reported '${GOT:-<nothing>}' rather than a 1002 close" ;;
    esac
done

# The runtime survives all of it -- failing a connection is not failing a
# server, and a build that closed by falling over would pass every line above.
if "$BIN" stats wsmf >/dev/null 2>&1; then
    ok "the runtime is still serving afterwards"
else
    bad "the server survives a peer sending nonsense" "stats no longer answers for wsmf"
fi

"$BIN" stop wsmf >/dev/null 2>&1; "$BIN" remove wsmf >/dev/null 2>&1
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
