#!/usr/bin/env bash
# Integration test: a text message that is not UTF-8 fails its connection.
#
# ─── WHY THIS FILE EXISTS ──────────────────────────────────────────────────
#
# RFC 6455 5.6: "the 'Payload data' is text data encoded as UTF-8".  8.1: "When
# an endpoint is to interpret a byte stream as UTF-8 but finds that the byte
# stream is not, in fact, a valid UTF-8 stream, that endpoint MUST _Fail the
# WebSocket Connection_."  7.4.1 gives 1007 for exactly that.
#
# The server never looked.  A text frame carrying ff fe was handed to the
# script as a string and, with no script, echoed back -- as a binary frame,
# because the outbound side does check.  So a client that sent garbage in a
# text frame got its garbage back under a different opcode and no word that
# anything was wrong, and a script was handed bytes the protocol promised it
# could never see.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ───────────────────────────────────────
#
#   ff fe, overlong, surrogate, truncated -- a server that does not check at
#       all (every one of these came back as an echo before), and a checker
#       that accepts what a lax decoder accepts: C0 AF is '/' spelled in two
#       bytes, ED A0 80 is U+D800, which UTF-8 may not encode.
#   bad split across fragments -- a checker that validates each fragment on
#       its own and misses a sequence the second fragment breaks.
#   close then EOF -- a server that sends the 1007 and keeps reading, or that
#       closes without saying why.
#   valid, split on a boundary and inside a code point -- a checker that
#       validates each fragment alone: "h\xc3" is not UTF-8 by itself, and the
#       message it begins is.  These pass on a build that does not check at
#       all; they are here so the check cannot be made per fragment.
#   invalid bytes in a BINARY frame -- a checker that looks at every data
#       frame: binary carries no encoding and must go through untouched.
#   a new connection afterwards -- a failure that took the runtime with it.
#
# ─── HOW ───────────────────────────────────────────────────────────────────
#
# One connection per case, because a failed one is over.  A no-script server
# with --send-to sender echoes each message to its sender, so an accepted
# message is visible as its echo and a refused one as a CLOSE.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: a text message that is not UTF-8 fails its connection ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

P=$((SL_PORT_BASE+1454))

daemon_isolate wsutf8
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

"$BIN" create server wsu8 -p "$P" --send-to sender -s >/dev/null 2>&1 \
    || daemon_required "create"
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$P" 2>/dev/null && break; sleep 0.1; done
sleep 0.4

python3 - "$P" > "$SOCKETLEY_TMPD/out.txt" 2>"$SOCKETLEY_TMPD/err.txt" <<'PYEOF' || true
import base64, os, socket, struct, sys

port = int(sys.argv[1])

def handshake():
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
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
    else: h.append(0x80 | 126); h += struct.pack("!H", n)
    m = os.urandom(4); h += m
    return bytes(h) + bytes(b ^ m[i % 4] for i, b in enumerate(payload))

# One whole server frame out of buf, or op None at EOF or timeout.
def take(s, buf):
    while True:
        if len(buf) >= 2:
            ln = buf[1] & 0x7F; off = 2
            if ln == 126 and len(buf) >= 4:
                ln = struct.unpack("!H", buf[2:4])[0]; off = 4
            if ln != 126 and len(buf) >= off + ln:
                return (buf[0] & 0x0F, buf[off:off+ln], buf[off+ln:])
        try:
            d = s.recv(65536)
        except Exception:
            return (None, b"timeout", buf)
        if not d: return (None, b"eof", buf)
        buf += d

out = []

# Send `frames` on a fresh connection and report the first frame back, and for
# a CLOSE whether the server then closed the socket as well.
def probe(name, frames):
    s, buf = handshake()
    if not s:
        out.append("%s handshake_failed" % name); return
    try:
        s.sendall(b"".join(frames))
        op, pay, buf = take(s, buf)
        if op is None:
            out.append("%s op=none (%s)" % (name, pay.decode())); return
        if op == 8:
            code = struct.unpack("!H", pay[:2])[0] if len(pay) >= 2 else -1
            nop, npay, buf = take(s, buf)
            after = "eof" if nop is None and npay == b"eof" else \
                    "open" if nop is None else "frame%d" % nop
            out.append("%s op=8 code=%d then=%s" % (name, code, after))
        else:
            out.append("%s op=%d payload=%s" % (name, op, pay.hex()))
    finally:
        s.close()

T, B, C = 0x1, 0x2, 0x0

# ─── not UTF-8, in a text message ──────────────────────────────────────────
probe("fffe",       [frame(b"\xff\xfe", T)])
probe("overlong",   [frame(b"a\xc0\xafb", T)])           # '/' in two bytes
probe("surrogate",  [frame(b"a\xed\xa0\x80b", T)])       # U+D800
probe("truncated",  [frame(b"abc\xe2\x82", T)])          # message ends mid-sequence
probe("badsplit",   [frame(b"ab\xe2\x82", T, fin=False),
                     frame(b"xy", C)])                   # the second fragment breaks it

# ─── UTF-8, split where a per-fragment check would refuse it ───────────────
probe("whole",      [frame("héllo €".encode(), T)])
probe("boundary",   [frame(b"h\xc3\xa9", T, fin=False),
                     frame(b"llo \xe2\x82\xac", C)])
probe("midpoint",   [frame(b"h\xc3", T, fin=False),
                     frame(b"\xa9llo \xe2", C, fin=False),
                     frame(b"\x82\xac", C)])

# ─── binary carries no encoding ────────────────────────────────────────────
probe("binary",     [frame(b"\xff\xfe\x00\x01", B)])

# ─── and the runtime is still there ────────────────────────────────────────
probe("after",      [frame(b"still-here", T)])

print("\n".join(out))
PYEOF

OUT=$(cat "$SOCKETLEY_TMPD/out.txt" 2>/dev/null || true)
line() { grep -m1 "^$1 " <<<"$OUT" || true; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$2', got '${3:-<nothing>}'"; fi; }

echo "  -- a text message that is not UTF-8 is answered 1007 and closed --"
check "ff fe"                              "fffe op=8 code=1007 then=eof"      "$(line fffe)"
check "an overlong encoding"               "overlong op=8 code=1007 then=eof"  "$(line overlong)"
check "an encoded surrogate"               "surrogate op=8 code=1007 then=eof" "$(line surrogate)"
check "a message that ends mid-sequence"   "truncated op=8 code=1007 then=eof" "$(line truncated)"
check "a sequence a later fragment breaks" "badsplit op=8 code=1007 then=eof"  "$(line badsplit)"

echo "  -- UTF-8 is accepted however it is fragmented --"
HELLO=$(printf 'h\xc3\xa9llo \xe2\x82\xac' | od -An -tx1 | tr -d ' \n')
check "unfragmented"                       "whole op=1 payload=$HELLO"    "$(line whole)"
check "split at a code point boundary"     "boundary op=1 payload=$HELLO" "$(line boundary)"
check "split inside a code point"          "midpoint op=1 payload=$HELLO" "$(line midpoint)"

echo "  -- and the rest is unchanged --"
check "invalid UTF-8 in a binary frame is delivered" "binary op=2 payload=fffe0001" "$(line binary)"
check "the runtime still serves a new connection" \
      "after op=1 payload=$(printf still-here | od -An -tx1 | tr -d ' \n')" "$(line after)"

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || {
    echo "  --- what python reported ---"
    echo "$OUT" | sed 's/^/      /'
    sed 's/^/      /' "$SOCKETLEY_TMPD/err.txt" 2>/dev/null | head -20
    exit 1
}
