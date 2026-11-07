#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a DNS TCP client that half-closes after its queries still reads every answer.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the peer's FIN taken as the end of the connection while answers were still queued behind a socket the client
#     had not read: the connection was closed with them, and a client that sends its queries and shuts its write
#     side (nc -N, a script's AXFR) got only what had fit in the socket
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate dnshalf
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1922))
trap 'daemon_stop' EXIT

echo "=== Integration: a DNS TCP client that half-closed after asking reads every answer ==="

daemon_start "$BIN"
cat > "$T/z.zone" <<'EOF'
$ORIGIN example.com.
$TTL 3600
@   IN SOA ns1 hostmaster ( 1 1h 15m 1w 300 )
    IN NS  ns1
ns1 IN A   192.0.2.53
EOF
for i in $(seq 1 40); do echo "big IN TXT \"record number $i, padded out to make the answer large: xxxxxxxxxxxxxxxxxxxx\""; done >> "$T/z.zone"
"$BIN" create dns ns -p "$P" --zone "$T/z.zone" --proxy none -s >/dev/null 2>&1
for _ in $(seq 1 50); do python3 -c "import socket;socket.create_connection(('127.0.0.1',$P),1)" 2>/dev/null && break; sleep 0.1; done

# Three thousand queries and the client's FIN, sent before a byte is read, so the end arrives while the answers wait
# behind a socket that is full.
res=$(python3 - "$P" <<'PY'
import socket, struct, sys, threading, time
N = 3000
def query(i):
    q = struct.pack(">HHHHHH", i, 0x0100, 1, 0, 0, 0)
    for label in (b"big", b"example", b"com"):
        q += bytes([len(label)]) + label
    q += b"\x00" + struct.pack(">HH", 16, 1)
    return struct.pack(">H", len(q)) + q
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 10)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
# Sent beside the reads, as the runtime stops reading a peer whose answers are not read.
def send():
    s.sendall(b"".join(query(i) for i in range(1, N + 1)))
    s.shutdown(socket.SHUT_WR)
threading.Thread(target=send, daemon=True).start()
time.sleep(1.5)
# Read through a small window, so answers are still queued behind it when the runtime meets the FIN.
s.settimeout(20)
buf = b""
good = bad = 0
expect = 1
while expect <= N:
    while len(buf) < 2:
        b = s.recv(16384)
        if not b: break
        buf += b
    if len(buf) < 2: break
    n = struct.unpack(">H", buf[:2])[0]
    while len(buf) < 2 + n:
        b = s.recv(16384)
        if not b: break
        buf += b
    if len(buf) < 2 + n: break
    msg, buf = buf[2:2 + n], buf[2 + n:]
    ident, flags, qd, an = struct.unpack(">HHHH", msg[:8])
    if ident == expect and qd == 1 and an == 40 and b"record number 40" in msg and b"\x55\x55\x55\x55" not in msg:
        good += 1
    else:
        bad += 1
    expect += 1
print(good, bad)
PY
)
expect "every answer arrives after the client's FIN" "$res" "3000 0"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
