#!/usr/bin/env bash
# Integration test: a WebSocket peer that pings and never reads costs the
# worker a bounded amount, however much it sends.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# Every other write the server makes goes through admit_send(), which closes a
# connection whose queue has reached --write-buffer.  The pong did not: it was
# pushed onto the queue directly, so a client sending masked pings and reading
# nothing grew the worker by roughly a byte for every byte it sent.
#
# And "closes" was only a flag.  The connection waited for a write the peer
# would never drain, while the multishot recv went on filling `partial` with
# everything it sent -- so bounding the pong alone moved the sixty megabytes
# from the write side to the read side.  A connection on its way out now takes
# nothing more in, and what it had queued still drains to a peer that reads.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# The flood is 120 MB in two halves.  The first is held to an allowance well
# under what the defect adds, and the second must cost nothing more at all --
# the property itself, which a connection still reading into `partial` fails
# however small the first figure is -- and a new client must still be served.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate wspingflood

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
         local l; for l in "${@:3}"; do echo "        $l"; done; }
cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: a WebSocket ping flood is held to the write bound ==="
daemon_start "$BIN"
P=$((SL_PORT_BASE + 1780))
"$BIN" create server wpf -p "$P" -s >/dev/null 2>&1
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done
WORKER=$(ss -ltnp 2>/dev/null | awk -v p=":$P" '$4 ~ p"$" {
    if (match($0, /pid=[0-9]+/)) print substr($0, RSTART+4, RLENGTH-4) }' | head -1)
[ -n "${WORKER:-}" ] || { echo "  FAIL: no worker pid for the listener"; exit 1; }
rss() { awk '/^VmRSS/{print $2}' "/proc/$WORKER/status" 2>/dev/null || echo 0; }

cat > "$SOCKETLEY_TMPD/flood.py" <<'PYEOF'
import base64, os, socket, struct, sys, time
port, total, marker = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
key = base64.b64encode(os.urandom(16)).decode()
s.sendall(("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % key).encode())
buf = b""
while b"\r\n\r\n" not in buf:
    buf += s.recv(4096)
if b" 101 " not in buf.split(b"\r\n")[0]:
    print("no-upgrade"); sys.exit(0)
payload = b"p" * 125
mask = b"\0\0\0\0"
ping = bytes([0x89, 0x80 | 125]) + mask + payload
batch = ping * 512
sent = 0
s.settimeout(10)
try:
    halfway = False
    while sent < total:
        s.sendall(batch)
        sent += len(batch)
        if not halfway and sent >= total // 2:
            halfway = True
            open(marker, "w").write("half")
            time.sleep(1)
    print("open %d" % sent)
except (BrokenPipeError, ConnectionResetError, socket.timeout) as e:
    print("closed %d" % sent)
time.sleep(0.5)
PYEOF

BASE=$(rss)
MARK="$SOCKETLEY_TMPD/half"
python3 "$SOCKETLEY_TMPD/flood.py" "$P" $((120 * 1024 * 1024)) "$MARK" >"$SOCKETLEY_TMPD/flood.out" 2>&1 &
FP=$!
PEAK=$BASE; HALF=""
while kill -0 "$FP" 2>/dev/null; do
    r=$(rss); [ "${r:-0}" -gt "$PEAK" ] && PEAK=$r
    [ -z "$HALF" ] && [ -e "$MARK" ] && HALF=$PEAK
    sleep 0.1
done
wait "$FP" 2>/dev/null
OUT=$(cat "$SOCKETLEY_TMPD/flood.out")
FIRST=$(( (${HALF:-$PEAK} - BASE) / 1024 ))
ADDED=$(( (PEAK - BASE) / 1024 ))
echo "  flood: $OUT, worker grew $FIRST MB over the first 60 MB and $ADDED MB over all 120"

if [ "$FIRST" -lt 40 ]; then pass "sixty megabytes of pings cost the worker $FIRST MB"
else fail "the pong queue is bounded" "the worker grew $FIRST MB over 60 MB of pings" \
          "-- a pong pushed past admit_send() queues one for every ping read"; fi

# The property itself: once the connection is past its bound, what it sends
# costs nothing more, which a dropped connection still reading into `partial`
# fails however small the first figure is.
if [ $((ADDED - FIRST)) -lt 5 ]; then pass "the second sixty megabytes cost nothing more ($((ADDED - FIRST)) MB)"
else fail "memory does not follow what the peer sends" \
          "the worker grew another $((ADDED - FIRST)) MB over the second 60 MB" \
          "-- a connection dropped at its bound kept reading into partial"; fi

if python3 - "$P" <<'PYEOF'
import base64, os, socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
key = base64.b64encode(os.urandom(16)).decode()
s.sendall(("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % key).encode())
sys.exit(0 if b" 101 " in s.recv(4096).split(b"\r\n")[0] else 1)
PYEOF
then pass "the runtime still upgrades a new client"
else fail "the runtime still serves" "a second client's upgrade failed"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
