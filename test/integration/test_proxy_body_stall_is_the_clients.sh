#!/usr/bin/env bash
# Integration test: a request body the client stops sending is the client's timeout, not the backend's.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# Each piece of a body moves the backend's deadline on, so a client that sends
# half its body and stops reached --backend-timeout with the backend holding
# everything it was given.  The sweep charged that to the backend and answered
# 504, so five stalled uploads from anyone opened the circuit breaker on a
# healthy backend for every other client.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# Six stalled uploads, one more than the breaker's threshold, must each be
# answered 408 and leave the backend answering a whole request 200; and a
# backend that is sent a whole request and says nothing is still answered 504,
# or a build that blames every client for every silence passes.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate pxbodystall
T="$SOCKETLEY_TMPD"

BE=$((SL_PORT_BASE+1869))
PX=$((SL_PORT_BASE+1870))
MUTE=$((SL_PORT_BASE+1863))
PM=$((SL_PORT_BASE+1866))
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1))
        if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
        else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi; }
cleanup() { [ -n "${BEPID:-}" ] && kill "$BEPID" 2>/dev/null; [ -n "${MUPID:-}" ] && kill "$MUPID" 2>/dev/null
            daemon_stop; }
trap cleanup EXIT

echo "=== Integration: a stalled request body is not the backend's failure ==="

# "answer": reads a head and its Content-Length body and answers 200; "mute": reads and never answers.
cat > "$T/be.py" <<'PYEOF'
import socket, sys, threading
mode, port = sys.argv[1], int(sys.argv[2])
def serve(c):
    buf = b""
    try:
        while True:
            while b"\r\n\r\n" not in buf:
                b = c.recv(65536)
                if not b: return
                buf += b
            if mode == "mute":
                while c.recv(65536): pass
                return
            head, buf = buf.split(b"\r\n\r\n", 1)
            n = 0
            for l in head.split(b"\r\n")[1:]:
                if l.lower().startswith(b"content-length:"):
                    n = int(l.split(b":", 1)[1])
            while len(buf) < n:
                b = c.recv(65536)
                if not b: return
                buf += b
            buf = buf[n:]
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    finally:
        c.close()
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", port)); ls.listen(64)
sys.stderr.write("be up\n"); sys.stderr.flush()
while True:
    c, _ = ls.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PYEOF
python3 -I "$T/be.py" answer "$BE" 2>"$T/be.log" & BEPID=$!
python3 -I "$T/be.py" mute "$MUTE" 2>"$T/mute.log" & MUPID=$!
for _ in $(seq 1 50); do grep -q "be up" "$T/be.log" 2>/dev/null && grep -q "be up" "$T/mute.log" 2>/dev/null && break
                         sleep 0.1; done

# Sends a head promising a hundred bytes and ten of them, then prints the status it is answered with.
cat > "$T/stall.py" <<'PYEOF'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
s.sendall(b"POST /pb/x HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\n" + b"x" * 10)
got = b""
try:
    while b"\r\n" not in got:
        d = s.recv(65536)
        if not d: break
        got += d
except OSError:
    pass
print(got.split(b" ")[1].decode() if got.count(b" ") else "closed")
PYEOF

daemon_start "$BIN"
"$BIN" create proxy pb -p "$PX" --backend "127.0.0.1:$BE" --protocol http -s >/dev/null 2>&1
"$BIN" create proxy pm -p "$PM" --backend "127.0.0.1:$MUTE" --protocol http -s >/dev/null 2>&1
post() { curl -s -m 10 -o /dev/null -w '%{http_code}' --data-binary hello "http://127.0.0.1:$1/$2/x"; }
for _ in $(seq 1 100); do [ "$(post "$PX" pb)" = 200 ] && break; sleep 0.1; done
ok "$(post "$PX" pb)" "200" "the backend answers a whole request"

STALLS=()
for i in 1 2 3 4 5 6; do python3 -I "$T/stall.py" "$PX" >"$T/stall.$i" 2>&1 & STALLS+=($!); done
wait "${STALLS[@]}" 2>/dev/null
ok "$(cat "$T"/stall.? | sort | uniq -c | tr -s ' ' | tr '\n' ' ')" " 6 408 " \
   "six uploads that stop halfway are each answered 408 Request Timeout"
ok "$(post "$PX" pb)" "200" "and the backend they went to is still reached, its breaker closed"
ok "$(post "$PM" pm)" "504" "a backend sent a whole request that says nothing is still answered 504"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
