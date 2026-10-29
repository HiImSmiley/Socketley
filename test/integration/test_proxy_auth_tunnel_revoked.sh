#!/usr/bin/env bash
# Integration test: a connection --auth let in ends when what let it in no longer would.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# --auth was asked once per request head.  After a 101 the proxy relays raw
# bytes and no head comes again, so a websocket opened with a token went on
# reaching the backend after the token was taken out of the file -- and under
# idp:, after its account was disabled or signed out everywhere.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# The tunnel must carry bytes both ways before the token goes, and while the
# token is still in the file a tunnel kept open past the recheck must survive,
# or a proxy that closes every tunnel after a second passes.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate pxauthtun
T="$SOCKETLEY_TMPD"

BE=$((SL_PORT_BASE+1867))
PX=$((SL_PORT_BASE+1868))
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1))
        if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
        else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi; }
cleanup() { [ -n "${BEPID:-}" ] && kill "$BEPID" 2>/dev/null; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: a tunnel --auth let in ends with its token ==="

# Answers 101 to an Upgrade and echoes every byte after it.
cat > "$T/be.py" <<'PYEOF'
import socket, sys, threading
port = int(sys.argv[1])
def serve(c):
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            b = c.recv(65536)
            if not b: return
            buf += b
        c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
        rest = buf.split(b"\r\n\r\n", 1)[1]
        if rest: c.sendall(rest)
        while True:
            b = c.recv(65536)
            if not b: return
            c.sendall(b)
    finally:
        c.close()
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", port)); ls.listen(16)
sys.stderr.write("be up\n"); sys.stderr.flush()
while True:
    c, _ = ls.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PYEOF
python3 -I "$T/be.py" "$BE" 2>"$T/be.log" & BEPID=$!
for _ in $(seq 1 50); do grep -q "be up" "$T/be.log" 2>/dev/null && break; sleep 0.1; done

# Opens a tunnel with the token, echoes once, then (after the third argument's seconds, with the fourth argument
# run in between) echoes every 0.2 s for four seconds; prints whether the tunnel echoed first, and then "open" or
# "closed".
cat > "$T/tun.py" <<'PYEOF'
import socket, subprocess, sys, time
port, token, settle, between = int(sys.argv[1]), sys.argv[2], float(sys.argv[3]), sys.argv[4]
s = socket.create_connection(("127.0.0.1", port), timeout=4)
s.sendall(b"GET /pt/ws HTTP/1.1\r\nHost: app\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
          b"Authorization: Bearer " + token.encode() + b"\r\n\r\n")
head = b""
while b"\r\n\r\n" not in head:
    d = s.recv(65536)
    if not d: break
    head += d
status = head.split(b" ", 2)[1].decode() if head.count(b" ") else "none"
def echo():
    try:
        s.sendall(b"ping")
        got = b""
        while len(got) < 4:
            d = s.recv(4 - len(got))
            if not d: return False
            got += d
        return got == b"ping"
    except OSError:
        return False
first = status == "101" and echo()
time.sleep(settle)
if between:
    subprocess.run(between, shell=True)
s.settimeout(1)
end, state = time.time() + 4, "open"
while time.time() < end:
    if not echo():
        state = "closed"; break
    time.sleep(0.2)
print("%s %s" % ("echoed" if first else "status=" + status, state))
PYEOF

daemon_start "$BIN"
printf 'the-first-token\n' > "$T/tokens"
"$BIN" create proxy pt -p "$PX" --backend "127.0.0.1:$BE" --protocol http --auth "bearer:$T/tokens" -s \
    >/dev/null 2>&1
for _ in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/"$PX") 2>/dev/null && break; sleep 0.1; done

ok "$(python3 -I "$T/tun.py" "$PX" the-first-token 2 '')" "echoed open" \
   "a tunnel whose token stays in the file stays open past the recheck"
ok "$(python3 -I "$T/tun.py" "$PX" the-first-token 0.2 "printf 'a-different-token\n' > '$T/tokens'")" \
   "echoed closed" "a tunnel whose token is taken out of the file is closed"
ok "$(python3 -I "$T/tun.py" "$PX" a-different-token 0 '')" "echoed open" \
   "and one opened with the token now in the file stays open"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
