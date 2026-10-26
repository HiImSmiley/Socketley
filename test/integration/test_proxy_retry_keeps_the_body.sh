#!/usr/bin/env bash
# Integration test: a retried request reaches the second backend whole, or is
# not retried at all.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# A retry resends saved_request, which holds the head and whatever body came in
# the first read; body bytes forwarded after that were never added to it.  So a
# PUT larger than one read, retried after the first backend dropped it, reached
# the second backend truncated -- which then waited for the rest until
# --backend-timeout and the client got a 504 for a request that had been
# half-delivered twice.  A request whose body has streamed past the first read
# is no longer retried; one that fits in it still is.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# Backend A reads the whole request and closes without answering, which is
# what earns a retry; backend B logs the length of every body it is sent.  A
# small PUT must still be retried and answered by B, so a build that stopped
# retrying altogether fails the control.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate pxretrybody

A=$((SL_PORT_BASE+1760)); B=$((A+1)); PX=$((A+2))
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1))
        if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
        else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi; }
cleanup() { kill ${APID:-} ${BPID:-} 2>/dev/null; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: a retry sends the whole body or none ==="

cat > "$SOCKETLEY_TMPD/be.py" <<'PYEOF'
import socket, sys, threading
port, role, log = int(sys.argv[1]), sys.argv[2], sys.argv[3]
def serve(c):
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            b = c.recv(65536)
            if not b: return
            buf += b
        head, body = buf.split(b"\r\n\r\n", 1)
        n = 0
        for l in head.split(b"\r\n"):
            if l.lower().startswith(b"content-length:"):
                n = int(l.split(b":")[1])
        c.settimeout(3)
        try:
            while len(body) < n:
                b = c.recv(65536)
                if not b: break
                body += b
        except socket.timeout:
            pass
        with open(log, "a") as f:
            f.write("%s %d of %d\n" % (role, len(body), n))
        if role == "A":
            return                      # read it all, answer nothing
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    finally:
        c.close()
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", port)); ls.listen(16)
sys.stderr.write("up\n"); sys.stderr.flush()
while True:
    c, _ = ls.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PYEOF
python3 "$SOCKETLEY_TMPD/be.py" "$A" A "$SOCKETLEY_TMPD/log" 2>"$SOCKETLEY_TMPD/a.err" & APID=$!
python3 "$SOCKETLEY_TMPD/be.py" "$B" B "$SOCKETLEY_TMPD/log" 2>"$SOCKETLEY_TMPD/b.err" & BPID=$!
for _ in $(seq 1 50); do grep -q up "$SOCKETLEY_TMPD/a.err" && grep -q up "$SOCKETLEY_TMPD/b.err" && break; sleep 0.1; done

daemon_start "$BIN"
# One proxy per case, so each starts its round robin on A.
for n in 0 1 2; do
    "$BIN" create proxy "rb$n" -p $((PX + n)) --backend "127.0.0.1:$A,127.0.0.1:$B" \
        --protocol http --strategy round-robin --retry 1 --backend-timeout 6 -s >/dev/null 2>&1
    for _ in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/$((PX + n))) 2>/dev/null && break; sleep 0.1; done
done

put() {
    python3 - "$1" "$2" "$3" "$4" <<'PYEOF'
import socket, sys, time
port, size = int(sys.argv[1]), int(sys.argv[2])
gap = float(sys.argv[3]) if len(sys.argv) > 3 else 0.0
name = sys.argv[4]
s = socket.create_connection(("127.0.0.1", port), timeout=10)
s.sendall(b"PUT /%s/x HTTP/1.1\r\nHost: h\r\nContent-Length: %d\r\n\r\n" % (name.encode(), size))
time.sleep(gap)
body = b"b" * size
for i in range(0, size, 16384):
    s.sendall(body[i:i + 16384])
    time.sleep(0.002)
t = time.time()
try:
    r = s.recv(4096).split(b"\r\n")[0].decode()
except Exception as e:
    r = type(e).__name__
print("%s %.1f" % (r.split(" ")[1] if " " in r else r, time.time() - t))
PYEOF
}

# Round robin starts on A, which reads and drops; the retry goes to B.
: > "$SOCKETLEY_TMPD/log"
set -- $(put "$PX" 100 0 rb0)
ok "${1:-}" "200" "a PUT that fits one read is retried and answered by the second backend"
: > "$SOCKETLEY_TMPD/log"
set -- $(put $((PX + 1)) 1000000 0 rb1)
B_LINE=$(grep '^B ' "$SOCKETLEY_TMPD/log" | head -1)
case "$B_LINE" in
    ""|"B 1000000 of 1000000") ok a a "the second backend never saw a truncated body" ;;
    *) ok "$B_LINE" "B 1000000 of 1000000, or nothing" "the second backend never saw a truncated body" ;;
esac
ok "${1:-}" "502" "a PUT that streamed past the first read is not retried: 502 at once"

# The same small PUT with its body a moment behind its head, so the proxy reads
# them apart -- which load did to the first case one run in sixteen: whether a
# 100-byte body could be retried depended on how TCP cut it.
: > "$SOCKETLEY_TMPD/log"
set -- $(put $((PX + 2)) 100 0.05 rb2)
ok "${1:-}" "200" "a small body read apart from its head is still retried"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
