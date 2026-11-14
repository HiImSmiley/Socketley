#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and SL_PORT_BASE ports.
# A request whose head arrived whole and whose body comes a byte at a time costs the server the bytes, not the head
# again for each: parse_partial judged a 14 KiB head of 3,500 lines on every read while it waited for the body, and a
# head sent a byte at a time was searched for its end from the first byte on every read.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

echo "=== Integration: an HTTP body trickled to the server costs its bytes ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; exit 0; }

daemon_isolate srvtrickle
trap daemon_stop EXIT
PASS=0; FAIL=0; TOTAL=0
PORT=$((SL_PORT_BASE+571))
daemon_start "$BIN"
mkdir -p "$SOCKETLEY_TMPD/www"
create_ok "server created" "$BIN" create server trk -p "$PORT" --http "$SOCKETLEY_TMPD/www" -s

# Every process of this daemon, by the socket in its environment, so the worker serving the port is counted.
H="$SOCKETLEY_TMPD/trickle.py"
cat >"$H" <<'PYEOF'
import os, socket, sys, time
port, sock = int(sys.argv[1]), sys.argv[2]
mode = sys.argv[3]

def cpu():
    total = 0
    for p in os.listdir("/proc"):
        if not p.isdigit():
            continue
        try:
            env = open(f"/proc/{p}/environ", "rb").read()
            if f"SOCKETLEY_SOCKET={sock}".encode() not in env.split(b"\0"):
                continue
            f = open(f"/proc/{p}/stat").read().rsplit(")", 1)[1].split()
            total += int(f[11]) + int(f[12])
        except OSError:
            pass
    return total / os.sysconf("SC_CLK_TCK")

for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        break
    except OSError:
        time.sleep(0.05)
s = socket.create_connection(("127.0.0.1", port), timeout=10)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
n = 12000
before = cpu()
if mode in ("body", "control"):
    lines = 3500 if mode == "body" else 1
    s.sendall(b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: %d\r\n" % n + b"a:\r\n" * lines + b"\r\n")
    time.sleep(0.05)
    for _ in range(n):
        s.send(b"x")
        time.sleep(0.0003)
else:
    head = b"GET /x HTTP/1.1\r\nHost: a\r\nX: " + b"\r" * (n - 40)
    for i in range(len(head)):
        s.send(head[i:i + 1])
        time.sleep(0.0003)
    s.sendall(b"\r\n\r\n")
answer = b""
s.settimeout(10)
try:
    while b"\r\n\r\n" not in answer:
        chunk = s.recv(4096)
        if not chunk:
            break
        answer += chunk
except OSError:
    pass
print("RESULT %.3f %s" % (cpu() - before, answer.split(b"\r\n", 1)[0].decode(errors="replace")))
PYEOF

# Against the same 12,000 reads behind a head of one line, which is what a read costs whatever the fix: the head judged
# on each of them cost 3.5 times that, and the head searched from its start on each 2.6 times.
run() { python3 "$H" "$PORT" "$SOCKETLEY_SOCKET" "$1" 2>&1 | grep '^RESULT' || true; }
BASE=$(run control | awk '{print $2}')
echo "  control: ${BASE:-?}s of CPU for 12,000 one-byte reads"
check() {
    local label=$1 mode=$2 out spent line
    out=$(run "$mode")
    spent=$(echo "$out" | awk '{print $2}')
    line=$(echo "$out" | cut -d' ' -f3-)
    TOTAL=$((TOTAL+1))
    if [ -n "$spent" ] && [ -n "$BASE" ] && awk -v s="$spent" -v b="$BASE" 'BEGIN{exit !(s < b * 1.5 + 0.1)}' &&
       [[ "$line" == HTTP/1.1* ]]; then
        PASS=$((PASS+1)); echo "  OK [$label]: ${spent}s of CPU, answered $line"
    else
        FAIL=$((FAIL+1)); echo "  FAIL [$label]: ${spent:-?}s of CPU (at most 1.5 x ${BASE:-?} + 0.1), answered '${line}'"
    fi
}
check "a 12,000-byte body a byte a read behind a 14 KiB head" body
check "a 12,000-byte head a byte a read" head

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
