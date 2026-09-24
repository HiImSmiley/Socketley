#!/usr/bin/env bash
# Integration test: an HTTP client that pipelines and never reads is closed at
# the write bound instead of growing the worker.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# queue_http_response() pushed every answer onto the write queue without
# asking admit_send(), the check every other server write makes, and the parse
# loop went straight on to the next pipelined request.  A .html file too large
# for the revalidation cache is built into a fresh buffer per GET, so a client
# sending the same GET a hundred times and reading nothing held a hundred
# copies of the file in the worker, for as long as it cared to.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# The allowance is a fraction of what the defect adds, the connection must be
# closed rather than merely slowed, and a client that pipelines and does read
# must still get every byte.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate httppipebound

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
         local l; for l in "${@:3}"; do echo "        $l"; done; }
cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: pipelined HTTP answers are held to the write bound ==="
WWW="$SOCKETLEY_TMPD/www"; mkdir -p "$WWW"
head -c 3000000 /dev/zero | tr '\0' 'h' > "$WWW/index.html"
daemon_start "$BIN"
P=$((SL_PORT_BASE + 1920))
"$BIN" create server hp -p "$P" --http "$WWW" -s >/dev/null 2>&1
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done
WORKER=$(ss -ltnp 2>/dev/null | awk -v p=":$P" '$4 ~ p"$" {
    if (match($0, /pid=[0-9]+/)) print substr($0, RSTART+4, RLENGTH-4) }' | head -1)
[ -n "${WORKER:-}" ] || { echo "  FAIL: no worker pid"; exit 1; }
rss() { awk '/^VmRSS/{print $2}' "/proc/$WORKER/status" 2>/dev/null || echo 0; }

cat > "$SOCKETLEY_TMPD/greedy.py" <<'PYEOF'
# Pipelines n GETs and reads nothing for three seconds, then drains what the
# server kept for it and reports whether the stream ended, and after how much.
import socket, sys, time
port, n = int(sys.argv[1]), int(sys.argv[2])
s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.sendall(b"GET /index.html HTTP/1.1\r\nHost: h\r\n\r\n" * n)
time.sleep(3)
s.settimeout(10)
got = 0
try:
    while True:
        b = s.recv(1 << 20)
        if not b:
            print("closed", got); break
        got += len(b)
except socket.timeout:
    print("open", got)
except (ConnectionResetError, BrokenPipeError):
    print("closed", got)
PYEOF
BASE=$(rss)
python3 "$SOCKETLEY_TMPD/greedy.py" "$P" 100 >"$SOCKETLEY_TMPD/g.out" 2>&1 &
GP=$!
PEAK=$BASE
while kill -0 "$GP" 2>/dev/null; do r=$(rss); [ "${r:-0}" -gt "$PEAK" ] && PEAK=$r; sleep 0.1; done
wait "$GP" 2>/dev/null
ADDED=$(( (PEAK - BASE) / 1024 ))
echo "  100 pipelined GETs of a 3 MB file, never read: worker grew $ADDED MB ($(cat "$SOCKETLEY_TMPD/g.out"))"
if [ "$ADDED" -lt 60 ]; then pass "the worker stayed near the bound ($ADDED MB for 300 MB asked)"
else fail "pipelined answers are bounded" "the worker grew $ADDED MB against an allowance of 60"; fi
# Closed at the bound and not answered in full: what was queued before the
# refusal is still delivered -- a slow reader is owed it -- and then the stream
# ends, where the unbounded build answered every one of the hundred.
read -r G_STATE G_BYTES < "$SOCKETLEY_TMPD/g.out"
if [ "$G_STATE" = "closed" ] && [ "${G_BYTES:-0}" -lt 60000000 ]; then
    pass "the client that would not read was cut at the bound and closed ($G_BYTES bytes)"
else fail "the client that would not read was cut at the bound and closed" \
          "it saw: $G_STATE after $G_BYTES bytes of 300000000"; fi

GOT=$(python3 - "$P" <<'PYEOF'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=20)
s.sendall(b"GET /index.html HTTP/1.1\r\nHost: h\r\n\r\n" * 2)
want, got = 2 * 3000000, 0
buf = b""
while got < want:
    b = s.recv(1 << 20)
    if not b: break
    buf += b
    got = buf.count(b"h" * 1000) * 1000
print(len(buf))
PYEOF
)
if [ "${GOT:-0}" -gt 6000000 ]; then pass "a client that pipelines and reads gets both answers"
else fail "pipelining that reads" "read $GOT bytes for two 3 MB answers"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
