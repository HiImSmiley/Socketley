#!/usr/bin/env bash
# Integration test: what a subscriber has to do to get itself disconnected.
#
# Every publish appends one entry to the subscriber's write queue. While that
# queue was bounded by entry count, a subscriber reading slowly was dropped after
# 4096 notifications — for the 30-byte messages pub/sub actually carries, that is
# about 120 KB, which is not a backlog worth killing a connection over. The bound
# is memory, so it has to be measured in bytes.
#
# The subscriber here reads nothing at all until every message has been sent, and
# uses a small receive buffer so the backlog really does land in the runtime's
# queue rather than in the kernel's socket buffers.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_daemon.sh"
daemon_isolate cachebacklog
PORT=19320
NAME=backlogcache
MSGS="${MSGS:-6000}"
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop "$NAME" 2>/dev/null || true
    sleep 0.2
    "$BIN" remove "$NAME" 2>/dev/null || true
    rm -f "$TMPD"/* 2>/dev/null || true
    rmdir "$TMPD" 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: pub/sub backlog ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 is required"
    exit 0
fi

TMPD=$(mktemp -d)

cat > "$TMPD/slowsub.py" <<'PY'
import socket, sys, time

port, count = int(sys.argv[1]), int(sys.argv[2])

sub = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# A small receive window keeps the kernel from quietly absorbing the backlog,
# so what piles up piles up where the test is looking.
sub.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
sub.connect(("127.0.0.1", port))
sub.sendall(b"subscribe backlog\n")
time.sleep(0.5)

pub = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
pub.connect(("127.0.0.1", port))
payload = b"".join(b"publish backlog msg%06d\n" % i for i in range(count))
pub.sendall(payload)

# Drain the publisher's replies so it does not become a slow reader itself.
pub.settimeout(5.0)
seen = 0
try:
    while seen < count:
        chunk = pub.recv(65536)
        if not chunk:
            break
        seen += chunk.count(b"\n")
except OSError:
    pass
pub.close()

time.sleep(0.5)

# Only now does the subscriber start reading.
sub.settimeout(5.0)
buf = b""
closed_early = False
try:
    while buf.count(b"\n") < count:
        chunk = sub.recv(65536)
        if not chunk:
            closed_early = True
            break
        buf += chunk
except socket.timeout:
    pass
except OSError:
    closed_early = True
sub.close()

delivered = sum(1 for line in buf.split(b"\n") if line.startswith(b"message backlog"))
print("delivered=%d" % delivered)
print("closed_early=%d" % (1 if closed_early else 0))
PY

daemon_start "$BIN"

"$BIN" create cache "$NAME" -p "$PORT" -s >/dev/null 2>&1 || true
# PING/+PONG, not an accepted connection: a cache accepts before it has
# finished loading and can answer.
ready_resp 127.0.0.1 "$PORT" 20 || true

OUT=$(timeout 60 python3 "$TMPD/slowsub.py" "$PORT" "$MSGS" 2>&1 || true)
DELIVERED=$(printf '%s\n' "$OUT" | sed -n 's/^delivered=//p')
CLOSED=$(printf '%s\n' "$OUT" | sed -n 's/^closed_early=//p')
DELIVERED=${DELIVERED:-0}
CLOSED=${CLOSED:-1}

TOTAL=$((TOTAL+1))
if [ "$CLOSED" = "0" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [connection stays open]: the runtime closed the subscriber"
fi

# The old entry cap was 4096, so a run that stops within a message or two of it
# is not merely short — it is short for that reason, and saying so turns a count
# into a diagnosis.
TOTAL=$((TOTAL+1))
if [ "$DELIVERED" -eq "$MSGS" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [every message arrives]: $DELIVERED of $MSGS"
    if [ "$DELIVERED" -ge 4090 ] && [ "$DELIVERED" -le 4100 ]; then
        echo "         stopped at the 4096-entry queue cap, not at a memory limit"
    fi
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
