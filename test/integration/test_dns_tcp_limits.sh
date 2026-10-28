#!/usr/bin/env bash
# Integration test: a DNS TCP connection holds a bounded amount of the runtime's memory, and a peer that stops
# reading does not keep its connection.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * every query read and answered while the peer reads nothing back, so the
#     answers waiting to be written grew to 256 MiB a connection
#   * a connection with answers still waiting never closed, however long its
#     peer had not read them
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v dig >/dev/null 2>&1 || { echo "  SKIP: dig is not installed (dnsutils / bind9-dnsutils)"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate dnslimits
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1725))
cleanup() {
    "$BIN" stop ns >/dev/null 2>&1 || true
    "$BIN" remove ns >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: DNS TCP connections are bounded ==="

daemon_start "$BIN"
cat > "$T/z.zone" <<'EOF'
$ORIGIN example.com.
$TTL 3600
@   IN SOA ns1 hostmaster ( 1 1h 15m 1w 300 )
    IN NS  ns1
    IN A   192.0.2.1
ns1 IN A   192.0.2.53
EOF
"$BIN" create dns ns -p "$P" --zone "$T/z.zone" --proxy none -s >/dev/null 2>&1
for _ in $(seq 1 50); do dig @127.0.0.1 -p "$P" +tcp +short +time=1 +tries=1 example.com A >/dev/null 2>&1 && break; sleep 0.1; done

# ── a peer that never reads ─────────────────────────────────────────────────
# Queries sent as fast as the runtime takes them, from a socket that reads nothing back: once the answers waiting
# pass the runtime's mark it stops reading, and what the client gets sent is what the socket buffers on the way hold.
res=$(python3 - "$P" <<'PY'
import select, socket, struct, sys, time
p = int(sys.argv[1])
rmem = int(open("/proc/sys/net/ipv4/tcp_rmem").read().split()[2])
wmem = int(open("/proc/sys/net/ipv4/tcp_wmem").read().split()[2])
bound = rmem + wmem + (4 << 20)
q = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
chunk = (struct.pack(">H", len(q)) + q) * 2000
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
s.connect(("127.0.0.1", p))
s.setblocking(False)
sent = 0
moved = time.time()
end = moved + 15
while time.time() < end and sent < 2 * bound:
    try:
        sent += s.send(chunk)
        moved = time.time()
    except BlockingIOError:
        if time.time() - moved > 2:
            break
        select.select([], [s], [], 0.2)
held = "held" if sent < bound else "read"
# Never read from: the runtime is to close it once its answers have not moved for a while.
start = time.time()
po = select.poll()
po.register(s, select.POLLHUP | select.POLLERR | select.POLLRDHUP)
closed = "open"
while time.time() - start < 45:
    if po.poll(1000):
        closed = "closed"
        break
print(held, closed, sent >> 20, int(time.time() - start))
PY
)
read -r held closed mib secs <<<"$res"
expect "a peer that reads no answers is not read from either (${mib} MiB taken)" "$held" "held"
expect "and its connection is closed once its answers stop moving (${secs}s)" "$closed" "closed"
expect "the runtime answers a fresh connection after it" \
    "$(dig @127.0.0.1 -p "$P" +tcp +short +time=2 +tries=1 example.com A 2>&1)" "192.0.2.1"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
