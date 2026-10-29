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
#   * a byte of a query that is never finished, sent every few seconds, kept
#     a connection from being quiet, so a few such filled the table
#   * a full table closing the newcomer rather than the quietest connection
#   * a peer reading its answers slowly closed as one that reads none, as the
#     write waiting behind the kernel's queue is not woken while it drains
#   * the flood itself cutting a query's length on a short send, so the
#     runtime reads garbage it never answers and the hold is never tested
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
    for r in ns small; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    for r in ns small; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
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
# Beside it a peer sends as much and reads its answers a kilobyte at a time, slowly, and keeps its connection.
res=$(python3 - "$P" <<'PY'
import select, socket, struct, sys, threading, time
p = int(sys.argv[1])
rmem = int(open("/proc/sys/net/ipv4/tcp_rmem").read().split()[2])
wmem = int(open("/proc/sys/net/ipv4/tcp_wmem").read().split()[2])
bound = rmem + wmem + (4 << 20)
q = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
chunk = (struct.pack(">H", len(q)) + q) * 2000
slow = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
slow.connect(("127.0.0.1", p))
threading.Thread(target=slow.sendall, args=(chunk * 64,), daemon=True).start()
opened = time.time()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
s.connect(("127.0.0.1", p))
s.setblocking(False)
sent = 0
off = 0
moved = time.time()
end = moved + 15
while time.time() < end and sent < 2 * bound:
    try:
        # A short send resumes where it stopped, or a query's length is cut and the runtime reads garbage.
        n = s.send(chunk[off:])
        sent += n
        off = (off + n) % len(chunk)
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
secs = 45
kept = "kept"
got = 0
# Watched until well past the 30 seconds after which a peer whose answers do not move is closed.
while time.time() - start < 45 and (closed == "open" or time.time() - opened < 40):
    if closed == "open" and po.poll(500):
        closed = "closed"
        secs = int(time.time() - start)
    elif closed == "closed":
        time.sleep(0.5)
    if kept == "kept":
        try:
            b = slow.recv(1024, socket.MSG_DONTWAIT)
            got += len(b)
            if not b:
                kept = "closed"
        except BlockingIOError:
            pass
        except OSError:
            kept = "closed"
print(held, closed, sent >> 20, secs, kept, got >> 10, int(time.time() - opened))
PY
)
read -r held closed mib secs kept kib slow_secs <<<"$res"
expect "a peer that reads no answers is not read from either (${mib} MiB taken)" "$held" "held"
expect "and its connection is closed once its answers stop moving (${secs}s)" "$closed" "closed"
expect "a peer reading its answers slowly keeps its connection (${kib} KiB read in ${slow_secs}s)" "$kept" "kept"
expect "the runtime answers a fresh connection after it" \
    "$(dig @127.0.0.1 -p "$P" +tcp +short +time=2 +tries=1 example.com A 2>&1)" "192.0.2.1"
stat_of() { "$BIN" stats "$1" 2>/dev/null | awk -F: -v k="$2" '$1==k {s+=$2} END {print s+0}'; }
expect "every query the runtime read of it was whole" "$(stat_of ns dropped)" "0"

# ── a table held by trickled bytes ──────────────────────────────────────────
P2=$((SL_PORT_BASE+1726))
"$BIN" create dns small -p "$P2" --zone "$T/z.zone" --max-connections 4 --proxy none -s >/dev/null 2>&1
for _ in $(seq 1 50); do dig @127.0.0.1 -p "$P2" +tcp +short +time=1 +tries=1 example.com A >/dev/null 2>&1 && break; sleep 0.1; done
sleep 1
# Every slot taken by a connection that sends a byte of a query it never finishes every two seconds: a client
# after them is still answered, and the trickling ones are closed as quiet however often a byte comes.
res=$(python3 - "$P2" <<'PY'
import select, socket, struct, sys, time
p = int(sys.argv[1])
def ask():
    q = struct.pack(">HHHHHH", 9, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    try:
        s = socket.create_connection(("127.0.0.1", p), 3)
        s.settimeout(3)
        s.sendall(struct.pack(">H", len(q)) + q)
        d = b""
        while len(d) < 2 or len(d) < 2 + struct.unpack(">H", d[:2])[0]:
            b = s.recv(4096)
            if not b:
                return "refused"
            d += b
        return "answered" if struct.unpack(">H", d[8:10])[0] == 1 else "wrong"
    except OSError:
        return "refused"
tricklers = []
for _ in range(4):
    s = socket.create_connection(("127.0.0.1", p), 3)
    s.sendall(b"\xff")
    tricklers.append(s)
time.sleep(1)
fresh = ask()
start = time.time()
po = select.poll()
for s in tricklers:
    po.register(s, select.POLLHUP | select.POLLERR | select.POLLRDHUP)
closed = set()
while time.time() - start < 20 and len(closed) < len(tricklers):
    for fd, _ in po.poll(500):
        closed.add(fd)
        po.unregister(fd)
    for s in tricklers:
        if s.fileno() not in closed:
            try:
                s.send(b"\x00")
            except OSError:
                pass
    time.sleep(1.5)
print(fresh, len(closed), int(time.time() - start))
PY
)
read -r fresh closed secs <<<"$res"
expect "a client is answered while every slot is held by a trickling connection" "$fresh" "answered"
expect "and the trickling connections are closed as quiet, though a byte came every two seconds (${secs}s)" "$closed" "4"
expect "the one closed to make room is counted" "$(stat_of small tcp_evicted)" "1"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
