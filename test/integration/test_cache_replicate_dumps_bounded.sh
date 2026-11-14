#!/usr/bin/env bash
# Integration test: REPLICATE from any client holds at most two copies of the dataset at once, and a copy nobody
# takes does not keep a follower out.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# Any client of a cache may send REPLICATE, and each one had the whole dataset serialised on the loop and held until
# the client read it: six connections that never read held six copies of a 20 MiB store, and a hundred would hold a
# hundred. At most two datasets' worth are on their way now and the rest are told "error: busy"; a dump that has
# moved nothing for SOCKETLEY_CACHE_DUMP_STALL_MS (a minute; three seconds here) is given up when a follower asks, so the
# follower created afterwards still syncs.
# suite: isolated
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate repldumps

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
HOLDER=""
cleanup() {
    [ -n "$HOLDER" ] && kill "$HOLDER" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: REPLICATE holds at most two dumps ==="
command -v redis-cli >/dev/null 2>&1 || { echo "  FAIL: redis-cli required"; exit 1; }
export SOCKETLEY_CACHE_DUMP_STALL_MS=3000
daemon_start "$BIN"
LP=$((SL_PORT_BASE + 1640)); FP=$((LP + 1))
KEYS=320        # 320 x 64 KiB = 20 MiB, far past what a socket buffers

"$BIN" create cache rd_leader -p "$LP" -s >/dev/null 2>&1
for _ in $(seq 1 100); do redis-cli -p "$LP" ping 2>/dev/null | grep -q PONG && break; sleep 0.1; done

python3 - "$LP" "$KEYS" <<'EOF'
import socket, sys
port, n = int(sys.argv[1]), int(sys.argv[2])
s = socket.create_connection(("127.0.0.1", port))
for i in range(n):
    val = (b"%06d" % i) * (65536 // 6) + b"x" * (65536 % 6)
    key = b"big:%d" % i
    s.sendall(b"*3\r\n$3\r\nSET\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n" % (len(key), key, len(val), val))
got = b""
while got.count(b"+OK\r\n") < n:
    chunk = s.recv(65536)
    if not chunk: break
    got += chunk
EOF

# Six clients ask for a dump and never read past its first line; the answers go to a file, the sockets stay open.
ANS="$SOCKETLEY_TMPD/answers"
python3 - "$LP" "$ANS" <<'EOF' &
import socket, sys, time
port, out = int(sys.argv[1]), sys.argv[2]
socks, firsts = [], []
for _ in range(6):
    s = socket.create_connection(("127.0.0.1", port))
    s.sendall(b"replicate\n")
    s.settimeout(5)
    line = b""
    try:
        while b"\n" not in line:
            chunk = s.recv(1)
            if not chunk:
                break
            line += chunk
    except OSError:
        pass
    firsts.append(line.split(b"\n")[0].decode(errors="replace"))
    socks.append(s)
with open(out, "w") as f:
    f.write("\n".join(firsts) + "\n")
time.sleep(120)
EOF
HOLDER=$!
for _ in $(seq 1 100); do [ -s "$ANS" ] && break; sleep 0.1; done

OKS=$(grep -c '^ok$' "$ANS" 2>/dev/null)
BUSY=$(grep -c '^error: busy' "$ANS" 2>/dev/null)
if [ "$OKS" = 2 ] && [ "$BUSY" = 4 ]; then pass "two of six REPLICATEs get a dump and four are told the leader is busy"
else fail "dumps held at once" "$OKS answered ok and $BUSY busy, want 2 and 4: $(tr '\n' '|' < "$ANS")"; fi

# The two dumps nobody reads stall; a follower that dials after three seconds has them given up and syncs.
sleep 3.5
"$BIN" create cache rd_follower -p "$FP" --replicate "127.0.0.1:$LP" -s >/dev/null 2>&1
F=""
for _ in $(seq 1 200); do
    F=$(redis-cli -p "$FP" dbsize 2>/dev/null)
    [ "$F" = "$KEYS" ] && break
    sleep 0.2
done
if [ "$F" = "$KEYS" ]; then pass "a follower syncs all $KEYS keys while the stalled dumps are still connected"
else fail "a follower behind stalled dumps" "follower dbsize '$F' after 40 s, want $KEYS"; fi

redis-cli -p "$LP" set after-sync yes >/dev/null 2>&1
G=""
for _ in $(seq 1 50); do
    G=$(redis-cli -p "$FP" get after-sync 2>/dev/null)
    [ "$G" = yes ] && break
    sleep 0.1
done
if [ "$G" = yes ]; then pass "a write after the sync reaches the follower"
else fail "live stream" "follower has '$G' for after-sync"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
exit "$FAIL"
