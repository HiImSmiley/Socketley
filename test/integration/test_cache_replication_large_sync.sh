#!/usr/bin/env bash
# Integration test: a follower can join a leader whose dataset is larger than
# the replication lag cap.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# A full sync is the whole dataset written as one queued blob, and the queue
# refused anything past MAX_FOLLOWER_PENDING (8 MiB) -- a cap meant for a
# follower falling behind the live stream, applied to the dump itself.  So a
# leader holding more than about 8 MiB could never be joined: every attempt
# serialised the whole store, was dropped with "full sync to follower failed",
# and the follower redialled on its backoff for as long as both ran, with
# nothing on the follower but an empty keyspace.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# The dataset is 20 MiB, well past the cap, and every key is counted and one
# value compared byte for byte; a write made after the sync must reach the
# follower too, so the live stream behind a large dump is covered as well.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate replbig

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
         local l; for l in "${@:3}"; do echo "        $l"; done; }
cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: a follower joins a leader larger than the lag cap ==="
command -v redis-cli >/dev/null 2>&1 || { echo "  FAIL: redis-cli required"; exit 1; }
daemon_start "$BIN"
LP=$((SL_PORT_BASE + 1620)); FP=$((LP + 1))
KEYS=320        # 320 x 64 KiB = 20 MiB

"$BIN" create cache rb_leader -p "$LP" -s >/dev/null 2>&1
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
print("  loaded", got.count(b"+OK\r\n"), "keys")
EOF

L=$(redis-cli -p "$LP" dbsize 2>/dev/null)
if [ "$L" = "$KEYS" ]; then pass "the leader holds all $KEYS keys"
else fail "leader load" "dbsize $L, want $KEYS"; fi

"$BIN" create cache rb_follower -p "$FP" --replicate "127.0.0.1:$LP" -s >/dev/null 2>&1
F=""
for _ in $(seq 1 150); do
    F=$(redis-cli -p "$FP" dbsize 2>/dev/null)
    [ "$F" = "$KEYS" ] && break
    sleep 0.2
done
if [ "$F" = "$KEYS" ]; then pass "the follower received all $KEYS keys of a 20 MiB dataset"
else fail "full sync past the lag cap" "follower dbsize '$F' after 30 s, want $KEYS" \
          "the dump was refused as lag and the follower never synced"; fi

WANT=$(redis-cli -p "$LP" get big:317 2>/dev/null | md5sum)
GOT=$(redis-cli -p "$FP" get big:317 2>/dev/null | md5sum)
if [ "$WANT" = "$GOT" ]; then pass "a synced value is byte for byte the leader's"
else fail "synced value" "md5 differs between leader and follower"; fi

redis-cli -p "$LP" set after sync >/dev/null 2>&1
V=""
for _ in $(seq 1 50); do
    V=$(redis-cli -p "$FP" get after 2>/dev/null)
    [ "$V" = "sync" ] && break
    sleep 0.1
done
if [ "$V" = "sync" ]; then pass "a write after the sync reaches the follower"
else fail "live stream behind the dump" "follower GET after = '$V'"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
