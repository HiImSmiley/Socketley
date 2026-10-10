#!/usr/bin/env bash
# Integration test: a follower takes a value of tens of megabytes in the leader's stream in time linear in its size.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the follower searching its whole unfinished line for a newline again at
#     every 4 KiB read: a 30 MB value is some 7,700 reads, each a search of all
#     that came before it -- over a hundred gigabytes of searching for one key
#   * the value arriving other than it is on the leader
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

daemon_isolate repllong
LP=$((SL_PORT_BASE+1972))
FP=$((SL_PORT_BASE+1973))
trap 'daemon_stop' EXIT

echo "=== Integration: a long line in the replication stream ==="

daemon_start "$BIN"
"$BIN" create cache ll -p "$LP" --read-buffer 128M -s >/dev/null 2>&1
for _ in $(seq 1 50); do python3 -c "import socket;socket.create_connection(('127.0.0.1',$LP),1)" 2>/dev/null && break; sleep 0.1; done

# The follower first, synced while there is nothing to sync, so the value reaches it as a command of the live stream
# rather than inside the dump.
"$BIN" create cache lf -p "$FP" --read-buffer 128M --replicate "127.0.0.1:$LP" -s >/dev/null 2>&1
for _ in $(seq 1 50); do python3 -c "import socket;socket.create_connection(('127.0.0.1',$FP),1)" 2>/dev/null && break; sleep 0.1; done
sleep 2
t0=$(date +%s)
# One value of 30 MB, set in RESP, and its digest.
WANT=$(python3 - "$LP" <<'PY'
import hashlib, socket, sys
v = (b"0123456789abcdef" * 2048) * 960        # 30 MiB
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 30)
s.sendall(b"*3\r\n$3\r\nSET\r\n$3\r\nbig\r\n$%d\r\n" % len(v) + v + b"\r\n")
s.settimeout(30); s.recv(64)
print(hashlib.md5(v).hexdigest())
PY
)
GOT=""
for _ in $(seq 1 60); do
    GOT=$(python3 - "$FP" <<'PY'
import hashlib, socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5)
s.sendall(b"*2\r\n$3\r\nGET\r\n$3\r\nbig\r\n")
s.settimeout(5); d = b""
try:
    while True:
        b = s.recv(1 << 20)
        if not b: break
        d += b
        if d.startswith(b"$-1") or (b"\r\n" in d and len(d) >= int(d[1:d.index(b"\r\n")]) + d.index(b"\r\n") + 4): break
except Exception: pass
print(hashlib.md5(d[d.index(b"\r\n") + 2:-2]).hexdigest() if d.startswith(b"$") and not d.startswith(b"$-1") else "")
PY
)
    [ -n "$GOT" ] && break
    sleep 1
done
took=$(( $(date +%s) - t0 ))
if [ "$GOT" = "$WANT" ] && [ "$took" -le 30 ]; then ok "a 30 MB value reaches the follower whole, in ${took}s"
else bad "a long line is taken in linear time" "the follower had '${GOT:-nothing}' after ${took}s (want $WANT within 30 s)"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
