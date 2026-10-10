#!/usr/bin/env bash
# Integration test: --max-connections refuses the connection past the limit, and --rate-limit drops what a client
# sends faster than it allows.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a fourth connection kept by a server limited to three
#   * one of the three it holds closed to make room, which a limit that
#     evicted rather than refused would do
#   * twenty lines sent at once all counted by a server limited to two a
#     second: the bucket starts full at two, so three at the most
#   * a client that went over held off for good rather than until its bucket
#     filled again
#
# This file asserted only that the server appeared in `ps` and that `stats`
# printed a total_connections line, which a server with no limit at all passes.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

daemon_isolate ratelimit
PORT=$((SL_PORT_BASE+230))
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
trap 'daemon_stop' EXIT

echo "=== Integration: rate limit & max connections ==="
daemon_start "$BIN"
"$BIN" create server rl_test -p "$PORT" --rate-limit 2 --max-connections 3 -s >/dev/null 2>&1
for _ in $(seq 1 50); do python3 -c "import socket;socket.create_connection(('127.0.0.1',$PORT),1).close()" 2>/dev/null && break; sleep 0.1; done
sleep 0.5
stat() { "$BIN" stats rl_test 2>/dev/null | sed -n "s/^$1://p"; }

# Three held, a fourth tried; then the first sends twenty lines at once, rests, and sends one more.
out=$(python3 - "$PORT" "$BIN" <<'PY'
import socket, subprocess, sys, time
port, binary = int(sys.argv[1]), sys.argv[2]
def stat(k):
    out = subprocess.run([binary, "stats", "rl_test"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if line.startswith(k + ":"):
            return int(line.split(":", 1)[1])
    return -1
held = [socket.create_connection(("127.0.0.1", port), 5) for _ in range(3)]
time.sleep(0.5)
fourth = socket.create_connection(("127.0.0.1", port), 5)
fourth.settimeout(2)
try:
    closed = fourth.recv(1) == b""
except socket.timeout:
    closed = False
except OSError:
    closed = True
alive = 0
for s in held:
    s.setblocking(False)
    try:
        alive += 0 if s.recv(1) == b"" else 1
    except BlockingIOError:
        alive += 1
    except OSError:
        pass
before = stat("total_messages")
held[0].sendall(b"".join(b"m%d\n" % i for i in range(20)))
time.sleep(1)
burst = stat("total_messages") - before
time.sleep(1.5)
held[0].sendall(b"later\n")
time.sleep(0.5)
after = stat("total_messages") - before - burst
print(int(closed), alive, burst, after)
PY
)
read -r closed alive burst after <<<"$out"
expect "a fourth connection to a server limited to three is closed" "$closed" 1
expect "and the three it holds are kept" "$alive" 3
if [ -n "$burst" ] && [ "$burst" -ge 1 ] && [ "$burst" -le 3 ]; then
    ok "twenty lines at once are counted no more than the bucket holds ($burst of 20)"
else
    bad "a limit of two a second drops the rest of a burst" "counted ${burst:-<none>} of 20"
fi
expect "and once the bucket has filled again a line is taken" "$after" 1

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
