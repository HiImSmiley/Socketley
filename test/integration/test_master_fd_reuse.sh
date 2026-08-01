#!/usr/bin/env bash
# Integration test: authority must not survive on a recycled file descriptor.
#
# In master mode the server records the authenticated client's fd and later
# decides who may broadcast by comparing against it. File descriptor numbers are
# reused by the kernel as soon as they are closed, so every teardown path has to
# clear that record — a path that forgets hands the next accepted connection
# broadcast authority it never authenticated for.
#
# test_master_mode.sh covers authentication itself but never disconnects an
# authenticated client, so nothing exercised what happens to its fd afterwards.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
daemon_isolate masterfd
PORT=19810
PW=s3cret
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop mfdsrv 2>/dev/null || true
    sleep 0.3
    "$BIN" remove mfdsrv 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: master authority across fd reuse ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not available"
    exit 0
fi

daemon_start "$BIN"
"$BIN" create server mfdsrv -p "$PORT" --mode master --master-pw "$PW" -s 2>&1 || true
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$PORT" 2>/dev/null && break; sleep 0.1; done
sleep 0.3

set +e
python3 - "$PORT" "$PW" <<'PYEOF'
import socket, sys, time

host, port, pw = "127.0.0.1", int(sys.argv[1]), sys.argv[2]

def conn():
    s = socket.create_connection((host, port), timeout=5)
    s.settimeout(2.0)
    return s

def drain(s):
    out = b""
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            out += b
    except socket.timeout:
        pass
    return out.decode(errors="replace")

observer = conn()          # ordinary client, sees whatever is broadcast
time.sleep(0.3)

master = conn()
master.sendall(f"master {pw}\n".encode())
time.sleep(0.3)
if "master: ok" not in drain(master):
    print("SETUP: authentication was refused", file=sys.stderr)
    sys.exit(2)

# Trip the unparsed-input cap: more than 1 MiB with no newline, so none of it is
# ever consumed as a command. This reaches a teardown path distinct from a plain
# disconnect.
try:
    master.sendall(b"X" * (1200 * 1024))
except OSError:
    pass
time.sleep(1.0)
master.close()
time.sleep(0.5)

# Takes the fd number the master just released.
newcomer = conn()
time.sleep(0.3)
newcomer.sendall(b"UNAUTHENTICATED-BROADCAST\n")
time.sleep(0.8)

seen = drain(observer)
newcomer.close()
observer.close()
sys.exit(1 if "UNAUTHENTICATED-BROADCAST" in seen else 0)
PYEOF
rc=$?
set -e

TOTAL=$((TOTAL+1))
case "$rc" in
    0) PASS=$((PASS+1)) ;;
    1) FAIL=$((FAIL+1)); echo "  FAIL: an unauthenticated client inherited master authority" ;;
    *) FAIL=$((FAIL+1)); echo "  FAIL: test setup did not complete (rc=$rc)" ;;
esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
