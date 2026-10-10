#!/usr/bin/env bash
# Integration test: a master login's password goes to the login and nowhere a message is kept.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * `master <password>` stored as a message in the server's linked cache,
#     where anyone who can read the cache reads the password
#   * the same line written to the -w file of received messages
#   * the messages after it no longer stored or written, which a fix that
#     stopped keeping messages at all would do
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
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate mlogin
T="$SOCKETLEY_TMPD"
SP=$((SL_PORT_BASE+1963))
CP=$((SL_PORT_BASE+1964))
trap 'daemon_stop' EXIT

echo "=== Integration: a master login is not kept ==="

daemon_start "$BIN"
PW=hunter2masterpass
"$BIN" create cache mc -p "$CP" -s >/dev/null 2>&1
"$BIN" create server ms -p "$SP" --mode master --master-pw "$PW" --cache mc -w "$T/received" -s >/dev/null 2>&1
for _ in $(seq 1 50); do python3 -c "import socket;socket.create_connection(('127.0.0.1',$SP),1)" 2>/dev/null && break; sleep 0.1; done

# One client logs in and then says something; a second asks the cache what was stored.
python3 - "$SP" "$PW" <<'PY'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5)
s.sendall(("master %s\n" % sys.argv[2]).encode())
time.sleep(0.3)
s.sendall(b"hello after login\n")
time.sleep(0.5)
s.close()
PY
sleep 1
stored=$(python3 - "$SP" <<'PY'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5)
s.settimeout(2)
out = b""
for n in (1, 2, 3):
    s.sendall(b"cache get %d\n" % n)
    time.sleep(0.3)
try:
    while True:
        b = s.recv(65536)
        if not b: break
        out += b
except Exception:
    pass
print(out.decode(errors="replace").replace("\n", " | "))
PY
)
expect "the password is not stored in the linked cache" "$(grep -c "$PW" <<<"$stored")" 0
expect "and the message after the login is" "$(grep -c 'hello after login' <<<"$stored")" 1
expect "the password is not written to the -w file" "$(grep -c "$PW" "$T/received" 2>/dev/null)" 0
expect "and the message after the login is" "$(grep -c 'hello after login' "$T/received" 2>/dev/null)" 1

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
