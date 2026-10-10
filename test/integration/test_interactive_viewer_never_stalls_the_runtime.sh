#!/usr/bin/env bash
# Integration test: an interactive session that stops reading does not stop the runtime it watches.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * notify_interactive() writing to the operator's terminal with a blocking
#     write from the runtime's own event loop: a session suspended with ^Z, or
#     a terminal scrolled back, fills the socket, and the server stops serving
#     every one of its clients until somebody reads
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

daemon_isolate stallview
P=$((SL_PORT_BASE+1971))
trap 'daemon_stop' EXIT

echo "=== Integration: a stalled interactive viewer does not stall the runtime ==="

daemon_start "$BIN"
"$BIN" create server sv -p "$P" -s >/dev/null 2>&1
for _ in $(seq 1 50); do python3 -c "import socket;socket.create_connection(('127.0.0.1',$P),1)" 2>/dev/null && break; sleep 0.1; done

got=$(PYTHONPATH="$HERE" python3 - "$BIN" "$SOCKETLEY_SOCKET" "$P" <<'PY'
import os, signal, socket, sys, time
from lib_interactive import session
binp, sock, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
viewer = session(binp, sock, "sv")
time.sleep(1.0)
# The operator walks away: the session reads nothing more, and its socket fills.
os.kill(viewer.pid, signal.SIGSTOP)
b = socket.create_connection(("127.0.0.1", port), 5)
a = socket.create_connection(("127.0.0.1", port), 5)
time.sleep(0.3)
line = b"y" * 1000 + b"\n"
# A server that stopped serving stops reading too, so the sender is bounded as well as the reader.
a.settimeout(15)
try:
    for _ in range(3000):
        a.sendall(line)
    a.sendall(b"END\n")
except Exception:
    pass
b.settimeout(15)
seen, buf = False, b""
deadline = time.time() + 15
try:
    while time.time() < deadline and not seen:
        d = b.recv(1 << 20)
        if not d: break
        buf = (buf + d)[-64:]
        seen = b"END\n" in buf
except Exception:
    pass
os.kill(viewer.pid, signal.SIGCONT)
viewer.kill()
print("reached" if seen else "stalled")
PY
)
expect "a client still hears everything while a viewer has stopped reading" "$got" "reached"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
