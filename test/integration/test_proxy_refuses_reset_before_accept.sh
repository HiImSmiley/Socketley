#!/usr/bin/env bash
# Integration test: a TCP proxy refuses a socket its client reset before it was
# accepted, and opens no backend for it
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A TCP proxy connects to its backend as it accepts, so a socket that comes off
# the backlog already reset would cost a backend connection and a handshake for
# a peer that cannot receive a byte -- under a flood of them, nearly every
# connection.  handle_accept refused such a socket by asking SO_ERROR and then,
# on a TCP listener, asked getpeername for the client's address and refused a
# socket without one; a reset socket fails both, so SO_ERROR is now asked on a
# unix listener alone and the refusal on a TCP one is getpeername's.  This file
# holds that refusal to account wherever it lives.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a backend connection opened for a client reset before the accept -- both
#     refusals gone, or the getpeername one taken to cover nothing because
#     SO_ERROR "already did"; a TCP proxy, since an HTTP one opens its backend
#     on the first request, which a reset socket never delivers
#   * a live client after them not answered, which would pass the first
#     assertion against a proxy that accepts nothing at all
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
daemon_isolate resetaccept
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
BEPID=""; STOPPED=""
cleanup(){
    [ -n "$STOPPED" ] && kill -CONT "$STOPPED" 2>/dev/null
    [ -n "$BEPID" ] && { kill -9 "$BEPID" 2>/dev/null; wait "$BEPID" 2>/dev/null || true; }
    rm -rf "$WORK"; daemon_stop
}
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: a TCP proxy refuses a socket reset before its accept ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

TP=$((SL_PORT_BASE + 1641)); BP=$((TP + 1))

# A backend that counts the connections it is given, one line each, and echoes.
cat > "$WORK/be.py" <<'PY'
import socket, sys, threading
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1]))); srv.listen(256)
def serve(c):
    with open(sys.argv[2], "a") as f: f.write("c\n")
    try:
        while True:
            d = c.recv(65536)
            if not d: return
            c.sendall(d)
    except OSError: pass
while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
: > "$WORK/accepted"
python3 "$WORK/be.py" "$BP" "$WORK/accepted" >/dev/null 2>&1 &
BEPID=$!

daemon_start "$BIN"
"$BIN" create proxy rt -p "$TP" --backend "127.0.0.1:$BP" --protocol tcp -s >/dev/null 2>&1 || true
for _ in $(seq 1 100); do
    SSO=$(ss -ltn 2>/dev/null)
    [[ "$SSO" == *":$TP "* && "$SSO" == *":$BP "* ]] && break
    sleep 0.1
done
W=$(ss -ltnp 2>/dev/null | awk -v p=":$TP" '$4 ~ p"$" { if (match($0, /pid=[0-9]+/)) print substr($0, RSTART+4, RLENGTH-4) }' | head -1)

# The worker held still while 40 clients connect and reset, so every one is on the backlog, reset, when it accepts.
cat > "$WORK/resets.py" <<'PY'
import socket, struct, sys, time
ss = []
for _ in range(40):
    s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)); ss.append(s)
time.sleep(0.2)
for s in ss: s.close()
PY
cat > "$WORK/live.py" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); s.settimeout(5)
s.sendall(b"ping"); d = b""
try:
    while len(d) < 4: d += s.recv(4096) or b"!" * 99
except OSError: pass
print("ok" if d == b"ping" else repr(d[:60]))
PY

if [ -z "$W" ]; then
    fail "the proxy's worker" "no worker listens on $TP"
else
    kill -STOP "$W"; STOPPED=$W
    python3 "$WORK/resets.py" "$TP" || true
    kill -CONT "$W"; STOPPED=""
    sleep 1
    OPENED=$(wc -l < "$WORK/accepted")
    if [ "$OPENED" = 0 ]; then pass
    else fail "no backend for a client reset before the accept" "$OPENED backend connections for 40 reset clients"; fi
    GOT=$(timeout 10 python3 "$WORK/live.py" "$TP" 2>&1) || true
    if [ "$GOT" = ok ]; then pass
    else fail "a live client after them is answered" "$GOT"; fi
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
