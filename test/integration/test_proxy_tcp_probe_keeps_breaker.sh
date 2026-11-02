#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a client of a --protocol tcp proxy that connects and goes is not charged to the backend.
#
# What it would catch: the backend's clean close after the client's FIN, which the proxy passes on, counted as a
# backend failure because nothing reached the client.  Five such clients -- a health check, a port scanner, a load
# balancer's probe -- opened the breaker of a healthy backend, and every client after was refused: measured, a run of
# wrk then reconnected 130,000 times in two seconds.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a TCP proxy's client that connects and goes leaves the backend's breaker shut ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }
daemon_isolate tcpprobe
T=$SOCKETLEY_TMPD
PB=$((SL_PORT_BASE + 1957)); PP=$((PB + 1)); PT=$((PB + 2))
unset SOCKETLEY_CONFIG
BE_PID=""
trap '[ -n "$BE_PID" ] && kill "$BE_PID" 2>/dev/null; daemon_stop' EXIT

# A backend that answers each line, and closes when its client does, as any server does.
cat > "$T/be.py" <<'PY'
import socket, sys, threading
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind(("127.0.0.1", int(sys.argv[1]))); l.listen(64)
def serve(c):
    with c:
        while True:
            d = c.recv(4096)
            if not d:
                return
            c.sendall(b"got " + d)
while True:
    c, _ = l.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
python3 "$T/be.py" "$PB" & BE_PID=$!
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=127.0.0.1 \
    -keyout "$T/k.pem" -out "$T/c.pem" >/dev/null 2>&1
daemon_start "$BIN"
"$BIN" create proxy plain -p "$PP" --protocol tcp --backend "127.0.0.1:$PB" -s >/dev/null 2>&1
"$BIN" create proxy tls -p "$PT" --protocol tcp --backend "127.0.0.1:$PB" --tls --cert "$T/c.pem" --key "$T/k.pem" -s \
    >/dev/null 2>&1
for p in "$PB" "$PP" "$PT"; do for _ in $(seq 1 50); do ss -ltnH "( sport = :$p )" | grep -q . && break; sleep 0.1; done; done

stat_of() { "$BIN" stats "$1" 2>/dev/null | awk -F: -v k="$2" '$1==k {print $2}'; }
for name in plain tls; do
    port=$([ $name = plain ] && echo "$PP" || echo "$PT")
    python3 - "$port" <<'PY'
import socket, sys, time
for _ in range(10):
    socket.create_connection(("127.0.0.1", int(sys.argv[1]))).close()
    time.sleep(0.05)
PY
    sleep 1
    f=$(stat_of $name backend_failures); o=$(stat_of $name open_circuits)
    if [ "${f:-x}" = 0 ] && [ "${o:-0}" = 0 ]; then ok
    else bad "$name: ten clients that connect and go charge the backend nothing" "backend_failures=${f:-?} open_circuits=${o:-0}"; fi
done

got=$(python3 - "$PP" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5); s.sendall(b"ping\n")
print(s.recv(100).decode().strip())
PY
)
if [ "$got" = "got ping" ]; then ok; else bad "and the next client is relayed" "got '${got}'"; fi
got=$(printf 'ping\n' | timeout 5 openssl s_client -quiet -connect "127.0.0.1:$PT" 2>/dev/null | head -1)
if [ "$got" = "got ping" ]; then ok; else bad "and over TLS as well" "got '${got}'"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
