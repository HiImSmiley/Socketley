#!/usr/bin/env bash
# Integration test: a TLS client that re-dials gives its new socket a handshake deadline of its own.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the deadline armed for the first socket staying armed after its handshake
#     finished: the second socket found it standing and armed none, the old one
#     fired as stale and only cleared its flag, and a target that then accepted
#     and never handshook held the client connected for good
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl CLI not available"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

daemon_isolate clienthsre
P=$((SL_PORT_BASE+1062))
HOLDER=""
cleanup() { [ -n "$HOLDER" ] && kill -9 "$HOLDER" 2>/dev/null; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: a re-dialled TLS socket has its own handshake deadline ==="

D=$SOCKETLEY_TMPD
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=127.0.0.1" \
    -addext "subjectAltName=IP:127.0.0.1" -keyout "$D/key.pem" -out "$D/cert.pem" >/dev/null 2>&1
[ -s "$D/cert.pem" ] || { echo "  SKIP: openssl could not generate a certificate"; exit 0; }

# The first connection is a real handshake, closed after two seconds; every later one is accepted and never answered.
python3 - "$P" "$D" <<'PY' >/dev/null 2>&1 &
import socket, ssl, sys, time
port, d = int(sys.argv[1]), sys.argv[2]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(d + "/cert.pem", d + "/key.pem")
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(16); s.settimeout(1)
held, n, end = [], 0, time.time() + 120
while time.time() < end:
    try: c, _ = s.accept()
    except socket.timeout: continue
    n += 1
    open(d + "/accepts", "w").write("%d %d\n" % (n, int(time.time())))
    if n == 1:
        t = ctx.wrap_socket(c, server_side=True); time.sleep(2); t.close()
    else:
        held.append(c)
PY
HOLDER=$!
disown "$HOLDER" 2>/dev/null || true
for _ in $(seq 1 40); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.25; done

daemon_start "$BIN"
"$BIN" create client hsr -t "127.0.0.1:$P" --tls --ca "$D/cert.pem" --reconnect 5 -s >/dev/null 2>&1

# The second socket opens about three seconds in; its own deadline drops it thirty seconds later.
n=0
for _ in $(seq 1 55); do
    read -r n _t < "$D/accepts" 2>/dev/null || n=0
    [ "${n:-0}" -ge 3 ] && break
    sleep 1
done
if [ "${n:-0}" -ge 3 ]; then ok "the silent second socket was dropped and the client dialled again"
else bad "the second socket has a deadline" "the target saw ${n:-0} connections in 55 s, want 3"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
