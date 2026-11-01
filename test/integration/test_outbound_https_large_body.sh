#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a request whose body is held in memory reaches an https:// host whole, however large.
#
# What it would catch: the outbound HTTP peer handing an in-memory body to the record layer in 1 MiB pieces with no
# flush between them.  The record layer holds at most 512 KiB of ciphertext, so the second piece was refused and the
# request failed with "the record layer took no more": every body over about 1 MiB to an https host -- an MQTT
# webhook rule's message here, and the same path for sync, replication and notifications.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: an in-memory body reaches an https host whole ==="
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }
daemon_isolate httpsbig
T=$SOCKETLEY_TMPD
PE=$((SL_PORT_BASE + 1987)); PH=$((PE + 1))
unset SOCKETLEY_CONFIG
HOOK_PID=""
trap '[ -n "$HOOK_PID" ] && kill "$HOOK_PID" 2>/dev/null; daemon_stop' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=127.0.0.1 -addext "subjectAltName=IP:127.0.0.1" \
    -keyout "$T/key.pem" -out "$T/cert.pem" >/dev/null 2>&1
# The hook: an HTTPS server that writes the length of every body it is posted, one per line.
cat > "$T/hook.py" <<'PY'
import http.server, ssl, sys
port, cert, key, out = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with open(out, "a") as f:
            f.write("%d\n" % len(body))
        self.send_response(204); self.send_header("Content-Length", "0"); self.end_headers()
    def log_message(self, *a):
        pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PY
python3 "$T/hook.py" "$PH" "$T/cert.pem" "$T/key.pem" "$T/posted" & HOOK_PID=$!

# The daemon trusts the hook's certificate as it would a system root.
SSL_CERT_FILE="$T/cert.pem" daemon_start "$BIN"
printf 'big/# https://127.0.0.1:%s/in\n' "$PH" > "$T/routes"
"$BIN" create mqtt edge -p "$PE" --anonymous --max-packet 8M --routes "$T/routes" -s >/dev/null 2>&1 \
    || bad "a broker with an https rule is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do ss -ltnH "( sport = :$PE )" | grep -q . && break; sleep 0.1; done

PYTHONPATH="$HERE" python3 - "$PE" <<'PY'
import sys
from lib_mqtt import connected
c = connected(int(sys.argv[1]), "big-pub")
for size in (1000, 3 << 20):
    c.publish("big/one", b"x" * size)
PY

for _ in $(seq 1 100); do [ "$(wc -l < "$T/posted" 2>/dev/null || echo 0)" -ge 2 ] && break; sleep 0.1; done
small=$(sed -n 1p "$T/posted" 2>/dev/null); large=$(sed -n 2p "$T/posted" 2>/dev/null)
if [ "${small:-0}" -gt 1000 ]; then ok; else bad "a small message is posted over https" "posted '${small:-nothing}'"; fi
if [ "${large:-0}" -gt $((3 << 20)) ]; then ok
else bad "and a 3 MiB one reaches it whole" "posted '${large:-nothing}': $(grep -i 'record layer\|webhook' "$SOCKETLEY_DLOG" | tail -2)"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
