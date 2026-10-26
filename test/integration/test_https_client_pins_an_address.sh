#!/usr/bin/env bash
# Integration test: an https:// URL with an address in it is checked against
# the certificate's IP SAN.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   an address  https://127.0.0.1/ reaches a server whose certificate names
#               127.0.0.1 as an iPAddress SAN and nothing else
#   not the CN  a certificate naming another address is refused, even with
#               127.0.0.1 as its common name, so the pin is set and is the
#               address's own
#
# The daemon's alert webhook is the client here, and its test endpoint says
# synchronously whether the post arrived.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate httpsip
T="$SOCKETLEY_TMPD"
M=$((SL_PORT_BASE+1960))
GOOD=$((SL_PORT_BASE+1961))
WRONG=$((SL_PORT_BASE+1962))
HOOK_PIDS=""
trap 'for p in $HOOK_PIDS; do kill "$p" 2>/dev/null; done; daemon_stop' EXIT

echo "=== Integration: an https URL with an address is checked against the IP SAN ==="

# A CA, so the daemon trusts both servers by one file and only the name decides.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=test-ca -keyout "$T/ca.key" -out "$T/ca.pem" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
leaf() {
    openssl req -newkey rsa:2048 -nodes -subj "/CN=$2" -keyout "$T/$1.key" -out "$T/$1.csr" 2>/dev/null
    printf 'subjectAltName=%s\n' "$3" > "$T/$1.ext"
    openssl x509 -req -in "$T/$1.csr" -CA "$T/ca.pem" -CAkey "$T/ca.key" -CAcreateserial -days 2 \
        -extfile "$T/$1.ext" -out "$T/$1.pem" 2>/dev/null
}
leaf good hook "IP:127.0.0.1"
leaf wrong 127.0.0.1 "IP:127.0.0.2"

# A hook over TLS that keeps the number of posts it was sent.
hook() {
    python3 - "$1" "$T/$2.pem" "$T/$2.key" "$T/$2.count" <<'PY' &
import http.server, ssl, sys
port, cert, key, count = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
n = [0]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get('content-length', 0)))
        n[0] += 1
        open(count, 'w').write(str(n[0]))
        self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
s = http.server.HTTPServer(('127.0.0.1', port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
s.socket = ctx.wrap_socket(s.socket, server_side=True)
s.serve_forever()
PY
    HOOK_PIDS="$HOOK_PIDS $!"
}
hook "$GOOD" good
hook "$WRONG" wrong
for p in "$GOOD" "$WRONG"; do
    for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null && break; sleep 0.1; done
done

ADMIN="AKIAHTTPSPINADMIN000:httpspinadminsecrethttpspinadminsecr00"
printf '[admin]\nadmin = true\n%s\n' "$ADMIN" > "$T/creds"
export SSL_CERT_FILE="$T/ca.pem"
U="http://127.0.0.1:$M"
# Starts the daemon posting to $1, signed in.
with_hook() {
    if [ -n "${SOCKETLEY_DPID:-}" ]; then
        kill "$SOCKETLEY_DPID"; wait "$SOCKETLEY_DPID" 2>/dev/null
        : > "$SOCKETLEY_DLOG"
    fi
    printf 'daemon = { metrics_port = %s, dashboard_credentials = "%s", alert_webhook = "%s" }\n' \
        "$M" "$T/creds" "$1" > "$T/daemon.lua"
    export SOCKETLEY_CONFIG="$T/daemon.lua"
    daemon_start "$BIN"
    for _ in $(seq 1 50); do curl -s -o /dev/null "$U/" && break; sleep 0.1; done
    curl -s -X POST -c "$T/jar" -u "$ADMIN" "$U/api/session" >/dev/null
}
post() { curl -s -m 20 -b "$T/jar" -H 'X-Socketley-Dashboard: 1' -X POST -o "$T/answer" -w '%{http_code}' "$U/api/alerts/test"; }

with_hook "https://127.0.0.1:$GOOD/hook"
expect "an address in the URL is matched against the certificate's IP SAN" "$(post) $(cat "$T/good.count" 2>/dev/null)" "204 1"

# The refusal means something only if the wrong hook is up and presents its certificate.
expect "the hook with the certificate for another address is up" \
    "$(openssl s_client -connect "127.0.0.1:$WRONG" </dev/null 2>/dev/null | openssl x509 -noout -subject 2>/dev/null | grep -c '127\.0\.0\.1')" "1"
with_hook "https://127.0.0.1:$WRONG/hook"
expect "a certificate for another address is refused, its common name notwithstanding" \
    "$(post) $(cat "$T/wrong.count" 2>/dev/null)" "502 "

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
