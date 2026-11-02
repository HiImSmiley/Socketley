#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: socketley's https client reads the trusted roots once, not once per request, and again when the
# file they come from changes.
#
# What each part would catch:
#   * a context made per request: every alert, web push and MTA-STS fetch parsed the whole system CA bundle again,
#     three milliseconds of CPU each before a byte was sent, five times what the request itself costs
#   * a context kept past a change of its roots: a hook whose certificate a new CA file signs is refused until restart
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: the https client reads its roots once, and again when they change ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }
if nm -C "$BIN" 2>/dev/null | grep -q '__asan_'; then
    echo "  SKIP: CPU per request measures the sanitizer, not the roots"; exit 0
fi
daemon_isolate httpsroots
T=$SOCKETLEY_TMPD
M=$((SL_PORT_BASE + 1937))
HOOK=$((SL_PORT_BASE + 1939))
HOOK_PID=""
trap '[ -n "$HOOK_PID" ] && kill "$HOOK_PID" 2>/dev/null; daemon_stop' EXIT

# Two CAs, each with a leaf for 127.0.0.1, so which one the daemon trusts decides whether a post arrives.
for c in a b; do
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=ca-$c" \
        -keyout "$T/ca-$c.key" -out "$T/ca-$c.pem" -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign" 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=hook -keyout "$T/leaf-$c.key" \
        -out "$T/leaf-$c.csr" 2>/dev/null
    printf 'subjectAltName=IP:127.0.0.1\n' > "$T/leaf.ext"
    openssl x509 -req -in "$T/leaf-$c.csr" -CA "$T/ca-$c.pem" -CAkey "$T/ca-$c.key" -CAcreateserial -days 2 \
        -extfile "$T/leaf.ext" -out "$T/leaf-$c.pem" 2>/dev/null
done
hook() {   # the CA whose leaf the hook presents
    [ -n "$HOOK_PID" ] && { kill "$HOOK_PID" 2>/dev/null; wait "$HOOK_PID" 2>/dev/null; }
    python3 - "$HOOK" "$T/leaf-$1.pem" "$T/leaf-$1.key" <<'PY' &
import http.server, ssl, sys
port, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get('content-length', 0)))
        self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer.allow_reuse_address = True
s = http.server.HTTPServer(('127.0.0.1', port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
s.socket = ctx.wrap_socket(s.socket, server_side=True)
s.serve_forever()
PY
    HOOK_PID=$!
    for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$HOOK") 2>/dev/null && break; sleep 0.1; done
}
hook a

ADMIN="AKIAHTTPSROOTSADMIN0:httpsrootsadminsecrethttpsrootsadminse"
printf '[admin]\nadmin = true\n%s\n' "$ADMIN" > "$T/creds"
cp "$T/ca-a.pem" "$T/roots.pem"
printf 'daemon = { metrics_port = %s, dashboard_credentials = "%s", alert_webhook = "https://127.0.0.1:%s/hook" }\n' \
    "$M" "$T/creds" "$HOOK" > "$T/daemon.lua"
U="http://127.0.0.1:$M"
SSL_CERT_FILE="$T/roots.pem" SOCKETLEY_CONFIG="$T/daemon.lua" daemon_start "$BIN"
for _ in $(seq 1 50); do curl -s -o /dev/null "$U/" && break; sleep 0.1; done
curl -s -X POST -c "$T/jar" -u "$ADMIN" "$U/api/session" >/dev/null
post() { curl -s -m 20 -b "$T/jar" -H 'X-Socketley-Dashboard: 1' -X POST -o /dev/null -w '%{http_code}' "$U/api/alerts/test"; }
cpu_ms() { awk -v hz="$(getconf CLK_TCK)" '{print ($14 + $15) * 1000 / hz}' "/proc/$SOCKETLEY_DPID/stat"; }

first=$(post)
c0=$(cpu_ms); codes=""
for _ in $(seq 1 60); do codes="$codes$(post)"; done
c1=$(cpu_ms)
per=$(awk -v a="$c0" -v b="$c1" 'BEGIN{printf "%.1f", (b - a) / 60}')
echo "  the daemon's CPU per alert posted over https: ${per} ms"
if [ "$first" = 204 ] && [ "$codes" = "$(printf '204%.0s' $(seq 1 60))" ]; then ok
else bad "every alert reaches the hook" "first $first, then $codes"; fi
if awk -v p="$per" 'BEGIN{exit !(p < 1.5)}'; then ok
else bad "the roots are read once, not per request" "${per} ms of CPU per alert"; fi

# The roots replaced in place by another CA, and the hook presenting that CA's leaf: taken without a restart.
hook b
cat "$T/ca-b.pem" > "$T/roots.pem"
got=$(post)
if [ "$got" = 204 ]; then ok; else bad "a change of the roots' file is read again" "the hook signed by the new CA got $got"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
