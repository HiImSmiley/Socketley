#!/usr/bin/env bash
# Integration test: what stands between the internet and the runtimes behind an entrance.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   uploads      --backend-timeout bounds the backend's silence after the
#                request, not an upload that takes longer than it
#   by name      a proxy with --domain is reached by its name through the
#                entrance: the path and the Host go on as they came, and the
#                scheme the entrance was reached over is the one its backend is
#                told; the entrance over TLS adds HSTS, once
#   --auth       bearer:<file> and basic:<credentials file> refuse a request
#                without the right answer, 401 with the scheme to answer in;
#                a non-admin's key is refused; the backend never sees the
#                credentials; an address that keeps failing is refused even
#                the right answer, 429 with Retry-After, and another is not --
#                behind the entrance the address is the one it heard from
#   redirect     --redirect-https answers 308 to the same name and path
#   metrics      the dashboard is served to a proxy (Via) whatever its Host,
#                refused a page's foreign Host, and never framed or cached
#   storage      behind a proxy --tls-offloaded names, failed sign-ins count
#                against the address in X-Forwarded-For, not the proxy's
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate entsec
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1930))
ECHO=$((P+1)) WEB=$((P+2)) HUB=$((P+4)) TUN=$((P+5)) MET=$((P+6)) R80=$((P+7)) MPORT=$((P+8)) ST=$((P+9))
ECHO_PID=""
trap 'kill $ECHO_PID 2>/dev/null; daemon_stop' EXIT

echo "=== Integration: the entrance's gate ==="

# A backend that answers with what it was asked, and a header of its own on /hsts.
python3 - "$ECHO" > "$T/echo.log" 2>&1 <<'PY' &
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        body = json.dumps({"path": self.path, "host": self.headers.get("Host", ""),
                           "proto": self.headers.get("X-Forwarded-Proto", ""),
                           "xff": self.headers.get("X-Forwarded-For", ""),
                           "auth": self.headers.get("Authorization", "")}).encode()
        self.send_response(200)
        if self.path == "/hsts":
            self.send_header("Strict-Transport-Security", "max-age=60")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        got = len(self.rfile.read(n))
        body = json.dumps({"got": got}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
ECHO_PID=$!
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$ECHO/" && break; sleep 0.1; done
field() { python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1" 2>/dev/null; }

cat > "$T/daemon.lua" <<EOF
daemon = { metrics_port = $MPORT }
EOF
export SOCKETLEY_CONFIG="$T/daemon.lua"
daemon_start "$BIN"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=example.com \
    -addext "subjectAltName=DNS:*.example.com,DNS:example.com" -keyout "$T/e.key" -out "$T/e.pem" >/dev/null 2>&1
"$BIN" create proxy web -p "$WEB" --tls --cert "$T/e.pem" --key "$T/e.key" -s >/dev/null 2>&1
"$BIN" create proxy hub -p "$HUB" --bind 127.0.0.1 --backend "127.0.0.1:$ECHO" --domain hub.example.com -s >/dev/null 2>&1
hs() { curl -sk --noproxy '*' -m 5 --resolve "$1:$WEB:127.0.0.1" "${@:3}" "https://$1:$WEB$2"; }

# ─── by name ────────────────────────────────────────────────────────────────
got=""
for _ in $(seq 1 40); do got=$(hs hub.example.com '/deep/path?x=1' | field path); [ -n "$got" ] && break; sleep 0.2; done
expect "a proxy with --domain, reached through the entrance, passes the path on as it came" "$got" "/deep/path?x=1"
expect "and the Host" "$(hs hub.example.com / | field host)" "hub.example.com:$WEB"
expect "and its backend is told the scheme the entrance was reached over" "$(hs hub.example.com / | field proto)" "https"
expect "and who asked, last, without the entrance as a hop of its own" \
    "$(hs hub.example.com / -H 'X-Forwarded-For: 203.0.113.9' | field xff)" "203.0.113.9, 127.0.0.1"
expect "the entrance over TLS tells the browser to stay on HTTPS" \
    "$(hs hub.example.com / -o /dev/null -D - | tr -d '\r' | grep -ci '^strict-transport-security: max-age=31536000')" 1
expect "and a backend's own HSTS is left alone, not doubled" \
    "$(hs hub.example.com /hsts -o /dev/null -D - | tr -d '\r' | grep -i '^strict-transport-security' | tr '\n' ' ')" \
    "Strict-Transport-Security: max-age=60 "
expect "a proxy without --domain still writes the scheme itself" \
    "$("$BIN" create proxy plain -p $((P+10)) --backend "127.0.0.1:$ECHO" -s >/dev/null 2>&1; sleep 0.5
       curl -s -m 5 -H 'X-Forwarded-Proto: https' "http://127.0.0.1:$((P+10))/plain/" | field proto)" "http"

# ─── an upload longer than --backend-timeout ────────────────────────────────
"$BIN" create proxy slow -p $((P+12)) --backend "127.0.0.1:$ECHO" --backend-timeout 1 -s >/dev/null 2>&1
sleep 0.5
got=$(python3 - "$((P+12))" <<'PY'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
s.sendall(b"POST /slow/ HTTP/1.1\r\nHost: x\r\nContent-Length: 3000\r\n\r\n")
for _ in range(3):
    time.sleep(0.7)
    s.sendall(b"x" * 1000)
s.settimeout(5)
data = b""
while b"\r\n\r\n" not in data:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk
print(data.split(b" ")[1].decode() if data else "none")
PY
)
expect "an upload slower than --backend-timeout is not cut off, the wait counted from its last byte" "$got" 200

# ─── --auth bearer ──────────────────────────────────────────────────────────
printf '# the tunnel\nsecret-token-one\n\nsecret-token-two\n' > "$T/tokens"
"$BIN" create proxy tun -p "$TUN" --bind 127.0.0.1 --backend "127.0.0.1:$ECHO" --domain tun.example.com \
    --auth "bearer:$T/tokens" -s >/dev/null 2>&1
tc() { curl -s -m 5 -o /dev/null -w '%{http_code}' "$@" "http://127.0.0.1:$TUN/"; }
for _ in $(seq 1 40); do [ "$(tc)" = 401 ] && break; sleep 0.2; done
expect "--auth bearer refuses a request without a token, saying how to answer" \
    "$(curl -s -m 5 -D - -o /dev/null "http://127.0.0.1:$TUN/" | tr -d '\r' | grep -i '^www-authenticate' )" \
    'WWW-Authenticate: Bearer realm="tun"'
expect "a wrong token is refused" "$(tc -H 'Authorization: Bearer nope')" 401
expect "either token of the file passes" "$(tc -H 'Authorization: Bearer secret-token-one')$(tc -H 'Authorization: Bearer secret-token-two')" 200200
expect "and the backend does not see it" \
    "$(curl -s -m 5 -H 'Authorization: Bearer secret-token-one' "http://127.0.0.1:$TUN/" | field auth)" ""
got=""
for _ in $(seq 1 40); do got=$(hs tun.example.com / -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer secret-token-two')
                         [ "$got" = 200 ] && break; sleep 0.2; done
expect "through the entrance too" "$got" 200
for _ in 1 2 3 4 5; do tc -H 'X-Forwarded-For: 10.0.0.1' -H 'Authorization: Bearer guess' >/dev/null; done
expect "an address that keeps failing is refused even the right token" \
    "$(tc -H 'X-Forwarded-For: 10.0.0.1' -H 'Authorization: Bearer secret-token-one')" 429
has_retry=$(curl -s -m 5 -D - -o /dev/null -H 'X-Forwarded-For: 10.0.0.1' "http://127.0.0.1:$TUN/" | tr -d '\r' |
            awk -F': ' 'tolower($1)=="retry-after" { print ($2 > 0 && $2 <= 900) }')
expect "and told for how long" "$has_retry" 1
expect "another address is not" "$(tc -H 'X-Forwarded-For: 10.0.0.2' -H 'Authorization: Bearer secret-token-one')" 200
expect "behind the entrance the address is the one it heard from, not the client's word" \
    "$(hs tun.example.com / -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 10.0.0.1' -H 'Authorization: Bearer secret-token-one')" 200
printf 'secret-token-three\n' > "$T/tokens"
sleep 1.5
expect "the file is read again when it changes" \
    "$(tc -H 'X-Forwarded-For: 10.0.0.5' -H 'Authorization: Bearer secret-token-three')$(tc -H 'X-Forwarded-For: 10.0.0.5' -H 'Authorization: Bearer secret-token-one')" 200401

# ─── --auth basic ───────────────────────────────────────────────────────────
ADMIN="AKIAGATEADMIN0000000:gateadminsecretgateadminsecret0000000000"
USER="AKIAGATEUSER00000000:gateusersecretgateusersecretgateuser00000"
{ echo "$ADMIN"; echo "[bob]"; echo "$USER"; } > "$T/creds"
"$BIN" create proxy met -p "$MET" --bind 127.0.0.1 --backend "127.0.0.1:$ECHO" --domain met.example.com \
    --auth "basic:$T/creds" -s >/dev/null 2>&1
mc() { curl -s -m 5 -o /dev/null -w '%{http_code}' "$@" "http://127.0.0.1:$MET/"; }
for _ in $(seq 1 40); do [ "$(mc)" = 401 ] && break; sleep 0.2; done
expect "--auth basic asks for the access key and secret" \
    "$(curl -s -m 5 -D - -o /dev/null "http://127.0.0.1:$MET/" | tr -d '\r' | grep -i '^www-authenticate')" \
    'WWW-Authenticate: Basic realm="met", charset="UTF-8"'
expect "an admin's key passes" "$(mc -u "$ADMIN")" 200
expect "another user's is refused" "$(mc -u "$USER")" 401
expect "and so is a wrong secret" "$(mc -u "${ADMIN%%:*}:wrong")" 401
expect "an --auth that is neither is refused at create" \
    "$("$BIN" create proxy bad -p $((P+11)) --backend "127.0.0.1:$ECHO" --auth "token:$T/tokens" 2>&1 | head -c 23)" \
    "--auth takes bearer:<fi"

# ─── --redirect-https ───────────────────────────────────────────────────────
"$BIN" create proxy r80 -p "$R80" --redirect-https -s >/dev/null 2>&1
sleep 0.5
expect "--redirect-https sends the client to HTTPS, the name and path kept" \
    "$(curl -s -m 5 -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Host: hub.example.com' "http://127.0.0.1:$R80/a?b=c")" \
    "308 https://hub.example.com/a?b=c"

# ─── metrics ────────────────────────────────────────────────────────────────
expect "the dashboard refuses a page's foreign Host" \
    "$(curl -s -m 5 -o /dev/null -w '%{http_code}' -H 'Host: evil.example' "http://127.0.0.1:$MPORT/")" 403
expect "and serves a proxy's request, which carries Via" \
    "$(curl -s -m 5 -o /dev/null -w '%{http_code}' -H 'Host: metrics.example.com' -H 'Via: 1.1 web' "http://127.0.0.1:$MPORT/")" 200
expect "never framed, sniffed or cached" \
    "$(curl -s -m 5 -D - -o /dev/null "http://127.0.0.1:$MPORT/" | tr -d '\r' |
       grep -ciE '^(x-frame-options: deny|x-content-type-options: nosniff|cache-control: no-store|referrer-policy: no-referrer)$')" 4

# ─── storage behind a proxy ─────────────────────────────────────────────────
"$BIN" create storage st -p "$ST" --dir "$T/st" --credentials "$T/creds" --tls-offloaded 127.0.0.1 -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$ST/" && break; sleep 0.1; done
sc() { curl -s -m 5 -o /dev/null -w '%{http_code}' -X PROPFIND "$@" "http://127.0.0.1:$ST/~dav/"; }
for _ in $(seq 1 12); do sc -H 'X-Forwarded-For: 10.0.0.3' -u "${ADMIN%%:*}:wrong" >/dev/null; done
expect "behind a proxy --tls-offloaded names, failed sign-ins count against the client's address" \
    "$(sc -H 'X-Forwarded-For: 10.0.0.3' -u "$ADMIN")" 429
expect "and not against the proxy's, which every other client comes through" \
    "$(sc -H 'X-Forwarded-For: 10.0.0.4' -u "$ADMIN")" 207

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
