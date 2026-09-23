#!/usr/bin/env bash
# Integration test: socketley.http verifies the certificate it is given.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# socketley.http used to dial TLS with SSL_VERIFY_NONE.  That bought encryption
# against somebody recording the wire and nothing at all against somebody
# answering in the server's place: any certificate was accepted, so a script
# fetching config, polling a health endpoint or shipping a token over https://
# was talking to whoever got there first.  It was hardened to SSL_VERIFY_PEER
# plus a hostname check, and nothing pinned either.
#
# A hardening with no test is a hardening that lasts until the next person who
# finds it inconvenient.  The failure mode is silent in the direction that
# matters: reverting it makes MORE requests succeed, so every other assertion
# in this suite goes on passing.
#
# ─── WHAT SEPARATES A REFUSED CERTIFICATE FROM A BROKEN FETCH ──────────────
#
# Both give a script `ok=false`, so `ok=false` is not the assertion.  Two things
# are:
#
#   * the error NAMES the certificate.  A connection that never landed, a
#     timeout and a refused chain all set ok=false; only one of them says
#     "certificate rejected", and that string is what tells an operator which
#     of the three happened.
#   * the same client, against the same content over plain HTTP, gets 200.
#     Without that control, "the https fetch failed" is equally true of a build
#     whose HTTP client does not work at all.
#
# A build with SSL_VERIFY_NONE fails the first: the handshake succeeds, the
# fetch proceeds, and the script gets ok=true — or, against a server that holds
# the connection open, "response timed out".  Neither mentions a certificate.
#
# ─── THE SECOND PHASE, AND WHAT IT OPENED ───────────────────────────────────
#
# This file used to say the hostname check could not be reached: an unknown CA
# is rejected first, so a self-signed certificate for the wrong name fails as
# "self signed certificate" and says nothing about the name, and reaching the
# name branch needs a CA the process already trusts -- which was taken to mean
# writing into the system trust store.
#
# It does not.  SSL_CTX_set_default_verify_paths(), which this client already
# calls, honours SSL_CERT_FILE, and a worker is exec'd with the daemon's
# environment -- so a certificate generated here is made trusted by naming it
# in one variable, and that file may hold more than one.  Phase two starts a
# second daemon with it set, and reaches the branch by dialling an address a
# trusted certificate does not cover: "IP address mismatch", which is a
# different sentence from "self signed certificate" and is the assertion.
#
# The same fixture is the only way to reach the TLS READ LOOP at all.
# Everything in phase one is refused at the handshake, so no test here had ever
# read a body over TLS -- which is where a truncated response is least visible,
# because SSL_OP_IGNORE_UNEXPECTED_EOF accepts a missing close_notify on
# purpose and the framing countdown is the only thing left that can tell.  That
# assertion lives here rather than beside its siblings in
# test_lua_http_stops_at_content_length.sh because this is where the fixture
# is.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luahttptls

PB=$((SL_PORT_BASE+370))
TLS_PORT=$((PB + 0))    # https, self-signed
PLAIN_PORT=$((PB + 1))  # http, the control
RPC_PORT=$((PB + 2))    # the script that does the fetching
TRUST_PORT=$((PB + 3))  # https, a certificate this process is told to trust
BADIP_PORT=$((PB + 4))  # https, trusted too, and valid for a name only
RPC2_PORT=$((PB + 5))   # the second phase's fetching script

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
assert_eq() {
    local label=$1 want=$2 got=$3; shift 3
    if [ "$got" = "$want" ]; then pass; else
        fail "$label" "got '$got', wanted '$want'" "$@"
    fi
}
assert_has() {
    local label=$1 needle=$2 hay=$3; shift 3
    if [ "${hay#*"$needle"}" != "$hay" ]; then pass; else
        fail "$label" "'$needle' is not in '$hay'" "$@"
    fi
}

HTTPD_STOP=""; HTTPD2_STOP=""; HTTPD2_PID=""
cleanup() {
    touch "${HTTPD_STOP:-/dev/null}"  2>/dev/null || true
    touch "${HTTPD2_STOP:-/dev/null}" 2>/dev/null || true
    [ -n "$HTTPD2_PID" ] && kill "$HTTPD2_PID" 2>/dev/null
    "$BIN" stop  httptls  >/dev/null 2>&1 || true
    "$BIN" stop  httptls2 >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove httptls  >/dev/null 2>&1 || true
    "$BIN" remove httptls2 >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: socketley.http verifies the certificate ==="

if ! command -v openssl >/dev/null 2>&1; then
    echo "  SKIP: openssl CLI not available (needed to generate a certificate)"
    exit 0
fi

CERTS="$SOCKETLEY_TMPD/certs"
mkdir -p "$CERTS"
# Self-signed, valid for the address it will be dialled on — so the ONLY thing
# wrong with it is that no trusted CA signed it.  A certificate that also had
# the wrong name would fail for either reason and prove neither.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$CERTS/key.pem" -out "$CERTS/cert.pem" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 || true
if [ ! -s "$CERTS/cert.pem" ] || [ ! -s "$CERTS/key.pem" ]; then
    echo "  SKIP: openssl could not generate a test certificate"
    exit 0
fi

daemon_start "$BIN"

# One responder, two listeners: the same body over TLS and over plain HTTP, so
# the control differs from the subject in exactly one thing.  It closes the
# connection after each reply — see test_lua_globals.sh for why the target is
# not a socketley --http server.
cat > "$SOCKETLEY_TMPD/httpd.py" <<'PYEOF'
import os, socket, ssl, sys, threading, time
tls_port, plain_port, cert, key, stop_path = (
    int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5])
BODY = b"TLS-BODY-FROM-SOCKETLEY"

def reply(c):
    try:
        c.settimeout(3)
        c.recv(65536)
        c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                  % len(BODY) + BODY)
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass

def listener(port, wrap):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port)); ls.listen(16); ls.settimeout(0.2)
    # The same two exits as test_lua_globals', for the reason given there: a
    # stop file that never arrives left one of these holding a port for five
    # days.
    stop_dir = os.path.dirname(stop_path) or "."
    deadline = time.time() + 600
    while (not os.path.exists(stop_path) and os.path.isdir(stop_dir)
           and time.time() < deadline):
        try:
            c, _ = ls.accept()
        except socket.timeout:
            continue
        except Exception:
            break
        if wrap is not None:
            try:
                c = wrap.wrap_socket(c, server_side=True)
            except Exception:
                # A client that refused our certificate aborts the handshake
                # here.  That is the case under test, not an error.
                try: c.close()
                except Exception: pass
                continue
        threading.Thread(target=reply, args=(c,), daemon=True).start()
    ls.close()

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
threading.Thread(target=listener, args=(tls_port, ctx), daemon=True).start()
listener(plain_port, None)
PYEOF

HTTPD_STOP="$SOCKETLEY_TMPD/httpd.stop"
python3 "$SOCKETLEY_TMPD/httpd.py" "$TLS_PORT" "$PLAIN_PORT" \
        "$CERTS/cert.pem" "$CERTS/key.pem" "$HTTPD_STOP" &
HTTPD_PID=$!

# The TLS listener is up and speaking TLS — proved with verification switched
# off, which is the one thing a client can do that socketley.http must not.
# Without this, "the certificate was refused" is equally true of a port with
# nothing on it.
cat > "$SOCKETLEY_TMPD/probe_tls.py" <<'PYEOF'
import socket, ssl, sys, time
port = int(sys.argv[1])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
deadline = time.time() + 15
while time.time() < deadline:
    try:
        with ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), 2),
                             server_hostname="localhost") as s:
            s.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            data = b""
            while True:
                d = s.recv(65536)
                if not d: break
                data += d
        if b"TLS-BODY-FROM-SOCKETLEY" in data:
            print("serving"); sys.exit(0)
    except Exception:
        pass
    time.sleep(0.2)
print("not-serving")
PYEOF
assert_eq "control: the TLS listener is up and serving over TLS" \
          "serving" "$(python3 "$SOCKETLEY_TMPD/probe_tls.py" "$TLS_PORT")" \
    "proved with certificate verification switched OFF — which is exactly what" \
    "socketley.http used to do and must not.  If this fails, the refusal below" \
    "is a port with nothing on it rather than a rejected certificate"

ready_http 127.0.0.1 "$PLAIN_PORT" / 15 || echo "  NOTE: the plain listener never answered"

RPC_LUA="$SOCKETLEY_TMPD/http.lua"
cat > "$RPC_LUA" <<LUAEOF
local TLS_URL   = "https://127.0.0.1:$TLS_PORT/"
local PLAIN_URL = "http://127.0.0.1:$PLAIN_PORT/"
LUAEOF
cat >> "$RPC_LUA" <<'LUAEOF'
local function reply(id, s) self.send(id, s) end

function on_client_message(id, msg)
    if msg == "tls" then
        local r = socketley.http({ url = TLS_URL, timeout_ms = 5000 })
        reply(id, "ok=" .. tostring(r.ok) ..
                  " status=" .. tostring(r.status) ..
                  " body=[" .. tostring(r.body) .. "]" ..
                  " error=[" .. tostring(r.error) .. "]")
    elseif msg == "plain" then
        local r = socketley.http({ url = PLAIN_URL, timeout_ms = 5000 })
        reply(id, "ok=" .. tostring(r.ok) ..
                  " status=" .. tostring(r.status) ..
                  " body=[" .. tostring(r.body) .. "]")
    end
end
LUAEOF

# In a function because each phase has its own tmpdir: daemon_isolate makes a
# new one and takes the old one with it, so a helper written once is gone by
# the time the second phase calls it.
write_ask_py() {
cat > "$SOCKETLEY_TMPD/ask.py" <<'PYEOF'
import select, socket, sys, time
port, text, budget = int(sys.argv[1]), sys.argv[2], float(sys.argv[3])
s = socket.create_connection(("127.0.0.1", port), 5)
s.sendall((text + "\n").encode())
out, end = b"", time.time() + budget
while time.time() < end:
    r, _, _ = select.select([s], [], [], 0.05)
    if not r:
        continue
    try:
        d = s.recv(65536)
    except Exception:
        break
    if not d:
        break
    out += d
    if b"\n" in out:
        break
s.close()
print(out.decode("latin-1").replace("\r", "").strip())
PYEOF
}
write_ask_py
ask() { python3 "$SOCKETLEY_TMPD/ask.py" "$1" "$2" "${3:-8.0}"; }

# In the daemon: socketley.http blocks the loop it runs on, and the man page
# says so.  Nothing here depends on that, but a worker would be the odd choice.
create_ok "fetching server created in the daemon" "$BIN" create server httptls \
    -p "$RPC_PORT" --mode in --lua "$RPC_LUA" -s
ready_tcp 127.0.0.1 "$RPC_PORT" 10 || echo "  NOTE: the fetching server never accepted"

# ── The control: the same client, the same body, no TLS ────────────────────
PLAIN=$(ask "$RPC_PORT" plain)
assert_eq "control: socketley.http fetches the same body over plain HTTP" \
          "ok=true status=200 body=[TLS-BODY-FROM-SOCKETLEY]" "$PLAIN" \
    "if this fails, the https refusal below says nothing about certificates —" \
    "the client simply does not work"

# ── The subject: a self-signed certificate is refused ──────────────────────
TLS=$(ask "$RPC_PORT" tls)
assert_has "a self-signed certificate is not accepted" "ok=false" "$TLS" \
    "with SSL_VERIFY_NONE this reads ok=true and the body comes back from a" \
    "server whose identity was never checked" "got: $TLS"
assert_has "...and no status came back, because no request was made" \
           "status=0" "$TLS" "got: $TLS"
assert_has "...and the body is empty" "body=[]" "$TLS" "got: $TLS"
assert_has "...and the error names the certificate as the reason" \
           "certificate" "$TLS" \
    "this is the assertion, not ok=false: a refused chain, a timeout and a" \
    "connection that never landed all set ok=false, and only one of them says" \
    "which happened.  A build that skipped verification and then hung on the" \
    "read reports 'response timed out' and passes every line above this one" \
    "got: $TLS"
assert_has "...and says the certificate was rejected rather than merely unread" \
           "rejected" "$TLS" "got: $TLS"

# The daemon ran a failed TLS handshake and is still here.
TOTAL=$((TOTAL+1))
if kill -0 "$SOCKETLEY_DPID" 2>/dev/null && daemon_alive "$SOCKETLEY_SOCKET"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: the daemon did not survive the refused handshake"
fi

# ── Phase two: a certificate this process is told to trust ─────────────────
# A second daemon, because phase one needs the same certificate to be UNtrusted
# and one process has one answer to that.
"$BIN" stop   httptls >/dev/null 2>&1 || true
sleep 0.3
"$BIN" remove httptls >/dev/null 2>&1 || true
touch "$HTTPD_STOP" 2>/dev/null || true
daemon_stop

daemon_isolate luahttptls2
CERTS2="$SOCKETLEY_TMPD/certs"
mkdir -p "$CERTS2"
# Two certificates and one trust file: the first valid for the address it will
# be dialled on, the second valid for a name and for no address at all, so the
# only thing wrong with the second is the one thing under test.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$CERTS2/a.key" -out "$CERTS2/a.pem" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 || true
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$CERTS2/b.key" -out "$CERTS2/b.pem" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1 || true
if [ ! -s "$CERTS2/a.pem" ] || [ ! -s "$CERTS2/b.pem" ]; then
    echo "  SKIP [phase two]: openssl could not generate the trusted pair"
else
cat "$CERTS2/a.pem" "$CERTS2/b.pem" > "$CERTS2/trust.pem"

cat > "$SOCKETLEY_TMPD/httpd2.py" <<'PYEOF'
import os, socket, ssl, sys, threading, time
trust_port, badip_port, certdir, stop_path = (
    int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4])
BODY = b"TRUSTED-TLS-BODY"

def reply(c):
    try:
        c.settimeout(3)
        req = c.recv(65536).decode("latin1")
        path = (req.split(" ") + ["", "/"])[1]
        if path.startswith("/short"):
            # Forty declared, ten sent, then a close -- and over TLS the close
            # is all the client gets, because the close_notify that would have
            # called it a truncation is one it accepts the absence of.
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\nSHORT-BODY")
        else:
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(BODY)
                      + BODY)
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass

# The same two exits as the phase-one listener, for the reason given there.
def listener(port, cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port)); ls.listen(16); ls.settimeout(0.2)
    stop_dir = os.path.dirname(stop_path) or "."
    deadline = time.time() + 600
    while (not os.path.exists(stop_path) and os.path.isdir(stop_dir)
           and time.time() < deadline):
        try:
            c, _ = ls.accept()
        except socket.timeout:
            continue
        except Exception:
            break
        try:
            c = ctx.wrap_socket(c, server_side=True)
        except Exception:
            # The client refusing the name is the case under test, not an error.
            try: c.close()
            except Exception: pass
            continue
        threading.Thread(target=reply, args=(c,), daemon=True).start()
    ls.close()

threading.Thread(target=listener,
                 args=(badip_port, os.path.join(certdir, "b.pem"),
                       os.path.join(certdir, "b.key")), daemon=True).start()
sys.stderr.write("httpd2 up\n"); sys.stderr.flush()
listener(trust_port, os.path.join(certdir, "a.pem"), os.path.join(certdir, "a.key"))
PYEOF

HTTPD2_STOP="$SOCKETLEY_TMPD/httpd2.stop"
python3 "$SOCKETLEY_TMPD/httpd2.py" "$TRUST_PORT" "$BADIP_PORT" "$CERTS2" \
        "$HTTPD2_STOP" 2>"$SOCKETLEY_TMPD/httpd2.log" &
HTTPD2_PID=$!
for i in $(seq 1 60); do
    grep -q "httpd2 up" "$SOCKETLEY_TMPD/httpd2.log" 2>/dev/null && break
    sleep 0.1
done

# The variable the whole phase rests on: OpenSSL reads it in
# SSL_CTX_set_default_verify_paths(), and the worker gets it because a worker
# is exec'd with the daemon's environment.
export SSL_CERT_FILE="$CERTS2/trust.pem"
daemon_start "$BIN"
write_ask_py

RPC2_LUA="$SOCKETLEY_TMPD/http2.lua"
cat > "$RPC2_LUA" <<LUAEOF
local TRUST_URL = "https://127.0.0.1:$TRUST_PORT/"
local SHORT_URL = "https://127.0.0.1:$TRUST_PORT/short"
local BADIP_URL = "https://127.0.0.1:$BADIP_PORT/"
LUAEOF
cat >> "$RPC2_LUA" <<'LUAEOF'
local function fetch(id, url)
    local r = socketley.http({ url = url, timeout_ms = 5000 })
    self.send(id, "ok=" .. tostring(r.ok) ..
                  " status=" .. tostring(r.status) ..
                  " body=[" .. tostring(r.body) .. "]" ..
                  " error=[" .. tostring(r.error) .. "]")
end

function on_client_message(id, msg)
    if     msg == "trusted" then fetch(id, TRUST_URL)
    elseif msg == "short"   then fetch(id, SHORT_URL)
    elseif msg == "badip"   then fetch(id, BADIP_URL) end
end
LUAEOF

create_ok "phase two: the fetching server is created" "$BIN" create server httptls2 \
    -p "$RPC2_PORT" --mode in --lua "$RPC2_LUA" -s
ready_tcp 127.0.0.1 "$RPC2_PORT" 10 || echo "  NOTE: the second fetching server never accepted"

# The control for the whole phase: if SSL_CERT_FILE did not take, this reads
# ok=false and the assertions under it pass for the wrong reason -- a refused
# handshake also returns no body and also fails a name check.
TRUSTED=$(ask "$RPC2_PORT" trusted)
assert_eq "a certificate named in SSL_CERT_FILE is accepted" \
          "ok=true status=200 body=[TRUSTED-TLS-BODY] error=[]" "$TRUSTED" \
    "this is the control: without it, everything below passes on a handshake" \
    "that never completed rather than on what it is meant to measure"

# The TLS read loop, reached for the first time by the line above.
SHORT_TLS=$(ask "$RPC2_PORT" short)
assert_has "a TLS response that stops short of its Content-Length is an error" \
           "short of its Content-Length" "$SHORT_TLS" \
    "forty declared, ten sent, then a close -- and TLS cannot tell that from a" \
    "complete answer, because the close_notify that would have is one" \
    "SSL_OP_IGNORE_UNEXPECTED_EOF accepts the absence of on purpose" \
    "got: $SHORT_TLS"
assert_has "...and no short body came back under it" "body=[]" "$SHORT_TLS" \
    "ten bytes returned here are ten bytes a script cannot tell from forty" \
    "got: $SHORT_TLS"

# The name check, on a chain that verifies: the branch this file used to say it
# could not reach.
BADIP=$(ask "$RPC2_PORT" badip)
assert_has "a trusted certificate that does not cover the address is refused" \
           "ok=false" "$BADIP" "got: $BADIP"
assert_has "...and the error names the address, not the chain" \
           "IP address mismatch" "$BADIP" \
    "the chain verifies here -- this certificate is in SSL_CERT_FILE too -- so" \
    "the only thing left to fail is the name, and a build that dropped the pin" \
    "would answer ok=true with a body signed by nobody in particular" \
    "got: $BADIP"
TOTAL=$((TOTAL+1))
case "$BADIP" in
    *"self signed"*)
        FAIL=$((FAIL+1))
        echo "  FAIL [...and it is the name that failed, not the trust]: $BADIP"
        echo "        this certificate is in SSL_CERT_FILE, so a chain error here means"
        echo "        the trust file did not take and the assertion above is hollow" ;;
    *) PASS=$((PASS+1)) ;;
esac
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
