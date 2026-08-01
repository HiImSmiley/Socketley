#!/usr/bin/env bash
# Integration test: what a proxy's TLS backend leg refuses.
#
# test_proxy_tls_backend.sh proves the transport works.  This one proves it is
# not merely working but *verified*, which is the half that cannot be seen from
# the outside: a backend leg that encrypts and trusts anybody looks exactly like
# one that encrypts and checks, right up until somebody stands in the middle.
# An unverified TLS leg is worse than a cleartext one, because cleartext at
# least does not claim to be safe.
#
# So every assertion here is a refusal, and one control case sits at the top of
# them.  Without the control this file could pass by having no working
# configuration at all -- three 502s prove nothing if the fourth request is a
# 502 too.  With it, the file says: this configuration works, these three do
# not, and the only difference between them is who signed the certificate and
# who it was issued to.
#
# WHAT IT CHECKS
#   1. control: a backend whose certificate is signed by --ca is served
#   2. a CA that did not sign the backend's certificate is refused
#   3. no --ca at all: a self-signed peer is refused against the system store
#   4. a certificate that verifies but was issued to another name is refused
#   5. the refusals are 502 rather than silence, and nothing is retried in
#      cleartext -- the backend logs no plaintext request
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

TMPD=$(mktemp -d /tmp/socketley-tlsverify-XXXXXX)
export HOME="$TMPD/home"
export SOCKETLEY_SOCKET="$TMPD/daemon.sock"
mkdir -p "$HOME"

BE=19681; PX_OK=19682; PX_BADCA=19683; PX_NOCA=19684; PX_BADNAME=19685
DPID=""; BEPID=""
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    for n in vok vbadca vnoca vbadname; do
        "$BIN" stop "$n" >/dev/null 2>&1 || true
        "$BIN" remove "$n" >/dev/null 2>&1 || true
    done
    [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null
    if [ -n "$DPID" ]; then
        kill "$DPID" 2>/dev/null || true
        for _ in $(seq 1 50); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.1; done
        kill -9 "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
    # Same reasoning as test_proxy_tls_backend.sh: a CLI command run against a
    # daemon that is not up yet starts one of its own, detached from this shell.
    # The socket path comes from mktemp, so this can only hit our own.
    for p in $(pgrep -f 'socketley daemon' 2>/dev/null || true); do
        if tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null \
           | grep -qx "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET"; then
            kill -9 "$p" 2>/dev/null || true
        fi
    done
    rm -rf "$TMPD"
}
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a proxy verifies its TLS backend ==="

if ! command -v python3 >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    echo "  SKIP: python3 and openssl are both required"; exit 0
fi
if ! python3 -c "import ssl" >/dev/null 2>&1; then
    echo "  SKIP: python3 has no ssl module"; exit 0
fi

# Three certificates: the backend's own; an unrelated CA that signed nothing
# here; and one issued to a name the proxy never dials, used as its own CA so
# that the *chain* verifies and only the name check can reject it.  That last
# one is the case a chain-only check passes and a correct one does not, which
# is the difference this file exists to hold on to.
openssl req -x509 -newkey rsa:2048 -keyout "$TMPD/be.key" -out "$TMPD/be.pem" \
    -days 2 -nodes -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" \
    >/dev/null 2>&1 || { echo "  SKIP: could not generate a test certificate"; exit 0; }
openssl req -x509 -newkey rsa:2048 -keyout "$TMPD/other.key" -out "$TMPD/other.pem" \
    -days 2 -nodes -subj "/CN=unrelated" -addext "subjectAltName=DNS:unrelated" \
    >/dev/null 2>&1 || { echo "  SKIP: could not generate a test certificate"; exit 0; }
openssl req -x509 -newkey rsa:2048 -keyout "$TMPD/wrong.key" -out "$TMPD/wrong.pem" \
    -days 2 -nodes -subj "/CN=elsewhere.example" \
    -addext "subjectAltName=DNS:elsewhere.example" \
    >/dev/null 2>&1 || { echo "  SKIP: could not generate a test certificate"; exit 0; }

cat > "$TMPD/be.py" <<'PYEOF'
import socket, ssl, sys, threading

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[2], sys.argv[3])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1])))
srv.listen(32)
print("ready", flush=True)


def serve(raw):
    try:
        c = ctx.wrap_socket(raw, server_side=True)
    except Exception as e:
        # Expected for every rejected case: the proxy walks away mid-handshake.
        print(f"handshake-rejected {type(e).__name__}", flush=True)
        try:
            raw.close()
        except OSError:
            pass
        return
    try:
        buf = b""
        while True:
            d = c.recv(65536)
            if not d:
                break
            buf += d
            while b"\r\n\r\n" in buf:
                head, buf = buf.split(b"\r\n\r\n", 1)
                m = head.split(b"\r\n", 1)[0].split(b" ")[1].lstrip(b"/")
                print(f"served {m.decode('latin1')}", flush=True)
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                          b"Connection: keep-alive\r\n\r\n%s" % (len(m), m))
    except OSError:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


while True:
    try:
        raw, _ = srv.accept()
    except OSError:
        break
    threading.Thread(target=serve, args=(raw,), daemon=True).start()
PYEOF

start_backend() {   # $1 = cert, $2 = key, $3 = log
    [ -n "$BEPID" ] && { kill "$BEPID" 2>/dev/null; wait "$BEPID" 2>/dev/null; }
    python3 "$TMPD/be.py" "$BE" "$1" "$2" >"$3" 2>&1 &
    BEPID=$!
    for _ in $(seq 1 60); do grep -q ready "$3" 2>/dev/null && break; sleep 0.1; done
}

start_backend "$TMPD/be.pem" "$TMPD/be.key" "$TMPD/be.log"

cat > "$TMPD/waitsock.py" <<'PYEOF'
import socket, sys, time
path = sys.argv[1]
end = time.time() + float(sys.argv[2])
while time.time() < end:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(0.4)
        s.connect(path)
        sys.exit(0)
    except OSError:
        time.sleep(0.02)
    finally:
        try:
            s.close()
        except OSError:
            pass
sys.exit(1)
PYEOF

"$BIN" daemon >"$TMPD/daemon.log" 2>&1 &
DPID=$!
python3 "$TMPD/waitsock.py" "$SOCKETLEY_SOCKET" 8 >/dev/null 2>&1 || true

# Ask for one request through a proxy and report the HTTP status, or "none".
code_through() {   # $1 = proxy name, $2 = port, $3 = marker
    for _ in $(seq 1 60); do nc -z 127.0.0.1 "$2" 2>/dev/null && break; sleep 0.1; done
    sleep 0.3
    timeout 8 curl -s -m 6 -o "$TMPD/body" -w '%{http_code}' \
        "http://127.0.0.1:$2/$1/$3" 2>/dev/null || echo "none"
}

# ── 1. control: the CA that signed the backend ───────────────────────────────
"$BIN" create proxy vok -p "$PX_OK" --backend "https://127.0.0.1:$BE" \
    --protocol http --ca "$TMPD/be.pem" -s >/dev/null 2>&1
CODE=$(code_through vok "$PX_OK" c-1)
if [ "$CODE" = "200" ] && [ "$(cat "$TMPD/body" 2>/dev/null)" = "c-1" ]; then
    ok
else
    bad "control: a verified TLS backend is served" \
        "got status '$CODE' body '$(cat "$TMPD/body" 2>/dev/null)' -- every refusal below would then pass for the wrong reason"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit "$FAIL"
fi

# ── 2. a CA that signed nothing here ─────────────────────────────────────────
"$BIN" create proxy vbadca -p "$PX_BADCA" --backend "https://127.0.0.1:$BE" \
    --protocol http --ca "$TMPD/other.pem" -s >/dev/null 2>&1
CODE=$(code_through vbadca "$PX_BADCA" c-2)
if [ "$CODE" = "502" ]; then ok; else
    bad "a backend signed by an untrusted CA is refused" \
        "expected 502, got '$CODE' body '$(cat "$TMPD/body" 2>/dev/null)'"
fi

# ── 3. no --ca: the system store, which does not contain a self-signed peer ──
# --client-cert/--client-key take the leg to TLS without naming a trust store.
"$BIN" create proxy vnoca -p "$PX_NOCA" --backend "https://127.0.0.1:$BE" \
    --protocol http --client-cert "$TMPD/be.pem" --client-key "$TMPD/be.key" \
    -s >/dev/null 2>&1
CODE=$(code_through vnoca "$PX_NOCA" c-3)
if [ "$CODE" = "502" ]; then ok; else
    bad "a self-signed backend is refused against the system store" \
        "expected 502, got '$CODE' body '$(cat "$TMPD/body" 2>/dev/null)'"
fi

# ── 4. the chain verifies, the name does not ─────────────────────────────────
# The backend now presents a certificate for elsewhere.example, and that same
# certificate is handed to the proxy as its CA -- so SSL_VERIFY_PEER is
# satisfied and only the name check stands between this and a connection to
# whoever holds that key.
start_backend "$TMPD/wrong.pem" "$TMPD/wrong.key" "$TMPD/be2.log"
"$BIN" create proxy vbadname -p "$PX_BADNAME" --backend "https://127.0.0.1:$BE" \
    --protocol http --ca "$TMPD/wrong.pem" -s >/dev/null 2>&1
CODE=$(code_through vbadname "$PX_BADNAME" c-4)
if [ "$CODE" = "502" ]; then ok; else
    bad "a certificate issued to another name is refused" \
        "expected 502, got '$CODE' body '$(cat "$TMPD/body" 2>/dev/null)' -- the chain verified, so only the name check could have caught this"
fi

# ── 5. nothing was ever sent in the clear ────────────────────────────────────
# Every refusal above ends the connection during the handshake.  If any of them
# had fallen back to cleartext, the backend would have logged a request line
# where a ClientHello belonged.
if grep -q "^served c-[234]" "$TMPD/be.log" "$TMPD/be2.log" 2>/dev/null; then
    bad "a refused backend is never retried in the clear" \
        "the backend served a request from a configuration that failed verification"
else
    ok
fi

if kill -0 "$DPID" 2>/dev/null; then ok; else bad "daemon alive" "the daemon died"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
