#!/usr/bin/env bash
# Integration test: a proxy speaking TLS -- to its backend, and to its clients.
#
# Both directions are documented.  socketley.1 gives --tls ("Enable TLS
# encryption for all connections"), --cert, --key, --ca, and the backend-mTLS
# pair --client-cert/--client-key, and its own example creates a proxy with
# "--tls --health-check tcp".  All six flags parse, are stored, are reported by
# inspect, and are rejected as live changes with "requires restart".
#
# Nothing reads them.  tls_context is referenced by no runtime -- the only
# OpenSSL calls outside it are in lua_context's HTTP client -- so a proxy
# created with --tls listens in plaintext, and a proxy pointed at an HTTPS
# backend sends it a plaintext request.  The two assertions that name this are
# the ones on the wire: the TLS backend logs an "HTTP_REQUEST" handshake error,
# meaning it received a plaintext request line where a ClientHello belonged, and
# the --tls listener answers an ordinary unencrypted GET with 200.
#
# The second of those is the one that matters most.  A listener created with
# --tls that quietly serves plaintext does not fail closed: an operator who asks
# for encryption gets a port that works, looks healthy, and encrypts nothing.
#
# The load section exists so that this becomes a real content check the moment
# the transport works: every request carries a marker "<connection>-<sequence>"
# that the backend echoes, so a TLS path that reassembles records wrongly shows
# up as garbled or crossed content rather than as a vague failure.  Until then
# it reports how far it got.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

TMPD=$(mktemp -d /tmp/socketley-tls-XXXXXX)
export HOME="$TMPD/home"
export SOCKETLEY_SOCKET="$TMPD/daemon.sock"
mkdir -p "$HOME"

TLS_BE=19591; PX_UP=19592; PLAIN_BE=19593; PX_DOWN=19594
CLIENTS=${CLIENTS:-8}
REQS=${REQS:-40}
DPID=""; TBPID=""; PBPID=""
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    for n in tlsup tlsdown; do
        "$BIN" stop "$n" >/dev/null 2>&1 || true
        "$BIN" remove "$n" >/dev/null 2>&1 || true
    done
    [ -n "$TBPID" ] && kill "$TBPID" 2>/dev/null
    [ -n "$PBPID" ] && kill "$PBPID" 2>/dev/null
    if [ -n "$DPID" ]; then
        kill "$DPID" 2>/dev/null || true
        for _ in $(seq 1 50); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.1; done
        kill -9 "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
    rm -rf "$TMPD"
}
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: proxy TLS, to the backend and to the client ==="

if ! command -v python3 >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    echo "  SKIP: python3 and openssl are both required"; exit 0
fi
if ! python3 -c "import ssl" >/dev/null 2>&1; then
    echo "  SKIP: python3 has no ssl module"; exit 0
fi

openssl req -x509 -newkey rsa:2048 -keyout "$TMPD/key.pem" -out "$TMPD/cert.pem" \
    -days 2 -nodes -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" \
    >/dev/null 2>&1 || { echo "  SKIP: could not generate a test certificate"; exit 0; }

# ---- backends -------------------------------------------------------------
cat > "$TMPD/be.py" <<'PYEOF'
import socket, ssl, sys, threading

mode, port = sys.argv[1], int(sys.argv[2])
ctx = None
if mode == "tls":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(sys.argv[3], sys.argv[4])

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(64)
print("ready", flush=True)


def serve(raw):
    c = raw
    if ctx is not None:
        try:
            c = ctx.wrap_socket(raw, server_side=True)
        except ssl.SSLError as e:
            # "HTTP_REQUEST" here means a plaintext request line arrived where a
            # ClientHello belonged -- which is exactly the finding.
            print(f"handshake-failed {e.reason}", flush=True)
            try:
                raw.close()
            except OSError:
                pass
            return
        except OSError:
            return
    try:
        buf = b""
        while True:
            data = c.recv(65536)
            if not data:
                break
            buf += data
            while b"\r\n\r\n" in buf:
                head, buf = buf.split(b"\r\n\r\n", 1)
                parts = head.split(b"\r\n", 1)[0].split(b" ")
                marker = parts[1].lstrip(b"/") if len(parts) > 1 else b"?"
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                          b"Connection: keep-alive\r\n\r\n%s" % (len(marker), marker))
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

python3 "$TMPD/be.py" tls   "$TLS_BE" "$TMPD/cert.pem" "$TMPD/key.pem" >"$TMPD/tlsbe.log" 2>&1 &
TBPID=$!
python3 "$TMPD/be.py" plain "$PLAIN_BE" >"$TMPD/plainbe.log" 2>&1 &
PBPID=$!
for _ in $(seq 1 60); do grep -q ready "$TMPD/tlsbe.log"   2>/dev/null && break; sleep 0.1; done
for _ in $(seq 1 60); do grep -q ready "$TMPD/plainbe.log" 2>/dev/null && break; sleep 0.1; done

# The whole test rests on this backend really being TLS.  If it is not, every
# assertion below would pass for the wrong reason.
if echo | timeout 8 openssl s_client -connect "127.0.0.1:$TLS_BE" -brief 2>&1 | grep -qi "TLSv1"; then
    ok
else
    bad "setup" "the TLS backend did not complete a handshake -- nothing below would mean anything"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit "$FAIL"
fi

"$BIN" daemon >"$TMPD/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 60); do "$BIN" ps >/dev/null 2>&1 && break; sleep 0.1; done

# ---- 1. upstream: proxy -> TLS backend ------------------------------------
"$BIN" create proxy tlsup -p "$PX_UP" --backend "127.0.0.1:$TLS_BE" --protocol http \
    --client-cert "$TMPD/cert.pem" --client-key "$TMPD/key.pem" --ca "$TMPD/cert.pem" \
    -s >/dev/null 2>&1 || true
for _ in $(seq 1 60); do nc -z 127.0.0.1 "$PX_UP" 2>/dev/null && break; sleep 0.1; done
sleep 0.5

if "$BIN" stats tlsup >/dev/null 2>&1; then ok; else
    bad "setup" "the proxy refused the backend-mTLS flags and did not start"
fi

BODY=$(timeout 8 curl -s -m 6 "http://127.0.0.1:$PX_UP/tlsup/u-0" 2>/dev/null || true)
if [ "$BODY" = "u-0" ]; then ok; else
    bad "a request reaches an HTTPS backend" "got '${BODY:-<nothing>}', expected 'u-0'"
fi

sleep 0.5
if grep -q "handshake-failed" "$TMPD/tlsbe.log" 2>/dev/null; then
    bad "the proxy speaks TLS to its backend" \
        "the backend rejected the handshake: $(grep -m1 handshake-failed "$TMPD/tlsbe.log") -- a plaintext request arrived where a ClientHello belonged"
else
    ok
fi

# ---- 2. downstream: TLS client -> proxy listener created with --tls --------
"$BIN" create proxy tlsdown -p "$PX_DOWN" --backend "127.0.0.1:$PLAIN_BE" --protocol http \
    --tls --cert "$TMPD/cert.pem" --key "$TMPD/key.pem" -s >/dev/null 2>&1 || true
for _ in $(seq 1 60); do nc -z 127.0.0.1 "$PX_DOWN" 2>/dev/null && break; sleep 0.1; done
sleep 0.5

if "$BIN" stats tlsdown >/dev/null 2>&1; then ok; else
    bad "setup" "the proxy refused --tls/--cert/--key and did not start"
fi

if echo | timeout 8 openssl s_client -connect "127.0.0.1:$PX_DOWN" -brief 2>&1 | grep -qi "TLSv1"; then
    ok
else
    bad "a --tls listener completes a TLS handshake" "no handshake on the port"
fi

# The security-relevant half: a port asked to be encrypted must not serve
# unencrypted requests.
PLAINCODE=$(timeout 8 curl -s -m 6 -o /dev/null -w '%{http_code}' \
            "http://127.0.0.1:$PX_DOWN/tlsdown/p-0" 2>/dev/null || true)
if [ "$PLAINCODE" = "200" ]; then
    bad "a --tls listener refuses plaintext" \
        "an unencrypted GET was served with HTTP 200 -- the port encrypts nothing"
else
    ok
fi

# ---- 3. content under concurrent load over the TLS path -------------------
LOAD=$(python3 - "$PX_DOWN" tlsdown "$CLIENTS" "$REQS" <<'PYEOF'
import ssl, socket, sys, threading
from collections import Counter

port, name, clients, reqs = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
res = Counter()
lock = threading.Lock()


def run(cid):
    local = Counter()
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        s = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
    except Exception as e:
        with lock:
            res["connect:" + type(e).__name__] += 1
        return
    try:
        s.settimeout(5)
        for i in range(reqs):
            marker = f"{cid}-{i}"
            s.sendall(f"GET /{name}/{marker} HTTP/1.1\r\nHost: h\r\n"
                      f"Connection: keep-alive\r\n\r\n".encode())
            chunk = s.recv(65536)
            if not chunk:
                local["missing"] += 1
                break
            body = chunk.split(b"\r\n\r\n", 1)[-1].decode("latin1")
            if body == marker:
                local["ok"] += 1
            elif "-" in body and body.split("-")[0].isdigit():
                local["crossed" if body.split("-")[0] != str(cid) else "wrongseq"] += 1
                break
            else:
                local["garbled"] += 1
                break
    except Exception as e:
        local[type(e).__name__] += 1
    finally:
        try:
            s.close()
        except Exception:
            pass
    with lock:
        res.update(local)


ts = [threading.Thread(target=run, args=(c,)) for c in range(clients)]
for t in ts:
    t.start()
for t in ts:
    t.join()
print("LOAD " + " ".join(f"{k}={v}" for k, v in sorted(res.items())))
PYEOF
)
echo "  $LOAD"
WANT=$((CLIENTS * REQS))
GOT=$(printf '%s\n' "$LOAD" | grep -o '\bok=[0-9]*' | cut -d= -f2 | head -1)
if [ "${GOT:-0}" -eq "$WANT" ] 2>/dev/null; then ok; else
    bad "every request over the TLS path returns its own marker" \
        "${GOT:-0} of $WANT correct"
fi
for K in crossed garbled wrongseq; do
    N=$(printf '%s\n' "$LOAD" | grep -o "\b$K=[0-9]*" | cut -d= -f2 | head -1)
    if [ "${N:-0}" -eq 0 ] 2>/dev/null; then ok; else bad "no $K responses over TLS" "got $N"; fi
done

if kill -0 "$DPID" 2>/dev/null; then ok; else bad "daemon alive" "the daemon died"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
