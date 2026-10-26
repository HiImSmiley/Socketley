#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# TLS on a server listener: a real handshake with data intact both ways, no
# downgrade for a plaintext client and no splice leaking plaintext, aborts that
# do not accumulate, mutual TLS, every incomplete flag set refused rather than
# falling back to cleartext, and which roles may hold these flags at all --
# with distinguishable payloads and bulk aborts, because the failure this is
# written against is a session that works once and stalls later.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# shellcheck source=lib_ready.sh
. "$(dirname "$0")/lib_ready.sh"
# shellcheck source=lib_create.sh
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0; TOTAL=0

echo "=== Integration: TLS on a server listener ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not available (needed for a TLS client)"
    exit 0
fi
if ! command -v openssl >/dev/null 2>&1; then
    echo "  SKIP: openssl CLI not available (needed to generate certificates)"
    exit 0
fi
if ! python3 -c 'import ssl' >/dev/null 2>&1; then
    echo "  SKIP: python3 has no ssl module"
    exit 0
fi

# Own daemon, socket and state directory, because this test asserts on the
# failed state of runtimes it deliberately misconfigures.
TMPDIR_T=$(mktemp -d /tmp/socketley-tls-XXXXXX)
export HOME="$TMPDIR_T/home"
export SOCKETLEY_SOCKET="$TMPDIR_T/daemon.sock"
. "$(dirname "$0")/lib_daemon.sh"
daemon_watch "$TMPDIR_T"   # its processes go with it if it is killed
mkdir -p "$HOME"
DPID=""

SRV_PORT=$((SL_PORT_BASE+731))
CACHE_PORT=$((SL_PORT_BASE+732))
MTLS_PORT=$((SL_PORT_BASE+733))
BAD_PORT=$((SL_PORT_BASE+734))
HTTP_PORT=$((SL_PORT_BASE+735))

cleanup() {
    [ -n "$DPID" ] && kill "$DPID" 2>/dev/null || true
    rm -rf "$TMPDIR_T"
}
trap cleanup EXIT

assert_eq() {
    TOTAL=$((TOTAL+1))
    local got="$1" expected="$2" label="$3"
    if [ "$got" = "$expected" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]:"
        echo "        expected: '$expected'"
        echo "        got:      '$got'"
    fi
}

assert_ok() {
    TOTAL=$((TOTAL+1))
    local rc="$1" label="$2"
    if [ "$rc" -eq 0 ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]"
    fi
}

# Run a command and echo its exit status, because half this file is about
# commands that are supposed to fail and `set -e` would end the run first.
rc_of() {
    local rc=0
    "$@" >"$TMPDIR_T/last-cmd.log" 2>&1 || rc=$?
    echo "$rc"
}

# ── certificates ────────────────────────────────────────────────────────────
# A self-signed leaf for the listener and a one-level CA that signs a client
# certificate, all expiring tomorrow in a directory the trap removes.
CERTS="$TMPDIR_T/certs"
mkdir -p "$CERTS"

# Each guarded so the SKIP below is reachable, because under `set -e` a failed
# openssl ended the file before the message explaining it could print.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$CERTS/server-key.pem" -out "$CERTS/server.pem" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 || true

# A second key never paired with any certificate, to prove that a key which
# does not match is refused rather than accepted.
openssl genrsa -out "$CERTS/other-key.pem" 2048 >/dev/null 2>&1 || true

openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$CERTS/ca-key.pem" -out "$CERTS/ca.pem" \
    -subj "/CN=socketley-test-ca" >/dev/null 2>&1 || true
openssl req -newkey rsa:2048 -nodes \
    -keyout "$CERTS/client-key.pem" -out "$CERTS/client.csr" \
    -subj "/CN=test-client" >/dev/null 2>&1 || true
openssl x509 -req -in "$CERTS/client.csr" -days 2 \
    -CA "$CERTS/ca.pem" -CAkey "$CERTS/ca-key.pem" -CAcreateserial \
    -out "$CERTS/client.pem" >/dev/null 2>&1 || true

if [ ! -s "$CERTS/server.pem" ] || [ ! -s "$CERTS/client.pem" ]; then
    echo "  SKIP: openssl could not generate the test certificates"
    exit 0
fi

"$BIN" daemon >"$TMPDIR_T/daemon.log" 2>&1 &
DPID=$!
SOCKETLEY_DLOG="$TMPDIR_T/daemon.log"
for _ in $(seq 1 60); do [ -S "$SOCKETLEY_SOCKET" ] && break; sleep 0.1; done
if [ ! -S "$SOCKETLEY_SOCKET" ]; then
    echo "  FAIL [setup]: daemon did not come up"
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# 1. A real handshake, and data in both directions
# ─────────────────────────────────────────────────────────────────────────────
# The cache link is what proves the plaintext survived the record layer byte
# for byte: every message the server receives is stored under an incrementing
# key, so reading those keys back shows exactly what the server understood.
create_ok "cache for the plaintext oracle created" \
    "$BIN" create cache tls_cache -p "$CACHE_PORT" -s
ready_resp 127.0.0.1 "$CACHE_PORT" 10 || true

CREATE_RC=$(rc_of "$BIN" create server tls_srv -p "$SRV_PORT" \
    --tls --cert "$CERTS/server.pem" --key "$CERTS/server-key.pem" \
    --cache tls_cache -s)
assert_eq "$CREATE_RC" "0" "create server with --tls --cert --key succeeds"
if [ "$CREATE_RC" != "0" ]; then
    echo "        daemon said: $(cat "$TMPDIR_T/last-cmd.log")"
fi

assert_ok "$(rc_of ready_tls 127.0.0.1 "$SRV_PORT" "$CERTS/server.pem" localhost 20)" \
    "TLS listener completes a verified handshake"

# One client and one session with payloads chosen so a shift or truncation is
# visible, and `|| true` because a listener that never came up would otherwise
# end the file before every assertion in it.
python3 - "$SRV_PORT" "$CERTS/server.pem" "$BIN" > "$TMPDIR_T/roundtrip.out" 2>&1 <<'PYEOF' || true
import socket, ssl, subprocess, sys, time

port, cafile, binary = int(sys.argv[1]), sys.argv[2], sys.argv[3]
payloads = [
    b"012345",
    b"0123456789",
    b'{"type":"chat","text":"hi"}',
    ("".join(str(i % 10) for i in range(700))).encode(),   # spans records
]

ctx = ssl.create_default_context(cafile=cafile)
ctx.check_hostname = True
raw = socket.create_connection(("127.0.0.1", port), timeout=10)
tls = ctx.wrap_socket(raw, server_hostname="localhost")
print("VERSION", tls.version())
print("CIPHER", tls.cipher()[0] if tls.cipher() else "")

for p in payloads:
    tls.sendall(p + b"\n")
    time.sleep(0.15)          # one read completion per message

# Server to client, over the same session.  The daemon is asked to broadcast
# from outside this process, so the bytes travel the full send_to ->
# flush_write_queue -> record layer -> io_uring write path.
time.sleep(0.3)
subprocess.run([binary, "send", "tls_srv", "TLS-BROADCAST-MARKER"],
               capture_output=True, timeout=10)

tls.settimeout(6)
got = b""
deadline = time.time() + 6
while b"TLS-BROADCAST-MARKER" not in got and time.time() < deadline:
    try:
        chunk = tls.recv(4096)
    except socket.timeout:
        break
    if not chunk:
        break
    got += chunk
print("BROADCAST", "yes" if b"TLS-BROADCAST-MARKER" in got else "no")
tls.close()
PYEOF

TLS_VERSION=$(grep '^VERSION ' "$TMPDIR_T/roundtrip.out" | cut -d' ' -f2- || true)
TLS_CIPHER=$(grep '^CIPHER ' "$TMPDIR_T/roundtrip.out" | cut -d' ' -f2- || true)
BROADCAST=$(grep '^BROADCAST ' "$TMPDIR_T/roundtrip.out" | cut -d' ' -f2- || true)

TOTAL=$((TOTAL+1))
case "$TLS_VERSION" in
    TLSv1.2|TLSv1.3) PASS=$((PASS+1)) ;;
    *) FAIL=$((FAIL+1)); echo "  FAIL [negotiated TLS version]: got '$TLS_VERSION'"
       sed 's/^/        /' "$TMPDIR_T/roundtrip.out" ;;
esac

TOTAL=$((TOTAL+1))
if [ -n "$TLS_CIPHER" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1)); echo "  FAIL [a cipher was negotiated]"
fi

assert_eq "$BROADCAST" "yes" "server -> client: broadcast arrives over the session"

sleep 0.5
read_key() { printf 'get %s\n' "$1" | nc -q 1 127.0.0.1 "$CACHE_PORT" 2>/dev/null | tr -d '\r\n'; }
BIG=$(python3 -c 'print("".join(str(i % 10) for i in range(700)))')

assert_eq "$(read_key 1)" "012345"                      "client -> server: 6 byte payload"
assert_eq "$(read_key 2)" "0123456789"                  "client -> server: 10 byte payload"
assert_eq "$(read_key 3)" '{"type":"chat","text":"hi"}' "client -> server: 27 byte JSON"
assert_eq "$(read_key 4)" "$BIG"                        "client -> server: 700 byte payload"

# ─────────────────────────────────────────────────────────────────────────────
# 2. No downgrade: a plaintext client is not served
# ─────────────────────────────────────────────────────────────────────────────
# A perfectly good cleartext line is not a TLS record, so the handshake fails
# and what must never happen is the line being delivered as a message -- with
# `|| true` because failing to connect is not a reason to stop the file.
python3 - "$SRV_PORT" >/dev/null 2>&1 <<'PYEOF' || true
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
s.sendall(b"PLAINTEXT-MUST-NOT-BE-DELIVERED\n")
s.settimeout(3)
try:
    s.recv(4096)     # an alert, or nothing; either way not an echo
except Exception:
    pass
time.sleep(0.2)
s.close()
PYEOF
sleep 0.6

# Compared against a key nothing ever wrote rather than against a literal, so
# the assertion is "this is a miss" and does not depend on how the cache spells
# one.
assert_eq "$(read_key 5)" "$(read_key 991)" \
    "plaintext on a TLS port is never delivered as a message"

# ─────────────────────────────────────────────────────────────────────────────
# 2b. HTTPS and wss:// on the same listener
# ─────────────────────────────────────────────────────────────────────────────
# Protocol detection runs on the decrypted stream, and the non-HTML file is the
# one that matters: the splice path would move plaintext into an encrypted
# stream, so it is bypassed and this asserts that it still is.
mkdir -p "$TMPDIR_T/www"
printf '<html><body>HTTPS-STATIC-OK</body></html>' > "$TMPDIR_T/www/index.html"
printf 'not-html-so-this-would-have-been-spliced' > "$TMPDIR_T/www/data.txt"

assert_eq "$(rc_of "$BIN" create server tls_http -p "$HTTP_PORT" \
    --tls --cert "$CERTS/server.pem" --key "$CERTS/server-key.pem" \
    --http "$TMPDIR_T/www" -s)" "0" "create a TLS listener serving static files"

assert_ok "$(rc_of ready_tls 127.0.0.1 "$HTTP_PORT" "$CERTS/server.pem" localhost 20)" \
    "static-file TLS listener completes a handshake"

if command -v curl >/dev/null 2>&1; then
    HTML=$(curl -s --max-time 10 --cacert "$CERTS/server.pem" \
        --resolve "localhost:$HTTP_PORT:127.0.0.1" \
        "https://localhost:$HTTP_PORT/" 2>/dev/null || true)
    TOTAL=$((TOTAL+1))
    case "$HTML" in
        *HTTPS-STATIC-OK*) PASS=$((PASS+1)) ;;
        *) FAIL=$((FAIL+1)); echo "  FAIL [https:// serves an HTML file]: got '$HTML'" ;;
    esac

    TXT=$(curl -s --max-time 10 --cacert "$CERTS/server.pem" \
        --resolve "localhost:$HTTP_PORT:127.0.0.1" \
        "https://localhost:$HTTP_PORT/data.txt" 2>/dev/null || true)
    assert_eq "$TXT" "not-html-so-this-would-have-been-spliced" \
        "https:// serves a non-HTML file (the splice path is bypassed, not leaked)"
fi

WSS=$(python3 - "$HTTP_PORT" "$CERTS/server.pem" 2>/dev/null <<'PYEOF'
import base64, os, socket, ssl, sys
port, cafile = int(sys.argv[1]), sys.argv[2]
ctx = ssl.create_default_context(cafile=cafile)
raw = socket.create_connection(("127.0.0.1", port), timeout=8)
s = ctx.wrap_socket(raw, server_hostname="localhost")
key = base64.b64encode(os.urandom(16)).decode()
s.sendall(f"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
          f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
          f"Sec-WebSocket-Version: 13\r\n\r\n".encode())
print("101" if b"101" in s.recv(512).split(b"\r\n")[0] else "no")
s.close()
PYEOF
) || true
# `|| true` because this python exits non-zero when the listener is not there,
# and an empty $WSS is not "101", which is what assert_eq is here to say.
assert_eq "$WSS" "101" "wss:// upgrade succeeds on the same TLS listener"

rc_of "$BIN" stop tls_http >/dev/null
sleep 0.2
rc_of "$BIN" remove tls_http >/dev/null

# ─────────────────────────────────────────────────────────────────────────────
# 3. Clients that abort mid-handshake
# ─────────────────────────────────────────────────────────────────────────────
# Three ways to leave a handshake unfinished, forty times each, with `|| true`
# because the aborts are the setup and the connections counter falling back to
# zero is the assertion.
python3 - "$SRV_PORT" "$CERTS/server.pem" >/dev/null 2>&1 <<'PYEOF' || true
import socket, ssl, struct, sys

port, cafile = int(sys.argv[1]), sys.argv[2]
LINGER0 = struct.pack("ii", 1, 0)      # close() sends RST, not FIN

ctx = ssl.create_default_context(cafile=cafile)
ctx.check_hostname = True

for _ in range(40):
    # (a) a real ClientHello, then gone
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=3)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER0)
        raw.setblocking(False)
        tls = ctx.wrap_socket(raw, server_hostname="localhost",
                              do_handshake_on_connect=False)
        try:
            tls.do_handshake()          # writes the ClientHello, wants a read
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError, OSError):
            pass
        tls.close()
    except Exception:
        pass

    # (b) a record header promising more than ever arrives
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        s.sendall(b"\x16\x03\x01\x01\x00" + b"\x01\x00\x00\xfc" + b"\x00" * 16)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER0)
        s.close()
    except Exception:
        pass

    # (c) connected and gone without a byte
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER0)
        s.close()
    except Exception:
        pass
PYEOF

# Connections has to fall back to zero, waited on with ready_conns so the
# accepted zero is one the runtime saw after the aborts rather than the pushed
# sample taken 14 ms before python had finished starting.
ready_conns "$BIN" tls_srv 0 15 || true
CONNS=""
# `|| true` because grep exits 1 on an absent field and pipefail promotes it,
# which ended the file at the sharpest assertion with everything after it
# unreported.
CONNS=$("$BIN" stats tls_srv 2>/dev/null | grep '^connections:' | cut -d: -f2 | tr -d ' ') || true
assert_eq "$CONNS" "0" "aborted handshakes leave no connections behind"

# And the listener still works afterwards.
assert_ok "$(rc_of ready_tls 127.0.0.1 "$SRV_PORT" "$CERTS/server.pem" localhost 15)" \
    "listener still completes a handshake after the aborts"

# ─────────────────────────────────────────────────────────────────────────────
# 4. Mutual TLS
# ─────────────────────────────────────────────────────────────────────────────
assert_eq "$(rc_of "$BIN" create server tls_mtls -p "$MTLS_PORT" \
    --tls --cert "$CERTS/server.pem" --key "$CERTS/server-key.pem" \
    --ca "$CERTS/ca.pem" -s)" "0" "create server with --ca (mutual TLS) succeeds"

ready_tcp 127.0.0.1 "$MTLS_PORT" 10 || true

MTLS_RESULT=$(python3 - "$MTLS_PORT" "$CERTS" 2>/dev/null <<'PYEOF'
import socket, ssl, sys, time
port, certs = int(sys.argv[1]), sys.argv[2]

# "Accepted" cannot be read off the handshake alone.  A TLS 1.3 server only
# discovers the missing client certificate after the client believes it is
# finished, so the refusal arrives as a fatal alert on the next exchange rather
# than out of wrap_socket().  The probe therefore sends a line and asks what
# happens: a session that stays open with nothing to say was accepted, and one
# that raises or reaches EOF was refused.
def attempt(with_cert):
    ctx = ssl.create_default_context(cafile=f"{certs}/server.pem")
    ctx.check_hostname = True
    if with_cert:
        ctx.load_cert_chain(f"{certs}/client.pem", f"{certs}/client-key.pem")
    tls = None
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=6)
        tls = ctx.wrap_socket(raw, server_hostname="localhost")
    except Exception:
        return False          # refused during the handshake itself (TLS 1.2)
    try:
        # Longer without a certificate, because the refusal is what is awaited and a
        # sanitized server under a parallel suite sent it after more than 2 s.
        tls.settimeout(2 if with_cert else 10)
        tls.sendall(b"mtls-probe\n")
        try:
            return True if tls.recv(1) else False   # data: alive; EOF: refused
        except socket.timeout:
            return True       # still open, nothing to say: accepted
    except Exception:
        return False          # fatal alert or reset: refused
    finally:
        try:
            tls.close()
        except Exception:
            pass

deadline = time.time() + 20
with_ = False
while time.time() < deadline:
    with_ = attempt(True)
    if with_:
        break
    time.sleep(0.2)
print("WITHCERT", "yes" if with_ else "no")
print("NOCERT", "yes" if attempt(False) else "no")
PYEOF
) || true
# `|| true` because an mTLS listener that never came up would end the file and
# take section 5 with it, while an empty result fails both assertions
# correctly.
assert_eq "$(echo "$MTLS_RESULT" | grep '^WITHCERT' | cut -d' ' -f2)" "yes" \
    "mTLS: a client certificate signed by --ca is accepted"
assert_eq "$(echo "$MTLS_RESULT" | grep '^NOCERT' | cut -d' ' -f2)" "no" \
    "mTLS: a client with no certificate is rejected"

# ─────────────────────────────────────────────────────────────────────────────
# 5. Fail closed
# ─────────────────────────────────────────────────────────────────────────────
# The seventh field of `ls` is the status, because CREATED is several words.
state_of() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2==n {print tolower($7)}'; }

# A certificate file that does not exist must leave the runtime failed with
# nothing listening, because a listener here would serve cleartext under a TLS
# configuration.
rc_of "$BIN" create server tls_missing -p "$BAD_PORT" \
    --tls --cert "$CERTS/does-not-exist.pem" --key "$CERTS/server-key.pem" >/dev/null
rc_of "$BIN" start tls_missing >/dev/null
sleep 0.5
assert_eq "$(state_of tls_missing)" "failed" "missing certificate: runtime fails to start"

TOTAL=$((TOTAL+1))
# Bash's own /dev/tcp, because a missing nc also exits non-zero and read as a closed port.
if timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$BAD_PORT" 2>/dev/null; then
    FAIL=$((FAIL+1)); echo "  FAIL [missing certificate: nothing listens on the port]"
else
    PASS=$((PASS+1))
fi
rc_of "$BIN" remove tls_missing >/dev/null

# (b) A key that is real but does not match the certificate.
rc_of "$BIN" create server tls_mismatch -p "$BAD_PORT" \
    --tls --cert "$CERTS/server.pem" --key "$CERTS/other-key.pem" >/dev/null
rc_of "$BIN" start tls_mismatch >/dev/null
sleep 0.5
assert_eq "$(state_of tls_mismatch)" "failed" "mismatched key: runtime fails to start"
rc_of "$BIN" remove tls_mismatch >/dev/null

# Incomplete flag sets each describe a listener that could only serve
# cleartext, so `create` refuses and leaves no runtime behind.
assert_eq "$(rc_of "$BIN" create server tls_nokey -p "$BAD_PORT" \
    --tls --cert "$CERTS/server.pem")" "1" "--tls --cert without --key is refused"
assert_eq "$(state_of tls_nokey)" "" "--tls --cert without --key creates no runtime"

assert_eq "$(rc_of "$BIN" create server tls_bare -p "$BAD_PORT" --tls)" "1" \
    "--tls with no certificate is refused"

assert_eq "$(rc_of "$BIN" create server tls_certonly -p "$BAD_PORT" \
    --cert "$CERTS/server.pem" --key "$CERTS/server-key.pem")" "1" \
    "a certificate without --tls is refused"

# ─────────────────────────────────────────────────────────────────────────────
# 6. Who may hold these flags
# ─────────────────────────────────────────────────────────────────────────────
# What this section enumerates is that every role takes a complete set, because
# none is left without a handshake behind it and a stale entry here is how the
# gate ends up refusing a role that has since grown one.
assert_eq "$(rc_of "$BIN" create cache tlsprobe_cache -p "$BAD_PORT" \
    --tls --cert "$CERTS/server.pem" --key "$CERTS/server-key.pem")" "0" \
    "--tls --cert --key on a cache runtime is accepted"
assert_eq "$(state_of tlsprobe_cache)" "created" "--tls on a cache runtime creates the runtime"
rc_of "$BIN" remove tlsprobe_cache >/dev/null

# ...and the incomplete sets are refused there for the same reason they are on
# a server: each describes a listener that could only serve cleartext.
assert_eq "$(rc_of "$BIN" create cache tlsprobe_cachebare -p "$BAD_PORT" --tls)" "1" \
    "--tls with no certificate is refused on a cache"
assert_eq "$(state_of tlsprobe_cachebare)" "" "--tls with no certificate creates no cache"

# The client takes the complete set, asserted here because this is the file
# that enumerates who may hold these flags.
assert_eq "$(rc_of "$BIN" create client tlsprobe_client -t "127.0.0.1:$BAD_PORT" \
    --tls --ca "$CERTS/server.pem")" "0" "--tls --ca on a client runtime is accepted"
rc_of "$BIN" remove tlsprobe_client >/dev/null

# The proxy terminates TLS on its listener and dials one to its backends,
# asserted here rather than only in its own file because a stale entry is how
# the gate refuses a role that has grown a handshake.
assert_eq "$(rc_of "$BIN" create proxy tlsprobe_proxy -p "$BAD_PORT" \
    --backend 127.0.0.1:1 --tls --cert "$CERTS/server.pem" \
    --key "$CERTS/server-key.pem")" "0" \
    "--tls --cert --key on a proxy runtime is accepted"
assert_eq "$(state_of tlsprobe_proxy)" "created" "--tls on a proxy runtime creates the runtime"
rc_of "$BIN" remove tlsprobe_proxy >/dev/null

# ...and the incomplete sets are refused there for the same reason they are on a
# server: each describes a listener that could only serve cleartext.
assert_eq "$(rc_of "$BIN" create proxy tlsprobe_pxbare -p "$BAD_PORT" \
    --backend 127.0.0.1:1 --tls)" "1" \
    "--tls with no certificate is refused on a proxy"
assert_eq "$(state_of tlsprobe_pxbare)" "" "--tls with no certificate creates no proxy"

assert_eq "$(rc_of "$BIN" create proxy tlsprobe_pxcert -p "$BAD_PORT" \
    --backend 127.0.0.1:1 --cert "$CERTS/server.pem" \
    --key "$CERTS/server-key.pem")" "1" \
    "a certificate without --tls is refused on a proxy"
assert_eq "$(state_of tlsprobe_pxcert)" "" "a certificate without --tls creates no proxy"

# --client-ca verifies the certificates clients present, which only a TLS
# listener can ask for, so on a cleartext port it would authenticate nobody
# while inspect reported mutual TLS.
assert_eq "$(rc_of "$BIN" create proxy tlsprobe_pxmca -p "$BAD_PORT" \
    --backend 127.0.0.1:1 --client-ca "$CERTS/ca.pem")" "1" \
    "--client-ca without --tls is refused on a proxy"
assert_eq "$(state_of tlsprobe_pxmca)" "" "--client-ca without --tls creates no proxy"

# Half a client-certificate pair loads nothing: the backend leg would present
# no certificate at all after the flag said it would.
assert_eq "$(rc_of "$BIN" create proxy tlsprobe_pxhalf -p "$BAD_PORT" \
    --backend 127.0.0.1:1 --client-cert "$CERTS/server.pem")" "1" \
    "--client-cert without --client-key is refused on a proxy"
assert_eq "$(state_of tlsprobe_pxhalf)" "" "--client-cert alone creates no proxy"

# A server has no backend leg, so the options that configure one are refused
# there even though it is a role that does handshake.
assert_eq "$(rc_of "$BIN" create server tlsprobe_srvmesh -p "$BAD_PORT" \
    --client-cert "$CERTS/server.pem" --client-key "$CERTS/server-key.pem")" "1" \
    "--client-cert on a server runtime is refused"

rc_of "$BIN" stop tls_srv tls_mtls tls_cache >/dev/null
sleep 0.3
rc_of "$BIN" remove tls_srv tls_mtls tls_cache >/dev/null

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
