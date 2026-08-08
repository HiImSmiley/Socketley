#!/usr/bin/env bash
# Integration test: TLS on a server listener.
#
# The project advertised TLS for years and had none: tls_context.cpp was a
# complete OpenSSL wrapper that nothing constructed, and every TLS flag was
# refused so that a listener could not come up promising encryption and serve
# cleartext.  A server runtime terminates TLS now — accept, handshake and
# record layer driven by the same io_uring completions as everything else,
# through a memory BIO pair so OpenSSL never touches a socket.
#
# The handshake is several rounds of "OpenSSL wants more bytes" / "OpenSSL has
# bytes to send" and each round is a completion, so the failure mode this file
# is written against is a session that works once and stalls, corrupts or leaks
# on some later connection.  That is why the payloads are distinguishable, why
# the aborts are run in bulk, and why the whole file is worth running more than
# once.
#
# WHAT IT CHECKS
#   1. a real handshake against a self-signed certificate, verified by the
#      client, and application data in both directions with the bytes intact
#   2. no downgrade: a plaintext client on the TLS port is dropped, and nothing
#      it sent is ever delivered to the runtime as a message; and https:// and
#      wss:// work on the same listener, with the zero-copy splice path for
#      static files bypassed rather than leaking plaintext into the stream
#   3. clients that abort mid-handshake do not accumulate — connections falls
#      back to zero and the listener still serves the next real client
#   4. mutual TLS: with --ca set, a client presenting no certificate is
#      rejected and one signed by that CA is accepted
#   5. fail closed: a certificate that cannot be loaded, a key that does not
#      match it, and every incomplete flag combination refuse rather than
#      falling back to a cleartext listener
#   6. who may hold these flags at all: no role is left without a handshake
#      behind it, so cache, proxy and client each take a complete set and
#      refuse the incomplete ones.  What each does with them is its own file's
#      subject — test_cache_tls.sh, test_proxy_tls_backend.sh,
#      test_client_tls.sh; this file only asserts who is allowed to hold them
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

# Own daemon, socket and state directory.  This test asserts on the failed
# state of runtimes it deliberately misconfigures, and against the shared
# daemon those would outlive the run.
TMPDIR_T=$(mktemp -d /tmp/socketley-tls-XXXXXX)
export HOME="$TMPDIR_T/home"
export SOCKETLEY_SOCKET="$TMPDIR_T/daemon.sock"
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

# Run a command and echo its exit status.  Half of this file is about commands
# that are *supposed* to fail, and under `set -e` a bare `cmd; rc=$?` ends the
# run before the assertion is ever reached.
rc_of() {
    local rc=0
    "$@" >"$TMPDIR_T/last-cmd.log" 2>&1 || rc=$?
    echo "$rc"
}

# ── certificates ────────────────────────────────────────────────────────────
# A self-signed leaf for the listener, and a separate one-level CA that signs a
# client certificate for the mutual-TLS case.  Everything expires tomorrow and
# lives in a directory the trap removes.
CERTS="$TMPDIR_T/certs"
mkdir -p "$CERTS"

# Each guarded, so that the SKIP below is reachable.  Under `set -e` an openssl
# that failed ended the file on the spot — silently, since all five are
# redirected to /dev/null — and the "could not generate the test certificates"
# message a few lines down, which exists precisely to say so, could never print.
# The existence check is the real gate; these statuses are not.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$CERTS/server-key.pem" -out "$CERTS/server.pem" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 || true

# A second key, never paired with any certificate.  Used to prove that a key
# which does not match the certificate is refused rather than accepted.
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

# One client, one session: send several payloads chosen so that a shift or a
# truncation in the BIO plumbing is visible (a repetitive payload would survive
# an off-by-one unnoticed), then ask the daemon to broadcast and read it back
# through the same session.
# `|| true`: a listener that never came up makes this exit non-zero, and a bare
# command that fails under `set -e` ends the file — here, before every assertion
# in the file.  The output is already being captured to a file that the checks
# below read, so an empty capture is a result they can report.
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
# The bytes below are a perfectly good line for the cleartext protocol.  On a
# TLS listener they are not a record, so the handshake fails and the connection
# is dropped -- what must never happen is the line being delivered as a message,
# which is what a listener that fell back to cleartext would do.
# `|| true`: this one only has to *happen* — what it proves is asserted a few
# lines down, off the daemon's own state.  Failing to connect is not a reason to
# stop the file, and under `set -e` a bare failing command was exactly that.
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
# Protocol detection runs on the decrypted stream, so a TLS listener serves
# HTTP and WebSocket without being told to.  The non-HTML file is the one that
# matters: static files are normally sent with splice(), which moves the file's
# bytes into the socket without OpenSSL ever seeing them.  On a TLS connection
# that would be plaintext in the middle of an encrypted stream, so the splice
# path is bypassed -- and this is the assertion that says it still is.
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
# `|| true` for the same reason as the curl capture above: this python exits
# non-zero when the listener is not there to connect to, and a lone `VAR=$(…)`
# would make that the end of the file rather than the end of this test.  An
# empty $WSS is not "101", which is what assert_eq is here to say.
assert_eq "$WSS" "101" "wss:// upgrade succeeds on the same TLS listener"

rc_of "$BIN" stop tls_http >/dev/null
sleep 0.2
rc_of "$BIN" remove tls_http >/dev/null

# ─────────────────────────────────────────────────────────────────────────────
# 3. Clients that abort mid-handshake
# ─────────────────────────────────────────────────────────────────────────────
# Three ways to leave a handshake unfinished, forty times each: a genuine
# ClientHello followed by an RST, a truncated record that can never complete,
# and a connection that is opened and closed without a byte.  A session leaked
# on any of those shows up as connections that never falls back to zero.
# `|| true`: the aborted handshakes are the setup, not the assertion — the
# assertion is the connections counter falling back to zero afterwards, and it
# cannot be read if a failure to connect ends the file first.
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
        raw.setblocking(False)
        tls = ctx.wrap_socket(raw, server_hostname="localhost",
                              do_handshake_on_connect=False)
        try:
            tls.do_handshake()          # writes the ClientHello, wants a read
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError, OSError):
            pass
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER0)
        raw.close()
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

# Connections has to fall back to zero.  A session or a connection struct left
# behind by an aborted handshake keeps this above zero for the rest of the
# runtime's life, which is the sharpest assertion in this file.
CONNS=""
for _ in $(seq 1 60); do
    # `|| true`: grep exits 1 when the field is absent, `pipefail` promotes it,
    # and a lone `VAR=$(…)` takes its status from the substitution — so a runtime
    # that is not there ended the file inside this poll loop, with the sharpest
    # assertion in the file and everything after it unreported.  CONNS is
    # pre-set to "" above precisely so an unreadable counter falls through to
    # assert_eq, which fails on "" and says what it wanted.
    CONNS=$("$BIN" stats tls_srv 2>/dev/null | grep '^connections:' | cut -d: -f2 | tr -d ' ') || true
    [ "$CONNS" = "0" ] && break
    sleep 0.1
done
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
        tls.settimeout(2)
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
# `|| true`: an mTLS listener that never came up makes this python exit
# non-zero, and a lone `VAR=$(…)` turned that into the end of the file — taking
# section 5, "fail closed", with it, which is about a different feature again.
# An empty $MTLS_RESULT fails both assertions below, which is the correct report.
assert_eq "$(echo "$MTLS_RESULT" | grep '^WITHCERT' | cut -d' ' -f2)" "yes" \
    "mTLS: a client certificate signed by --ca is accepted"
assert_eq "$(echo "$MTLS_RESULT" | grep '^NOCERT' | cut -d' ' -f2)" "no" \
    "mTLS: a client with no certificate is rejected"

# ─────────────────────────────────────────────────────────────────────────────
# 5. Fail closed
# ─────────────────────────────────────────────────────────────────────────────
# The STATUS column of `ls`, lower-cased.  Columns are
# ID NAME TYPE PORT CONN "OWNED BY" STATUS CREATED..., and CREATED is several
# words ("0 seconds ago"), so the status is the seventh field and not the last.
state_of() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2==n {print tolower($7)}'; }

# (a) A certificate file that does not exist.  The runtime must go to failed,
#     and nothing may be listening on its port -- a listener that came up here
#     would be serving cleartext under a TLS configuration.
rc_of "$BIN" create server tls_missing -p "$BAD_PORT" \
    --tls --cert "$CERTS/does-not-exist.pem" --key "$CERTS/server-key.pem" >/dev/null
rc_of "$BIN" start tls_missing >/dev/null
sleep 0.5
assert_eq "$(state_of tls_missing)" "failed" "missing certificate: runtime fails to start"

TOTAL=$((TOTAL+1))
if nc -z 127.0.0.1 "$BAD_PORT" 2>/dev/null; then
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

# (c) Incomplete flag sets.  Each of these describes a listener that could only
#     serve cleartext, so `create` refuses and leaves no runtime behind.
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
# This section used to enumerate the roles that had no handshake behind them
# and still refused the flags outright.  There are none left: every runtime
# type terminates or dials TLS somewhere, so what it enumerates now is that
# each of them takes a complete set — and a stale entry here is exactly how the
# gate ends up refusing a role that has since grown a handshake.
#
# A cache listener was the last one to arrive.  It terminates TLS on its own
# port with the same three flags a server uses, and RESP runs on the decrypted
# stream; see test_cache_tls.sh for the transport, the mutual-TLS case and the
# one thing a TLS cache still refuses, which is replicating in cleartext out of
# an encrypted port.
#
# tlsprobe_ and not tls_: tls_cache is the live cache this file linked the
# server to, and asking `ls` about it would answer for that one instead.
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

# The client takes the complete set, as the proxy below does.  Asserted
# here because this is the file that enumerates who may hold these flags.
assert_eq "$(rc_of "$BIN" create client tlsprobe_client -t "127.0.0.1:$BAD_PORT" \
    --tls --ca "$CERTS/server.pem")" "0" "--tls --ca on a client runtime is accepted"
rc_of "$BIN" remove tlsprobe_client >/dev/null

# The proxy is no longer one of them: it terminates TLS on its own listener and
# dials one to its backends, so the complete set is accepted here exactly as it
# is on a server.  Asserted in this file rather than only in the proxy's own,
# because this is the file that enumerates who may hold these flags — and a
# stale entry here is how the gate ends up refusing a role that has since grown
# a handshake.  See test_proxy_tls_backend.sh for the transport itself.
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

# --client-ca verifies the certificates *clients* present, which only a TLS
# listener can ask for.  On a cleartext port it would authenticate nobody while
# inspect reported mutual TLS, which is the shape this whole gate exists for.
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
