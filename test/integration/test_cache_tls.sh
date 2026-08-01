#!/usr/bin/env bash
# Integration test: TLS on a cache listener.
#
# The cache was the last of the four runtimes speaking only cleartext.  Its TLS
# flags were refused outright, which was honest but was also the whole of what
# an operator got: a Redis-compatible cache that could not be put on an
# untrusted network at all.  It terminates TLS now, on the server runtime's
# design and deliberately not a second one -- a memory BIO pair per connection,
# ciphertext carried by the same io_uring submissions as every other byte, the
# handshake advanced one completion at a time.  RESP and the line protocol run
# on the decrypted stream, so an existing client speaks the protocol it always
# did, one layer up.
#
# The handshake is several rounds of "OpenSSL wants more bytes" / "OpenSSL has
# bytes to send" and each round is a completion, so the failure this file is
# written against is a session that works once and then stalls, truncates or
# leaks on some later connection.  That is why the values are distinguishable
# rather than repetitive, why the aborts are run in bulk, and why the file is
# worth running more than once.
#
# WHAT IT CHECKS
#   1. a real handshake against a self-signed certificate, verified by the
#      client, with RESP running over the encrypted stream and values coming
#      back byte for byte -- including one that spans several records
#   2. the line protocol on the same listener, since RESP is auto-detected from
#      the first decrypted byte and that detection now runs on plaintext the
#      record layer produced
#   3. no downgrade: a plaintext client on the TLS port is dropped rather than
#      left hanging, and the command it sent is never executed
#   4. mutual TLS: with --ca set, a client presenting no certificate is
#      rejected and one signed by that CA is accepted
#   5. clients that abort mid-handshake do not accumulate
#   6. fail closed: a certificate that cannot be read, a key that does not match
#      it, and every incomplete flag combination refuse rather than falling back
#      to a cleartext listener
#   7. replication is refused on a TLS cache, in all three places it can be
#      asked for -- at create, on the restore path at start, and at the
#      REPLICATE command, which is the only one of the three that is not
#      configuration -- while a cleartext cache replicates exactly as before
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# shellcheck source=lib_ready.sh
. "$(dirname "$0")/lib_ready.sh"

PASS=0; FAIL=0; TOTAL=0

echo "=== Integration: TLS on a cache listener ==="

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
# state of runtimes it deliberately misconfigures, and it restarts the daemon to
# reach the restore path; against the shared daemon both would be destructive.
TMPDIR_T=$(mktemp -d /tmp/socketley-cachetls-XXXXXX)
export HOME="$TMPDIR_T/home"
export SOCKETLEY_SOCKET="$TMPDIR_T/daemon.sock"
mkdir -p "$HOME"
STATE_DIR="$HOME/.local/share/socketley/runtimes"
DPID=""

TLS_PORT=19741
LINE_PORT=19742
MTLS_PORT=19743
BAD_PORT=19744
LEADER_PORT=19745
FOLLOWER_PORT=19746

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

# Run a command and echo its exit status.  Much of this file is about commands
# that are *supposed* to fail, and under `set -e` a bare `cmd; rc=$?` ends the
# run before the assertion is ever reached.
rc_of() {
    local rc=0
    "$@" >"$TMPDIR_T/last-cmd.log" 2>&1 || rc=$?
    echo "$rc"
}

# Whether the last rc_of command's output contained this text.
#
# Most of the refusals below are refused by a binary *without* this feature as
# well, for an entirely different reason -- a cache used to refuse every TLS
# flag outright, so "exit 1" was already the answer to --tls --cert with no
# --key, to --ca without --tls, and to --tls with --replicate.  Asserting the
# status alone would therefore pass against a binary that has none of this,
# which is the exact way a file full of refusal assertions once proved nothing.
# The reason is the assertion; the status is not.
says() {
    if grep -qF -- "$1" "$TMPDIR_T/last-cmd.log" 2>/dev/null; then
        echo yes
    else
        echo no
    fi
}

start_daemon() {
    "$BIN" daemon >>"$TMPDIR_T/daemon.log" 2>&1 &
    DPID=$!
    for _ in $(seq 1 60); do [ -S "$SOCKETLEY_SOCKET" ] && break; sleep 0.1; done
    [ -S "$SOCKETLEY_SOCKET" ]
}

# ── certificates ────────────────────────────────────────────────────────────
# A self-signed leaf for the listener, and a separate one-level CA that signs a
# client certificate for the mutual-TLS case.  Everything expires tomorrow and
# lives in a directory the trap removes.
CERTS="$TMPDIR_T/certs"
mkdir -p "$CERTS"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$CERTS/cache-key.pem" -out "$CERTS/cache.pem" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

# A second key, never paired with any certificate.  Used to prove that a key
# which does not match the certificate is refused rather than accepted.
openssl genrsa -out "$CERTS/other-key.pem" 2048 >/dev/null 2>&1

openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$CERTS/ca-key.pem" -out "$CERTS/ca.pem" \
    -subj "/CN=socketley-cache-test-ca" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
    -keyout "$CERTS/client-key.pem" -out "$CERTS/client.csr" \
    -subj "/CN=test-client" >/dev/null 2>&1
openssl x509 -req -in "$CERTS/client.csr" -days 2 \
    -CA "$CERTS/ca.pem" -CAkey "$CERTS/ca-key.pem" -CAcreateserial \
    -out "$CERTS/client.pem" >/dev/null 2>&1

if [ ! -s "$CERTS/cache.pem" ] || [ ! -s "$CERTS/client.pem" ]; then
    echo "  SKIP: openssl could not generate the test certificates"
    exit 0
fi

if ! start_daemon; then
    echo "  FAIL [setup]: daemon did not come up"
    exit 1
fi

# The STATUS column of `ls`, lower-cased.  Columns are
# ID NAME TYPE PORT CONN "OWNED BY" STATUS CREATED..., and CREATED is several
# words ("0 seconds ago"), so the status is the seventh field and not the last.
state_of() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2==n {print tolower($7)}'; }

# ─────────────────────────────────────────────────────────────────────────────
# 1. A real handshake, and RESP over the encrypted stream
# ─────────────────────────────────────────────────────────────────────────────
CREATE_RC=$(rc_of "$BIN" create cache tlscache -p "$TLS_PORT" \
    --tls --cert "$CERTS/cache.pem" --key "$CERTS/cache-key.pem" -s)
assert_eq "$CREATE_RC" "0" "create cache with --tls --cert --key succeeds"
if [ "$CREATE_RC" != "0" ]; then
    echo "        daemon said: $(cat "$TMPDIR_T/last-cmd.log")"
fi

assert_ok "$(rc_of ready_tls 127.0.0.1 "$TLS_PORT" "$CERTS/cache.pem" localhost 20)" \
    "TLS cache listener completes a verified handshake"

# One client, one session: SET several values chosen so that a shift or a
# truncation in the BIO plumbing is visible (a repetitive value would survive an
# off-by-one unnoticed), then GET them all back through the same session.  The
# large one deliberately spans several TLS records.
python3 - "$TLS_PORT" "$CERTS/cache.pem" > "$TMPDIR_T/resp.out" 2>&1 <<'PYEOF' || true
import socket, ssl, sys

port, cafile = int(sys.argv[1]), sys.argv[2]
values = {
    "k1": "012345",
    "k2": "0123456789",
    "k3": '{"type":"chat","text":"hi"}',
    "k4": "".join(str(i % 10) for i in range(20000)),   # spans many records
}

def cmd(*parts):
    out = f"*{len(parts)}\r\n".encode()
    for p in parts:
        b = p.encode()
        out += b"$" + str(len(b)).encode() + b"\r\n" + b + b"\r\n"
    return out

ctx = ssl.create_default_context(cafile=cafile)
ctx.check_hostname = True
raw = socket.create_connection(("127.0.0.1", port), timeout=10)
tls = ctx.wrap_socket(raw, server_hostname="localhost")
print("VERSION", tls.version())
print("CIPHER", tls.cipher()[0] if tls.cipher() else "")

f = tls.makefile("rwb")

def line():
    return f.readline().rstrip(b"\r\n")

def bulk():
    hdr = line()
    if not hdr.startswith(b"$"):
        return hdr
    n = int(hdr[1:])
    if n < 0:
        return None
    data = f.read(n)
    f.read(2)
    return data

for k, v in values.items():
    f.write(cmd("SET", k, v)); f.flush()
    line()

ok = True
for k, v in values.items():
    f.write(cmd("GET", k)); f.flush()
    got = bulk()
    if got != v.encode():
        ok = False
        print("MISMATCH", k, "len", len(got) if got is not None else -1,
              "expected", len(v))
print("ROUNDTRIP", "yes" if ok else "no")

# PING on the same session, after the large value, so a record layer that
# desynchronised on a multi-record write shows up here rather than silently.
f.write(cmd("PING")); f.flush()
print("PING", line().decode(errors="replace"))
tls.close()
PYEOF

TLS_VERSION=$(grep '^VERSION ' "$TMPDIR_T/resp.out" | cut -d' ' -f2- || true)
TLS_CIPHER=$(grep '^CIPHER ' "$TMPDIR_T/resp.out" | cut -d' ' -f2- || true)
ROUNDTRIP=$(grep '^ROUNDTRIP ' "$TMPDIR_T/resp.out" | cut -d' ' -f2- || true)
PINGED=$(grep '^PING ' "$TMPDIR_T/resp.out" | cut -d' ' -f2- || true)

TOTAL=$((TOTAL+1))
case "$TLS_VERSION" in
    TLSv1.2|TLSv1.3) PASS=$((PASS+1)) ;;
    *) FAIL=$((FAIL+1)); echo "  FAIL [negotiated TLS version]: got '$TLS_VERSION'"
       sed 's/^/        /' "$TMPDIR_T/resp.out" ;;
esac

TOTAL=$((TOTAL+1))
if [ -n "$TLS_CIPHER" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1)); echo "  FAIL [a cipher was negotiated]"
fi

assert_eq "$ROUNDTRIP" "yes" "RESP over TLS: every value comes back byte for byte"
assert_eq "$PINGED" "+PONG"  "RESP over TLS: the session is still framed after a 20KB value"

# ─────────────────────────────────────────────────────────────────────────────
# 2. The line protocol on a TLS listener
# ─────────────────────────────────────────────────────────────────────────────
# RESP is auto-detected from the first byte of the *decrypted* stream, so a
# client that does not speak it must still be understood.  A listener that fed
# detection ciphertext instead would take the first byte of a ClientHello and
# decide from that.
assert_eq "$(rc_of "$BIN" create cache tlsline -p "$LINE_PORT" \
    --tls --cert "$CERTS/cache.pem" --key "$CERTS/cache-key.pem" -s)" "0" \
    "create a second TLS cache for the line protocol"

assert_ok "$(rc_of ready_tls 127.0.0.1 "$LINE_PORT" "$CERTS/cache.pem" localhost 20)" \
    "line-protocol TLS cache completes a handshake"

LINE_OUT=$(python3 - "$LINE_PORT" "$CERTS/cache.pem" 2>/dev/null <<'PYEOF'
import socket, ssl, sys
port, cafile = int(sys.argv[1]), sys.argv[2]
ctx = ssl.create_default_context(cafile=cafile)
raw = socket.create_connection(("127.0.0.1", port), timeout=8)
tls = ctx.wrap_socket(raw, server_hostname="localhost")
f = tls.makefile("rwb")
f.write(b"set line-key line-value\n"); f.flush()
f.readline()
f.write(b"get line-key\n"); f.flush()
print(f.readline().rstrip(b"\r\n").decode(errors="replace"))
tls.close()
PYEOF
) || true
assert_eq "$LINE_OUT" "line-value" "line protocol works on the decrypted stream"

# ─────────────────────────────────────────────────────────────────────────────
# 3. No downgrade: a plaintext client is refused, not served and not hung
# ─────────────────────────────────────────────────────────────────────────────
# The bytes below are a perfectly good RESP SET.  On a TLS listener they are not
# a record, so the handshake fails and the connection is dropped.  Two things
# must hold and both are asserted: the client is *told* -- it reaches EOF or is
# reset rather than sitting on an open socket waiting forever -- and the command
# is never executed.
PLAIN_RESULT=$(python3 - "$TLS_PORT" 2>/dev/null <<'PYEOF'
import socket, sys
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.sendall(b"*3\r\n$3\r\nSET\r\n$9\r\nplainkey\x31\r\n$10\r\nplainvalue\r\n")
s.settimeout(5)
try:
    data = s.recv(4096)
    # An alert, or a clean EOF.  Either is the listener refusing; what must not
    # happen is "+OK", and what must not happen is nothing at all.
    print("CLOSED", "yes" if data == b"" or data[:1] == b"\x15" else "no")
    print("REPLY", repr(data[:16]))
except socket.timeout:
    print("CLOSED", "hung")          # still open with nothing said: a hang
except OSError:
    print("CLOSED", "yes")           # reset
    print("REPLY", "b''")
s.close()
PYEOF
) || true
assert_eq "$(echo "$PLAIN_RESULT" | grep '^CLOSED' | cut -d' ' -f2)" "yes" \
    "a plaintext client on a TLS cache port is refused rather than left hanging"

# ...and the SET it sent never happened.  Read back through a real session.
#
# The verdict is one word rather than two values compared against each other:
# "the two lookups agree" is true of a dead port as well, where both are empty,
# so on its own it would pass against a binary that has none of this.  It is
# only evidence when the session it was read over worked -- which is why a key
# that *is* set has to come back correct in the same breath.
MISS_CHECK=$(python3 - "$TLS_PORT" "$CERTS/cache.pem" 2>/dev/null <<'PYEOF'
import socket, ssl, sys
port, cafile = int(sys.argv[1]), sys.argv[2]
def cmd(*parts):
    out = f"*{len(parts)}\r\n".encode()
    for p in parts:
        b = p.encode()
        out += b"$" + str(len(b)).encode() + b"\r\n" + b + b"\r\n"
    return out
ctx = ssl.create_default_context(cafile=cafile)
raw = socket.create_connection(("127.0.0.1", port), timeout=8)
tls = ctx.wrap_socket(raw, server_hostname="localhost")
f = tls.makefile("rwb")
def get(k):
    f.write(cmd("GET", k)); f.flush()
    hdr = f.readline().rstrip(b"\r\n")
    if hdr.startswith(b"$") and int(hdr[1:]) >= 0:
        n = int(hdr[1:]); d = f.read(n); f.read(2); return d
    return None
plain = get("plainkey1")
never = get("a-key-nothing-ever-wrote")
known = get("k1")
tls.close()
# A live session (k1 reads back), the plaintext client's key a miss, and a miss
# spelled the same way as one for a key nobody ever mentioned.
if known == b"012345" and plain is None and never is None:
    print("VERDICT not-executed")
else:
    print("VERDICT", "known=%r plain=%r never=%r" % (known, plain, never))
PYEOF
) || true
assert_eq "$(echo "$MISS_CHECK" | grep '^VERDICT' | cut -d' ' -f2-)" "not-executed" \
    "the plaintext client's command is never executed"

# ─────────────────────────────────────────────────────────────────────────────
# 4. Mutual TLS
# ─────────────────────────────────────────────────────────────────────────────
assert_eq "$(rc_of "$BIN" create cache tlsmtls -p "$MTLS_PORT" \
    --tls --cert "$CERTS/cache.pem" --key "$CERTS/cache-key.pem" \
    --ca "$CERTS/ca.pem" -s)" "0" "create cache with --ca (mutual TLS) succeeds"

ready_tcp 127.0.0.1 "$MTLS_PORT" 10 || true

MTLS_RESULT=$(python3 - "$MTLS_PORT" "$CERTS" 2>/dev/null <<'PYEOF'
import socket, ssl, sys, time
port, certs = int(sys.argv[1]), sys.argv[2]

# "Accepted" cannot be read off the handshake alone.  A TLS 1.3 server only
# discovers the missing client certificate after the client believes it is
# finished, so the refusal arrives as a fatal alert on the next exchange rather
# than out of wrap_socket().  The probe therefore sends a PING and asks what
# happens: +PONG means accepted, an exception or EOF means rejected.
#
# Three outcomes and not two, deliberately.  "Rejected" and "there is nothing
# listening on this port" look identical from the client's side, so a two-state
# probe reports the no-certificate case as a pass against a binary that cannot
# create this runtime at all -- an assertion that is satisfied by the feature
# being absent is not an assertion.  A refused connect is its own answer here.
def attempt(with_cert):
    ctx = ssl.create_default_context(cafile=f"{certs}/cache.pem")
    ctx.check_hostname = True
    if with_cert:
        ctx.load_cert_chain(f"{certs}/client.pem", f"{certs}/client-key.pem")
    tls = None
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=6)
    except OSError:
        return "no-listener"
    try:
        tls = ctx.wrap_socket(raw, server_hostname="localhost")
    except Exception:
        return "rejected"     # refused during the handshake itself (TLS 1.2)
    try:
        tls.settimeout(3)
        tls.sendall(b"*1\r\n$4\r\nPING\r\n")
        return "accepted" if tls.recv(64).startswith(b"+PONG") else "rejected"
    except Exception:
        return "rejected"     # fatal alert or reset
    finally:
        try:
            tls.close()
        except Exception:
            pass

deadline = time.time() + 20
with_ = "no-listener"
while time.time() < deadline:
    with_ = attempt(True)
    if with_ == "accepted":
        break
    time.sleep(0.2)
print("WITHCERT", with_)
print("NOCERT", attempt(False))
PYEOF
) || true
assert_eq "$(echo "$MTLS_RESULT" | grep '^WITHCERT' | cut -d' ' -f2)" "accepted" \
    "mTLS: a client certificate signed by --ca is accepted, and RESP answers"
assert_eq "$(echo "$MTLS_RESULT" | grep '^NOCERT' | cut -d' ' -f2)" "rejected" \
    "mTLS: a client with no certificate is rejected by the listener"

# ─────────────────────────────────────────────────────────────────────────────
# 5. Clients that abort mid-handshake
# ─────────────────────────────────────────────────────────────────────────────
# Three ways to leave a handshake unfinished, forty times each: a genuine
# ClientHello followed by an RST, a truncated record that can never complete,
# and a connection opened and closed without a byte.  A session or a connection
# struct leaked on any of those shows up as connections that never falls back
# to zero.
python3 - "$TLS_PORT" "$CERTS/cache.pem" >/dev/null 2>&1 <<'PYEOF' || true
import socket, ssl, struct, sys

port, cafile = int(sys.argv[1]), sys.argv[2]
LINGER0 = struct.pack("ii", 1, 0)      # close() sends RST, not FIN

ctx = ssl.create_default_context(cafile=cafile)
ctx.check_hostname = True

for _ in range(40):
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=3)
        raw.setblocking(False)
        tls = ctx.wrap_socket(raw, server_hostname="localhost",
                              do_handshake_on_connect=False)
        try:
            tls.do_handshake()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError, OSError):
            pass
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER0)
        raw.close()
    except Exception:
        pass

    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        s.sendall(b"\x16\x03\x01\x01\x00" + b"\x01\x00\x00\xfc" + b"\x00" * 16)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER0)
        s.close()
    except Exception:
        pass

    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER0)
        s.close()
    except Exception:
        pass
PYEOF

CONNS=""
for _ in $(seq 1 60); do
    # `|| true`: with no such runtime the grep matches nothing and the pipeline
    # fails, which under `set -eo pipefail` ends the run at this line -- and a
    # file that stops here has said nothing about any assertion below it.
    CONNS=$("$BIN" stats tlscache 2>/dev/null | grep '^connections:' | cut -d: -f2 | tr -d ' ' || true)
    [ "$CONNS" = "0" ] && break
    sleep 0.1
done
assert_eq "$CONNS" "0" "aborted handshakes leave no connections behind"

assert_ok "$(rc_of ready_tls 127.0.0.1 "$TLS_PORT" "$CERTS/cache.pem" localhost 15)" \
    "listener still completes a handshake after the aborts"

# The dataset survived all of that.  A session freed while the ring still held
# it, or a struct reissued with the previous connection's session on it, does
# not always show up as a lost connection -- it shows up as a cache that has
# stopped answering correctly.
POSTABORT=$(python3 - "$TLS_PORT" "$CERTS/cache.pem" 2>/dev/null <<'PYEOF'
import socket, ssl, sys
port, cafile = int(sys.argv[1]), sys.argv[2]
ctx = ssl.create_default_context(cafile=cafile)
raw = socket.create_connection(("127.0.0.1", port), timeout=8)
tls = ctx.wrap_socket(raw, server_hostname="localhost")
f = tls.makefile("rwb")
f.write(b"*2\r\n$3\r\nGET\r\n$2\r\nk1\r\n"); f.flush()
hdr = f.readline().rstrip(b"\r\n")
n = int(hdr[1:]); print(f.read(n).decode(errors="replace"))
tls.close()
PYEOF
) || true
assert_eq "$POSTABORT" "012345" "the dataset is intact after the aborted handshakes"

# ─────────────────────────────────────────────────────────────────────────────
# 6. Fail closed
# ─────────────────────────────────────────────────────────────────────────────
# Every refusal below is also a refusal on a binary that has none of this
# feature, because a cache used to refuse all four TLS flags outright.  So the
# assertions are on the *reason*, not on the exit status: a message naming the
# flag that is actually missing can only come from a build that got as far as
# looking at the set.  "created no runtime" is folded into the same verdict for
# the same reason -- on its own it is true of a binary that refuses everything.
refusal_verdict() {   # <runtime-name> <expected fragment>
    local name="$1" want="$2"
    echo "rc=$(cat "$TMPDIR_T/last-rc")/said=$(says "$want")/state=$(state_of "$name")"
}
create_refused() {    # <name> <fragment> <label> <create args...>
    local name="$1" want="$2" label="$3"; shift 3
    local rc; rc=$(rc_of "$@")
    echo "$rc" > "$TMPDIR_T/last-rc"
    assert_eq "$(refusal_verdict "$name" "$want")" "rc=1/said=yes/state=" "$label"
}

# (a) A certificate file that does not exist.  The runtime must go to failed,
#     and nothing may be listening on its port -- a listener that came up here
#     would be serving cleartext under a TLS configuration.  Both halves are
#     one verdict: "nothing is listening" is also true when the runtime could
#     never be created, so it is evidence only next to a runtime that exists
#     and is in `failed`.
rc_of "$BIN" create cache tlsmissing -p "$BAD_PORT" \
    --tls --cert "$CERTS/does-not-exist.pem" --key "$CERTS/cache-key.pem" >/dev/null
rc_of "$BIN" start tlsmissing >/dev/null
sleep 0.5
BOUND=closed
nc -z 127.0.0.1 "$BAD_PORT" 2>/dev/null && BOUND=open
assert_eq "$(state_of tlsmissing)/$BOUND" "failed/closed" \
    "missing certificate: cache goes to failed and binds nothing"
rc_of "$BIN" remove tlsmissing >/dev/null

# (b) A key that is real but does not match the certificate.
rc_of "$BIN" create cache tlsmismatch -p "$BAD_PORT" \
    --tls --cert "$CERTS/cache.pem" --key "$CERTS/other-key.pem" >/dev/null
rc_of "$BIN" start tlsmismatch >/dev/null
sleep 0.5
BOUND=closed
nc -z 127.0.0.1 "$BAD_PORT" 2>/dev/null && BOUND=open
assert_eq "$(state_of tlsmismatch)/$BOUND" "failed/closed" \
    "mismatched key: cache goes to failed and binds nothing"
rc_of "$BIN" remove tlsmismatch >/dev/null

# (c) Incomplete flag sets.  Each describes a listener that could only serve
#     cleartext, so `create` refuses, names the flag that is missing, and
#     leaves no runtime behind.
create_refused tlsnokey "needs --key" "--tls --cert without --key is refused, naming --key" \
    "$BIN" create cache tlsnokey -p "$BAD_PORT" --tls --cert "$CERTS/cache.pem"

create_refused tlsbare "needs --cert" "--tls with no certificate is refused, naming --cert" \
    "$BIN" create cache tlsbare -p "$BAD_PORT" --tls

create_refused tlscertonly "needs --tls as well" \
    "a certificate without --tls is refused, naming --tls" \
    "$BIN" create cache tlscertonly -p "$BAD_PORT" \
    --cert "$CERTS/cache.pem" --key "$CERTS/cache-key.pem"

# --ca on a cache is the client CA for its own listener, exactly as on a server,
# so it needs an encrypted listener to mean anything at all.
create_refused tlscaonly "needs --tls as well" \
    "--ca without --tls is refused on a cache, naming --tls" \
    "$BIN" create cache tlscaonly -p "$BAD_PORT" --ca "$CERTS/ca.pem"

# Not asserted here: the gate also refuses --client-ca / --client-cert /
# --client-key on a cache, as it does on a server, because they configure a
# backend leg neither role has.  There is no way to reach that branch from
# outside -- the flag handlers do not offer those options on a cache, and
# parse_json_string() reads the mesh_* fields for a proxy only, so a document
# carrying them onto a cache has them dropped before the gate is asked.  It is
# defence in depth for the day one of those two things changes, and an
# assertion that cannot be made to fail is not evidence of anything.

# ─────────────────────────────────────────────────────────────────────────────
# 7. Replication and TLS do not mix, and the refusal holds everywhere
# ─────────────────────────────────────────────────────────────────────────────
# A cache's replication link is not encrypted by anything: a follower dials its
# leader itself, in cleartext, and on the leader a promoted follower is written
# to by a second writer that goes around the record layer.  Encrypting the
# listener and replicating out of it would put the whole dataset on the wire in
# the clear from a runtime `inspect` reports as encrypted, so the combination is
# refused rather than half-honoured.
#
# (a) At create.  On the reason again, not the status: a binary without this
#     feature refuses the very same command because --tls is not a cache flag
#     there at all, and would sail through an assertion that only read the exit
#     code.  Only a build that accepts --tls on a cache can refuse it *for the
#     replication*.
create_refused tlsrepl "--replicate: a cache's replication link is not encrypted" \
    "--tls together with --replicate is refused at create, naming --replicate" \
    "$BIN" create cache tlsrepl -p "$BAD_PORT" \
    --tls --cert "$CERTS/cache.pem" --key "$CERTS/cache-key.pem" \
    --replicate "127.0.0.1:$LEADER_PORT"

# (b) On the restore path.  This is the one that matters most and the one a
#     create-time check cannot reach: a state file carrying both fields is read
#     at boot and started without any command line being involved.  Written by
#     hand here for exactly that reason -- there is deliberately no supported
#     way to produce it, which is what makes it the interesting case.
rc_of "$BIN" create cache tlsrestore -p "$BAD_PORT" \
    --replicate "127.0.0.1:$LEADER_PORT" >/dev/null
assert_eq "$(state_of tlsrestore)" "created" \
    "precondition: a cleartext replicating cache is created normally"

"$BIN" stop tlsrestore >/dev/null 2>&1 || true
kill "$DPID" 2>/dev/null || true
wait "$DPID" 2>/dev/null || true
DPID=""

RESTORE_JSON="$STATE_DIR/tlsrestore.json"
TOTAL=$((TOTAL+1))
if [ -f "$RESTORE_JSON" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1)); echo "  FAIL [precondition: state file for tlsrestore exists]: $RESTORE_JSON"
fi

if [ -f "$RESTORE_JSON" ]; then
    python3 - "$RESTORE_JSON" "$CERTS" <<'PYEOF' || true
import json, sys
path, certs = sys.argv[1], sys.argv[2]
with open(path) as fh:
    cfg = json.load(fh)
cfg["tls"] = True
cfg["cert_path"] = f"{certs}/cache.pem"
cfg["key_path"] = f"{certs}/cache-key.pem"
with open(path, "w") as fh:
    json.dump(cfg, fh, indent=2)
PYEOF
fi

if ! start_daemon; then
    echo "  FAIL [setup]: daemon did not come back up"
    exit 1
fi
sleep 0.3

# The runtime is restored; starting it must be refused for the replication, it
# must not end up running, and it must not be listening on the port.  One
# verdict for all three: each on its own is satisfied by a binary that refuses
# every TLS flag on a cache and so never gets near the question.
START_RC=$(rc_of "$BIN" start tlsrestore)
SAID_REPL=$(says "--replicate: a cache's replication link is not encrypted")
RSTATE=$(state_of tlsrestore)
BOUND=closed
nc -z 127.0.0.1 "$BAD_PORT" 2>/dev/null && BOUND=open
assert_eq "rc=$START_RC/said=$SAID_REPL/running=$([ "$RSTATE" = running ] && echo yes || echo no)/bound=$BOUND" \
          "rc=1/said=yes/running=no/bound=closed" \
    "a restored cache with TLS and replication refuses to start, naming --replicate"
rc_of "$BIN" remove tlsrestore >/dev/null

# (c) At the REPLICATE command.  A cache becomes a *leader* when a client asks
#     it to, long after any configuration was validated, so this is the half no
#     gate can catch and it has to be refused at the command itself.
rc_of "$BIN" create cache tlsleader -p "$LEADER_PORT" \
    --tls --cert "$CERTS/cache.pem" --key "$CERTS/cache-key.pem" -s >/dev/null
assert_ok "$(rc_of ready_tls 127.0.0.1 "$LEADER_PORT" "$CERTS/cache.pem" localhost 20)" \
    "a TLS cache with no replication configuration starts normally"

REPL_ANSWER=$(python3 - "$LEADER_PORT" "$CERTS/cache.pem" 2>/dev/null <<'PYEOF'
import socket, ssl, sys
port, cafile = int(sys.argv[1]), sys.argv[2]
ctx = ssl.create_default_context(cafile=cafile)
raw = socket.create_connection(("127.0.0.1", port), timeout=8)
tls = ctx.wrap_socket(raw, server_hostname="localhost")
f = tls.makefile("rwb")
f.write(b"replicate\n"); f.flush()
first = f.readline().rstrip(b"\r\n")
print("FIRST", first.decode(errors="replace")[:5])
# A refusal leaves this an ordinary client connection, so the next commands are
# still answered.  A promotion would have made the socket a replication stream
# with this runtime as its only writer, and these would return the dump, the
# "commands are not accepted" line, or nothing at all.
#
# Line protocol and not RESP: the first byte this connection sent was "r", so
# it was detected as a line client and stays one.
f.write(b"set after-replicate still-a-client\n"); f.flush()
f.readline()
f.write(b"get after-replicate\n"); f.flush()
print("AFTER", f.readline().rstrip(b"\r\n").decode(errors="replace"))
tls.close()
PYEOF
) || true
assert_eq "$(echo "$REPL_ANSWER" | grep '^FIRST' | cut -d' ' -f2-)" "error" \
    "REPLICATE on a TLS cache is refused rather than promoting it to leader"
assert_eq "$(echo "$REPL_ANSWER" | grep '^AFTER' | cut -d' ' -f2-)" "still-a-client" \
    "a refused REPLICATE leaves the connection an ordinary client"

# (d) ...and none of this broke replication for a cleartext cache, which is the
#     configuration every existing deployment is running.
#
#     These two are regression guards and not oracles for this feature: they
#     pass against a binary without it, by design, because what they assert is
#     that nothing changed for a cache that never asked for TLS.  Every other
#     assertion in this file fails against such a binary.
rc_of "$BIN" create cache plainleader -p "$FOLLOWER_PORT" -s >/dev/null
assert_ok "$(rc_of ready_resp 127.0.0.1 "$FOLLOWER_PORT" 15)" \
    "regression guard: a cleartext cache comes up"

PLAIN_REPL=$(python3 - "$FOLLOWER_PORT" 2>/dev/null <<'PYEOF'
import socket, sys
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=8)
f = s.makefile("rwb")
f.write(b"replicate\n"); f.flush()
print(f.readline().rstrip(b"\r\n").decode(errors="replace"))
s.close()
PYEOF
) || true
assert_eq "$PLAIN_REPL" "ok" \
    "regression guard: REPLICATE on a cleartext cache still promotes it to leader"

rc_of "$BIN" stop tlscache tlsline tlsmtls tlsleader plainleader >/dev/null
sleep 0.3
rc_of "$BIN" remove tlscache tlsline tlsmtls tlsleader plainleader >/dev/null

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
