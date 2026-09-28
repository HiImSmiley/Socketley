#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# A client that encrypts and trusts anybody looks exactly like one that
# encrypts and checks, right up until somebody stands in the middle, so most of
# what is asserted here are refusals -- an unknown CA, an expired certificate,
# a chain that verifies under the wrong name, a self-signed peer against the
# system store, a plaintext peer -- with two controls in front, since four
# silences prove nothing if the fifth case is silent too, plus the peer's log
# showing no refusal ever delivered anything, the configuration gate, and a
# cache still refusing TLS outright.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"

TMPD=$(mktemp -d /tmp/socketley-clienttls-XXXXXX)
export HOME="$TMPD/home"
export SOCKETLEY_SOCKET="$TMPD/daemon.sock"
. "$(dirname "$0")/lib_daemon.sh"
daemon_watch "$TMPD"   # its processes go with it if it is killed
mkdir -p "$HOME"

PEER=$((SL_PORT_BASE+781))
DPID=""; PEERPID=""
PASS=0; FAIL=0; TOTAL=0

NAMES="tok tplain tbadca texpired tbadname tnoca tcleartext"

cleanup() {
    for n in $NAMES tudp tudp2 tcache thalf1 thalf2 tnotls; do
        "$BIN" stop "$n" >/dev/null 2>&1 || true
        "$BIN" remove "$n" >/dev/null 2>&1 || true
    done
    [ -n "$PEERPID" ] && kill "$PEERPID" 2>/dev/null
    if [ -n "$DPID" ]; then
        kill "$DPID" 2>/dev/null || true
        for _ in $(seq 1 50); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.1; done
        kill -9 "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
    # Matched on the environment rather than the command line, because a -f
    # pattern also matches the shell carrying it, and the socket path comes
    # from mktemp so this can only hit our own.
    for p in $(pgrep -x socketley 2>/dev/null || true); do
        if grep -qx "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" \
                < <(tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null); then
            kill -9 "$p" 2>/dev/null || true
        fi
    done
    rm -rf "$TMPD"
}
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a client dials TLS and verifies the peer ==="

if ! command -v python3 >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    echo "  SKIP: python3 and openssl are both required"; exit 0
fi
if ! python3 -c "import ssl" >/dev/null 2>&1; then
    echo "  SKIP: python3 has no ssl module"; exit 0
fi

# Four certificates, each isolating one reason to refuse -- with the wrong-name
# one handed over as the CA too, so the chain verifies and only the name check
# can reject it, which is the case a chain-only check passes.
gen() {  # $1 = base, $2 = CN, $3 = SAN, $4... = extra openssl args
    local base=$1 cn=$2 san=$3; shift 3
    openssl req -x509 -newkey rsa:2048 -keyout "$TMPD/$base.key" -out "$TMPD/$base.pem" \
        -nodes -subj "/CN=$cn" -addext "subjectAltName=$san" "$@" >/dev/null 2>&1
}
gen peer    127.0.0.1        "IP:127.0.0.1"        -days 2 \
  || { echo "  SKIP: could not generate a test certificate"; exit 0; }
gen other   unrelated        "DNS:unrelated"       -days 2 \
  || { echo "  SKIP: could not generate a test certificate"; exit 0; }
gen wrong   elsewhere.example "DNS:elsewhere.example" -days 2 \
  || { echo "  SKIP: could not generate a test certificate"; exit 0; }
# An expired certificate needs an explicit window in the past, which `openssl
# req -x509` grew only in 3.5, so python mints it where installed and the case
# is skipped rather than silently turned into a valid certificate.
HAVE_EXPIRED=0
if openssl req -x509 -newkey rsa:2048 -keyout "$TMPD/expired.key" \
        -out "$TMPD/expired.pem" -nodes -subj "/CN=127.0.0.1" \
        -addext "subjectAltName=IP:127.0.0.1" \
        -not_before 20200101000000Z -not_after 20200201000000Z >/dev/null 2>&1; then
    HAVE_EXPIRED=1
elif python3 - "$TMPD/expired.pem" "$TMPD/expired.key" <<'PYEOF' >/dev/null 2>&1
import datetime, ipaddress, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
cert = (x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2020, 2, 1))
        .add_extension(x509.SubjectAlternativeName(
            [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256()))
open(sys.argv[1], "wb").write(cert.public_bytes(serialization.Encoding.PEM))
open(sys.argv[2], "wb").write(key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption()))
PYEOF
then
    HAVE_EXPIRED=1
fi

# The peer speaks TLS when given a certificate and plaintext when not, logging
# one line per application message, which is the log the refusals below are
# checked against.
cat > "$TMPD/peer.py" <<'PYEOF'
import socket, ssl, sys, threading

port = int(sys.argv[1])
mode = sys.argv[2]          # "tls" or "plain"
ctx = None
if mode == "tls":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(sys.argv[3], sys.argv[4])

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(32)
print("ready", flush=True)


def serve(raw):
    c = raw
    if ctx is not None:
        try:
            c = ctx.wrap_socket(raw, server_side=True)
        except Exception as e:
            # Expected for every rejected case: the client walks away
            # mid-handshake rather than talking to us.
            print(f"handshake-rejected {type(e).__name__}", flush=True)
            try:
                raw.close()
            except OSError:
                pass
            return
    else:
        # A cleartext peer facing a TLS client sees a ClientHello where a line
        # belonged.  Log the first bytes so the test can tell a record from a
        # message -- 0x16 0x03 is a TLS handshake record.
        try:
            head = c.recv(8, socket.MSG_PEEK)
            if head[:1] == b"\x16":
                print("saw-tls-record", flush=True)
        except OSError:
            pass
    try:
        buf = b""
        while True:
            d = c.recv(65536)
            if not d:
                break
            buf += d
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.rstrip(b"\r")
                if not line:
                    continue
                print(f"got {line.decode('latin1')}", flush=True)
                try:
                    c.sendall(b"echo-" + line + b"\n")
                except OSError:
                    return
    except (OSError, ssl.SSLError):
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

start_peer() {   # $1 = log, $2 = mode, $3 = cert, $4 = key
    [ -n "$PEERPID" ] && { kill "$PEERPID" 2>/dev/null; wait "$PEERPID" 2>/dev/null; }
    python3 "$TMPD/peer.py" "$PEER" "$2" "${3:-}" "${4:-}" >"$1" 2>&1 &
    PEERPID=$!
    for _ in $(seq 1 60); do grep -q ready "$1" 2>/dev/null && break; sleep 0.1; done
}

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

start_peer "$TMPD/peer.log" tls "$TMPD/peer.pem" "$TMPD/peer.key"

"$BIN" daemon >"$TMPD/daemon.log" 2>&1 &
DPID=$!
python3 "$TMPD/waitsock.py" "$SOCKETLEY_SOCKET" 8 >/dev/null 2>&1 || true

# Create a client, start it, send one line, and report whether the peer
# received it as application data.
delivered() {   # $1 = name, $2 = marker, $3... = create flags
    local name=$1 marker=$2; shift 2
    "$BIN" create client "$name" -t "127.0.0.1:$PEER" "$@" -s >/dev/null 2>&1
    # Give the dial, the handshake and the send room without pinning a deadline
    # to the wall clock: poll for the answer instead.
    for _ in $(seq 1 40); do
        "$BIN" send "$name" "$marker" >/dev/null 2>&1
        grep -q "^got $marker\$" "$TMPD"/peer*.log 2>/dev/null && { echo yes; return; }
        sleep 0.1
    done
    echo no
}

# ── 1. control: the CA that signed the peer ──────────────────────────────────
R=$(delivered tok m-1 --tls --ca "$TMPD/peer.pem")
if [ "$R" = "yes" ]; then
    ok
else
    bad "control: a verified TLS peer receives the message" \
        "the message never arrived -- every refusal below would then pass for the wrong reason"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit "$FAIL"
fi

# ── 2. control: it was --tls that did it ─────────────────────────────────────
# The same peer without --tls delivers nothing, which is what says case 1 went
# through the record layer rather than past it.
R=$(delivered tplain m-2)
if [ "$R" = "no" ]; then ok; else
    bad "a cleartext client gets nothing from a TLS peer" \
        "the peer accepted a plaintext line, so case 1 proves nothing about TLS"
fi

# ── 3. a CA that signed nothing here ─────────────────────────────────────────
R=$(delivered tbadca m-3 --tls --ca "$TMPD/other.pem")
if [ "$R" = "no" ]; then ok; else
    bad "a peer signed by an untrusted CA is refused" \
        "the message was delivered over a chain no configured CA signed"
fi

# ── 4. an expired certificate ────────────────────────────────────────────────
if [ "$HAVE_EXPIRED" = "1" ]; then
    start_peer "$TMPD/peer_exp.log" tls "$TMPD/expired.pem" "$TMPD/expired.key"
    R=$(delivered texpired m-4 --tls --ca "$TMPD/expired.pem")
    if [ "$R" = "no" ]; then ok; else
        bad "an expired certificate is refused" \
            "the message was delivered to a peer whose certificate expired in 2020"
    fi
else
    echo "  SKIP: neither openssl nor python could mint an expired certificate"
fi

# The peer's certificate for another name is handed to the client as its CA, so
# verification is satisfied and only the name check stands between this and a
# connection to whoever holds that key.
start_peer "$TMPD/peer_wrong.log" tls "$TMPD/wrong.pem" "$TMPD/wrong.key"
R=$(delivered tbadname m-5 --tls --ca "$TMPD/wrong.pem")
if [ "$R" = "no" ]; then ok; else
    bad "a certificate issued to another name is refused" \
        "the chain verified, so only the name check could have caught this -- and it did not"
fi

# ── 6. no --ca: the system store, which holds no self-signed peer ────────────
start_peer "$TMPD/peer2.log" tls "$TMPD/peer.pem" "$TMPD/peer.key"
R=$(delivered tnoca m-6 --tls)
if [ "$R" = "no" ]; then ok; else
    bad "a self-signed peer is refused against the system store" \
        "--tls with no --ca accepted a certificate the system store cannot chain"
fi

# ── 7. a plaintext peer, and no fallback ─────────────────────────────────────
start_peer "$TMPD/peer_plain.log" plain
R=$(delivered tcleartext m-7 --tls --ca "$TMPD/peer.pem")
if [ "$R" = "no" ]; then ok; else
    bad "a TLS client never falls back to cleartext" \
        "the peer received the message in the clear from a client configured with --tls"
fi
# and the peer saw a record, not a line: the client really did offer TLS rather
# than failing before it dialled.
if grep -q "saw-tls-record" "$TMPD/peer_plain.log" 2>/dev/null; then ok; else
    bad "the TLS client offered a handshake to the plaintext peer" \
        "no TLS record reached the peer, so case 7 may have passed by never connecting"
fi

# Every refusal above ends during the handshake, so any that had fallen back to
# cleartext or verified nothing would have left its marker in the peer's log.
if grep -qE "^got m-[234567]\$" "$TMPD"/peer*.log 2>/dev/null; then
    bad "a refused peer is never talked to anyway" \
        "the peer logged application data from a configuration that failed verification"
else
    ok
fi

# ── 9. the configuration gate ────────────────────────────────────────────────
# Each of these could only present nothing, verify nothing, or dial in the
# clear, so they are refused where they are typed.
"$BIN" create client thalf1 -t "127.0.0.1:$PEER" --tls --cert "$TMPD/peer.pem" >/dev/null 2>&1
if [ $? -ne 0 ]; then ok; else bad "--cert without --key is refused" "it was accepted"; fi
"$BIN" create client thalf2 -t "127.0.0.1:$PEER" --tls --key "$TMPD/peer.key" >/dev/null 2>&1
if [ $? -ne 0 ]; then ok; else bad "--key without --cert is refused" "it was accepted"; fi
"$BIN" create client tnotls -t "127.0.0.1:$PEER" --ca "$TMPD/peer.pem" >/dev/null 2>&1
if [ $? -ne 0 ]; then ok; else bad "--ca without --tls is refused" "it was accepted"; fi

# --tls on a UDP client would need DTLS and the flags are accepted in either
# order, so it is caught at start and asked both ways -- with the exit code
# asserted and the absence asked of `ls` as well, because the old oracle rested
# on a `ps` check that any failed create satisfies.
"$BIN" create client tudp -t "127.0.0.1:$PEER" --udp --tls -s >/dev/null 2>&1
CREATE_RC=$?
sleep 0.5
LISTED=$("$BIN" ps -a 2>/dev/null; "$BIN" ls 2>/dev/null)
if [ $CREATE_RC -ne 0 ] && ! printf '%s\n' "$LISTED" | grep -q "tudp"; then ok; else
    bad "--tls on a UDP client is refused where it is started" \
        "a UDP client came up under a TLS configuration and is sending datagrams in the clear"
fi

# Without -s the create itself is refused, because the rule is a question about
# two flags that needs no socket to answer and moved to tls_config_refusal --
# while the property the old assertion also covered, a runtime whose start
# fails staying visible and failed, is held down by test_ps_failed_visible.sh.
"$BIN" create client tudp2 -t "127.0.0.1:$PEER" --udp --tls >/dev/null 2>&1
CREATE2_RC=$?
sleep 0.3
if [ $CREATE2_RC -ne 0 ] \
   && ! "$BIN" ps -a 2>/dev/null | grep -q "tudp2"; then
    ok
else
    bad "--tls on a UDP client is refused at create, leaving nothing behind" \
        "$("$BIN" ps -a 2>/dev/null | tr '\n' '|')"
fi

# ── 10. a cache still refuses TLS ────────────────────────────────────────────
"$BIN" create cache tcache -p $((SL_PORT_BASE+782)) --tls >/dev/null 2>&1
if [ $? -ne 0 ]; then ok; else
    bad "a cache still refuses TLS" \
        "a cache accepted --tls and would listen in cleartext on a port reported as encrypted"
fi

if kill -0 "$DPID" 2>/dev/null; then ok; else bad "daemon alive" "the daemon died"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
