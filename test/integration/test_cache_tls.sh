#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# TLS on a cache listener: a real handshake with RESP and the line protocol
# over the encrypted stream, no downgrade for a plaintext client, mutual TLS,
# aborts that do not accumulate, every incomplete flag set refused rather than
# falling back to cleartext, and replication refused at create, at restore and
# at the REPLICATE command -- with every probe printing one token per claim, so
# an empty answer can only mean the probe never ran and a timeout is reported
# as not measurable rather than as the cache answering wrongly.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# shellcheck source=lib_ready.sh
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0; HERR=0; TOTAL=0

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

# Own daemon, socket and state directory, because this test misconfigures
# runtimes and restarts the daemon to reach the restore path.
TMPDIR_T=$(mktemp -d /tmp/socketley-cachetls-XXXXXX)
export HOME="$TMPDIR_T/home"
export SOCKETLEY_SOCKET="$TMPDIR_T/daemon.sock"
. "$(dirname "$0")/lib_daemon.sh"
daemon_watch "$TMPDIR_T"   # its processes go with it if it is killed
mkdir -p "$HOME"
DPID=""

# Where this daemon's state actually lives, found rather than constructed,
# because a keyed socket gives a keyed state directory and a copy of that rule
# here would go stale.
state_dir() {
    local base="$HOME/.local/share/socketley" d
    for d in "$base"/runtimes.*; do
        [ -d "$d" ] && { printf '%s\n' "$d"; return 0; }
    done
    printf '%s\n' "$base/runtimes"
}

TLS_PORT=$((SL_PORT_BASE+741))
LINE_PORT=$((SL_PORT_BASE+742))
MTLS_PORT=$((SL_PORT_BASE+743))
BAD_PORT=$((SL_PORT_BASE+744))
LEADER_PORT=$((SL_PORT_BASE+745))
FOLLOWER_PORT=$((SL_PORT_BASE+746))

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

# A claim this run was unable to put the question to, kept apart from a failure
# and counted separately, though both end the run non-zero.
herr() {
    local label=$1 reason=$2; shift 2
    TOTAL=$((TOTAL+1)); HERR=$((HERR+1))
    echo "  NOT MEASURABLE [$label]: $reason"
    local line
    for line in "$@"; do echo "        $line"; done
}

# True for the tokens that mean the client's budget ran out and no others, as
# an explicit list so a token added later is classified deliberately and
# defaults to the strict side.
unmeasurable_token() {   # value
    case "$1" in
        '<connect-timeout>'|'<handshake-timeout>'|'<stalled>') return 0 ;;
        *) return 1 ;;
    esac
}

# Everything a probe said, printed only beside an assertion that did not pass,
# with stderr included because a probe that died has a traceback and that is
# the only place the reason lives.
probe_said() {   # file
    local n
    n=$(wc -l <"$1" 2>/dev/null || echo 0)
    if [ "$n" -eq 0 ]; then
        echo "        --- the probe printed nothing at all, on either stream ---"
        return
    fi
    echo "        --- what the probe said ---"
    sed 's/^/        /' "$1" 2>/dev/null || true
}

# assert_eq with the three things a probe can produce kept apart, where the
# empty string is its own failure because no path prints it and it can only
# mean python3 never got as far as printing.
assert_probe() {
    local got="$1" expected="$2" label="$3" file="${4:-}"
    if [ -z "$got" ]; then
        TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
        echo "  FAIL [$label]: the probe printed no token at all, so it never ran --"
        echo "        no python3, or it died before reaching its own handler.  Every path"
        echo "        that completes prints something, so this is not the cache answering"
        echo "        wrongly and it is not a missed timeout either."
        [ -n "$file" ] && probe_said "$file"
        return
    fi
    if unmeasurable_token "$got"; then
        herr "$label" "the probe answered $got, wanted '$expected'" \
            "The client's own budget ran out before the cache had answered.  On a" \
            "quiet box the handshake here takes 0.01s and this never fires; under" \
            "foreign load it does.  Nothing in this says the build misbehaved --" \
            "it says this run could not put the question.  Check what else was" \
            "running, and re-run alone."
        return
    fi
    TOTAL=$((TOTAL+1))
    if [ "$got" = "$expected" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]:"
        echo "        expected: '$expected'"
        echo "        got:      '$got'"
        [ -n "$file" ] && probe_said "$file"
    fi
}

# The marked line a probe printed for one claim, head -1 because a probe
# settles unreached markers at the end and an answered one must not be read
# twice.
marker() {   # file marker
    grep "^$2 " "$1" 2>/dev/null | head -1 | cut -d' ' -f2- || true
}

# Run a command and echo its exit status, because much of this file is about
# commands that are supposed to fail and `set -e` would end the run first.
rc_of() {
    local rc=0
    "$@" >"$TMPDIR_T/last-cmd.log" 2>&1 || rc=$?
    echo "$rc"
}

# Whether the last rc_of output contained this text, because most refusals
# below are also refused by a binary without this feature and the reason is the
# assertion rather than the status.
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

# ── the probes' shared vocabulary ───────────────────────────────────────────
# Written once and imported through PYTHONPATH rather than pasted into eight
# heredocs that would drift apart.
cat >"$TMPDIR_T/cachetls_probe.py" <<'PYEOF'
"""The words every probe in test_cache_tls.sh answers in.

Two rules, and everything here exists to keep them:

  * a probe owes the shell one marked line per claim it was going to answer,
    and pays anything it did not reach with a token naming why.  The empty
    string is then printed by no path at all, so it can mean the one thing it
    actually means -- python3 never ran.
  * a token names an OBSERVATION and nothing more.  Whether <stalled> is a
    defect or a loaded machine is the shell's judgement, not this module's, and
    it is written down there.
"""
import socket
import ssl


class Owed:
    """The markers a probe owes, and what it pays the unreached ones with.

    say() answers one; settle() pays the rest.  A marker answered twice would
    make the shell read the first line and ignore the second, which is why say()
    strikes it off rather than leaving it to be settled again at the end.
    """

    def __init__(self, *markers):
        self._owed = list(markers)

    def say(self, marker, value):
        print(marker, value, flush=True)
        if marker in self._owed:
            self._owed.remove(marker)

    def settle(self, token):
        for m in self._owed:
            print(m, token, flush=True)
        self._owed = []


def dial(port, timeout, host="127.0.0.1"):
    """(socket, None), or (None, token) naming why there is no socket.

    A refused connect and a connect that timed out are deliberately different
    tokens: the first says nothing is bound there, which is an answer, and the
    second says this client gave up, which is not.
    """
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except ConnectionRefusedError:
        return None, "<no-listener>"
    except (socket.timeout, TimeoutError):
        return None, "<connect-timeout>"
    except OSError as e:
        return None, "<error:connect-%s>" % (e.__class__.__name__,)
    s.settimeout(timeout)
    return s, None


def handshake(raw, cafile, servername="localhost", client=None, verify=True):
    """(tls socket, None), or (None, token) naming why there is no session.

    The timeout clause comes first on purpose.  socket.timeout IS TimeoutError
    on this python and both are subclasses of OSError, as is ssl.SSLError, so a
    handshake that ran out of budget would otherwise be caught by a later clause
    and reported as the listener refusing it -- which is the whole confusion
    this file is being repaired for.
    """
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.check_hostname = verify
    if not verify:
        ctx.verify_mode = ssl.CERT_NONE
    if client:
        ctx.load_cert_chain(client[0], client[1])
    try:
        return ctx.wrap_socket(raw, server_hostname=servername), None
    except (socket.timeout, TimeoutError):
        return None, "<handshake-timeout>"
    except (ssl.SSLZeroReturnError, ssl.SSLEOFError,
            ConnectionResetError, BrokenPipeError):
        return None, "<dropped>"
    except ssl.SSLError:
        return None, "<handshake-failed>"
    except OSError as e:
        return None, "<error:handshake-%s>" % (e.__class__.__name__,)


def session(port, cafile, timeout, servername="localhost", client=None):
    """dial + handshake in one: (tls, None) or (None, token)."""
    raw, tok = dial(port, timeout)
    if tok:
        return None, tok
    tls, tok = handshake(raw, cafile, servername, client)
    if tok:
        try:
            raw.close()
        except OSError:
            pass
        return None, tok
    return tls, None


def read_token(exc):
    """The token for an exception raised on an established session.

    Timeout first, for the same reason as above.
    """
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "<stalled>"
    if isinstance(exc, (ssl.SSLZeroReturnError, ssl.SSLEOFError,
                        ConnectionResetError, BrokenPipeError)):
        return "<dropped>"
    return "<error:%s>" % (exc.__class__.__name__,)


def text_or_blank(data):
    """A reply as text, or <dropped>/<blank-reply>.

    An empty read means the peer hung up with an answer owed; bytes that strip
    to nothing are a different thing and are not folded into it.
    """
    if not data:
        return "<dropped>"
    text = (data.decode(errors="replace") if isinstance(data, bytes) else data).strip()
    return text if text else "<blank-reply>"


def shut(*socks):
    for s in socks:
        try:
            s.close()
        except OSError:
            pass
PYEOF
# Every probe below imports it by name; nothing else on this box is called
# cachetls_probe, and the directory is one mktemp made for this run.
export PYTHONPATH="$TMPDIR_T"

# ── certificates ────────────────────────────────────────────────────────────
# A self-signed leaf for the listener and a one-level CA that signs a client
# certificate, all expiring tomorrow in a directory the trap removes.
CERTS="$TMPDIR_T/certs"
mkdir -p "$CERTS"

# Each guarded so the SKIP below is reachable, because under `set -e` a failed
# openssl ended the file before the message explaining it could print.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$CERTS/cache-key.pem" -out "$CERTS/cache.pem" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 || true

# A second key never paired with any certificate, to prove that a key which
# does not match is refused rather than accepted.
openssl genrsa -out "$CERTS/other-key.pem" 2048 >/dev/null 2>&1 || true

openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$CERTS/ca-key.pem" -out "$CERTS/ca.pem" \
    -subj "/CN=socketley-cache-test-ca" >/dev/null 2>&1 || true
openssl req -newkey rsa:2048 -nodes \
    -keyout "$CERTS/client-key.pem" -out "$CERTS/client.csr" \
    -subj "/CN=test-client" >/dev/null 2>&1 || true
openssl x509 -req -in "$CERTS/client.csr" -days 2 \
    -CA "$CERTS/ca.pem" -CAkey "$CERTS/ca-key.pem" -CAcreateserial \
    -out "$CERTS/client.pem" >/dev/null 2>&1 || true

if [ ! -s "$CERTS/cache.pem" ] || [ ! -s "$CERTS/client.pem" ]; then
    echo "  SKIP: openssl could not generate the test certificates"
    exit 0
fi

if ! start_daemon; then
    echo "  FAIL [setup]: daemon did not come up"
    exit 1
fi

# The seventh field of `ls` is the status, because CREATED is several words --
# with `|| true` so a failed `ls` does not end the file at the assignment
# rather than at the assertion.
state_of() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2==n {print tolower($7)}' || true; }

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

# One client and one session, with values chosen so a shift or truncation in
# the BIO plumbing is visible and one large enough to span several records.
python3 - "$TLS_PORT" "$CERTS/cache.pem" > "$TMPDIR_T/resp.out" 2>&1 <<'PYEOF' || true
import sys
from cachetls_probe import Owed, read_token, session, shut

port, cafile = int(sys.argv[1]), sys.argv[2]
values = {
    "k1": "012345",
    "k2": "0123456789",
    "k3": '{"type":"chat","text":"hi"}',
    "k4": "".join(str(i % 10) for i in range(20000)),   # spans many records
}

# The four claims this probe owes an answer to.  Anything it does not reach is
# paid with the token naming why, so no assertion below can read an empty value
# unless python3 itself never ran.
owed = Owed("VERSION", "CIPHER", "ROUNDTRIP", "PING")


def cmd(*parts):
    out = f"*{len(parts)}\r\n".encode()
    for p in parts:
        b = p.encode()
        out += b"$" + str(len(b)).encode() + b"\r\n" + b + b"\r\n"
    return out


tls, tok = session(port, cafile, 10)
if tok:
    owed.settle(tok)
    sys.exit(0)

try:
    owed.say("VERSION", tls.version())
    owed.say("CIPHER", tls.cipher()[0] if tls.cipher() else "<blank-reply>")

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
    owed.say("ROUNDTRIP", "yes" if ok else "no")

    # PING on the same session, after the large value, so a record layer that
    # desynchronised on a multi-record write shows up here rather than silently.
    f.write(cmd("PING")); f.flush()
    owed.say("PING", line().decode(errors="replace") or "<dropped>")
except Exception as e:            # noqa: BLE001 -- every path owes an answer
    owed.settle(read_token(e))
finally:
    owed.settle("<error:no-answer>")
    shut(tls)
PYEOF

TLS_VERSION=$(marker "$TMPDIR_T/resp.out" VERSION)
TLS_CIPHER=$(marker "$TMPDIR_T/resp.out" CIPHER)
ROUNDTRIP=$(marker "$TMPDIR_T/resp.out" ROUNDTRIP)
PINGED=$(marker "$TMPDIR_T/resp.out" PING)

# Not assert_probe, because the expectation is a set of two acceptable answers
# rather than one string.
if [ -z "$TLS_VERSION" ]; then
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [negotiated TLS version]: the probe printed no token at all, so it never ran"
    probe_said "$TMPDIR_T/resp.out"
elif unmeasurable_token "$TLS_VERSION"; then
    herr "negotiated TLS version" "the probe answered $TLS_VERSION" \
        "The handshake did not finish inside the client's 10s budget.  That is" \
        "this run failing to put the question, not the listener refusing."
else
    TOTAL=$((TOTAL+1))
    case "$TLS_VERSION" in
        TLSv1.2|TLSv1.3) PASS=$((PASS+1)) ;;
        *) FAIL=$((FAIL+1)); echo "  FAIL [negotiated TLS version]: got '$TLS_VERSION'"
           probe_said "$TMPDIR_T/resp.out" ;;
    esac
fi

# The claim is that the answer is not a token, because a non-empty check passes
# on '<handshake-timeout>' as readily as on a cipher name.
if [ -z "$TLS_CIPHER" ]; then
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [a cipher was negotiated]: the probe printed no token at all, so it never ran"
    probe_said "$TMPDIR_T/resp.out"
elif unmeasurable_token "$TLS_CIPHER"; then
    herr "a cipher was negotiated" "the probe answered $TLS_CIPHER" \
        "The handshake did not finish inside the client's 10s budget."
else
    TOTAL=$((TOTAL+1))
    case "$TLS_CIPHER" in
        '<'*'>') FAIL=$((FAIL+1))
                 echo "  FAIL [a cipher was negotiated]: got '$TLS_CIPHER'"
                 probe_said "$TMPDIR_T/resp.out" ;;
        *)       PASS=$((PASS+1)) ;;
    esac
fi

assert_probe "$ROUNDTRIP" "yes" "RESP over TLS: every value comes back byte for byte" \
    "$TMPDIR_T/resp.out"
assert_probe "$PINGED" "+PONG"  "RESP over TLS: the session is still framed after a 20KB value" \
    "$TMPDIR_T/resp.out"

# ─────────────────────────────────────────────────────────────────────────────
# 2. The line protocol on a TLS listener
# ─────────────────────────────────────────────────────────────────────────────
# RESP is auto-detected from the first decrypted byte, so a listener feeding
# detection ciphertext would decide from the first byte of a ClientHello.
assert_eq "$(rc_of "$BIN" create cache tlsline -p "$LINE_PORT" \
    --tls --cert "$CERTS/cache.pem" --key "$CERTS/cache-key.pem" -s)" "0" \
    "create a second TLS cache for the line protocol"

assert_ok "$(rc_of ready_tls 127.0.0.1 "$LINE_PORT" "$CERTS/cache.pem" localhost 20)" \
    "line-protocol TLS cache completes a handshake"

python3 - "$LINE_PORT" "$CERTS/cache.pem" >"$TMPDIR_T/line.out" 2>&1 <<'PYEOF' || true
import sys
from cachetls_probe import Owed, read_token, session, shut, text_or_blank

port, cafile = int(sys.argv[1]), sys.argv[2]
owed = Owed("LINE")

tls, tok = session(port, cafile, 8)
if tok:
    owed.settle(tok)
    sys.exit(0)

try:
    f = tls.makefile("rwb")
    f.write(b"set line-key line-value\n"); f.flush()
    f.readline()
    f.write(b"get line-key\n"); f.flush()
    owed.say("LINE", text_or_blank(f.readline().rstrip(b"\r\n")))
except Exception as e:            # noqa: BLE001
    owed.settle(read_token(e))
finally:
    owed.settle("<error:no-answer>")
    shut(tls)
PYEOF
assert_probe "$(marker "$TMPDIR_T/line.out" LINE)" "line-value" \
    "line protocol works on the decrypted stream" "$TMPDIR_T/line.out"

# ─────────────────────────────────────────────────────────────────────────────
# 3. No downgrade: a plaintext client is refused, not served and not hung
# ─────────────────────────────────────────────────────────────────────────────
# A perfectly good RESP SET is not a TLS record, so the handshake fails and
# both halves are asserted: the client is told rather than left hanging, and
# the command is never executed.
python3 - "$TLS_PORT" >"$TMPDIR_T/plain.out" 2>&1 <<'PYEOF' || true
import socket
import sys
from cachetls_probe import Owed, dial, read_token, shut

port = int(sys.argv[1])
owed = Owed("CLOSED", "REPLY")

s, tok = dial(port, 5)
if tok:
    owed.settle(tok)
    sys.exit(0)

try:
    s.sendall(b"*3\r\n$3\r\nSET\r\n$9\r\nplainkey\x31\r\n$10\r\nplainvalue\r\n")
    data = s.recv(4096)
    # An alert, or a clean EOF.  Either is the listener refusing; what must not
    # happen is "+OK", and what must not happen is nothing at all.
    owed.say("CLOSED", "yes" if data == b"" or data[:1] == b"\x15" else "no")
    owed.say("REPLY", repr(data[:16]))
except (socket.timeout, TimeoutError):
    # Accepted, still open, nothing said.  <stalled> rather than a verdict of
    # its own: see the header.  A listener that really hangs produces this every
    # run for ever; a box too busy to answer in five seconds produces it once.
    owed.settle("<stalled>")
except (ConnectionResetError, BrokenPipeError):
    # A reset is the listener refusing, exactly as a clean EOF is, and it is what
    # the assertion is asking for.  It is NOT <dropped>: the claim here is that
    # nothing comes back, and a reset is that.  This was the OSError arm of the
    # original probe and it stays a positive answer.
    owed.say("CLOSED", "yes")
    owed.say("REPLY", "b''")
except Exception as e:            # noqa: BLE001
    owed.settle(read_token(e))
finally:
    owed.settle("<error:no-answer>")
    shut(s)
PYEOF
assert_probe "$(marker "$TMPDIR_T/plain.out" CLOSED)" "yes" \
    "a plaintext client on a TLS cache port is refused rather than left hanging" \
    "$TMPDIR_T/plain.out"

# The SET it sent never happened, read back through a real session, as one
# verdict because two empty lookups agree on a dead port too.
python3 - "$TLS_PORT" "$CERTS/cache.pem" >"$TMPDIR_T/miss.out" 2>&1 <<'PYEOF' || true
import sys
from cachetls_probe import Owed, read_token, session, shut

port, cafile = int(sys.argv[1]), sys.argv[2]
owed = Owed("VERDICT")


def cmd(*parts):
    out = f"*{len(parts)}\r\n".encode()
    for p in parts:
        b = p.encode()
        out += b"$" + str(len(b)).encode() + b"\r\n" + b + b"\r\n"
    return out


# This is the probe whose death was reported as `expected: 'not-executed'
# got: ''`.  It dies here, on the handshake, and the reason is now a token
# rather than a traceback on a stream nobody was reading.
tls, tok = session(port, cafile, 8)
if tok:
    owed.settle(tok)
    sys.exit(0)

try:
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
    # A live session (k1 reads back), the plaintext client's key a miss, and a
    # miss spelled the same way as one for a key nobody ever mentioned.
    if known == b"012345" and plain is None and never is None:
        owed.say("VERDICT", "not-executed")
    else:
        owed.say("VERDICT", "known=%r plain=%r never=%r" % (known, plain, never))
except Exception as e:            # noqa: BLE001
    owed.settle(read_token(e))
finally:
    owed.settle("<error:no-answer>")
    shut(tls)
PYEOF
assert_probe "$(marker "$TMPDIR_T/miss.out" VERDICT)" "not-executed" \
    "the plaintext client's command is never executed" "$TMPDIR_T/miss.out"

# ─────────────────────────────────────────────────────────────────────────────
# 4. Mutual TLS
# ─────────────────────────────────────────────────────────────────────────────
assert_eq "$(rc_of "$BIN" create cache tlsmtls -p "$MTLS_PORT" \
    --tls --cert "$CERTS/cache.pem" --key "$CERTS/cache-key.pem" \
    --ca "$CERTS/ca.pem" -s)" "0" "create cache with --ca (mutual TLS) succeeds"

ready_tcp 127.0.0.1 "$MTLS_PORT" 10 || true

python3 - "$MTLS_PORT" "$CERTS" >"$TMPDIR_T/mtls.out" 2>&1 <<'PYEOF' || true
import socket
import ssl
import sys
import time
from cachetls_probe import Owed, dial, handshake, shut

port, certs = int(sys.argv[1]), sys.argv[2]
owed = Owed("WITHCERT", "NOCERT")

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
#
# A FOURTH OUTCOME, and it is the repair.  This used to end
# `except Exception: return "rejected"`, which is also what a handshake that ran
# out of its six-second budget raises -- socket.timeout is TimeoutError is an
# OSError on this python, and so is ssl.SSLError.  So a NOCERT probe that never
# got an answer at all returned the very string the assertion below wants, and
# passed.  An assertion satisfied by the probe failing is not an assertion.
# dial() and handshake() split the timeouts out by name before anything else
# can claim them.
def attempt(with_cert):
    client = (f"{certs}/client.pem", f"{certs}/client-key.pem") if with_cert else None
    raw, tok = dial(port, 6)
    if tok:
        return tok
    tls, tok = handshake(raw, f"{certs}/cache.pem", "localhost", client)
    if tok:
        shut(raw)
        # A handshake the listener refused IS the rejection this test is looking
        # for, and it is what TLS 1.2 produces; a handshake that timed out is
        # not, and now says so.
        return "rejected" if tok in ("<handshake-failed>", "<dropped>") else tok
    try:
        tls.settimeout(3)
        tls.sendall(b"*1\r\n$4\r\nPING\r\n")
        return "accepted" if tls.recv(64).startswith(b"+PONG") else "rejected"
    except (socket.timeout, TimeoutError):
        return "<stalled>"        # the session came up and then said nothing
    except (ssl.SSLError, OSError):
        return "rejected"         # fatal alert or reset: the listener refusing
    finally:
        shut(tls)


deadline = time.time() + 20
with_ = "<no-listener>"
while time.time() < deadline:
    with_ = attempt(True)
    if with_ == "accepted":
        break
    time.sleep(0.2)
owed.say("WITHCERT", with_)
owed.say("NOCERT", attempt(False))
owed.settle("<error:no-answer>")
PYEOF
assert_probe "$(marker "$TMPDIR_T/mtls.out" WITHCERT)" "accepted" \
    "mTLS: a client certificate signed by --ca is accepted, and RESP answers" \
    "$TMPDIR_T/mtls.out"
assert_probe "$(marker "$TMPDIR_T/mtls.out" NOCERT)" "rejected" \
    "mTLS: a client with no certificate is rejected by the listener" \
    "$TMPDIR_T/mtls.out"

# ─────────────────────────────────────────────────────────────────────────────
# 5. Clients that abort mid-handshake
# ─────────────────────────────────────────────────────────────────────────────
# Three ways to leave a handshake unfinished, forty times each, because a
# session or struct leaked on any of them shows up as connections that never
# falls back to zero.
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
        tls.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER0)
        tls.close()
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
# Not assert_eq, because '' here means six seconds of `stats` printed no
# connections line at all, which is the runtime or the daemon being gone.
TOTAL=$((TOTAL+1))
if [ -z "$CONNS" ]; then
    FAIL=$((FAIL+1))
    echo "  FAIL [aborted handshakes leave no connections behind]: 'stats tlscache' never"
    echo "        printed a 'connections:' line in six seconds of asking -- the runtime or"
    echo "        the daemon is gone, which is a failure and not a count of zero"
elif [ "$CONNS" = "0" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [aborted handshakes leave no connections behind]: still $CONNS connections"
    echo "        six seconds after the last aborted handshake -- nothing will wake them"
fi

assert_ok "$(rc_of ready_tls 127.0.0.1 "$TLS_PORT" "$CERTS/cache.pem" localhost 15)" \
    "listener still completes a handshake after the aborts"

# The dataset survived all of that, because a session freed while the ring held
# it shows up as a cache that has stopped answering correctly rather than as a
# lost connection.
python3 - "$TLS_PORT" "$CERTS/cache.pem" >"$TMPDIR_T/postabort.out" 2>&1 <<'PYEOF' || true
import sys
from cachetls_probe import Owed, read_token, session, shut, text_or_blank

port, cafile = int(sys.argv[1]), sys.argv[2]
owed = Owed("VALUE")

tls, tok = session(port, cafile, 8)
if tok:
    owed.settle(tok)
    sys.exit(0)

try:
    f = tls.makefile("rwb")
    f.write(b"*2\r\n$3\r\nGET\r\n$2\r\nk1\r\n"); f.flush()
    hdr = f.readline().rstrip(b"\r\n")
    if not hdr.startswith(b"$"):
        # A reply that is not a bulk header at all.  int(hdr[1:]) used to raise
        # here and the probe died with nothing said, which is the same hole as
        # the handshake timeout: the cache answering something unexpected is
        # exactly what this check exists to catch, so it has to be reportable.
        owed.say("VALUE", text_or_blank(hdr))
    else:
        n = int(hdr[1:])
        owed.say("VALUE", text_or_blank(f.read(n)) if n >= 0 else "<nil>")
except Exception as e:            # noqa: BLE001
    owed.settle(read_token(e))
finally:
    owed.settle("<error:no-answer>")
    shut(tls)
PYEOF
assert_probe "$(marker "$TMPDIR_T/postabort.out" VALUE)" "012345" \
    "the dataset is intact after the aborted handshakes" "$TMPDIR_T/postabort.out"

# ─────────────────────────────────────────────────────────────────────────────
# 6. Fail closed
# ─────────────────────────────────────────────────────────────────────────────
# The assertions are on the reason rather than the exit status, because a
# binary that refuses all four TLS flags outright would pass a status check.
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

# A certificate file that does not exist must leave the runtime failed with
# nothing listening, as one verdict because an absent listener is also true of
# a runtime that was never created.
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

# Incomplete flag sets each describe a listener that could only serve
# cleartext, so `create` refuses, names the missing flag and leaves no runtime
# behind.
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

# The mesh options on a cache are not asserted here, because no path from
# outside can reach that branch and an assertion that cannot be made to fail is
# not evidence.

# ─────────────────────────────────────────────────────────────────────────────
# 7. Replication and TLS do not mix, and the refusal holds everywhere
# ─────────────────────────────────────────────────────────────────────────────
# A TLS cache that replicates would put its whole dataset on the wire in the
# clear, refused at create on the reason rather than the status -- only a build
# that accepts --tls on a cache can refuse it for the replication.
create_refused tlsrepl "--replicate: a cache's replication link is not encrypted" \
    "--tls together with --replicate is refused at create, naming --replicate" \
    "$BIN" create cache tlsrepl -p "$BAD_PORT" \
    --tls --cert "$CERTS/cache.pem" --key "$CERTS/cache-key.pem" \
    --replicate "127.0.0.1:$LEADER_PORT"

# On the restore path, which a create-time check cannot reach, written by hand
# because there is deliberately no supported way to produce such a state file.
rc_of "$BIN" create cache tlsrestore -p "$BAD_PORT" \
    --replicate "127.0.0.1:$LEADER_PORT" >/dev/null
assert_eq "$(state_of tlsrestore)" "created" \
    "precondition: a cleartext replicating cache is created normally"

"$BIN" stop tlsrestore >/dev/null 2>&1 || true
kill "$DPID" 2>/dev/null || true
wait "$DPID" 2>/dev/null || true
DPID=""

RESTORE_JSON="$(state_dir)/tlsrestore.json"
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

# Refused, not running and not listening, as one verdict because each alone is
# satisfied by a binary that never gets near the question.
START_RC=$(rc_of "$BIN" start tlsrestore)
SAID_REPL=$(says "--replicate: a cache's replication link is not encrypted")
RSTATE=$(state_of tlsrestore)
BOUND=closed
nc -z 127.0.0.1 "$BAD_PORT" 2>/dev/null && BOUND=open
assert_eq "rc=$START_RC/said=$SAID_REPL/running=$([ "$RSTATE" = running ] && echo yes || echo no)/bound=$BOUND" \
          "rc=1/said=yes/running=no/bound=closed" \
    "a restored cache with TLS and replication refuses to start, naming --replicate"
rc_of "$BIN" remove tlsrestore >/dev/null

# At the REPLICATE command, which is the half no gate can catch, because a
# cache becomes a leader when a client asks long after any configuration was
# validated.
rc_of "$BIN" create cache tlsleader -p "$LEADER_PORT" \
    --tls --cert "$CERTS/cache.pem" --key "$CERTS/cache-key.pem" -s >/dev/null
assert_ok "$(rc_of ready_tls 127.0.0.1 "$LEADER_PORT" "$CERTS/cache.pem" localhost 20)" \
    "a TLS cache with no replication configuration starts normally"

python3 - "$LEADER_PORT" "$CERTS/cache.pem" >"$TMPDIR_T/repl.out" 2>&1 <<'PYEOF' || true
import sys
from cachetls_probe import Owed, read_token, session, shut, text_or_blank

port, cafile = int(sys.argv[1]), sys.argv[2]
owed = Owed("FIRST", "AFTER")

tls, tok = session(port, cafile, 8)
if tok:
    owed.settle(tok)
    sys.exit(0)

try:
    f = tls.makefile("rwb")
    f.write(b"replicate\n"); f.flush()
    first = text_or_blank(f.readline().rstrip(b"\r\n"))
    owed.say("FIRST", first[:5] if not first.startswith("<") else first)
    # A refusal leaves this an ordinary client connection, so the next commands
    # are still answered.  A promotion would have made the socket a replication
    # stream with this runtime as its only writer, and these would return the
    # dump, the "commands are not accepted" line, or nothing at all.
    #
    # Line protocol and not RESP: the first byte this connection sent was "r",
    # so it was detected as a line client and stays one.
    f.write(b"set after-replicate still-a-client\n"); f.flush()
    f.readline()
    f.write(b"get after-replicate\n"); f.flush()
    owed.say("AFTER", text_or_blank(f.readline().rstrip(b"\r\n")))
except Exception as e:            # noqa: BLE001
    owed.settle(read_token(e))
finally:
    owed.settle("<error:no-answer>")
    shut(tls)
PYEOF
assert_probe "$(marker "$TMPDIR_T/repl.out" FIRST)" "error" \
    "REPLICATE on a TLS cache is refused rather than promoting it to leader" \
    "$TMPDIR_T/repl.out"
assert_probe "$(marker "$TMPDIR_T/repl.out" AFTER)" "still-a-client" \
    "a refused REPLICATE leaves the connection an ordinary client" \
    "$TMPDIR_T/repl.out"

# And none of this broke replication for a cleartext cache, which are
# regression guards rather than oracles and pass against a binary without the
# feature by design.
rc_of "$BIN" create cache plainleader -p "$FOLLOWER_PORT" -s >/dev/null
assert_ok "$(rc_of ready_resp 127.0.0.1 "$FOLLOWER_PORT" 15)" \
    "regression guard: a cleartext cache comes up"

python3 - "$FOLLOWER_PORT" >"$TMPDIR_T/plainrepl.out" 2>&1 <<'PYEOF' || true
import sys
from cachetls_probe import Owed, dial, read_token, shut, text_or_blank

port = int(sys.argv[1])
owed = Owed("REPL")

s, tok = dial(port, 8)
if tok:
    owed.settle(tok)
    sys.exit(0)

try:
    f = s.makefile("rwb")
    f.write(b"replicate\n"); f.flush()
    owed.say("REPL", text_or_blank(f.readline().rstrip(b"\r\n")))
except Exception as e:            # noqa: BLE001
    owed.settle(read_token(e))
finally:
    owed.settle("<error:no-answer>")
    shut(s)
PYEOF
assert_probe "$(marker "$TMPDIR_T/plainrepl.out" REPL)" "ok" \
    "regression guard: REPLICATE on a cleartext cache still promotes it to leader" \
    "$TMPDIR_T/plainrepl.out"

rc_of "$BIN" stop tlscache tlsline tlsmtls tlsleader plainleader >/dev/null
sleep 0.3
rc_of "$BIN" remove tlscache tlsline tlsmtls tlsleader plainleader >/dev/null

# Every assertion is accounted for in exactly one column, because herr() takes
# a total of its own and a caller that also pre-increments charges one
# assertion twice.
if [ "$((PASS+FAIL+HERR))" -ne "$TOTAL" ]; then
    echo "  FAIL [counters]: $PASS passed + $FAIL failed + $HERR not measurable"
    echo "        does not equal $TOTAL counted -- this summary is wrong, not just the run"
    FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1))
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $HERR not measurable)"
if [ "$FAIL" -eq 0 ] && [ "$HERR" -eq 0 ]; then echo "  OK"
elif [ "$FAIL" -eq 0 ]; then echo "  NOT MEASURABLE -- this run could not put the question, see above"
else echo "  FAILED"; fi
exit $((FAIL+HERR))
