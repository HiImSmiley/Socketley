#!/usr/bin/env bash
# Integration test: a TLS client resumes on whichever shard it lands on, and a ticket older than two key periods does
# not resume at all.
#
# Each shard kept its own session cache and issued no tickets of its own, so under --shards 4 a returning client
# resumed only when SO_REUSEPORT sent it back to the shard it first met: about one time in four.  The shards now seal
# tickets with keys they share, a new one each period that still opens tickets through the next.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate tlsresume
PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: TLS sessions resume across shards, and their keys rotate ==="
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
python3 -c 'import ssl' >/dev/null 2>&1 || { echo "  SKIP: python3 ssl is required"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
T="$SOCKETLEY_TMPD"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost -addext subjectAltName=DNS:localhost \
    -keyout "$T/key.pem" -out "$T/cert.pem" >/dev/null 2>&1
mkdir -p "$T/www"
echo hello >"$T/www/index.html"

# Four seconds a key, so two periods can be waited out.
PERIOD=4
export SOCKETLEY_TLS_TICKET_SECS=$PERIOD
P=$((SL_PORT_BASE + 1071))
daemon_start "$BIN"
"$BIN" create server web -p "$P" --http "$T/www" --shards 4 --tls --cert "$T/cert.pem" --key "$T/key.pem" -s \
    >/dev/null 2>&1
for _ in $(seq 1 100); do (exec 3<>"/dev/tcp/127.0.0.1/$P") 2>/dev/null && break; sleep 0.1; done
# Every shard listening, so the reconnections are spread over all four.
for _ in $(seq 1 100); do
    [ "$(ss -Hltn "sport = :$P" 2>/dev/null | wc -l)" -ge 4 ] && break
    sleep 0.1
done

# One request per connection, its answer read whole so a TLS 1.3 ticket that follows the handshake has arrived, and the
# client the one to close, since a server's close sends no close_notify and OpenSSL will not resume a session ended
# without one.
cat >"$T/client.py" <<'PY'
import socket, ssl, sys, time

port, cafile = int(sys.argv[1]), sys.argv[2]

def context(version):
    c = ssl.create_default_context(cafile=cafile)
    c.minimum_version = c.maximum_version = version
    return c

def get(ctx, session=None):
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5),
                        server_hostname="localhost", session=session)
    s.sendall(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
    got = b""
    while b"\r\n\r\n" not in got:
        got += s.recv(65536)
    head, body = got.split(b"\r\n\r\n", 1)
    length = int([l.split(b":")[1] for l in head.split(b"\r\n") if l.lower().startswith(b"content-length:")][0])
    while len(body) < length:
        body += s.recv(65536)
    reused, sess = s.session_reused, s.session
    s.close()
    return reused, sess

def resumptions(version, n):
    ctx = context(version)
    _, sess = get(ctx)
    reused = 0
    for _ in range(n):
        r, sess = get(ctx, sess)
        reused += 1 if r else 0
    return reused

if sys.argv[3] == "spread":
    print(resumptions(ssl.TLSVersion.TLSv1_3, 40), resumptions(ssl.TLSVersion.TLSv1_2, 40))
else:
    # A ticket taken just after a period begins, offered again one period later and two periods later; the same
    # monotonic clock the shards read.
    period = float(sys.argv[4])
    ctx = context(ssl.TLSVersion.TLSv1_3)
    begun = (int(time.monotonic() / period) + 1) * period
    time.sleep(begun + 0.3 - time.monotonic())
    _, sess = get(ctx)
    time.sleep(begun + period + 0.3 - time.monotonic())
    one, _ = get(ctx, sess)
    time.sleep(begun + 2 * period + 0.3 - time.monotonic())
    two, _ = get(ctx, sess)
    print(int(one), int(two))
PY

read -r R13 R12 < <(python3 "$T/client.py" "$P" "$T/cert.pem" spread 2>&1)
if [ "${R13:-0}" -ge 39 ]; then pass
else fail "a TLS 1.3 client resumes on every shard" "resumed ${R13:-none} of 40 reconnections"; fi
if [ "${R12:-0}" -ge 39 ]; then pass
else fail "a TLS 1.2 client resumes on every shard" "resumed ${R12:-none} of 40 reconnections"; fi

read -r ONE TWO < <(python3 "$T/client.py" "$P" "$T/cert.pem" age "$PERIOD" 2>&1)
if [ "${ONE:-}" = "1" ]; then pass
else fail "a ticket of the previous period still resumes" "got '${ONE:-}'"; fi
if [ "${TWO:-}" = "0" ]; then pass
else fail "a ticket two periods old does not resume" "got '${TWO:-}'"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
