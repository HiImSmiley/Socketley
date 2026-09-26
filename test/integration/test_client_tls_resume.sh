#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# A client that reconnects should not buy the same certificate twice.  The peer
# here is the oracle: python reports session_reused per connection, so what is
# asserted is the server's own view of whether it did a full handshake, not a
# timing or a log line the client writes about itself.
#
# The first connection must be full -- it is the control, and without it every
# later assertion would pass on a peer that resumes everything or on a test
# that never connected at all.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"

TMPD=$(mktemp -d /tmp/socketley-tlsresume-XXXXXX)
export HOME="$TMPD/home"
export SOCKETLEY_SOCKET="$TMPD/daemon.sock"
mkdir -p "$HOME"

PEER=$((SL_PORT_BASE+787))
DROPS=5                    # connections the peer drops, forcing a re-dial
WANT=$((DROPS+1))          # plus the one it keeps, which carries the message
DPID=""; PEERPID=""
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop tresume >/dev/null 2>&1 || true
    "$BIN" remove tresume >/dev/null 2>&1 || true
    [ -n "$PEERPID" ] && kill "$PEERPID" 2>/dev/null
    if [ -n "$DPID" ]; then
        kill "$DPID" 2>/dev/null || true
        for _ in $(seq 1 50); do kill -0 "$DPID" 2>/dev/null || break; sleep 0.1; done
        kill -9 "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
    # Matched on the environment rather than the command line, because a -f
    # pattern also matches the shell carrying it.
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

echo "=== Integration: a reconnecting TLS client resumes its session ==="

if ! command -v python3 >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    echo "  SKIP: python3 and openssl are both required"; exit 0
fi
if ! python3 -c "import ssl" >/dev/null 2>&1; then
    echo "  SKIP: python3 has no ssl module"; exit 0
fi

openssl req -x509 -newkey rsa:2048 -keyout "$TMPD/peer.key" -out "$TMPD/peer.pem" \
    -nodes -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" -days 2 \
    >/dev/null 2>&1 || { echo "  SKIP: could not generate a test certificate"; exit 0; }

# Drops the first $DROPS connections after greeting them, then keeps the next
# one and echoes on it -- so the run ends on a resumed session that has to
# carry application data, and not merely on a handshake that looked right.
cat > "$TMPD/peer.py" <<'PYEOF'
import socket, ssl, sys, time

port, cert, key, drops = int(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(32)
print("ready", flush=True)

n = 0
while True:
    raw, _ = srv.accept()
    n += 1
    try:
        c = ctx.wrap_socket(raw, server_side=True)
    except Exception as e:
        print(f"conn {n} handshake-failed {type(e).__name__}", flush=True)
        raw.close()
        continue
    print(f"conn {n} reused={1 if c.session_reused else 0}", flush=True)
    try:
        c.sendall(b"hello\n")
        if n <= drops:
            # Long enough for the client to take the greeting and the session
            # ticket that follows it, which is what there is to resume.
            time.sleep(0.5)
            c.close()
            continue
        buf = b""
        while True:
            d = c.recv(65536)
            if not d:
                break
            buf += d
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.rstrip(b"\r")
                if line:
                    print(f"got {line.decode('latin1')}", flush=True)
    except (OSError, ssl.SSLError):
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass
PYEOF

python3 "$TMPD/peer.py" "$PEER" "$TMPD/peer.pem" "$TMPD/peer.key" "$DROPS" \
    >"$TMPD/peer.log" 2>&1 &
PEERPID=$!
for _ in $(seq 1 60); do grep -q ready "$TMPD/peer.log" 2>/dev/null && break; sleep 0.1; done

"$BIN" daemon >"$TMPD/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 80); do [ -S "$SOCKETLEY_SOCKET" ] && break; sleep 0.1; done

"$BIN" create client tresume -t "127.0.0.1:$PEER" --tls --ca "$TMPD/peer.pem" \
    --reconnect -s >/dev/null 2>&1
if [ $? -ne 0 ]; then
    bad "the TLS client is created and started" "create failed"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit "$FAIL"
fi

# The re-dials are the measurement, so wait for them rather than for a clock:
# each costs the client's one-second backoff plus the peer's half-second hold.
for _ in $(seq 1 600); do
    [ "$(grep -c '^conn ' "$TMPD/peer.log" 2>/dev/null)" -ge "$WANT" ] && break
    sleep 0.1
done

CONNS=$(grep -c '^conn ' "$TMPD/peer.log" 2>/dev/null)
if [ "${CONNS:-0}" -ge "$WANT" ]; then ok; else
    bad "the client re-dialled after each drop" \
        "$CONNS of $WANT connections reached the peer -- nothing below measures resumption"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"; exit "$FAIL"
fi

# The control: nothing is cached before the first connection, so it has to be a
# full handshake.  A peer that reported every connection as resumed would pass
# the assertion below while proving nothing.
if grep -q "^conn 1 reused=0$" "$TMPD/peer.log"; then ok; else
    bad "the first connection is a full handshake" \
        "$(grep '^conn 1 ' "$TMPD/peer.log")"
fi

# The measurement.  One short of the re-dials, because a ticket that has not
# arrived by the time the peer drops the socket costs a full handshake and is
# not a defect; zero is.
RESUMED=$(grep -c "reused=1" "$TMPD/peer.log")
if [ "${RESUMED:-0}" -ge $((DROPS-1)) ]; then ok; else
    bad "a re-dial resumes the session instead of handshaking in full" \
        "only $RESUMED of $DROPS re-dials were resumed: $(grep -c 'reused=0' "$TMPD/peer.log") full handshakes in $CONNS connections"
fi

# And the session that was resumed is a working one: the connection the peer
# kept is the last of the run, and it has to carry a message both ways.
if grep -q "^conn $WANT reused=1$" "$TMPD/peer.log"; then ok; else
    bad "the connection that stays up is itself a resumed one" \
        "$(grep "^conn $WANT " "$TMPD/peer.log")"
fi

DELIVERED=no
for _ in $(seq 1 40); do
    "$BIN" send tresume m-resumed >/dev/null 2>&1
    grep -q "^got m-resumed$" "$TMPD/peer.log" 2>/dev/null && { DELIVERED=yes; break; }
    sleep 0.1
done
if [ "$DELIVERED" = "yes" ]; then ok; else
    bad "application data crosses a resumed session" \
        "the peer never received the message over the resumed connection"
fi

if kill -0 "$DPID" 2>/dev/null; then ok; else bad "daemon alive" "the daemon died"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
