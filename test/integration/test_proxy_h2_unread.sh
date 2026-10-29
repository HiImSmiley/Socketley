#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
# An HTTP/2 client at the entrance that does not read is held to a bound.
#
#   resets    a frame that draws an RST_STREAM (a PRIORITY of the wrong length,
#             on any stream) drew one per frame with no count, so a peer that
#             sent them and never read grew the session's queue by 13 bytes per
#             9 it sent; past the bound on resets the connection now ends with
#             GOAWAY ENHANCE_YOUR_CALM, as it does for the peer's own resets
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
# A thousand such frames in one flight: before the bound every one was answered
# and no GOAWAY came, so the count of resets and the GOAWAY's code are both asked.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate pxh2unread
P=$((SL_PORT_BASE+1864))
T="$SOCKETLEY_TMPD"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: an HTTP/2 client that does not read is bounded ==="

if ! command -v openssl >/dev/null 2>&1; then
    echo "  SKIP: openssl is not installed, so the entrance has no certificate to offer"
    echo ""
    echo "=== Results: 0/0 passed, 0 failed ==="
    exit 0
fi

daemon_start "$BIN"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=example.com \
    -addext "subjectAltName=DNS:*.example.com,DNS:example.com" \
    -keyout "$T/e.key" -out "$T/e.pem" >/dev/null 2>&1

mkdir -p "$T/one"
echo "from-one" >"$T/one/who.txt"
E=$((P+1))
"$BIN" create server one -p $((P+2)) --http "$T/one" --domain one.example.com -s >/dev/null 2>&1
"$BIN" create proxy ent -p "$E" --tls --cert "$T/e.pem" --key "$T/e.key" -s >/dev/null 2>&1

routed() { local f; f=$(find "$T" -name 'routes-ent' | head -1); [ -n "$f" ] && grep -q one.example.com "$f"; }
for _ in $(seq 1 60); do routed && break; sleep 0.2; done
if ! routed; then
    bad "the entrance learned the name" "its table never carried it"
    echo ""
    echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
    exit 1
fi
for _ in $(seq 1 40); do
    [ "$(curl -sk --noproxy '*' -m 5 --resolve "one.example.com:$E:127.0.0.1" -o /dev/null -w '%{http_version}' \
         "https://one.example.com:$E/who.txt")" = 2 ] && break
    sleep 0.2
done

# The client's own frames written by hand, so nothing here depends on an HTTP/2 library.
cat >"$T/h2raw.py" <<'PY'
import socket, ssl, struct, sys, time

def frame(ftype, flags, sid, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack(">I", sid) + payload

def connect(port):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), 5), server_hostname="one.example.com")
    if s.selected_alpn_protocol() != "h2":
        print("no-h2"); sys.exit(0)
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0))
    return s

def frames_until_closed(s, wait):
    data, end = b"", time.time() + wait
    s.settimeout(0.5)
    while time.time() < end:
        try:
            d = s.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            break
        if not d:
            break
        data += d
    out, at = [], 0
    while at + 9 <= len(data):
        n = int.from_bytes(data[at:at + 3], "big")
        out.append((data[at + 3], data[at + 9:at + 9 + n]))
        at += 9 + n
    return out

port, what = int(sys.argv[1]), sys.argv[2]
if what == "resets":
    s = connect(port)
    # A PRIORITY with no payload on a stream never opened: a stream error, answered with an RST_STREAM.
    s.sendall(frame(2, 0, 3) * 1000)
    got = frames_until_closed(s, 5)
    rst = sum(1 for t, _ in got if t == 3)
    away = [int.from_bytes(p[4:8], "big") for t, p in got if t == 7 and len(p) >= 8]
    print("%s %d" % ("goaway=%d" % away[-1] if away else "none", 1 if rst <= 400 else 0))
PY

got=$(python3 -I "$T/h2raw.py" "$E" resets 2>&1)
expect "a thousand frames that each draw a reset end the session with ENHANCE_YOUR_CALM, after at most 400" \
    "$got" "goaway=11 1"
expect "and the entrance still answers the next client" \
    "$(curl -sk --noproxy '*' -m 5 --resolve "one.example.com:$E:127.0.0.1" "https://one.example.com:$E/who.txt")" \
    "from-one"

echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
