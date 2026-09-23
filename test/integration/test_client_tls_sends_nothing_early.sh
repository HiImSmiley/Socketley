#!/usr/bin/env bash
# Integration test: a --tls client puts no application byte on the wire before
# its ClientHello.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# try_connect() ran invoke_on_connect() three lines above start_tls(), and
# lua_send() decided "this is a TLS connection, so queue it and let tls_flush
# put a record on the wire" by testing m_conn->ssl -- which start_tls has not
# created yet.  A script sending from on_connect therefore took the plain arm
# and armed a cleartext write on a socket that was about to become TLS.
#
# Two things go wrong at once.  The operator asked for encryption and the
# payload goes out in the clear; and the peer reads that first byte as a TLS
# record content type -- 'S' rather than 0x16 -- and aborts, so the handshake
# never completes and --reconnect repeats the whole thing.
#
# tls_flush() already describes the behaviour that was intended, and could not
# happen: "Application data only once the handshake is done, so a message
# queued by on_connect waits rather than being handed to an SSL that would
# answer WANT_READ."
#
# ─── WHY THE PEER IS A PLAIN LISTENER ───────────────────────────────────────
#
# What is under test is the first thing written, not what a handshake settles
# on.  A plain socket records that exactly and needs no certificate the client
# would have to be taught to trust; the handshake failing afterwards is
# expected and is not what any assertion reads.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   the control sends       a build where on_connect never runs, or where the
#                           script is wrong -- without it, "no payload on the
#                           wire" passes for the wrong reason
#   first byte is 0x16      the payload taking the plain arm ahead of the
#                           ClientHello
#   the payload is absent   the same thing, read the other way: a record that
#                           begins correctly can still carry cleartext behind it
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate tlsearly

P_TLS=$((SL_PORT_BASE+1692))
P_PLAIN=$((SL_PORT_BASE+1693))
SECRET="SECRET-PAYLOAD-FROM-ON-CONNECT"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local l; for l in "${@:3}"; do echo "        $l"; done; }

cleanup() {
    "$BIN" stop c_tls   >/dev/null 2>&1 || true
    "$BIN" stop c_plain >/dev/null 2>&1 || true
    [ -n "${LPID:-}" ] && kill "$LPID" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a --tls client writes no cleartext before its ClientHello ==="

# One listener, two ports, each recording the first bytes of the first
# connection it accepts and then holding the socket open so the client does not
# immediately reconnect and overwrite the record.
cat > "$SOCKETLEY_TMPD/listen.py" <<'PYEOF'
import socket, sys, threading, time
tls_port, plain_port, outdir = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]

def one(port, tag):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port)); ls.listen(8); ls.settimeout(0.3)
    deadline = time.time() + 90
    while time.time() < deadline:
        try:
            c, _ = ls.accept()
        except socket.timeout:
            continue
        except Exception:
            break
        got = b""
        try:
            # The first bytes, then a short grace for whatever follows them.
            # Waiting for a fixed count instead recorded nothing for the plain
            # control, whose whole message is 31 bytes -- and an unrecorded
            # control is one that proves nothing.
            c.settimeout(8)
            got += c.recv(4096)
            c.settimeout(0.5)
            while len(got) < 4096:
                d = c.recv(4096)
                if not d:
                    break
                got += d
        except Exception:
            pass
        with open("%s/%s.bin" % (outdir, tag), "wb") as fh:
            fh.write(got)
        # Held open: a close would start the reconnect clock and the next
        # dial would rewrite the file this test reads.
        time.sleep(60)
        try: c.close()
        except Exception: pass
        return
    ls.close()

threading.Thread(target=one, args=(plain_port, "plain"), daemon=True).start()
sys.stderr.write("listening\n"); sys.stderr.flush()
one(tls_port, "tls")
PYEOF

python3 "$SOCKETLEY_TMPD/listen.py" "$P_TLS" "$P_PLAIN" "$SOCKETLEY_TMPD" \
        2>"$SOCKETLEY_TMPD/listen.log" &
LPID=$!
for _ in $(seq 1 60); do
    grep -q listening "$SOCKETLEY_TMPD/listen.log" 2>/dev/null && break
    sleep 0.1
done

cat > "$SOCKETLEY_TMPD/send.lua" <<LUAEOF
function on_connect()
    self.send("$SECRET")
end
LUAEOF

daemon_start "$BIN"
"$BIN" create client c_plain -t "127.0.0.1:$P_PLAIN" --lua "$SOCKETLEY_TMPD/send.lua" -s >/dev/null 2>&1
"$BIN" create client c_tls   -t "127.0.0.1:$P_TLS" --tls --lua "$SOCKETLEY_TMPD/send.lua" -s >/dev/null 2>&1
# Long enough for the grace read above to have closed both records.
sleep 6

hexfirst() { [ -s "$1" ] && od -An -tx1 -N1 "$1" | tr -d ' \n' || echo "--"; }
haspay()   { [ -s "$1" ] && grep -qa "$SECRET" "$1" && echo yes || echo no; }

PLAIN_FIRST=$(hexfirst "$SOCKETLEY_TMPD/plain.bin")
PLAIN_PAY=$(haspay   "$SOCKETLEY_TMPD/plain.bin")
TLS_FIRST=$(hexfirst "$SOCKETLEY_TMPD/tls.bin")
TLS_PAY=$(haspay     "$SOCKETLEY_TMPD/tls.bin")

echo "  plain client -> first byte 0x$PLAIN_FIRST, payload on the wire: $PLAIN_PAY"
echo "  --tls client -> first byte 0x$TLS_FIRST, payload on the wire: $TLS_PAY"

# The control.  Without it, "no payload" below is equally true of a build whose
# on_connect never ran at all.
if [ "$PLAIN_PAY" = "yes" ]; then ok
else bad "control: a plain client does send the payload from on_connect" \
         "nothing matching the payload reached the listener" \
         "the assertions below would then pass on a build that sends nothing"; fi

if [ "$TLS_FIRST" = "16" ]; then ok
else bad "a --tls client's first byte is a TLS handshake record" \
         "got 0x$TLS_FIRST, wanted 0x16" \
         "0x53 is 'S', the first letter of the payload: the send took the" \
         "plain arm because m_conn->ssl was still null inside on_connect"; fi

if [ "$TLS_PAY" = "no" ]; then ok
else bad "and the payload does not appear on the wire in the clear" \
         "the listener read it verbatim from a connection the operator asked" \
         "to be encrypted"; fi

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
