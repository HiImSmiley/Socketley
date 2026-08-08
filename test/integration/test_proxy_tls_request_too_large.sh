#!/usr/bin/env bash
# Integration test: the 1 MiB buffered-request ceiling is answered 413 on a
# --tls listener, not closed on in silence.
#
# ─── WHAT THIS PINS ─────────────────────────────────────────────────────────
#
# The proxy holds at most 1 MiB for a connection whose request has already been
# forwarded -- the body past the declared Content-Length, and the requests
# pipelined behind it.  Nothing drains that until the response in front of it
# finishes, so a client that writes faster than the backend answers reaches the
# ceiling on a perfectly well-formed connection.  The man page promises that
# case a 413, with exactly one exception: a backend response already on the
# wire, where a status line would land mid-message.
#
# On a cleartext listener that was true.  On a --tls listener it was not, and
# the page was therefore wrong rather than silent: the ceiling is reached inside
# the record layer while it is decrypting, which expressed it by marking the
# connection closing, and the branch that writes the 413 sits below the point
# the TLS path returns from.  The client got a close with no status -- the exact
# state the 413 exists to end.
#
# ─── WHY IT ASSERTS A READ AND NOT AN EXIT CODE ─────────────────────────────
#
# "The connection went away" is what both the broken and the fixed build do;
# it is the *status ahead of the close* that is the whole difference.  So the
# client here reads the connection to EOF and asserts on what came back, and a
# build that closes politely without answering fails on an empty read rather
# than passing on a tidy exit.  The 413 must also arrive BEFORE the close, which
# is the same statement: an answer that never reaches the wire is not an answer.
set -uo pipefail

SDIR="$(cd "$(dirname "$0")" && pwd)"
BIN="${BIN:-$SDIR/../../bin/Release/socketley}"
[ -x "$BIN" ] || { echo "ERROR: socketley not found at $BIN"; exit 1; }
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"

. "$SDIR/lib_ready.sh"
. "$SDIR/lib_create.sh"
. "$SDIR/lib_daemon.sh"

echo "=== Integration: a request past the ceiling is answered 413 over TLS ==="

if ! command -v python3 >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    echo "  SKIP: python3 and openssl are both required"; exit 0
fi

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

PORT_BASE=$((SL_PORT_BASE+960))
BE=$((PORT_BASE+1))
PX=$((PORT_BASE+2))     # TLS listener
PXP=$((PORT_BASE+3))    # cleartext listener, the control

daemon_isolate tls413
TMPD="$SOCKETLEY_TMPD"
BEPID=""

cleanup() {
    [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null
    for n in t413 t413p; do
        "$BIN" stop "$n" >/dev/null 2>&1 || true
        "$BIN" remove "$n" >/dev/null 2>&1 || true
    done
    daemon_stop
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -keyout "$TMPD/px.key" -out "$TMPD/px.pem" \
    -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1

# A backend that accepts and then says nothing.  Silence is the condition: the
# ceiling is only reachable while the response in front of the buffered bytes is
# unfinished, and a backend that answers promptly drains them instead.  It is
# also what keeps the run on the answerable side of the page's one exception --
# with no response byte on the client's wire, a status line still starts at a
# message boundary.
cat >"$TMPD/be.py" <<PY
import socket, threading
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", $BE)); s.listen(64)
held = []
while True:
    try:
        c, _ = s.accept()
    except OSError:
        break
    held.append(c)          # never answered, never closed
PY
python3 "$TMPD/be.py" >/dev/null 2>&1 &
BEPID=$!
ready_tcp 127.0.0.1 "$BE" 5 || true

daemon_start "$BIN"

create_ok "tls proxy created" \
    "$BIN" create proxy t413 -p "$PX" --backend "127.0.0.1:$BE" --protocol http \
        --tls --cert "$TMPD/px.pem" --key "$TMPD/px.key" -s
create_ok "cleartext proxy created" \
    "$BIN" create proxy t413p -p "$PXP" --backend "127.0.0.1:$BE" --protocol http -s

ready_tcp 127.0.0.1 "$PX" 10  || true
ready_tcp 127.0.0.1 "$PXP" 10 || true

# Send a well-formed request, then flood past the ceiling behind it.  The flood
# is 3 MiB: comfortably past the 1 MiB the proxy holds, and the same size the
# cleartext path was measured against.
cat >"$TMPD/flood.py" <<'PY'
import socket, ssl, sys

host, port, use_tls = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "tls"
name = sys.argv[4]

s = socket.create_connection((host, port), timeout=20)
if use_tls:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(s, server_hostname="localhost")

req = (f"GET /{name}/x HTTP/1.1\r\nHost: localhost\r\n"
       f"Content-Length: 0\r\n\r\n").encode()
s.sendall(req)

# Let the request be parsed and forwarded before flooding behind it.  This is
# not politeness, it is the case under test: the 1 MiB ceiling counts what is
# buffered BEHIND a request already in flight.  Flooding in the same breath puts
# the whole lot in front of the header parse instead, where the 16 KiB header
# cap answers 431 long before the megabyte one is reached -- a different limit,
# correctly applied, and not this test's subject.
import time
time.sleep(0.5)

# Everything past the declared length: this is what the proxy has to hold.
blob = b"A" * 65536
sent = 0
try:
    while sent < 3 * 1024 * 1024:
        s.sendall(blob)
        sent += len(blob)
except Exception:
    pass   # the proxy may refuse and close mid-flood; that is the case under test

# Read to EOF.  What came back before the close is the whole question.
s.settimeout(10)
got = b""
try:
    while True:
        d = s.recv(65536)
        if not d:
            break
        got += d
        if len(got) > 65536:
            break
except Exception:
    pass
try:
    s.close()
except Exception:
    pass

sys.stdout.write(got[:200].decode("latin-1", "replace"))
PY

# ── the control: the same flood on a cleartext listener ─────────────────────
# Stated first and asserted, not assumed.  It is what makes a failure on the TLS
# leg a statement about TLS rather than about the ceiling, the backend or the
# machine.
PLAIN=$(python3 "$TMPD/flood.py" 127.0.0.1 "$PXP" plain t413p 2>/dev/null)
case "$PLAIN" in
    "HTTP/1.1 413"*) ok ;;
    *) bad "cleartext listener answers 413 past the ceiling" \
           "got '$(printf '%s' "$PLAIN" | head -c 60)' -- the control did not hold, so nothing below is about TLS" ;;
esac

# ── the case under test ─────────────────────────────────────────────────────
TLSOUT=$(python3 "$TMPD/flood.py" 127.0.0.1 "$PX" tls t413 2>/dev/null)
case "$TLSOUT" in
    "HTTP/1.1 413"*) ok ;;
    "") bad "tls listener answers 413 past the ceiling" \
            "the connection closed with nothing on it -- a silent close is what the 413 exists to end" ;;
    *) bad "tls listener answers 413 past the ceiling" \
           "got '$(printf '%s' "$TLSOUT" | head -c 60)'" ;;
esac

# The daemon has to still be there: an answer produced from inside the record
# layer must not have cost the runtime.
if "$BIN" stats t413 >/dev/null 2>&1; then ok; else
    bad "the tls proxy is still running afterwards" "stats does not answer for t413"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
