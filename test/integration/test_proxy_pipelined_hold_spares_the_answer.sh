#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: bytes a client sends behind its request do not cut short the answer still on its way to it.
#
# What each part would catch:
#   * the header deadline a pipelined hold arms (10 s from the first byte behind the request) ending the connection
#     while the answer is still going out: the close's FIN follows what the socket holds, and the client reads a
#     clean end of an answer that is short by whatever was still queued -- with Connection: close, whose trailing
#     bytes are no request at all, and with a keep-alive request whose next one waits behind it
#   * the same through a backend and through --root, which serves the file itself
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
exec 2>&1

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

echo "=== Integration: a proxy's answer outlives the hold on the bytes behind its request ==="
python3 -c 'import socket' >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
daemon_isolate pxhold
unset SOCKETLEY_CONFIG
trap daemon_stop EXIT
T="$SOCKETLEY_TMPD"
mkdir -p "$T/www"
SIZE=$((6 * 1024 * 1024))
head -c "$SIZE" /dev/urandom >"$T/www/big.bin"

# One connection: the request and some bytes behind it, then nothing read for longer than the header deadline, then
# everything.  Prints how much of the first answer's body came and how it ended.
cat >"$T/client.py" <<'PY'
import socket, sys, time

port, path, host, behind = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
s = socket.socket()
s.settimeout(30)
s.connect(("127.0.0.1", port))
closing = behind == "close"
if closing:
    s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, host)).encode())
    behind = [b"xxxx", b"xxxx"]
else:
    # A keep-alive request, and the start of the next one behind it.
    s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (path, host)).encode())
    behind = [("GET %s HTTP/1.1\r\n" % path).encode(), b"Ho"]
# In two reads apart from the request's, so the bytes are taken as they come and not only with the request.
for piece in behind:
    time.sleep(0.3)
    s.sendall(piece)
time.sleep(11.0)
got, how = bytearray(), "timeout"
try:
    while True:
        head, sep, body = bytes(got).partition(b"\r\n\r\n")
        if not closing and sep:
            length = int([l.split(b":")[1] for l in head.split(b"\r\n") if l.lower().startswith(b"content-length:")][0])
            if len(body) >= length:
                how = "whole"
                break
        b = s.recv(1 << 20)
        if not b:
            how = "eof"
            break
        got += b
except ConnectionResetError:
    how = "reset"
except socket.timeout:
    pass
head, sep, body = bytes(got).partition(b"\r\n\r\n")
n = len(body)
if not closing and sep:
    length = int([l.split(b":")[1] for l in head.split(b"\r\n") if l.lower().startswith(b"content-length:")][0])
    n = min(n, length)
print(n, how)
PY

P_SRV=$((SL_PORT_BASE + 1521))
P_PX=$((SL_PORT_BASE + 1522))
P_FC=$((SL_PORT_BASE + 1523))

daemon_start "$BIN"
"$BIN" create server srv -p "$P_SRV" --http "$T/www" -s >/dev/null 2>&1
"$BIN" create proxy px -p "$P_PX" --protocol http --backend "127.0.0.1:$P_SRV" -s >/dev/null 2>&1
"$BIN" create proxy fc -p "$P_FC" --domain fc.test --backend "fastcgi://unix:$T/none.sock" --root "$T/www" -s >/dev/null 2>&1
for p in "$P_SRV" "$P_PX" "$P_FC"; do
    ready_tcp 127.0.0.1 "$p" 15 || bad "port $p listens" "$(tail -3 "$SOCKETLEY_DLOG")"
done
ready_http 127.0.0.1 "$P_SRV" /big.bin >/dev/null 2>&1 || true

# The four at once, since each waits out the deadline.
CLIENTS=()
python3 "$T/client.py" "$P_PX" /px/big.bin localhost close >"$T/px.close" 2>&1 & CLIENTS+=($!)
python3 "$T/client.py" "$P_FC" /big.bin fc.test close >"$T/fc.close" 2>&1 & CLIENTS+=($!)
python3 "$T/client.py" "$P_PX" /px/big.bin localhost next >"$T/px.next" 2>&1 & CLIENTS+=($!)
python3 "$T/client.py" "$P_FC" /big.bin fc.test next >"$T/fc.next" 2>&1 & CLIENTS+=($!)
wait "${CLIENTS[@]}"

check "proxy (http): Connection: close and bytes behind it" "$(tail -1 "$T/px.close")" "$SIZE eof"
check "proxy (--root): Connection: close and bytes behind it" "$(tail -1 "$T/fc.close")" "$SIZE eof"
check "proxy (http): a keep-alive answer with the next request behind it" "$(tail -1 "$T/px.next")" "$SIZE whole"
check "proxy (--root): a keep-alive answer with the next request behind it" "$(tail -1 "$T/fc.next")" "$SIZE whole"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
