#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a client that half-closes after a request on a kept-alive connection gets that answer whole.
#
# What it would catch:
#   * conn_server's standing multishot recv taking the client's FIN, which a single read armed after the answer used
#     to meet only once the answer had gone, as the end of the connection while the answer was still being sent: a
#     16 MiB file cut short at whatever the socket had taken
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: an answer to a client that half-closed after asking arrives whole ==="
daemon_isolate halfclose
P=$((SL_PORT_BASE + 1921))
unset SOCKETLEY_CONFIG
R=$(mktemp -d)
trap 'daemon_stop; rm -rf "$R"' EXIT
daemon_start "$BIN"

printf 'small\n' > "$R/small.txt"
head -c $((16 << 20)) /dev/urandom > "$R/big.bin"
"$BIN" create web site -p "$P" --root "$R" -s >/dev/null 2>&1 || bad "create" "the web runtime was not made"
ready_tcp 127.0.0.1 "$P" 15 || bad "listen" "port $P"

out=$(python3 - "$P" <<'EOF'
import socket, sys, time
port = int(sys.argv[1])

def answer(s, buf):
    """One answer off `s`: its status and body, with what follows it left in the buffer."""
    while b'\r\n\r\n' not in buf:
        d = s.recv(65536)
        if not d:
            return None, b'', buf
        buf += d
    head, _, buf = buf.partition(b'\r\n\r\n')
    n = int([l.split(b':')[1] for l in head.split(b'\r\n') if l.lower().startswith(b'content-length:')][0])
    while len(buf) < n:
        d = s.recv(1 << 20)
        if not d:
            break
        buf += d
    return head.split(b' ')[1], buf[:n], buf[n:]

s = socket.socket()
# A small window, so the answer cannot be in the socket by the time the client's FIN arrives.
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
s.connect(('127.0.0.1', port))
s.settimeout(20)
s.sendall(b'GET /small.txt HTTP/1.1\r\nHost: x\r\n\r\n')
st, body, rest = answer(s, b'')
print('first', st.decode() if st else '-', len(body))
s.sendall(b'GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n')
s.shutdown(socket.SHUT_WR)
time.sleep(0.5)
st, body, rest = answer(s, rest)
print('second', st.decode() if st else '-', len(body))
EOF
)
grep -q '^first 200 6$' <<<"$out" && ok || bad "the first answer" "$out"
grep -q "^second 200 $((16 << 20))\$" <<<"$out" && ok || bad "the answer after the client's FIN is whole" "$out"

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
