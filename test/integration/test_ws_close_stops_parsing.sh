#!/usr/bin/env bash
# Integration test: nothing is processed after the connection is marked closing.
#
# The read path parsed everything still sitting in the buffer, no matter what an
# earlier message had done.  A WebSocket CLOSE frame sets the connection closing
# and queues the close response; frames behind it in the same write were then
# still parsed and dispatched, and the responses went into a queue the teardown
# immediately discarded.  So the server did the work, the peer never saw an
# answer, and RFC 6455 says those frames should not have been processed at all.
#
# Observable through the runtime's message counter: the trailing TEXT frame must
# not be counted.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# shellcheck source=lib_create.sh
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

# Own daemon, socket and state directory: against the shared one this test does
# not discriminate — leftover state and a warm daemon change what the server
# reads in a single go.
TMPDIR_T=$(mktemp -d /tmp/socketley-wsclose-XXXXXX)
export HOME="$TMPDIR_T/home"
export SOCKETLEY_SOCKET="$TMPDIR_T/daemon.sock"
mkdir -p "$HOME"
DPID=""

SRV_PORT=$((SL_PORT_BASE+288))
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    [ -n "$DPID" ] && kill "$DPID" 2>/dev/null || true
    rm -rf "$TMPDIR_T"
}
trap cleanup EXIT

echo "=== Integration: no parsing past a WebSocket close ==="

"$BIN" daemon >"$TMPDIR_T/daemon.log" 2>&1 &
DPID=$!
# Named so that a refused create can print what the daemon said about it; the
# CLI's own message is `could not start runtime` whenever the reason was found
# after the request reached the daemon.
SOCKETLEY_DLOG="$TMPDIR_T/daemon.log"
sleep 2

create_ok "server created" "$BIN" create server wsclose_srv -p "$SRV_PORT" -s
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$SRV_PORT" 2>/dev/null && break; sleep 0.1; done
sleep 0.3

# `|| true` on the pipeline, and the grep is what needs it: it exits 1 when
# there is no such field, which is the normal answer for a runtime a refused
# create never built, and `pipefail` makes that the status of the assignment —
# which, being a lone `VAR=$(…)`, is the status of the whole simple command.
# Under `set -euo pipefail` this line was therefore the entire file when a create
# failed: not one of its three assertions ran and no `Results` line printed.
#
# Empty is exactly the right value to carry forward.  The check immediately
# below already asks `[ -n "$BEFORE" ]` and prints "cannot read the message
# counter — is the runtime up?", which names the cause better than anything the
# assignment could have done; it only ever needed the file to still be running.
BEFORE=$("$BIN" stats wsclose_srv 2>/dev/null | grep '^total_messages:' | cut -d: -f2) || true
TOTAL=$((TOTAL+1))
if [ -n "$BEFORE" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: cannot read the message counter — is the runtime up?"
fi

# `|| true` here for the same reason as the captures either side of it, in the
# shape a bare command takes it — on the command line, because the heredoc body
# follows the redirection.  Under `set -e` this python was the end of the file
# whenever it could not connect, which is exactly what a refused create leaves
# behind: the run stopped on a traceback with no `Results` line and neither of
# the two assertions that follow.  Failing to deliver the frames is not a reason
# to stop asking what the counter did — it is the reason the counter did
# nothing, and the check below states that in one line instead of a stack trace.
python3 - "$SRV_PORT" <<'PYEOF' || true
import base64, os, socket, struct, sys, time

port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=5)
key = base64.b64encode(os.urandom(16)).decode()
s.sendall(f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n"
          f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
          f"Sec-WebSocket-Version: 13\r\n\r\n".encode())
buf = b""
while b"\r\n\r\n" not in buf:
    chunk = s.recv(4096)
    if not chunk:
        sys.exit("server closed during handshake")
    buf += chunk
if b"101" not in buf.split(b"\r\n")[0]:
    sys.exit("upgrade failed")

def frame(payload, opcode, fin=True):
    header = bytearray([(0x80 if fin else 0x00) | opcode])
    n = len(payload)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126); header += struct.pack("!H", n)
    else:
        header.append(0x80 | 127); header += struct.pack("!Q", n)
    mask = os.urandom(4)
    header += mask
    return bytes(header) + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

# CLOSE and TEXT in a single write, so both land in one read buffer.
s.sendall(frame(b"", 0x8) + frame(b"must-not-be-processed", 0x1))
# Give the server time to read and act on both frames before the socket goes
# away — closing immediately can mean the trailing frame is never read at all,
# which would make this test pass for the wrong reason.
time.sleep(0.6)
s.close()
PYEOF

sleep 1
AFTER=$("$BIN" stats wsclose_srv 2>/dev/null | grep '^total_messages:' | cut -d: -f2) || true

# The `-n` guards on both sides are load-bearing and stay that way: two unread
# counters are both empty, and "" = "" would report "no work past close" as a
# pass for a runtime that was never there.
TOTAL=$((TOTAL+1))
if [ -n "$BEFORE" ] && [ -n "$AFTER" ] && [ "$AFTER" = "$BEFORE" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [no work past close]: message counter went $BEFORE -> $AFTER;"
    echo "        the frame behind the close was parsed and its answer discarded"
fi

# The runtime has to survive it — stopping at closing must not skip the teardown.
TOTAL=$((TOTAL+1))
if "$BIN" stats wsclose_srv >/dev/null 2>&1; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [runtime alive]: server did not survive the close"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
