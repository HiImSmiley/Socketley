#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a relay whose backend has half-closed and reads nothing waits for room without turning the loop.
#
# io_uring wakes every poll with EPOLLRDHUP, so the poll a spliced leg waits on for room in the backend's socket came
# back at once once that backend had sent its FIN, without POLLOUT; the splice answered EAGAIN, the poll was armed
# again, and the worker spent a whole core going round until the backend read.  The invariants build saw it as eight
# completions with nothing moving in test_proxy_relay_keeps_order.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
. "$HERE/lib_ready.sh"
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

daemon_isolate halfclosedbe
T=$SOCKETLEY_TMPD
PP=$((SL_PORT_BASE + 1640)); PB=$((SL_PORT_BASE + 1641))
BEPID=""
trap '[ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null; daemon_stop' EXIT

echo "=== Integration: a relay to a half-closed backend that reads nothing waits without turning the loop ==="

# A backend that says one line, sends its FIN and never reads, with as small a window as the kernel gives.
python3 - "$PB" > "$T/be.log" 2>&1 <<'PY' &
import socket, sys, time
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
srv.bind(("127.0.0.1", int(sys.argv[1]))); srv.listen(4)
held = []
while True:
    c, _ = srv.accept()
    c.sendall(b"hello\n")
    c.shutdown(socket.SHUT_WR)
    held.append(c)
PY
BEPID=$!
daemon_start "$BIN"
"$BIN" create proxy hcp -p "$PP" --backend "127.0.0.1:$PB" --protocol tcp -s >/dev/null 2>&1 \
    || bad "the proxy is made" "$(tail -3 "$SOCKETLEY_DLOG")"
ready_listening "$PP" 10 || bad "the proxy listens" "$(tail -5 "$SOCKETLEY_DLOG")"
WP=$("$BIN" stats hcp 2>/dev/null | sed -n 's/^pid://p' | head -1)

out=$(python3 - "$PP" "${WP:-0}" <<'PY'
import os, socket, sys, time
port, wpid = int(sys.argv[1]), int(sys.argv[2])
def ticks():
    with open("/proc/%d/stat" % wpid) as f:
        st = f.read().rsplit(")", 1)[1].split()
    return int(st[11]) + int(st[12])
c = socket.create_connection(("127.0.0.1", port), timeout=10)
c.recv(100)
c.setblocking(False)
# Full reads of a stream, which put the leg on the splice path, until nothing more fits anywhere on the way.
sent, block, idle = 0, b"x" * 65536, 0
while idle < 20:
    try:
        sent += c.send(block); idle = 0
    except BlockingIOError:
        idle += 1; time.sleep(0.05)
# Stuck: the backend reads nothing, so whatever the worker spends now is spent waiting.
t0, k0 = time.monotonic(), ticks()
time.sleep(3)
cores = (ticks() - k0) / os.sysconf("SC_CLK_TCK") / (time.monotonic() - t0)
print("%d %.2f" % (sent, cores))
PY
)
read -r sent cores <<<"$out"
echo "  ${sent:-?} bytes sent toward a backend that reads nothing; the worker spent ${cores:-?} cores while they waited"
[ "${sent:-0}" -gt 1048576 ] && ok "the stream filled the way to the backend (${sent} bytes)" \
    || bad "the stream filled the way to the backend" "only ${sent:-0} bytes went: $out"
# Round and round is a whole core; waiting is the pause between two askings, a few percent in any build.
awk -v c="${cores:-9}" 'BEGIN{exit !(c < 0.25)}' && ok "and the worker waited rather than turned (${cores} cores)" \
    || bad "the worker waits for room rather than turning its loop" "${cores:-?} cores while nothing could move"

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
