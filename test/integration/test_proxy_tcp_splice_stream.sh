#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a --protocol tcp proxy splices a side that streams and copies one that exchanges messages.
#
# What each part would catch:
#   * a stream never turned over to splice, which costs it two copies of every byte: no pipe in the worker
#   * a side turned over or back with bytes in flight on the copy path, which puts later bytes ahead of earlier
#   * a message exchange turned over at all, or a side that went back to copying and never answered again
#   * the end of a stream lost or sent early once spliced: the half-close after the last byte
#   * a splice that reads a blocking socket's empty queue as its peer's end, which ended every pair spliced from
#     its first byte after one message
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

echo "=== Integration: a TCP proxy splices a stream and copies messages ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_isolate tcpsplice
T=$(mktemp -d)
P=$((SL_PORT_BASE + 1997)); BE=$((P + 1))
unset SOCKETLEY_CONFIG SOCKETLEY_PROXY_SPLICE
ECHO_PID=""
trap '[ -n "$ECHO_PID" ] && kill $ECHO_PID 2>/dev/null; daemon_stop; rm -rf "$T"' EXIT

# An echo backend, one thread per connection, that closes its side once the client has closed its own.
cat > "$T/echo.py" <<'PY'
import socket, sys, threading
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind(("127.0.0.1", int(sys.argv[1]))); l.listen(64)
def serve(c):
    while True:
        d = c.recv(1 << 20)
        if not d:
            break
        c.sendall(d)
    c.shutdown(socket.SHUT_WR); c.close()
while True:
    c, _ = l.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
# The client: a stream of `mib` MiB both ways, then `msgs` messages one at a time, then its half-close, and the
# echo's end of stream awaited.  `pipes` is the most pipe ends the worker held, asked every 4 MiB of the stream.
cat > "$T/client.py" <<'PY'
import hashlib, os, socket, subprocess, sys, threading, time
port, mib, msgs, worker = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
s = socket.create_connection(("127.0.0.1", port)); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
blob = os.urandom(1 << 20); sent = hashlib.sha256(); got = hashlib.sha256(); total = mib << 20; seen = [0]; pipes = [0]
def pipes_now():
    try:
        return sum(1 for f in os.listdir("/proc/%s/fd" % worker) if os.readlink("/proc/%s/fd/%s" % (worker, f)).startswith("pipe:"))
    except OSError:
        return -1
def reader():
    while seen[0] < total:
        d = s.recv(1 << 20)
        if not d:
            break
        got.update(d); seen[0] += len(d)
        if seen[0] >> 22 != (seen[0] - len(d)) >> 22:
            pipes[0] = max(pipes[0], pipes_now())
r = threading.Thread(target=reader); r.start()
for i in range(mib):
    s.sendall(blob); sent.update(blob)
r.join()
ok_stream = seen[0] == total and sent.hexdigest() == got.hexdigest()
ok_msgs = True
s.settimeout(5)
for i in range(msgs):
    m = b"message-%06d" % i
    s.sendall(m); back = b""
    while len(back) < len(m):
        d = s.recv(64)
        if not d:
            break
        back += d
    ok_msgs = ok_msgs and back == m
after = pipes_now()
s.shutdown(socket.SHUT_WR)
tail = s.recv(16)
print("stream=%d msgs=%d eof=%d after=%d pipes=%d" % (ok_stream, ok_msgs, tail == b"", after, pipes[0]))
PY

python3 "$T/echo.py" "$BE" & ECHO_PID=$!
daemon_start "$BIN"
"$BIN" create proxy relay -p "$P" --protocol tcp --backend "127.0.0.1:$BE" -s >/dev/null 2>&1
for _ in $(seq 1 50); do ss -ltn | grep -q ":$P " && break; sleep 0.1; done
worker=$(ss -ltnp | awk -v p=":$P" '$4 ~ p"$" {match($0,/pid=[0-9]+/); print substr($0,RSTART+4,RLENGTH-4)}' | head -1)
pipes_of() { ls -l /proc/"$1"/fd 2>/dev/null | grep -c 'pipe:'; }
base_pipes=$(pipes_of "$worker")

out=$(timeout 60 python3 "$T/client.py" "$P" 64 0 "$worker")
expect "a 64 MiB stream both ways arrives whole and in order" "$(sed 's/ after=.*//; s/ msgs=[01]//' <<<"$out")" "stream=1 eof=1"
pipes=${out##*pipes=}
if [ "${pipes:-0}" -ge $((base_pipes + 2)) ]; then ok
else bad "and goes by splice, through a pipe per side" "the worker held $pipes pipe ends mid-stream, $base_pipes at rest"; fi

out=$(timeout 60 python3 "$T/client.py" "$P" 0 200 "$worker")
expect "messages one at a time are answered, and the end follows them" "$(sed 's/ after=.*//' <<<"$out")" "stream=1 msgs=1 eof=1"
expect "and a pair that only exchanges messages holds no pipe" "$(pipes_of "$worker")" "$base_pipes"

out=$(timeout 60 python3 "$T/client.py" "$P" 32 200 "$worker")
expect "a stream and then messages on one pair, each in order, the end last" "$(sed 's/ after=.*//' <<<"$out")" "stream=1 msgs=1 eof=1"
after=${out#* after=}; after=${after%% *}
expect "and its messages go back to copying, each side's pipe given back" "$after" "$base_pipes"

daemon_stop
daemon_isolate tcpsplice1
SOCKETLEY_PROXY_SPLICE=1 daemon_start "$BIN"
SOCKETLEY_PROXY_SPLICE=1 "$BIN" create proxy relay1 -p "$P" --protocol tcp --backend "127.0.0.1:$BE" -s >/dev/null 2>&1
for _ in $(seq 1 50); do ss -ltn | grep -q ":$P " && break; sleep 0.1; done
worker=$(ss -ltnp | awk -v p=":$P" '$4 ~ p"$" {match($0,/pid=[0-9]+/); print substr($0,RSTART+4,RLENGTH-4)}' | head -1)
if tr '\0' '\n' < /proc/"$worker"/environ 2>/dev/null | grep -qx 'SOCKETLEY_PROXY_SPLICE=1'; then ok
else bad "the worker spliced from the first byte is asked to" "SOCKETLEY_PROXY_SPLICE=1 is not in its environment"; fi
out=$(timeout 60 python3 "$T/client.py" "$P" 8 200 "$worker")
expect "spliced from its first byte, a stream and then messages, the end last" "$(sed 's/ after=.*//' <<<"$out")" "stream=1 msgs=1 eof=1"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
