#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a client that spun through a stream goes quiet once the stream stops.
#
# What it would catch: a client spins its loop before sleeping while its reads are stream-sized, so a stream it
# drains faster than it arrives does not cost the sender a wake-up per write.  That spin is bounded by a credit
# every quiet turn spends; a credit that something kept refilling would leave a client that once read a stream
# burning its core for as long as the connection stays open with nothing on it.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a client goes quiet after a stream ==="
daemon_isolate clispin
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1983))
unset SOCKETLEY_CONFIG
SRV_PID=""
trap '[ -n "$SRV_PID" ] && kill $SRV_PID 2>/dev/null; daemon_stop' EXIT

# 32 MB of 64-byte lines as fast as the socket takes them, the client's count read back, and then the connection held
# open with nothing on it.
cat > "$T/peer.py" <<'PY'
import socket, sys, time
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind(("127.0.0.1", int(sys.argv[1]))); l.listen(1)
print("ready", flush=True)
c, _ = l.accept()
chunk = (b"s" * 63 + b"\n") * 16384
for _ in range(32):
    c.sendall(chunk)
c.sendall(b"END\n")
buf = b""
while b"\n" not in buf:
    d = c.recv(4096)
    if not d:
        break
    buf += d
print("got", buf.decode().strip(), flush=True)
time.sleep(60)
PY
cat > "$T/count.lua" <<'LUA'
local n = 0
function on_message(msg)
  if msg == "END" then self.send("done " .. n) else n = n + 1 end
end
LUA

python3 "$T/peer.py" "$P" >"$T/peer.log" 2>&1 & SRV_PID=$!
for _ in $(seq 1 50); do grep -q ready "$T/peer.log" 2>/dev/null && break; sleep 0.1; done
daemon_start "$BIN"
"$BIN" create client spin -t "127.0.0.1:$P" --lua "$T/count.lua" -s >/dev/null 2>&1
for _ in $(seq 1 300); do grep -q '^got' "$T/peer.log" 2>/dev/null && break; sleep 0.1; done

got=$(sed -n 's/^got //p' "$T/peer.log")
if [ "$got" = "done 524288" ]; then ok; else bad "the stream arrives whole" "client answered '${got:-nothing}'"; fi

# CPU ticks of every process of this daemon but the daemon itself, which is the client's worker.
ticks() {
    local p t=0
    for p in $(pgrep -x socketley); do
        [ "$p" = "$SOCKETLEY_DPID" ] && continue
        grep -qz "^SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET\$" "/proc/$p/environ" 2>/dev/null || continue
        t=$((t + $(awk '{print $14 + $15}' "/proc/$p/stat" 2>/dev/null || echo 0)))
    done
    echo "$t"
}
sleep 1
t0=$(ticks); sleep 3; t1=$(ticks)
hz=$(getconf CLK_TCK)
used=$((t1 - t0))
# A twentieth of a core over three seconds: an idle client spends nothing like it, a spinning one spends all of it.
if [ "$used" -lt $((hz * 3 / 20)) ]; then ok; else
    bad "an idle connection after a stream costs no core" "$used ticks of $((hz * 3)) in 3 s"
fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
