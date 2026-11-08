#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, directories and port window, so it runs beside the others
# Integration test: a client script that sends in a loop until self.pending() reaches self.watermark() fills its
# queue and is called back by on_writable, against a reader that keeps up.
#
# What it would catch: every line of such a loop going straight to the socket by sendmsg() while nothing was in
# flight, so the queue stayed empty, on_writable never fired and the one callback sent a syscall per line for as long
# as the socket took them -- 200 MB/s where the queued path moved 5 GB/s, and a benchmark run that stopped at 0 bytes.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a client producer pacing on the watermark fills its queue ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
daemon_isolate clientfill
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 102))
trap 'daemon_stop' EXIT

# A reader that takes everything as fast as it comes, for three seconds, and says how much it took.
cat > "$T/sink.py" <<'PY'
import socket, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(1)
print("READY", flush=True)
c, _ = s.accept(); c.settimeout(0.5)
tot, t0 = 0, time.time()
while time.time() - t0 < 3:
    try:
        d = c.recv(1 << 20)
    except socket.timeout:
        continue
    if not d:
        break
    tot += len(d)
print("BYTES %d" % tot, flush=True)
PY
cat > "$T/pump.lua" <<'LUA'
local LINE = string.rep("s", 63) .. "\n"
local fired = 0
local function pump()
    local wm = self.watermark()
    while self.pending() < wm do
        if not self.send(LINE) then return end
    end
end
function on_connect() pump() end
function on_writable()
    fired = fired + 1
    if fired == 3 then socketley.log("FILL writable fired 3 times") end
    pump()
end
LUA

python3 "$T/sink.py" "$P" > "$T/sink.out" 2>&1 &
SINK=$!
for _ in $(seq 1 50); do grep -q READY "$T/sink.out" 2>/dev/null && break; sleep 0.1; done
daemon_start "$BIN"
"$BIN" create client fill -t "127.0.0.1:$P" --lua "$T/pump.lua" -s >/dev/null 2>&1
wait "$SINK"
BYTES=$(grep -o 'BYTES [0-9]*' "$T/sink.out" | cut -d' ' -f2)
"$BIN" stop fill >/dev/null 2>&1
echo "  $((${BYTES:-0} >> 20)) MiB taken in 3 s"

if grep -q 'FILL writable fired 3 times' "$SOCKETLEY_DLOG" 2>/dev/null; then ok
else bad "the queue filled and on_writable called the producer back" \
         "on_writable fired fewer than 3 times in 3 s; $((${BYTES:-0} >> 20)) MiB reached the reader"; fi

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
