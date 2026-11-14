#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: self.pending() while sends are staged says what the queue holds.
#
# What it would catch: a producer's self.pending() is answered in Lua from the stage while one is open -- the
# connection's queued bytes as of the last flush plus what is staged -- and self.pending(id) still asks C.  A queued
# figure not brought up to date where the queue changes under an open stage reads low or high, and a producer pacing
# on it stops early or overruns its watermark.  Every check compares the two, across stage flushes and drains.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: self.pending() while sends are staged ==="
daemon_isolate clipend
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1985))
unset SOCKETLEY_CONFIG
SRV_PID=""
trap '[ -n "$SRV_PID" ] && kill $SRV_PID 2>/dev/null; daemon_stop' EXIT

# A sink that reads in bursts with pauses between, so the queue fills, drains and fills again, and that reports the
# client's REPORT line.
cat > "$T/peer.py" <<'PY'
import socket, sys, time
l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind(("127.0.0.1", int(sys.argv[1]))); l.listen(1)
print("ready", flush=True)
c, _ = l.accept()
c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
buf = b""
end = time.time() + 60
while time.time() < end:
    d = c.recv(65536)
    if not d:
        break
    buf = buf[-200:] + d
    i = buf.find(b"REPORT ")
    if i >= 0 and b"\n" in buf[i:]:
        print("got", buf[i:buf.index(b"\n", i)].decode(), flush=True)
        break
    time.sleep(0.002)
time.sleep(2)
PY
# Lines of 64 B and of 200 B, the second past the stage's 128-byte limit so it goes through C and flushes the stage.
cat > "$T/pump.lua" <<'LUA'
local SHORT = string.rep("s", 63) .. "\n"
local LONG = string.rep("l", 199) .. "\n"
local checks, wrong, k, done = 0, 0, 0, false
local function pump()
  if done then return end
  local wm = self.watermark()
  while true do
    local a, b = self.pending(), self.pending(1)
    checks = checks + 1
    if a ~= b then wrong = wrong + 1 end
    if checks >= 400000 then
      done = true
      self.send("REPORT " .. checks .. " " .. wrong)
      return
    end
    if a >= wm then return end
    k = k + 1
    if not self.send(k % 50 == 0 and LONG or SHORT) then return end
  end
end
function on_connect() pump() end
function on_writable() pump() end
LUA

python3 "$T/peer.py" "$P" >"$T/peer.log" 2>&1 & SRV_PID=$!
for _ in $(seq 1 50); do grep -q ready "$T/peer.log" 2>/dev/null && break; sleep 0.1; done
daemon_start "$BIN"
"$BIN" create client pend -t "127.0.0.1:$P" --lua "$T/pump.lua" -s >/dev/null 2>&1
for _ in $(seq 1 600); do grep -q '^got' "$T/peer.log" 2>/dev/null && break; sleep 0.1; done

got=$(sed -n 's/^got //p' "$T/peer.log")
if [ "$got" = "REPORT 400000 0" ]; then ok; else
    bad "self.pending() agrees with self.pending(1) at every check" "client reported '${got:-nothing}', want 'REPORT 400000 0'"
fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
