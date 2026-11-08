#!/usr/bin/env bash
# Integration test: a group_send made by a callback the end of a worker's turn runs -- on_writable here -- reaches
# the room at once, and not only when some other completion next wakes the loop.
#
# What it would catch: a fan-out's writes started at the end of the turn by a flush placed before the turn's own
# callbacks, so what on_writable sent to the room waited for the next wake -- here for the slow reader whose queue
# fired it to read again: 48 to 225 ms here, against 0 with the writes started after them.
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

echo "=== Integration: a group_send from on_writable reaches the room at once ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
daemon_isolate fanoutturn
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 101))
trap 'daemon_stop' EXIT
daemon_start "$BIN"

cat > "$T/room.lua" <<'LUA'
local big = string.rep("x", 1024 * 1024)
function on_client_message(id, msg)
    if msg == "join" then
        self.join_group(id, "room")
        self.send(id, "joined")
    elseif msg == "fill" then
        -- One megabyte past the watermark, so the queue crosses back under it while the reader is still behind.
        for _ = 1, math.floor(self.watermark() / #big) + 1 do self.send(id, big) end
    end
    return true
end
function on_writable(id)
    self.group_send("room", "drained")
end
LUA
"$BIN" create server room -p "$P" --lua "$T/room.lua" -s >/dev/null 2>&1
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done

# The filler reads part of its queue, enough to bring it under the watermark, and then stops for PAUSE seconds;
# the member must hear "drained" well inside that pause.
timeout 60 python3 - "$P" > "$T/out" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
PAUSE = 2.0
rounds = []
for r in range(5):
    m = socket.create_connection(("127.0.0.1", port), 5); m.settimeout(10)
    m.sendall(b"join\n")
    buf = b""
    while b"joined\n" not in buf:
        buf += m.recv(4096)
    f = socket.socket(); f.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    f.connect(("127.0.0.1", port)); f.settimeout(10)
    f.sendall(b"fill\n")
    got = 0
    while got < 3 * (1 << 20):
        got += len(f.recv(1 << 16))
    paused = time.time()
    m.settimeout(PAUSE + 1)
    buf = b""
    try:
        while b"drained\n" not in buf:
            d = m.recv(4096)
            if not d: break
            buf += d
        heard = time.time() - paused
    except socket.timeout:
        heard = None
    f.close(); m.close()
    rounds.append(heard)
    time.sleep(0.2)
print(" ".join("none" if h is None else "%.0f" % (h * 1000) for h in rounds))
PY
GAPS=$(cat "$T/out")
echo "  ms from the reader's pause to the room hearing it: $GAPS"
# A round with no "drained" is not counted: when the kernel takes the whole fill at once the queue never crosses the
# watermark and on_writable has no reason to fire, on the tree before the change as well.
late=0; measured=0
for g in $GAPS; do [ "$g" = none ] && continue; measured=$((measured + 1)); [ "$g" -gt 25 ] && late=$((late + 1)); done
if [ "$measured" -ge 2 ] && [ $((late * 2)) -lt "$measured" ]; then ok
else bad "group_send from on_writable" "$late of $measured measured rounds heard it over 25 ms into the reader's pause: $GAPS"; fi

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
