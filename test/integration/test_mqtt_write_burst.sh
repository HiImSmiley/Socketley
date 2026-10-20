#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a subscriber that reads as fast as it can is written as fast as it reads.
#
# ─── THE DEFECT ────────────────────────────────────────────────────────────
#
# A connection has one write in flight, and a write from one buffer was capped
# at 1 MiB.  A loop turn that read a publisher's burst queued far more than
# that for its subscriber, so the subscriber was sent 1 MiB a turn while the
# kernel's queue towards it sat empty, and a QoS 0 message past --write-buffer
# was dropped as if the subscriber were slow.
#
# ─── WHAT WAS MEASURED, AND ON WHICH BUILD ─────────────────────────────────
#
# 32f842c6, Release, one publisher sending 20,000 QoS 0 messages of 4,000
# bytes in one write, one subscriber reading in a loop:
#
#   --write-buffer 4M    11,275 of 20,000 delivered    -> fixed: 20,000
#   --write-buffer 16M   13,517 to 16,178 of 20,000    -> fixed: 20,000
#
# The same cap was a quarter of the broker's fan-in rate: one shard 1.37M
# messages a second, 4.80M without it.
#
# ─── HOW THIS IS ASSERTED ──────────────────────────────────────────────────
#
# --write-buffer 16M, so a reader the scheduler takes away for a moment under a
# parallel suite has 16 MiB before a drop would be the right answer; the
# broken build drops a third even so.  The broker's own dropped_slow is read
# beside the count, so a short count says whether the broker or the reader
# lost it.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
. "$HERE/lib_ready.sh"

PASS=0; FAIL=0
expect() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "  FAIL [$1]: got '$2', want '$3'"; fi; }

echo "=== Integration: a subscriber that keeps up is not dropped as slow ==="
daemon_isolate mqttburst
P=$((SL_PORT_BASE + 1930))
N=20000
trap 'daemon_stop' EXIT
daemon_start "$BIN"

"$BIN" create mqtt mb -p "$P" --anonymous --write-buffer 16M -s >/dev/null 2>&1 \
    || daemon_bail mb "the broker was not made"
ready_tcp 127.0.0.1 "$P" || daemon_bail mb "the broker does not listen"

GOT=$(PYTHONPATH="$HERE" python3 - "$P" "$N" 2>&1 <<'PY'
import socket, sys, threading
from lib_mqtt import Client, varint, s
port, count = int(sys.argv[1]), int(sys.argv[2])

sub = Client(port, version=4)
sub.connect(client_id="burst-sub")
sub.subscribe(("burst", 0))

# Counted off the raw socket, since a parser per message would be the slow
# subscriber this file is not about.
got = 0
def reader():
    global got
    sub.sock.settimeout(5.0)
    buf = bytearray()
    while got < count:
        try:
            d = sub.sock.recv(1 << 20)
        except socket.timeout:
            return
        if not d:
            return
        buf += d
        i = 0
        while len(buf) - i >= 2:
            n, mul, j = 0, 1, i + 1
            while j < len(buf):
                c = buf[j]; j += 1; n += (c & 0x7f) * mul; mul *= 128
                if not c & 0x80:
                    break
            else:
                break
            if len(buf) - j < n:
                break
            if buf[i] >> 4 == 3:
                got += 1
            i = j + n
        del buf[:i]

t = threading.Thread(target=reader)
t.start()
pub = Client(port, version=4)
pub.connect(client_id="burst-pub")
body = s("burst") + b"x" * 4000
pub.sock.sendall((bytes([0x30]) + varint(len(body)) + body) * count)
t.join(60)
print(got)
PY
)
# The worker pushes its counters on a timer, and a burst that went through at once is over before the first one.
STATS=""
for _ in $(seq 1 50); do
    STATS=$("$BIN" stats mb 2>/dev/null)
    [ "$(sed -n 's/^received_qos0://p' <<<"$STATS")" = "$N" ] && break
    sleep 0.2
done
# A counter at zero is left out of stats, so an absent dropped_slow is none; sent_qos0 says the stats were read.
SENT=$(sed -n 's/^sent_qos0://p' <<<"$STATS")
DROPPED=$(sed -n 's/^dropped_slow://p' <<<"$STATS")
DROPPED=${DROPPED:-0}
echo "  observed: $GOT of $N delivered, the broker sent ${SENT:-?} and dropped $DROPPED as slow"
# 11,275 on the broken build at 4M, 13,517 to 16,178 at 16M.
expect "every message of the burst reaches the subscriber" "$GOT" "$N"
expect "the broker says it sent every one"                 "$SENT" "$N"
expect "and dropped none of them as slow"                  "$DROPPED" "0"

echo ""
echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  PASSED" || echo "  FAILED"
exit "$FAIL"
