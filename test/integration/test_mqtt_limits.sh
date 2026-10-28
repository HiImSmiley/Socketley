#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# What one MQTT client may make the broker hold, and what it may take of another's.
#
# What each part would catch:
#   * an unfinished WebSocket frame held up to 16 MiB however small --max-packet is, before any CONNECT
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
. "$HERE/lib_ready.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
. "$HERE/lib_verdicts.sh"

echo "=== Integration: an mqtt client is held to its own share ==="
daemon_isolate mqttlimits
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1728))
PW=$((SL_PORT_BASE + 1729))
trap 'daemon_stop' EXIT
daemon_start "$BIN"

"$BIN" create mqtt lm -p "$P" --anonymous --ws "$PW" --max-packet 64K -s >/dev/null 2>&1 \
    && ok || bad "an anonymous broker with WebSocket is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for p in "$P" "$PW"; do ready_tcp 127.0.0.1 "$p" || bad "port $p listens" "$(tail -5 "$SOCKETLEY_DLOG")"; done

run() {
    PYTHONPATH="$HERE" python3 - "$1" "$P" "$PW" "$BIN" "$T" 2>&1 <<'PY'
import os, socket, struct, subprocess, sys, time
from lib_mqtt import *
phase, port, wsport, binary, tmpd = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5]

def ws_frame_cap():
    c = Client(wsport, ws="/mqtt", timeout=3)
    # A binary frame that says it is 1 MiB, of which 300 KiB come: more than four packets of --max-packet 64K.
    try:
        c.sock.sock.sendall(bytes([0x82, 0x80 | 127]) + struct.pack(">Q", 1 << 20) + os.urandom(4) +
                            b"\0" * (300 << 10))
    except OSError:
        pass
    truth("an unfinished WebSocket frame past four of the largest packets is refused at once", c.closed_within(3))
    w = Client(wsport, ws="/mqtt")
    check("a client over WebSocket is let in", w.connect("ws-big")[1], 0)
    code = w.publish("big/x", b"x" * (60 << 10), qos=1)
    truth("and a packet just under --max-packet in one frame is taken", code < 0x80, "PUBACK %#x" % code)
    w.disconnect()

if phase == "ws":
    guarded("ws frame cap", ws_frame_cap)
PY
}
tally < <(run ws)

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
