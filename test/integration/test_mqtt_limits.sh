#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# What one MQTT client may make the broker hold, and what it may take of another's.
#
# What each part would catch:
#   * an unfinished WebSocket frame held up to 16 MiB however small --max-packet is, before any CONNECT
#   * a WebSocket client that sends pings and reads no pongs read on regardless, its queue growing without end
#   * retained messages whose properties --retained-max does not count, so the store grows past it without end
#   * messages kept for one owner's away sessions bounded only in count, so many sessions hold memory without end
#   * a topic or filter of thousands of levels taken, whose walk through the topic trees ends the worker
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

"$BIN" create mqtt lm -p "$P" --anonymous --ws "$PW" --max-packet 64K --write-buffer 1M --retained-max 256K --queue-max 1M -s >/dev/null 2>&1 \
    && ok || bad "an anonymous broker with WebSocket is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for p in "$P" "$PW"; do ready_tcp 127.0.0.1 "$p" || bad "port $p listens" "$(tail -5 "$SOCKETLEY_DLOG")"; done

run() {
    PYTHONPATH="$HERE" python3 - "$1" "$P" "$PW" "$BIN" "$T" 2>&1 <<'PY'
import os, select, socket, struct, subprocess, sys, time
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

def ws_ping_flood():
    rmem = int(open("/proc/sys/net/ipv4/tcp_rmem").read().split()[2])
    wmem = int(open("/proc/sys/net/ipv4/tcp_wmem").read().split()[2])
    # The broker's hold at --write-buffer 1M, the buffers of both sockets on the way, and room over.
    bound = rmem + 2 * wmem + (2 << 20) + (4 << 20)
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
    raw.connect(("127.0.0.1", wsport))
    raw.settimeout(5)
    ws = WS(raw, "127.0.0.1", "/mqtt")
    body = s("MQTT") + bytes([4, 0x02]) + struct.pack(">H", 0) + s("ws-flood")
    ws.sendall(bytes([CONNECT << 4]) + varint(len(body)) + body)
    check("a 3.1.1 client with keep alive 0 is let in over WebSocket", ws.recv(4), b"\x20\x02\x00\x00")
    mask = os.urandom(4)
    ping = bytes([0x89, 0x80 | 125]) + mask + (mask * 32)[:125]
    chunk = ping * 1000
    raw.setblocking(False)
    sent, off, moved = 0, 0, time.time()
    end = moved + 15
    while time.time() < end and sent < 2 * bound:
        try:
            # A short send goes on where it stopped, since one begun again cuts a frame in two and is refused for it.
            n = raw.send(chunk[off:])
            sent += n
            off = (off + n) % len(chunk)
            moved = time.time()
        except BlockingIOError:
            if time.time() - moved > 2:
                break
            select.select([], [raw], [], 0.2)
    truth("pings from a client that reads no pongs stop being read (%d MiB taken)" % (sent >> 20), sent < bound)
    # Once it reads, it is read again: a PINGREQ behind every ping is answered, sent as the socket takes it.
    m = os.urandom(4)
    pending = chunk[off:off + (-off) % len(ping)] + bytes([0x82, 0x82]) + m + bytes([(PINGREQ << 4) ^ m[0], m[1]])
    end = time.time() + 30
    tail = b""
    got = False
    while time.time() < end and not got:
        if pending:
            try:
                pending = pending[raw.send(pending):]
            except BlockingIOError:
                pass
        r, _, _ = select.select([raw], [], [], 0.2)
        if not r:
            continue
        try:
            b = raw.recv(1 << 20)
        except BlockingIOError:
            continue
        if not b:
            break
        got = b"\x82\x02\xd0\x00" in tail + b
        tail = (tail + b)[-3:]
    truth("and once it reads its pongs it is read again, its PINGREQ answered", got)
    raw.close()

def deep_topics():
    # Another client, connected throughout: a worker that ends takes it with it.
    bystander = Client(port)
    check("a bystander is let in", bystander.connect("deep-bystander")[1], 0)
    c = Client(port)
    check("a client is let in", c.connect("deep")[1], 0)
    check("a filter of 256 levels is taken", c.subscribe(("/" * 255, 0)), [0])
    check("one of 257 is refused as no filter", c.subscribe(("/" * 256, 0)), [0x8F])
    check("one of 60000 is refused as no filter", c.subscribe(("/" * 59999, 0)), [0x8F])
    c.publish("/" * 255, b"x", qos=1)
    truth("a topic of 256 levels is published and delivered", any(m.payload == b"x" for m in c.messages(1, 3)))
    try:
        c.publish("/" * 59999, b"y", qos=1, retain=True)
    except Closed:
        pass
    truth("a PUBLISH to a topic of 60000 levels ends that client's connection", c.closed_within(3))
    try:
        served = bystander.ping()
    except (Closed, OSError):
        served = False
    truth("and the bystander is still served", served)
    if served:
        bystander.disconnect()

def retained_props():
    c = Client(port)
    check("a client is let in to retain", c.connect("props")[1], 0)
    # Each a one-byte payload with 60000 bytes of user property: the bound of 256K holds four, not a fifth.
    codes = [c.publish("keep/%d" % i, b"x", qos=1, retain=True, props={0x26: [("k", "v" * 60000)]}) for i in range(6)]
    check("retained messages are held to --retained-max with their properties counted",
          [x < 0x80 for x in codes], [True] * 4 + [False] * 2)
    check("and the refusal is the quota's", codes[5], 0x97)
    for i in range(6):
        c.publish("keep/%d" % i, b"", qos=1, retain=True)
    check("once cleared, the room is there again",
          c.publish("keep/again", b"x", qos=1, retain=True, props={0x26: [("k", "v" * 60000)]}) < 0x80, True)
    c.disconnect()

def held_for_owner():
    # Four sessions of one address, away, each subscribed to its own topic; twenty 60000-byte messages for each.
    for i in range(4):
        c = Client(port, version=4); c.connect("away%d" % i, clean=False); c.subscribe(("away/%d" % i, 1)); c.close()
    p = Client(port); p.connect("away-pub")
    for i in range(4):
        for _ in range(20):
            p.publish("away/%d" % i, b"z" * 60000, qos=1)
    p.disconnect()
    # The worker reports its figures every so often, so they are waited for.
    end = time.time() + 10
    while stat_sum(binary, "lm", "dropped_queue") == 0 and time.time() < end:
        time.sleep(0.3)
    held = stat_sum(binary, "lm", "queued")
    truth("what one owner's away sessions hold is bounded by --queue-max (%d of 80 kept)" % held, 0 < held <= 17)
    # What was kept is sent: the first session took the room, and the others found none.
    c = Client(port, version=4)
    c.connect("away0", clean=False)
    truth("and a session taken up again is sent what it kept", len(c.messages(1, 3)) == 1)
    c.close()

if phase == "held":
    guarded("held for owner", held_for_owner)

if phase == "props":
    guarded("retained properties", retained_props)

if phase == "deep":
    guarded("deep topics", deep_topics)

if phase == "ws":
    guarded("ws frame cap", ws_frame_cap)
    guarded("ws ping flood", ws_ping_flood)
PY
}
tally < <(run ws)
tally < <(run deep)
tally < <(run props)
tally < <(run held)

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
