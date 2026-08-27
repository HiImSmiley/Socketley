#!/usr/bin/env python3
"""Reproduction: relay traffic lands ahead of a WebSocket handshake response.

Against a plain `server` runtime with no Lua, from N threads, each alternating
between two short-lived connections:

  odd  i -> connect, send "hello tcp <i>\\n", close.  Never reads.
  even i -> connect, send a WebSocket upgrade, read the reply, close.

The upgrade must be answered with "HTTP/1.1 101".  Sometimes the first bytes on
that connection are "hello tcp <i>\\n" instead, with the 101 arriving behind
them.

This is NOT a client receiving data it was not entitled to, and an earlier
version of this file said it was.  A server defaults to `--mode inout`, which
relays every client's messages to every other client -- man/socketley.1 calls it
"the default broadcast (in inout and master modes)".  The upgrader was always
going to receive that traffic, and does: after the handshake completes the same
client keeps receiving the same messages, correctly framed.  What is wrong is
the ORDER.  A connection joins the relay set when it is accepted, before its
first read has classified it, so relay bytes are written to it raw while its
HTTP request is still in flight -- and they arrive in front of the response to
that request, which is a corrupted handshake.

The control check below is kept, but it proves less than it looks: broadcast
excludes the sender, and the control connection is the only client at that
moment, so an unanswered line rules out an ECHO, not a relay.  The check that
matters is the mode comparison, same binary and workload back to back:

    --mode in    (no relay)          2000/2000 mixed operations, 0 foreign
    --mode inout (default, relays)   1996/2000,                  4 foreign

The failure needs the two connection kinds alternating on one thread; upgrades
alone are clean, and so are senders and upgraders in separate thread pools.

From 2a94cf2, the first implementation commit.

Usage: repro_ws_crosstalk.py [PORT] [ROUNDS]
Exits 1 if relay bytes ever preceded a handshake response.
"""
import collections
import socket
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 19090
ROUNDS = int(sys.argv[2]) if len(sys.argv) > 2 else 10
TOTAL, CONC = 200, 20

UPGRADE = (
    b"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
    b"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
)

foreign = collections.Counter()
other = collections.Counter()
lock = threading.Lock()


def upgrade_once():
    try:
        s = socket.create_connection(("127.0.0.1", PORT), 1.0)
        s.settimeout(1.0)
        s.sendall(UPGRADE)
        data = s.recv(256)
        s.close()
    except Exception as e:
        with lock:
            other[type(e).__name__] += 1
        return False
    if b"101" in data.split(b"\r\n")[0]:
        return True
    with lock:
        if b"hello tcp" in data:
            foreign[data.split(b"\n")[0].decode("latin-1", "replace")] += 1
        else:
            other[data[:40].decode("latin-1", "replace") or "empty"] += 1
    return False


def send_once(i):
    try:
        s = socket.create_connection(("127.0.0.1", PORT), 1.0)
        s.sendall(b"hello tcp %d\n" % i)
        s.close()
        return True
    except Exception as e:
        with lock:
            other["send:" + type(e).__name__] += 1
        return False


def control():
    """Rules out an echo, and only that.  broadcast() excludes the sender and
    this is the only client connected, so silence here says the server does not
    reply to its own sender -- it says nothing about what it relays to others.
    Kept because an echoing server would make the result unreadable, not because
    it establishes the defect."""
    s = socket.create_connection(("127.0.0.1", PORT), 1.0)
    s.settimeout(0.6)
    s.sendall(b"control\n")
    try:
        back = s.recv(256)
    except socket.timeout:
        back = b""
    s.close()
    return back


def run_round():
    results = []
    per = TOTAL // CONC

    def worker(base):
        mine = []
        for k in range(per):
            i = base + k
            mine.append(send_once(i) if i % 2 else upgrade_once())
        with lock:
            results.extend(mine)

    threads = [threading.Thread(target=worker, args=(j * per,)) for j in range(CONC)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return sum(results)


back = control()
if back:
    print("control: the server answered a plain line with %r — "
          "this reproduction cannot tell crosstalk from an echo, stopping" % back[:40])
    sys.exit(2)
print("control: a plain line goes unanswered, as it must")

ok = sum(run_round() for _ in range(ROUNDS))
total = ROUNDS * TOTAL
print("mixed operations: %d/%d" % (ok, total))
print("foreign payload delivered to an upgrade: %d" % sum(foreign.values()))
for k, v in foreign.items():
    print("   %-24s x%d" % (k, v))
if other:
    print("other failures: %s" % dict(other))

sys.exit(1 if foreign else 0)
