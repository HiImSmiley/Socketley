#!/usr/bin/env python3
"""HTTP/3 at its edges, for test_storage_http3.sh, over aioquic.

usage:
  lib_storage_http3_edge.py migrate PORT CAFILE FILE   a client whose address changes every 300 packets, through a relay in
                                                       this process, puts FILE and reads it back; prints "same" or
                                                       what differed, then the relay's rebind count
  lib_storage_http3_edge.py halfopen PORT N            N handshakes begun from N ports and never finished
  lib_storage_http3_edge.py stalled PORT CAFILE PATH SECS  a GET whose answer the client holds back for SECS by its window,
                                                       then lets through; prints reset, whole, differs or closed
  lib_storage_http3_edge.py peer PORT CAFILE [CERT KEY]  one GET; prints the server certificate's serial and subject
                                                       and the status, or "refused" when the handshake fails
"""
import asyncio
import hashlib
import socket
import sys

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated


class Client(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.h3 = H3Connection(self._quic)
        self.waiting = {}
        self.closed = None

    def quic_event_received(self, ev):
        if isinstance(ev, ConnectionTerminated):
            self.closed = ev
            for st in self.waiting.values():
                st["done"].set()
            return
        for e in self.h3.handle_event(ev):
            st = self.waiting.get(e.stream_id)
            if st is None:
                continue
            if isinstance(e, HeadersReceived) and st["status"] is None:
                st["status"] = dict(e.headers).get(b":status", b"").decode()
            elif isinstance(e, DataReceived):
                st["body"].append(e.data)
            if getattr(e, "stream_ended", False):
                self.waiting.pop(e.stream_id, None)
                st["done"].set()

    async def request(self, method, path, body=None):
        sid = self._quic.get_next_available_stream_id()
        st = {"status": None, "body": [], "done": asyncio.Event()}
        self.waiting[sid] = st
        self.h3.send_headers(sid, [(b":method", method.encode()), (b":scheme", b"https"),
                                   (b":authority", b"localhost"), (b":path", path.encode())],
                             end_stream=body is None)
        if body is not None:
            for i in range(0, len(body), 1 << 16):
                self.h3.send_data(sid, body[i:i + (1 << 16)], end_stream=i + (1 << 16) >= len(body))
                self.transmit()
                await asyncio.sleep(0.002)
            if not body:
                self.h3.send_data(sid, b"", end_stream=True)
        self.transmit()
        await asyncio.wait_for(st["done"].wait(), 60)
        return st["status"], b"".join(st["body"])


def config(ca, cert=None, key=None):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, server_name="localhost",
                            max_stream_data=16 << 20, max_data=64 << 20)
    cfg.load_verify_locations(ca)
    if cert:
        cfg.load_cert_chain(cert, key)
    return cfg


async def open_client(port, cfg, via=None):
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    tr, p = await loop.create_datagram_endpoint(lambda: Client(QuicConnection(configuration=cfg)), sock=sock)
    p.connect(("127.0.0.1", via or port))
    await asyncio.wait_for(p.wait_connected(), 10)
    p._tr = tr
    return p


class Relay:
    """Carries one client's datagrams to the server from a source port that changes every `every` of them, so how
    often it moves does not depend on how fast the transfer goes."""

    def __init__(self, server_port, every):
        self.loop = asyncio.get_running_loop()
        self.server = ("127.0.0.1", server_port)
        self.down = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.down.bind(("127.0.0.1", 0))
        self.down.setblocking(False)
        self.port = self.down.getsockname()[1]
        self.client = None
        self.up = None
        self.rebinds = 0
        self.every = every
        self.sent = 0
        self.loop.add_reader(self.down, self.from_client)
        self.rebind()

    def rebind(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.setblocking(False)
        old, self.up = self.up, s
        self.loop.add_reader(s, lambda: self.from_server(s))
        if old is not None:
            self.rebinds += 1
            self.loop.call_later(1, lambda: (self.loop.remove_reader(old), old.close()))

    def from_client(self):
        while True:
            try:
                data, addr = self.down.recvfrom(65535)
            except BlockingIOError:
                return
            self.client = addr
            self.up.sendto(data, self.server)
            self.sent += 1
            if self.sent % self.every == 0:
                self.rebind()

    def from_server(self, s):
        while True:
            try:
                data, _ = s.recvfrom(65535)
            except (BlockingIOError, OSError):
                return
            if self.client:
                self.down.sendto(data, self.client)


async def migrate(port, ca, path):
    data = open(path, "rb").read()
    relay = Relay(port, 300)
    c = await open_client(port, config(ca), via=relay.port)
    put, _ = await c.request("PUT", "/hthree/moved", data)
    got, back = await c.request("GET", "/hthree/moved")
    same = hashlib.sha256(back).digest() == hashlib.sha256(data).digest()
    print("%s %s %s rebinds=%d" % (put, got, "same" if same else "differs (%d bytes)" % len(back), relay.rebinds))
    c.close()


def halfopen(port, n):
    socks = []
    for _ in range(n):
        q = QuicConnection(configuration=QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                                                           server_name="localhost"))
        q.connect(("127.0.0.1", port), now=0)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for data, _ in q.datagrams_to_send(now=0):
            s.sendto(data, ("127.0.0.1", port))
        socks.append(s)
    print("sent %d" % n)


async def peer(port, ca, cert=None, key=None):
    try:
        c = await open_client(port, config(ca, cert, key))
    except Exception:
        print("refused")
        return
    x = c._quic.tls._peer_certificate
    st, _ = await c.request("GET", "/")
    if st is None and c.closed is not None:
        print("refused")
        return
    print("%x %s %s" % (x.serial_number, x.subject.rfc4514_string(), st))
    c.close()


async def stalled(port, ca, path, wait):
    """A GET whose answer the client lets only the first bytes of through, by a window it does not open again, for
    `wait` seconds while it keeps the connection alive; meanwhile other objects are put and read, so memory the
    server let go of is used again. Then the window is opened. Prints what became of the answer: "reset" when the
    server gave the stream up, "whole" when every byte came and is the object's, "differs at N" when bytes came that
    are not the object's, "closed" when the connection ended instead."""
    want = None
    async def other(i):
        q = await open_client(port, config(ca))
        try:
            if i == 0:
                return (await q.request("GET", path))[1]
            body = bytes([0x41 + i % 20]) * (150000 + 4096 * i)
            await q.request("PUT", "/stall/churn%d" % i, body)
            await q.request("GET", "/stall/churn%d" % i)
        finally:
            q.close()
            q._tr.close()
    want = await other(0)
    cfg = config(ca)
    cfg.max_stream_data = 2048
    p = await open_client(port, cfg)
    quic = p._quic
    # The window is not opened while the answer is held: aioquic does that by itself as bytes arrive.
    limits, quic._write_stream_limits = quic._write_stream_limits, lambda *a, **k: None
    sid = quic.get_next_available_stream_id()
    st = {"status": None, "body": [], "done": asyncio.Event()}
    p.waiting[sid] = st
    reset = []
    seen = p.quic_event_received
    def watch(ev):
        if type(ev).__name__ == "StreamReset" and ev.stream_id == sid:
            reset.append(ev.error_code)
            st["done"].set()
        seen(ev)
    p.quic_event_received = watch
    p.h3.send_headers(sid, [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"localhost"),
                            (b":path", path.encode())], end_stream=True)
    p.transmit()
    for i in range(int(wait)):
        await asyncio.sleep(1)
        quic.send_ping(i)
        p.transmit()
        if i >= 5 and i % 2 == 1:
            await other(i)
    for i in range(1, 6):
        await other(40 + i)
    quic._write_stream_limits = limits
    for _ in range(40):
        if st["done"].is_set() or p.closed:
            break
        quic.send_ping(999)
        p.transmit()
        await asyncio.sleep(0.25)
    got = b"".join(st["body"])
    if reset:
        print("reset")
    elif p.closed and not st["done"].is_set():
        print("closed")
    elif got == want:
        print("whole")
    else:
        at = next((i for i in range(min(len(got), len(want))) if got[i] != want[i]), min(len(got), len(want)))
        print("differs at %d of %d (%d came)" % (at, len(want), len(got)))
    p.close()
    p._tr.close()


cmd = sys.argv[1]
if cmd == "migrate":
    asyncio.run(migrate(int(sys.argv[2]), sys.argv[3], sys.argv[4]))
elif cmd == "halfopen":
    halfopen(int(sys.argv[2]), int(sys.argv[3]))
elif cmd == "peer":
    asyncio.run(peer(int(sys.argv[2]), sys.argv[3], *sys.argv[4:6]))
elif cmd == "stalled":
    asyncio.run(stalled(int(sys.argv[2]), sys.argv[3], sys.argv[4], float(sys.argv[5])))
