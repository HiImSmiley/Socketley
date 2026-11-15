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
  lib_storage_http3_edge.py crowd PORT CAFILE N        N connections from 127.0.0.1 held open, then one more from it
                                                       and one from 127.0.0.2; prints how many were kept and whether
                                                       each of the two was "served" or "refused"
  lib_storage_http3_edge.py critical PORT CAFILE CASE  one of the critical streams (RFC 9114 6.2.1, RFC 9204 4.2) ended,
                                                       asked to end, or opened twice: reset_ctrl fin_ctrl stop_srv_ctrl
                                                       fin_enc reset_dec dup_ctrl dup_enc dup_dec; prints the close the
                                                       server sent, "app 0x104", or "open" when none came in 3 s
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


async def open_client(port, cfg, via=None, src="127.0.0.1", wait=10):
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((src, 0))
    tr, p = await loop.create_datagram_endpoint(lambda: Client(QuicConnection(configuration=cfg)), sock=sock)
    p.connect(("127.0.0.1", via or port))
    p._tr = tr
    try:
        await asyncio.wait_for(p.wait_connected(), wait)
    except BaseException:
        tr.close()
        raise
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


async def crowd(port, ca, n):
    held = []
    for i in range(0, n, 16):
        batch = await asyncio.gather(*(open_client(port, config(ca)) for _ in range(min(16, n - i))),
                                     return_exceptions=True)
        held += [c for c in batch if not isinstance(c, BaseException)]

    async def one(src):
        try:
            c = await open_client(port, config(ca), src=src, wait=4)
        except BaseException:
            return "refused"
        st, _ = await c.request("GET", "/")
        c.close()
        c._tr.close()
        return "served" if st else "refused"

    more = await one("127.0.0.1")
    other = await one("127.0.0.2")
    print("kept %d, then %s, other %s" % (len(held), more, other))
    for c in held:
        c.close()
        c._tr.close()


class Bare(QuicConnectionProtocol):
    """A QUIC client with no HTTP/3 of its own, so its unidirectional streams are the caller's to write."""
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.closed = None

    def quic_event_received(self, ev):
        if isinstance(ev, ConnectionTerminated):
            self.closed = ev


async def critical(port, ca, case):
    from aioquic.buffer import encode_uint_var
    if case.startswith("dup_"):
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        tr, c = await loop.create_datagram_endpoint(lambda: Bare(QuicConnection(configuration=config(ca))), sock=sock)
        c.connect(("127.0.0.1", port))
        c._tr = tr
        await asyncio.wait_for(c.wait_connected(), 10)
    else:
        c = await open_client(port, config(ca))
    q = c._quic
    if case.startswith("dup_"):
        # The client's three unidirectional streams written by hand, one kind twice in place of another; a fourth
        # would be past the three the server allows.
        order = {"ctrl": [0x00, 0x02, 0x00], "enc": [0x00, 0x02, 0x02], "dec": [0x00, 0x03, 0x03]}[case[4:]]
        for i, t in enumerate(order):
            sid = q.get_next_available_stream_id(is_unidirectional=True)
            # a control stream begins with SETTINGS, here an empty one
            q.send_stream_data(sid, encode_uint_var(t) + (b"\x04\x00" if t == 0x00 and i == 0 else b""))
    else:
        h = c.h3
        c.transmit()
        await asyncio.sleep(0.3)
        ctrl, enc, dec = h._local_control_stream_id, h._local_encoder_stream_id, h._local_decoder_stream_id
        if case == "reset_ctrl":
            q.reset_stream(ctrl, 0x100)
        elif case == "fin_ctrl":
            q.send_stream_data(ctrl, b"", end_stream=True)
        elif case == "fin_enc":
            q.send_stream_data(enc, b"", end_stream=True)
        elif case == "reset_dec":
            q.reset_stream(dec, 0x100)
        elif case == "stop_srv_ctrl":
            # the server's control stream is the first stream it opens, 3
            q.stop_stream(3, 0x100)
    c.transmit()
    for _ in range(30):
        if c.closed is not None:
            break
        await asyncio.sleep(0.1)
    t = c.closed
    if t is None:
        print("open")
    else:
        # aioquic gives an application close no frame type, and a transport close the type of the frame it was for
        print("%s 0x%x" % ("app" if t.frame_type is None else "transport", t.error_code))
    c._tr.close()


cmd = sys.argv[1]
if cmd == "migrate":
    asyncio.run(migrate(int(sys.argv[2]), sys.argv[3], sys.argv[4]))
elif cmd == "halfopen":
    halfopen(int(sys.argv[2]), int(sys.argv[3]))
elif cmd == "peer":
    asyncio.run(peer(int(sys.argv[2]), sys.argv[3], *sys.argv[4:6]))
elif cmd == "crowd":
    asyncio.run(crowd(int(sys.argv[2]), sys.argv[3], int(sys.argv[4])))
elif cmd == "critical":
    asyncio.run(critical(int(sys.argv[2]), sys.argv[3], sys.argv[4]))
elif cmd == "stalled":
    asyncio.run(stalled(int(sys.argv[2]), sys.argv[3], sys.argv[4], float(sys.argv[5])))
