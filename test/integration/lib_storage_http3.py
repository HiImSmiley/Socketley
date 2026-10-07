#!/usr/bin/env python3
"""HTTP/3 against a storage runtime with --tls, spoken with aioquic over QUIC.

usage: lib_storage_http3.py PORT CAFILE BIGFILE

A bucket made, a large object put and read back byte for byte, HEAD, a Range, a missing key, a listing and the web
interface's page; twenty requests in parallel and four hundred one after another on one connection, more than the
128 streams it may have open at once; uploads and downloads abandoned midway, after which the runtime still serves.

Prints one PASS or FAIL line per assertion and a final "Results:" line, and exits with the number of failures.
"""
import asyncio
import contextlib
import hashlib
import socket
import sys

try:
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    from aioquic.quic.events import StreamReset
    import aioquic
except ImportError:
    print("  SKIP: the python aioquic library is not installed (pip install aioquic)")
    print("Results: 0 passed, 0 failed")
    sys.exit(0)
# 0.9 (Ubuntu 24.04's python3-aioquic) opens no new stream on a connection after resetting one, so the abandoned
# upload below would fail on the client's side.
if int(aioquic.__version__.split(".")[0]) < 1:
    print("  SKIP: aioquic %s is older than 1.0 (pip install -U aioquic)" % aioquic.__version__)
    print("Results: 0 passed, 0 failed")
    sys.exit(0)

PORT = int(sys.argv[1])
CA, BIG = sys.argv[2], sys.argv[3]
AUTH = "localhost:%d" % PORT
PASS = FAIL = 0


def check(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print("  PASS: " + name)
    else:
        FAIL += 1
        print("  FAIL [%s]: got %r, want %r" % (name, got, want))


class H3(H3Connection):
    # aioquic holds a HEAD's answer to its content-length as if it had a body; RFC 9110 9.3.2 says it has none.
    def __init__(self, quic):
        super().__init__(quic)
        self.heads = set()

    def _check_content_length(self, stream):
        if stream.stream_id not in self.heads:
            super()._check_content_length(stream)


class Client(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.h3 = H3(self._quic)
        self.waiting = {}

    def quic_event_received(self, ev):
        if isinstance(ev, StreamReset) and ev.stream_id in self.waiting:
            st = self.waiting.pop(ev.stream_id)
            st["reset"] = ev.error_code
            st["done"].set()
            return
        for e in self.h3.handle_event(ev):
            st = self.waiting.get(e.stream_id)
            if st is None:
                continue
            if isinstance(e, HeadersReceived) and st["headers"] is None:
                st["headers"] = dict(e.headers)
            elif isinstance(e, DataReceived):
                st["body"].append(e.data)
            if getattr(e, "stream_ended", False):
                self.waiting.pop(e.stream_id, None)
                st["done"].set()

    async def request(self, method, path, body=None, headers=(), stop_after=None):
        """The answer as (status, body); with stop_after, only sends that much of the body and abandons the stream."""
        sid = self._quic.get_next_available_stream_id()
        hs = [(b":method", method.encode()), (b":scheme", b"https"), (b":authority", AUTH.encode()),
              (b":path", path.encode())] + [(k.encode(), v.encode()) for k, v in headers]
        st = {"headers": None, "body": [], "done": asyncio.Event(), "reset": None}
        self.waiting[sid] = st
        if method == "HEAD":
            self.h3.heads.add(sid)
        self.h3.send_headers(sid, hs, end_stream=body is None)
        if body is not None:
            sent, step = 0, 1 << 18
            while True:
                piece = body[sent:sent + step]
                sent += len(piece)
                last = sent >= len(body)
                if stop_after is not None and sent >= stop_after:
                    self._quic.reset_stream(sid, 0x10c)   # H3_REQUEST_CANCELLED
                    self.transmit()
                    self.waiting.pop(sid, None)
                    return None
                self.h3.send_data(sid, piece, end_stream=last)
                self.transmit()
                await asyncio.sleep(0)
                if last:
                    break
        self.transmit()
        await asyncio.wait_for(st["done"].wait(), 60)
        if st["reset"] is not None:
            return ("reset", b"")
        return (st["headers"].get(b":status", b"").decode(), b"".join(st["body"]))


@contextlib.asynccontextmanager
async def connection():
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, max_stream_data=16 << 20, max_data=64 << 20)
    cfg.load_verify_locations(CA)
    cfg.server_name = "localhost"
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    transport, proto = await loop.create_datagram_endpoint(lambda: Client(QuicConnection(configuration=cfg)), sock=sock)
    try:
        proto.connect(("127.0.0.1", PORT))
        await asyncio.wait_for(proto.wait_connected(), 10)
        yield proto
    finally:
        proto.close()
        await proto.wait_closed()
        transport.close()


async def main():
    big = open(BIG, "rb").read()
    digest = hashlib.sha256(big).hexdigest()
    async with connection() as c:
        check("a bucket is made", (await c.request("PUT", "/hthree"))[0], "200")
        check("a large object is put", (await c.request("PUT", "/hthree/big", big))[0], "200")
        st, data = await c.request("GET", "/hthree/big")
        check("and read back byte for byte", (st, hashlib.sha256(data).hexdigest()), ("200", digest))
        st, data = await c.request("HEAD", "/hthree/big")
        check("a HEAD gives its length and no body", (st, len(data)), ("200", 0))
        st, data = await c.request("GET", "/hthree/big", headers=[("range", "bytes=1000-1999")])
        check("a Range is exact", (st, data), ("206", big[1000:2000]))
        check("a body put is stored", (await c.request("PUT", "/hthree/s.txt", b"streamed"))[0], "200")
        st, data = await c.request("GET", "/hthree/none")
        check("a missing key is 404 with its XML", (st, b"<Code>NoSuchKey</Code>" in data), ("404", True))
        st, data = await c.request("GET", "/hthree?list-type=2")
        check("a listing names both", (st, data.count(b"<Key>")), ("200", 2))
        st, data = await c.request("GET", "/~ui/")
        check("the web interface's page is served", (st, b"<html" in data), ("200", True))
        res = await asyncio.gather(*[c.request("GET", "/hthree/s.txt") for _ in range(20)])
        check("twenty requests in parallel on one connection", sorted(set(res)), [("200", b"streamed")])
        ok = 0
        for _ in range(8):
            res = await asyncio.gather(*[c.request("GET", "/hthree/s.txt") for _ in range(50)])
            ok += sum(1 for r in res if r == ("200", b"streamed"))
        check("four hundred more on the same connection, past its 128 streams", ok, 400)

    # Abandoned midway: an upload reset after a part of its body, a download whose connection goes.
    async with connection() as c:
        await c.request("PUT", "/hthree/cut", big, stop_after=len(big) // 3)
        st, _ = await c.request("GET", "/hthree/cut")
        check("an upload reset midway leaves no object", st, "404")
    for _ in range(3):
        with contextlib.suppress(asyncio.TimeoutError):
            async with connection() as c:
                await asyncio.wait_for(c.request("GET", "/hthree/big"), 0.05)
    async with connection() as c:
        st, data = await c.request("GET", "/hthree/big")
        check("after downloads cut off, the object is still read whole", (st, hashlib.sha256(data).hexdigest()),
              ("200", digest))


asyncio.run(main())
print("Results: %d passed, %d failed" % (PASS, FAIL))
sys.exit(FAIL)
