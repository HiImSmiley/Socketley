#!/usr/bin/env python3
"""HTTP/3 against an entrance proxy, spoken with aioquic over QUIC.
usage: lib_proxy_http3.py PORT CAFILE BIGFILE [PORT2]

PORT2 is an entrance with --backend-timeout 30 and --write-buffer 256K, in front of slow.example.com, whose backend
reads nothing of a request for three seconds.

What it holds down is what forced the entrance to read the frames at all: each stream is routed by its own
`:authority`, so two names on ONE connection reach their two different runtimes, and a stream naming a name the
handshake did not is refused.  Plus the ordinary things -- an answer whole, a body up, several streams at once, and
a second request after one has ended.

Prints one PASS or FAIL line per assertion and a final "Results:" line, and exits with the number of failures.
"""
import asyncio
import contextlib
import os
import socket
import sys

try:
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, StreamReset
    import aioquic
except ImportError:
    print("  SKIP: the python aioquic library is not installed (pip install aioquic)")
    print("Results: 0 passed, 0 failed")
    sys.exit(0)

if int(aioquic.__version__.split(".")[0]) < 1:
    print("  SKIP: aioquic %s is older than 1.0 (pip install -U aioquic)" % aioquic.__version__)
    print("Results: 0 passed, 0 failed")
    sys.exit(0)

PORT = int(sys.argv[1])
CA, BIG = sys.argv[2], sys.argv[3]
PORT2 = int(sys.argv[4]) if len(sys.argv) > 4 else 0
PASS = FAIL = 0


def check(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print("  PASS: " + name)
    else:
        FAIL += 1
        print("  FAIL [%s]: got %r, want %r" % (name, got, want))


class Client(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.h3 = H3Connection(self._quic)
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

    def begin(self, authority, path, method="GET", body=None, extra=(), part=None):
        """Opens a stream and returns its state; the answer is awaited with finish().  `part` is a first piece of a
        body sent without its end, the rest left to the caller."""
        sid = self._quic.get_next_available_stream_id()
        hs = [(b":method", method.encode()), (b":scheme", b"https"),
              (b":authority", authority.encode()), (b":path", path.encode())] + list(extra)
        st = {"headers": None, "body": [], "done": asyncio.Event(), "reset": None, "sid": sid}
        self.waiting[sid] = st
        self.h3.send_headers(sid, hs, end_stream=body is None and part is None)
        if body is not None:
            self.h3.send_data(sid, body, end_stream=True)
        elif part is not None:
            self.h3.send_data(sid, part, end_stream=False)
        self.transmit()
        return st

    @staticmethod
    async def finish(st, timeout=30):
        await asyncio.wait_for(st["done"].wait(), timeout)
        if st["reset"] is not None:
            return ("reset", b"")
        return (st["headers"].get(b":status", b"").decode(), b"".join(st["body"]))

    async def request(self, authority, path, method="GET", body=None):
        return await self.finish(self.begin(authority, path, method, body))


@contextlib.asynccontextmanager
async def connection(server_name, port=None, idle=None):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, max_stream_data=16 << 20, max_data=64 << 20)
    if idle is not None:
        cfg.idle_timeout = idle
    cfg.load_verify_locations(CA)
    cfg.server_name = server_name
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    transport, proto = await loop.create_datagram_endpoint(lambda: Client(QuicConnection(configuration=cfg)), sock=sock)
    try:
        proto.connect(("127.0.0.1", port or PORT))
        await asyncio.wait_for(proto.wait_connected(), 3)
        yield proto
    finally:
        proto.close()
        await proto.wait_closed()
        transport.close()


def peak_mib():
    """The largest peak resident size, in MiB, of the processes of this test's daemon."""
    want = ("SOCKETLEY_SOCKET=" + os.environ.get("SOCKETLEY_SOCKET", "")).encode()
    best = 0
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open("/proc/%s/environ" % d, "rb") as f:
                if want not in f.read().split(b"\0"):
                    continue
            with open("/proc/%s/status" % d) as f:
                for line in f:
                    if line.startswith("VmHWM:"):
                        best = max(best, int(line.split()[1]) // 1024)
        except OSError:
            pass
    return best


def qint(prefix_bits, first, v):
    m = (1 << prefix_bits) - 1
    if v < m:
        return bytes([first | v])
    out = [first | m]
    v -= m
    while v >= 128:
        out.append((v & 0x7f) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def varint(v):
    return bytes([v]) if v < 0x40 else (v | 0x4000).to_bytes(2, "big") if v < 0x4000 else (v | 0x80000000).to_bytes(4, "big")


class Raw(QuicConnectionProtocol):
    """QUIC with HTTP/3 written by hand, for what aioquic's own encoder would never send."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.got, self.closed = {}, None

    def quic_event_received(self, ev):
        if isinstance(ev, StreamDataReceived):
            self.got.setdefault(ev.stream_id, bytearray()).extend(ev.data)
        elif isinstance(ev, StreamReset):
            self.got[ev.stream_id] = "reset"
        elif isinstance(ev, ConnectionTerminated):
            self.closed = ev.error_code


async def qpack_expansion(authority, refs):
    """One 4000-byte field put into the entrance's QPACK table, then a request whose header block names it `refs`
    times at one byte each.  Answers what came back on the stream: its first bytes, "reset", or "closed"."""
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, max_stream_data=16 << 20, max_data=64 << 20)
    cfg.load_verify_locations(CA)
    cfg.server_name = authority
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    transport, proto = await loop.create_datagram_endpoint(lambda: Raw(QuicConnection(configuration=cfg)), sock=sock)
    try:
        proto.connect(("127.0.0.1", PORT))
        await asyncio.wait_for(proto.wait_connected(), 3)
        q = proto._quic
        q.send_stream_data(q.get_next_available_stream_id(is_unidirectional=True), b"\x00\x04\x00")
        value = b"A" * 4000
        q.send_stream_data(q.get_next_available_stream_id(is_unidirectional=True),
                           b"\x02" + qint(5, 0x20, 4096) + qint(5, 0x40, 3) + b"x-a" + qint(7, 0, len(value)) + value)
        q.send_stream_data(q.get_next_available_stream_id(is_unidirectional=True), b"\x03")
        block = bytes([2, 0, 0xD1, 0xD7, 0xC1]) + b"\x50" + qint(7, 0, len(authority)) + authority.encode()
        block += b"\x80" * refs
        sid = q.get_next_available_stream_id()
        q.send_stream_data(sid, b"\x01" + varint(len(block)) + block, end_stream=True)
        proto.transmit()
        for _ in range(150):
            await asyncio.sleep(0.1)
            if proto.closed is not None or sid in proto.got:
                break
        g = proto.got.get(sid)
        return "closed" if proto.closed is not None else "nothing" if g is None else g if isinstance(g, str) else bytes(g)
    finally:
        proto.close()
        transport.close()


async def main():
    big = open(BIG, "rb").read()

    # The entrance has to be up and its table read before a name routes anywhere.  Bounded tightly and with the
    # first failure reported rather than retried forty times: with no UDP socket there -- which is what
    # SOCKETLEY_PROXY_HTTP3=0 leaves -- a long wait per try made this file take ten minutes to say so.
    ready, why = False, "no answer"
    for _ in range(12):
        try:
            async with connection("one.example.com") as c:
                if (await c.request("one.example.com", "/who.txt"))[1].strip() == b"from-one":
                    ready = True
                    break
        except Exception as e:
            why = "%s: %s" % (type(e).__name__, e)
        await asyncio.sleep(0.25)
    if not ready:
        print("  FAIL [the entrance answers over HTTP/3 at all]: %s" % why)
        print("Results: 0 passed, 1 failed")
        return 1

    async with connection("one.example.com") as c:
        # Each stream is a client connection of the entrance's own, with a descriptor and a backend connection, so it
        # allows as few at once as its HTTP/2 does; the endpoint once offered every host's 128 whatever it asked for,
        # and one address's connections held a descriptor table's worth.
        check("the entrance allows eight streams at once on a connection, as over HTTP/2",
              c._quic._remote_max_streams_bidi, 8)
        check("a request over HTTP/3 is routed to the runtime its name has",
              await c.request("one.example.com", "/who.txt"), ("200", b"from-one\n"))

        # The reason the frames are read at all.  A browser coalesces names onto one connection whenever one
        # certificate covers them, and this connection's handshake named one.example.com: the second stream's own
        # `:authority` is the only thing that can tell the entrance it must not serve it from here.  421 is the
        # answer RFC 9110 15.5.22 gives for it, and the client opens its own connection and retries.
        a = c.begin("one.example.com", "/who.txt")
        b = c.begin("two.example.com", "/who.txt")
        check("two names coalesced onto one connection: the first is served, the second refused",
              (await Client.finish(a), (await Client.finish(b))[0]),
              (("200", b"from-one\n"), "421"))

        check("a large answer arrives whole over a stream",
              (await c.request("one.example.com", "/big.txt"))[1] == big, True)

        # A small body first, so a failure says whether it is the body path or the flow control over a window.
        small, _ = await c.request("one.example.com", "/who.txt", "POST", b"x" * 64)
        check("a small body up a stream reaches the backend and is answered (%s)" % small,
              small in ("200", "404", "405", "501"), True)

        st, _ = await c.request("one.example.com", "/who.txt", "POST", big)
        # The backend answers a POST to a path it does not serve with 404, 405 or 501; what is held down is that
        # the body's own frames reached it and it answered at all, with the status in the name so a failure says it.
        check("a body up a stream reaches the backend and is answered (%s)" % st,
              st in ("200", "404", "405", "501"), True)

        # Over the eight streams a session allows at once: every one must be answered, none lost and none hung.
        states = [c.begin("one.example.com", "/who.txt") for _ in range(20)]
        got = [await Client.finish(s) for s in states]
        check("twenty streams at once are all answered, over the bound of eight",
              sorted({g[0] for g in got}), ["200"])

        check("a stream ends, so the next request on the connection is answered too",
              await c.request("one.example.com", "/who.txt"), ("200", b"from-one\n"))

    # A header block is QPACK: one byte may name a 4000-byte field of the dynamic table, so 100 KB of them was 400 MB of
    # fields, all gathered before the head's size was judged -- 2.4 GB of peak memory from a 200 KB request.  The head
    # is measured as it arrives and gathered no further than its bound, and the request is answered 431.
    before = peak_mib()
    got = await qpack_expansion("one.example.com", 100000)
    after = peak_mib()
    check("a header block naming one 4000-byte field 100000 times is answered 431",
          "431" if isinstance(got, bytes) and b"431" in got[:16] else got, "431")
    check("and gathering it costs the entrance no more than 64 MiB of peak memory (%d -> %d MiB)" % (before, after),
          after - before < 64, True)

    # A body that stops: past the entrance's --backend-timeout (2 s here) the request is the client's to have lost,
    # and the stream is reset as a cancelled request, HTTP/2's CANCEL -- it was reset with H3_INTERNAL_ERROR, which
    # told the client the server had failed.
    async with connection("echo.example.com") as c:
        st = c.begin("echo.example.com", "/stall", "POST", None, [(b"content-length", b"20")], b"a" * 10)
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(st["done"].wait(), 10)
        check("a body that stops past --backend-timeout is reset as a cancelled request (0x10c)",
              hex(st["reset"]) if st["reset"] is not None else st["headers"], hex(0x10c))

    if PORT2:
        # A body that pauses longer than the QUIC idle timeout the client asked for, 2 s, and shorter than the
        # entrance's own --backend-timeout of 30: the entrance keeps the connection alive while the request is open,
        # where QUIC used to end it without a word at its idle timeout while HTTP/1.1 waited.
        async with connection("echo.example.com", PORT2, idle=2.0) as c:
            st = c.begin("echo.example.com", "/pause", "POST", None, [(b"content-length", b"20")], b"a" * 10)
            await asyncio.sleep(4)
            if c._quic._close_event is None:
                c.h3.send_data(st["sid"], b"b" * 10, end_stream=True)
                c.transmit()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(st["done"].wait(), 10)
            check("a body paused past the client's 2 s QUIC idle timeout, within the entrance's bounds, is answered",
                  (st["headers"] or {}).get(b":status", b"").decode() + " " + b"".join(st["body"]).decode(),
                  "200 len=20")

        # An upload faster than its backend reads: held while the backend's queue is over the watermark, as a TCP
        # client's reads are, rather than forwarded until the queue reached --write-buffer and the request was cut off.
        size = 32 << 20
        async with connection("slow.example.com", PORT2) as c:
            st = c.begin("slow.example.com", "/up", "POST", b"u" * size, [(b"content-length", b"%d" % size)])
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(st["done"].wait(), 60)
            check("a 32 MiB upload to a backend that reads nothing for 3 s arrives whole",
                  ("reset 0x%x" % st["reset"]) if st["reset"] is not None else
                  (st["headers"] or {}).get(b":status", b"").decode() + " " + b"".join(st["body"]).decode(),
                  "200 len=%d" % size)

    print("Results: %d passed, %d failed" % (PASS, FAIL))
    return FAIL


sys.exit(asyncio.run(main()))
