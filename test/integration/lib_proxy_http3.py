#!/usr/bin/env python3
"""HTTP/3 against an entrance proxy, spoken with aioquic over QUIC.
usage: lib_proxy_http3.py PORT CAFILE BIGFILE

What it holds down is what forced the entrance to read the frames at all: each stream is routed by its own
`:authority`, so two names on ONE connection reach their two different runtimes, and a stream naming a name the
handshake did not is refused.  Plus the ordinary things -- an answer whole, a body up, several streams at once, and
a second request after one has ended.

Prints one PASS or FAIL line per assertion and a final "Results:" line, and exits with the number of failures.
"""
import asyncio
import contextlib
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

if int(aioquic.__version__.split(".")[0]) < 1:
    print("  SKIP: aioquic %s is older than 1.0 (pip install -U aioquic)" % aioquic.__version__)
    print("Results: 0 passed, 0 failed")
    sys.exit(0)

PORT = int(sys.argv[1])
CA, BIG = sys.argv[2], sys.argv[3]
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

    def begin(self, authority, path, method="GET", body=None):
        """Opens a stream and returns its state; the answer is awaited with finish()."""
        sid = self._quic.get_next_available_stream_id()
        hs = [(b":method", method.encode()), (b":scheme", b"https"),
              (b":authority", authority.encode()), (b":path", path.encode())]
        st = {"headers": None, "body": [], "done": asyncio.Event(), "reset": None}
        self.waiting[sid] = st
        self.h3.send_headers(sid, hs, end_stream=body is None)
        if body is not None:
            self.h3.send_data(sid, body, end_stream=True)
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
async def connection(server_name):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, max_stream_data=16 << 20, max_data=64 << 20)
    cfg.load_verify_locations(CA)
    cfg.server_name = server_name
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    transport, proto = await loop.create_datagram_endpoint(lambda: Client(QuicConnection(configuration=cfg)), sock=sock)
    try:
        proto.connect(("127.0.0.1", PORT))
        await asyncio.wait_for(proto.wait_connected(), 3)
        yield proto
    finally:
        proto.close()
        await proto.wait_closed()
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

    print("Results: %d passed, %d failed" % (PASS, FAIL))
    return FAIL


sys.exit(asyncio.run(main()))
