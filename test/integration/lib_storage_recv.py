#!/usr/bin/env python3
"""How the storage runtime's connections receive, spoken raw.

usage: lib_storage_recv.py PORT BIN NAME MODE

MODE is what the daemon was started with: "default" (a buffer ring and one recv
that keeps delivering), "single" (SOCKETLEY_RECV_MULTISHOT=0), "tiny"
(SOCKETLEY_STORAGE_RECV_BUFS=2, a ring that runs dry) or "none"
(SOCKETLEY_STORAGE_RECV_BUFS=0, no ring at all).  The requests are the same in
all four and every answer is checked byte for byte, because what changes is
where the bytes are read into and not what the client is owed.

Prints one PASS or FAIL line per assertion and a final "Results:" line, and
exits with the number of failures.
"""
import hashlib
import os
import socket
import subprocess
import sys
import threading
import time

PORT = int(sys.argv[1])
BIN = sys.argv[2]
NAME = sys.argv[3]
MODE = sys.argv[4]

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: [%s] %s" % (MODE, name))
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, detail))


def stats():
    out = subprocess.run([BIN, "stats", NAME], capture_output=True, text=True).stdout
    d = {}
    for line in out.splitlines():
        k, _, v = line.partition(":")
        d[k.strip()] = v.strip()
    return d


def counter(key):
    """A counter once the worker has reported: its stats trail the traffic by a moment, so wait until they stop moving."""
    last = None
    for _ in range(20):
        time.sleep(0.7)
        d = stats()
        now = (d.get("requests"), d.get("recv_cancels"), d.get("recv_fallbacks"), d.get("recv_direct_bytes"))
        if now == last:
            return int(d.get(key, "0"))
        last = now
    return int(d.get(key, "0"))


def pattern(n, seed):
    """Bytes that differ with the seed and with every position."""
    block = hashlib.sha256(b"recv-%d" % seed).digest() * 128
    reps = n // len(block) + 1
    return (block * reps)[:n]


class Conn:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", PORT), 10)
        self.s.settimeout(30)
        self.buf = b""

    def send(self, data):
        self.s.sendall(data)

    def _fill(self):
        d = self.s.recv(1 << 20)
        if not d:
            raise EOFError("closed")
        self.buf += d

    def response(self, head_only=False):
        """One response: (status, headers, body), whatever follows kept."""
        while b"\r\n\r\n" not in self.buf:
            self._fill()
        head, _, rest = self.buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        status = int(lines[0].split()[1])
        headers = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(b":")
            headers[k.strip().lower().decode()] = v.strip().decode()
        need = 0 if head_only or status in (100, 204, 304) else int(headers.get("content-length", "0"))
        self.buf = rest
        while len(self.buf) < need:
            self._fill()
        body, self.buf = self.buf[:need], self.buf[need:]
        return status, headers, body

    def eof(self):
        """Everything up to the peer's close."""
        try:
            while True:
                self._fill()
        except EOFError:
            return self.buf

    def close(self):
        self.s.close()


def put_req(path, body, extra=""):
    return ("PUT %s HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n%s\r\n" % (path, len(body), extra)).encode() + body


def get_req(path, method="GET", extra=""):
    return ("%s %s HTTP/1.1\r\nHost: x\r\n%s\r\n" % (method, path, extra)).encode()


def put(path, body):
    c = Conn()
    c.send(put_req(path, body))
    st, _, _ = c.response()
    c.close()
    return st


def get(path):
    c = Conn()
    c.send(get_req(path))
    st, _, body = c.response()
    c.close()
    return st, body


c0 = Conn()
c0.send(("PUT /rbk HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n").encode())
check("the bucket is made", c0.response()[0] in (200, 409))
c0.close()

BIG = pattern(300 * 1024, 1)
check("a 300 KiB object is stored", put("/rbk/big", BIG) == 200)
HUGE = pattern(8 * 1024 * 1024, 2)
check("an 8 MiB object is stored", put("/rbk/huge", HUGE) == 200)
SMALL = pattern(2000, 3)
check("a 2000 byte object is stored", put("/rbk/small", SMALL) == 200)

# ── requests sent ahead of the answer to the one before ─────────────────────
c = Conn()
c.send(b"".join(get_req("/rbk/big") for _ in range(40)))
ok = True
for i in range(40):
    st, _, body = c.response()
    if st != 200 or body != BIG:
        ok = False
        break
check("forty pipelined GETs are each answered, in order", ok, "response %d" % i)
c.close()

c = Conn()
c.send(get_req("/rbk/big") + get_req("/rbk/small", "HEAD") + get_req("/rbk/small") + get_req("/rbk/nothing"))
st1, _, b1 = c.response()
st2, h2, _ = c.response(head_only=True)
st3, _, b3 = c.response()
st4, _, _ = c.response()
check("a GET, a HEAD, a GET and a miss sent together are answered in order",
      (st1, b1 == BIG, st2, h2.get("content-length"), st3, b3 == SMALL, st4) ==
      (200, True, 200, "2000", 200, True, 404), str((st1, st2, st3, st4)))
c.close()

# ── a peer that has said all it will say still gets its answer ──────────────
c = Conn()
c.send(get_req("/rbk/huge"))
c.s.shutdown(socket.SHUT_WR)
raw = c.eof()
head, _, body = raw.partition(b"\r\n\r\n")
check("a request followed by a half-close is answered whole", head.startswith(b"HTTP/1.1 200") and body == HUGE,
      "%d body bytes" % len(body))
c.close()

c = Conn()
c.send(get_req("/rbk/big") + get_req("/rbk/small"))
c.s.shutdown(socket.SHUT_WR)
raw = c.eof()
check("two requests followed by a half-close are both answered", raw.count(b"HTTP/1.1 200") == 2 and
      raw.endswith(SMALL), "%d bytes" % len(raw))
c.close()

# ── more sent ahead than the runtime will hold is taken up again later ──────
before = counter("recv_cancels")
c = Conn()
N = 16000
heads = get_req("/rbk/small", "HEAD")
c.send(get_req("/rbk/huge"))
sender = threading.Thread(target=lambda: c.send(heads * N))
sender.start()
cancels = counter("recv_cancels") - before
if MODE == "default":
    check("what piled up behind an unread answer stopped the recv that delivers it", cancels >= 1, str(cancels))
st, _, body = c.response()
ok = st == 200 and body == HUGE
n = 0
try:
    for n in range(N):
        st, h, _ = c.response(head_only=True)
        if st != 200 or h.get("content-length") != "2000":
            ok = False
            break
    else:
        n = N
except Exception as e:
    ok = False
    print("    %r after %d" % (e, n))
sender.join()
check("and every one of %d requests behind an 8 MiB answer is answered after it" % N, ok and n == N, "n=%d" % n)
c.close()

# ── bodies, from the smallest to what is read where it is written ───────────
for size in (0, 1, 4096, 20000, 32 * 1024 - 1, 32 * 1024, 100000, 1 << 20):
    body = pattern(size, 10 + size)
    st = put("/rbk/p%d" % size, body)
    st2, back = get("/rbk/p%d" % size)
    check("a %d byte body arrives with its head and reads back" % size, st == 200 and st2 == 200 and back == body,
          "%s %s %d" % (st, st2, len(back)))

d0 = counter("recv_direct_bytes")
for size in (4096, 20000, 32 * 1024 - 1):
    body = pattern(size, size)
    c = Conn()
    raw = put_req("/rbk/s%d" % size, body)
    c.send(raw[:len(raw) - size])
    time.sleep(0.1)
    c.send(body)
    check("a %d byte body that follows its head is stored" % size, c.response()[0] == 200)
    c.close()
check("bodies under 32 KiB that follow their head are taken from the ring's buffers and none is read directly",
      counter("recv_direct_bytes") == d0, str(counter("recv_direct_bytes") - d0))

body = pattern(5 << 20, 20)
before = counter("recv_cancels")
direct_before = counter("recv_direct_bytes")
c = Conn()
c.send(("PUT /rbk/cont HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nExpect: 100-continue\r\n\r\n" % len(body)).encode())
st, _, _ = c.response()
check("100-continue is answered before any of the body is sent", st == 100, str(st))
for off in range(0, len(body), 65536):
    c.send(body[off:off + 65536])
st, h, _ = c.response()
check("a 5 MiB body sent in pieces after 100-continue is stored", st == 200 and h.get("etag") == '"%s"' % hashlib.md5(body).hexdigest(), str((st, h.get("etag"))))
c.close()
st, back = get("/rbk/cont")
check("and reads back", st == 200 and back == body)
direct = counter("recv_direct_bytes") - direct_before
check("all but the first few hundred kilobytes of a 5 MiB body were read straight into the put's buffer", direct >= 4 << 20,
      str(direct))
if MODE == "default":
    check("and the recv that keeps delivering was taken back once to make it so", counter("recv_cancels") - before >= 1)

# the head and the first bytes of the body in one segment, the rest a moment later
body = pattern(3 << 20, 21)
c = Conn()
c.send(put_req("/rbk/split", body)[:5000])
time.sleep(0.3)
c.send(put_req("/rbk/split", body)[5000:])
st, _, _ = c.response()
c.close()
st2, back = get("/rbk/split")
check("a body begun with its head and finished after a pause is stored whole", st == 200 and back == body)

# a body a few hundred bytes at a time
body = pattern(100000, 22)
raw = put_req("/rbk/trickle", body)
c = Conn()
for off in range(0, len(raw), 700):
    c.send(raw[off:off + 700])
    if off % 7000 == 0:
        time.sleep(0.005)
st, _, _ = c.response()
c.close()
st2, back = get("/rbk/trickle")
check("a body sent in 700 byte pieces is stored whole", st == 200 and back == body)

# the same body as chunks
body = pattern(3 << 20, 23)
c = Conn()
c.send(b"PUT /rbk/chunked HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
for off in range(0, len(body), 16384):
    piece = body[off:off + 16384]
    c.send(b"%x\r\n" % len(piece) + piece + b"\r\n")
c.send(b"0\r\n\r\n")
st, _, _ = c.response()
c.close()
st2, back = get("/rbk/chunked")
check("a 3 MiB chunked body is stored whole", st == 200 and back == body, str((st, len(back))))

# requests that follow a body in the same segment
b1, b2 = pattern(3000, 30), pattern(7000, 31)
c = Conn()
c.send(put_req("/rbk/pa", b1) + put_req("/rbk/pb", b2) + get_req("/rbk/pb") + get_req("/rbk/pa"))
r = [c.response() for _ in range(4)]
check("two puts and two gets in one segment are answered in order",
      [x[0] for x in r] == [200, 200, 200, 200] and r[2][2] == b2 and r[3][2] == b1)
c.close()

# ── a body refused before it was read, and the request after it ─────────────
body = pattern(200000, 40)
c = Conn()
c.send(("PUT /rbk/small HTTP/1.1\r\nHost: x\r\nIf-None-Match: *\r\nContent-Length: %d\r\n\r\n" % len(body)).encode() + body +
       get_req("/rbk/small"))
st1, _, _ = c.response()
st2, _, b2 = c.response()
check("a refused body is read and dropped, and the request behind it answered", st1 == 412 and st2 == 200 and b2 == SMALL, str((st1, st2)))
c.close()

# ── a head that never finishes, and one that arrives in pieces ──────────────
c = Conn()
raw = get_req("/rbk/small")
for i in range(0, len(raw), 3):
    c.send(raw[i:i + 3])
    time.sleep(0.002)
st, _, b = c.response()
check("a head sent three bytes at a time is parsed", st == 200 and b == SMALL)
c.close()

c = Conn()
c.send(b"GET /rbk/small HTTP/1.1\r\nHost: x\r\nX-Half: ")
c.close()
st, b = get("/rbk/small")
check("a head cut off by the peer leaves the runtime serving", st == 200 and b == SMALL)

# ── idle connections come back to life ──────────────────────────────────────
idle = [Conn() for _ in range(300)]
time.sleep(0.3)
ok = True
for c in idle:
    c.send(get_req("/rbk/small"))
for c in idle:
    st, _, b = c.response()
    ok = ok and st == 200 and b == SMALL
check("three hundred idle connections each answer the request they then send", ok)
for c in idle:
    c.send(get_req("/rbk/small"))
ok = True
for c in idle:
    st, _, b = c.response()
    ok = ok and st == 200 and b == SMALL
check("and a second request on each", ok)
for c in idle:
    c.close()

# ── a buffer lent is given back ─────────────────────────────────────────────
before = counter("recv_fallbacks")
c = Conn()
ok = True
for i in range(300):
    c.send(get_req("/rbk/small"))
    st, _, b = c.response()
    ok = ok and st == 200 and b == SMALL
c.close()
check("300 requests one after another are each answered", ok)
check("and none of them found the ring empty, so every buffer it lent came back", counter("recv_fallbacks") == before,
      str(counter("recv_fallbacks") - before))

# ── many at once, the ring under more completions than it has buffers ───────
errs = []
before = counter("recv_fallbacks")


def worker(i):
    try:
        c = Conn()
        for r in range(40):
            body = pattern(1000 + (i * 97 + r * 31) % 40000, 1000 + i * 100 + r)
            path = "/rbk/w%d_%d" % (i, r % 3)
            c.send(put_req(path, body) + get_req(path))
            st, _, _ = c.response()
            st2, _, back = c.response()
            if st != 200 or st2 != 200 or back != body:
                errs.append((i, r, st, st2))
                return
        c.close()
    except Exception as e:
        errs.append((i, repr(e)))


ts = [threading.Thread(target=worker, args=(i,)) for i in range(64)]
for t in ts:
    t.start()
for t in ts:
    t.join()
check("64 connections putting and getting together are each answered right", not errs, str(errs[:3]))
fallbacks = counter("recv_fallbacks") - before
if MODE == "tiny":
    check("a ring of two buffers ran dry and the receives were taken by buffers of their own", fallbacks > 0, str(fallbacks))
else:
    print("  (recv_fallbacks +%d in %s)" % (fallbacks, MODE))

# a runtime that has been through all that is still whole
st, back = get("/rbk/big")
check("the runtime still answers", st == 200 and back == BIG)
time.sleep(0.5)
check("and no connection is left behind", int(stats().get("connections", "0")) <= 1, stats().get("connections", "?"))

print("  Results: %d/%d passed (%d failed)" % (passed, passed + failed, failed))
sys.exit(failed)
