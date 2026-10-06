#!/usr/bin/env python3
"""HTTP/2 against a storage runtime, spoken frame by frame with the h2 library over cleartext (prior knowledge).

usage: lib_storage_http2.py PORT BIN NAME

What curl cannot show: a download read through a window of 1 KiB opened a little at a time, uploads on several
streams of one connection at once, a stream answered while another's large body is still going, and the limits --
a body longer than its content-length, a header in capitals, a first frame that is not SETTINGS, the 129th stream,
resets and CONTINUATIONs by the hundred.

Prints one PASS or FAIL line per assertion and a final "Results:" line, and exits with the number of failures.
"""
import hashlib
import os
import socket
import sys
import time

try:
    import h2.config
    import h2.connection
    import h2.events
    import h2.settings
except ImportError:
    print("  SKIP: the python h2 library is not installed (pip install h2)")
    print("Results: 0 passed, 0 failed")
    sys.exit(0)

PORT = int(sys.argv[1])
BIN, NAME = sys.argv[2], sys.argv[3]
AUTH = "127.0.0.1:%d" % PORT
BUCKET = "httptwo"

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: %s" % name)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, detail))


class Client:
    def __init__(self, settings=None, window=None):
        self.s = socket.create_connection(("127.0.0.1", PORT), 10)
        self.s.settimeout(20)
        self.c = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
        self.c.initiate_connection()
        if settings:
            self.c.update_settings(settings)
        self.flush()
        self.resp, self.body, self.ended, self.resets = {}, {}, set(), {}
        self.goaway = None
        self.window = window

    def flush(self):
        d = self.c.data_to_send()
        if d:
            self.s.sendall(d)

    def pump(self, until, deadline=20, ack=True):
        end = time.time() + deadline
        while not until() and time.time() < end:
            try:
                d = self.s.recv(1 << 20)
            except socket.timeout:
                break
            if not d:
                break
            for e in self.c.receive_data(d):
                if isinstance(e, h2.events.ResponseReceived):
                    self.resp[e.stream_id] = dict(e.headers)
                elif isinstance(e, h2.events.DataReceived):
                    self.body.setdefault(e.stream_id, bytearray()).extend(e.data)
                    if ack:
                        self.c.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                elif isinstance(e, h2.events.StreamEnded):
                    self.ended.add(e.stream_id)
                elif isinstance(e, h2.events.StreamReset):
                    self.resets[e.stream_id] = e.error_code
                elif isinstance(e, h2.events.ConnectionTerminated):
                    self.goaway = e.error_code
            self.flush()
        return until()

    def request(self, method, path, body=None, headers=(), end=True):
        sid = self.c.get_next_available_stream_id()
        h = [(":method", method), (":scheme", "http"), (":authority", AUTH), (":path", path)] + list(headers)
        if body is not None:
            h.append(("content-length", str(len(body))))
        self.c.send_headers(sid, h, end_stream=body is None and end)
        self.flush()
        return sid

    def send_body(self, sid, body):
        # As much as the windows let through, then waiting for updates, as a browser does.
        off = 0
        while off < len(body):
            win = min(self.c.local_flow_control_window(sid), self.c.max_outbound_frame_size)
            if win <= 0:
                self.pump(lambda: self.c.local_flow_control_window(sid) > 0 or sid in self.resets, 10)
                if sid in self.resets:
                    return
                continue
            n = min(win, len(body) - off)
            self.c.send_data(sid, body[off:off + n], end_stream=off + n == len(body))
            off += n
            self.flush()

    def close(self):
        self.s.close()


def raw(frames, wait=2.0):
    """Sends bytes as they are after the preface and returns what came back."""
    s = socket.create_connection(("127.0.0.1", PORT), 10)
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frames)
    s.settimeout(wait)
    got = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            got += d
    except socket.timeout:
        pass
    s.close()
    return got


def frame(ftype, flags, sid, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([ftype, flags]) + sid.to_bytes(4, "big") + payload


def goaway_code(data):
    at = 0
    while at + 9 <= len(data):
        n = int.from_bytes(data[at:at + 3], "big")
        if data[at + 3] == 7 and at + 9 + 8 <= len(data):
            return int.from_bytes(data[at + 13:at + 17], "big")
        at += 9 + n
    return None


# ── a bucket and an object ───────────────────────────────────────────────────
c = Client()
sid = c.request("PUT", "/" + BUCKET)
c.pump(lambda: sid in c.ended)
check("a bucket is made over HTTP/2", c.resp.get(sid, {}).get(":status") == "200", c.resp.get(sid))
big = os.urandom(3 << 20)
sid = c.request("PUT", "/%s/big" % BUCKET, big, end=False)
c.send_body(sid, big)
c.pump(lambda: sid in c.ended)
check("a 3 MiB body is put through the windows", c.resp.get(sid, {}).get(":status") == "200", c.resp.get(sid))
c.close()

# ── a download through a window of 1 KiB, opened a little at a time ──────────
c = Client(settings={h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 1024})
c.pump(lambda: c.c.remote_settings.acknowledged if hasattr(c.c.remote_settings, "acknowledged") else True, 1)
sid = c.request("GET", "/%s/big" % BUCKET)
c.pump(lambda: sid in c.ended, 60)
got = bytes(c.body.get(sid, b""))
check("a download read through a 1 KiB window is whole", hashlib.md5(got).digest() == hashlib.md5(big).digest(),
      "%d of %d bytes" % (len(got), len(big)))
c.close()

# ── several uploads on one connection at once, and a small answer beside a large one ─
c = Client()
parts = [os.urandom((1 << 20) + i * 7777) for i in range(4)]
sids = [c.request("PUT", "/%s/side%d" % (BUCKET, i), parts[i], end=False) for i in range(4)]
# The bodies interleaved, a slice of each in turn.
offs = [0] * 4
while any(offs[i] < len(parts[i]) for i in range(4)):
    for i, s in enumerate(sids):
        if offs[i] >= len(parts[i]):
            continue
        n = min(16384, len(parts[i]) - offs[i], c.c.local_flow_control_window(s))
        if n <= 0:
            c.pump(lambda: c.c.local_flow_control_window(s) > 0, 5)
            continue
        c.c.send_data(s, parts[i][offs[i]:offs[i] + n], end_stream=offs[i] + n == len(parts[i]))
        offs[i] += n
        c.flush()
c.pump(lambda: all(s in c.ended for s in sids), 30)
check("four uploads interleaved on one connection are each answered 200",
      [c.resp.get(s, {}).get(":status") for s in sids] == ["200"] * 4, [c.resp.get(s) for s in sids])
gets = [c.request("GET", "/%s/side%d" % (BUCKET, i)) for i in range(4)]
c.pump(lambda: all(s in c.ended for s in gets), 30)
check("and read back byte for byte", all(bytes(c.body.get(g, b"")) == parts[i] for i, g in enumerate(gets)))

slow = Client(settings={h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 65535})
bg = slow.request("GET", "/%s/big" % BUCKET)
slow.pump(lambda: len(slow.body.get(bg, b"")) > 0, 10, ack=False)
small = slow.request("HEAD", "/%s/side0" % BUCKET)
t0 = time.time()
slow.pump(lambda: small in slow.ended, 10, ack=False)
check("a stream is answered while another's body waits for its window",
      small in slow.ended and slow.resp.get(small, {}).get(":status") == "200" and bg not in slow.ended,
      "%s %s" % (slow.resp.get(small), time.time() - t0))
slow.close()
c.close()

# ── what a request may not be ────────────────────────────────────────────────
c = Client()
sid = c.c.get_next_available_stream_id()
c.c.send_headers(sid, [(":method", "PUT"), (":scheme", "http"), (":authority", AUTH),
                       (":path", "/%s/long" % BUCKET), ("content-length", "5")])
c.c.send_data(sid, b"0123456789", end_stream=True)
c.flush()
c.pump(lambda: sid in c.resets or sid in c.ended, 5)
check("a body longer than its content-length is reset with PROTOCOL_ERROR", c.resets.get(sid) == 1, c.resets)
c.close()

# h2 would refuse to send a capital, so the block is HPACK written by hand: a literal name "X-Up" without indexing.
lit = b"\x00\x04X-Up\x01v"
hdr = b"\x82\x86\x84" + b"\x41\x0e" + AUTH.encode()[:14] + lit   # GET, http, /, :authority
got = raw(frame(4, 0, 0) + frame(1, 0x5, 1, hdr))
check("a header in capitals is reset with PROTOCOL_ERROR", b"\x00\x00\x04\x03\x00\x00\x00\x00\x01\x00\x00\x00\x01" in got,
      got[:120])
check("a first frame that is not SETTINGS ends the connection with PROTOCOL_ERROR", goaway_code(raw(frame(6, 0, 0, b"12345678"))) == 1)
check("DATA on stream 0 does too", goaway_code(raw(frame(4, 0, 0) + frame(0, 0, 0, b"x"))) == 1)
check("a frame past the size this side reads is FRAME_SIZE_ERROR",
      goaway_code(raw(frame(4, 0, 0) + frame(0, 0, 1, b"x" * 20000))) == 6)
check("a WINDOW_UPDATE of nothing to the connection is PROTOCOL_ERROR",
      goaway_code(raw(frame(4, 0, 0) + frame(8, 0, 0, b"\x00\x00\x00\x00"))) == 1)

hblock = b"\x82\x86\x84\x41\x09127.0.0.1"


def rst_code(data, sid):
    at = 0
    while at + 9 <= len(data):
        n = int.from_bytes(data[at:at + 3], "big")
        if data[at + 3] == 3 and int.from_bytes(data[at + 5:at + 9], "big") == sid and at + 13 <= len(data):
            return int.from_bytes(data[at + 9:at + 13], "big")
        at += 9 + n
    return None


# A GET ended by both sides, then DATA on it; and HEADERS and PRIORITY naming their own stream as their parent.
done = frame(4, 0, 0) + frame(1, 0x5, 1, hblock)
got = raw(done + frame(0, 0x1, 1, b"late"), 2)
check("DATA on a stream that has ended is reset with STREAM_CLOSED", rst_code(got, 1) == 5, got[:80])
check("HEADERS that depend on their own stream are reset with PROTOCOL_ERROR",
      rst_code(raw(frame(4, 0, 0) + frame(1, 0x25, 3, (3).to_bytes(4, "big") + b"\x10" + hblock)), 3) == 1)
check("and so is a PRIORITY that does", rst_code(raw(frame(4, 0, 0) + frame(2, 0, 5, (5).to_bytes(4, "big") + b"\x10")), 5) == 1)

# ── limits ───────────────────────────────────────────────────────────────────
c = Client()
# Each waits for a body it was promised, so it stays open; the client has not yet read this side's limit.
first = [c.request("PUT", "/%s/wait%d" % (BUCKET, i), end=False, headers=[("content-length", "10")]) for i in range(129)]
c.pump(lambda: first[-1] in c.resets, 5)
check("the 129th stream open at once is refused", c.resets.get(first[-1]) == 7, len(c.resets))
c.close()

flood = frame(4, 0, 0)
for i in range(1, 1200, 2):
    flood += frame(1, 0x4, i, hblock) + frame(3, 0, i, b"\x00\x00\x00\x08")
check("streams opened and reset by the hundred end the connection with ENHANCE_YOUR_CALM",
      goaway_code(raw(flood, 3)) == 11)
cont = frame(4, 0, 0) + frame(1, 0, 1, hblock) + b"".join(frame(9, 0, 1, b"\x40\x01a\x01b") for _ in range(200))
check("CONTINUATIONs without end are ENHANCE_YOUR_CALM", goaway_code(raw(cont, 3)) == 11)

c = Client()
sid = c.request("GET", "/%s/side1" % BUCKET)
c.pump(lambda: sid in c.ended, 10)
check("and the runtime still serves", c.resp.get(sid, {}).get(":status") == "200")
c.close()

print("Results: %d passed, %d failed" % (passed, failed))
sys.exit(failed)
