#!/usr/bin/env python3
"""Uploads that trickle in, spoken raw: a body sent one TCP segment at a time.

usage: lib_storage_slow_upload.py PORT BIN NAME ACCESS SECRET

Each body is written 1448 bytes per send with TCP_NODELAY and a pause between
sends, at most 3.6 MB/s, which is how an upload over a slow uplink reaches the
server.  The runtime is expected to store every byte as before, to verify what
it verified before, to answer as soon as the last byte is in, and to take such a
body in a few receives per 10 ms pace tick and in 64 KiB digest handoffs rather
than one of each per segment, which `stats` counts as body_recvs and
hash_handoffs.

Prints one PASS or FAIL line per assertion and a final "Results:" line, and
exits with the number of failures.
"""
import base64
import hashlib
import os
import re
import socket
import subprocess
import sys
import time
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib_s3_signing as sig  # noqa: E402

PORT = int(sys.argv[1])
BIN = sys.argv[2]
NAME = sys.argv[3]
AK = sys.argv[4]
SK = sys.argv[5]
HOST = "127.0.0.1:%d" % PORT
BUCKET = "slow"
SEG = 1448
# A segment every 0.4 ms, slower than the runtime takes one in, so each arrives on its own.
GAP = 0.0004

passed = failed = 0


def check(name, cond, detail="", show=False):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: %s%s" % (name, ": %s" % detail if show else ""))
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


def counters():
    """body_recvs and hash_handoffs once the worker has reported, None for one it does not report."""
    last = None
    for _ in range(20):
        time.sleep(0.6)
        d = stats()
        now = (d.get("requests"), d.get("body_recvs"), d.get("hash_handoffs"))
        if now == last:
            break
        last = now
    return tuple(int(v) if v is not None else None for v in (d.get("body_recvs"), d.get("hash_handoffs")))


def pattern(n, seed):
    block = hashlib.sha256(b"slow-%d" % seed).digest() * 256
    return (block * (n // len(block) + 1))[:n]


class Conn:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", PORT), 10)
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.s.settimeout(10)
        self.buf = b""

    def trickle(self, data):
        for i in range(0, len(data), SEG):
            self.s.sendall(data[i:i + SEG])
            time.sleep(GAP)

    def response(self):
        while b"\r\n\r\n" not in self.buf:
            d = self.s.recv(65536)
            if not d:
                raise EOFError("closed")
            self.buf += d
        head, _, rest = self.buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        status = int(lines[0].split()[1])
        headers = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(b":")
            headers[k.strip().lower().decode()] = v.strip().decode()
        need = int(headers.get("content-length", "0"))
        self.buf = rest
        while len(self.buf) < need:
            d = self.s.recv(65536)
            if not d:
                raise EOFError("closed")
            self.buf += d
        body, self.buf = self.buf[:need], self.buf[need:]
        return status, headers, body

    def close(self):
        self.s.close()


def request(method, path, query="", payload_hash=sig.EMPTY, extra=None, body=b"", length=None):
    """The head of a signed request, with its body appended."""
    s = sig.sign(method, path, query, HOST, AK, SK, payload_hash, extra_headers=extra)
    lines = ["%s %s%s HTTP/1.1" % (method, path, "?" + query if query else ""), "Host: " + HOST,
             "Content-Length: %d" % (len(body) if length is None else length)]
    lines += ["%s: %s" % (k, v) for k, v in s.headers.items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def simple(method, path, query=""):
    c = Conn()
    c.s.sendall(request(method, path, query))
    r = c.response()
    c.close()
    return r


def framed(payload, trailer_value):
    """STREAMING-UNSIGNED-PAYLOAD-TRAILER framing, 64 KiB chunks, as botocore frames it."""
    pieces = [payload[i:i + 65536] for i in range(0, len(payload), 65536)]
    return sig.unsigned_chunks(pieces, [("x-amz-checksum-crc32", trailer_value)])


def crc32_b64(b):
    return base64.b64encode(zlib.crc32(b).to_bytes(4, "big")).decode()


def put_request(path, payload, kind, query="", extra=None):
    extra = dict(extra or {})
    if kind == "signed":
        return request("PUT", path, query, sig.sha256hex(payload), extra, payload)
    if kind == "unsigned":
        return request("PUT", path, query, "UNSIGNED-PAYLOAD", extra, payload)
    extra.update({"content-encoding": "aws-chunked", "x-amz-decoded-content-length": str(len(payload)),
                  "x-amz-trailer": "x-amz-checksum-crc32"})
    return request("PUT", path, query, "STREAMING-UNSIGNED-PAYLOAD-TRAILER", extra,
                   framed(payload, crc32_b64(payload)))


def trickled_put(c, path, payload, kind, query="", extra=None):
    """(status, headers, body, seconds from the last byte sent to the answer)."""
    c.trickle(put_request(path, payload, kind, query, extra))
    t = time.monotonic()
    st, h, b = c.response()
    return st, h, b, time.monotonic() - t


status, _, _ = simple("PUT", "/" + BUCKET)
check("the bucket is made", status == 200, status)

MIB = 1 << 20
for i, kind in enumerate(("signed", "unsigned", "trailer")):
    # An odd length, so the end of the body is never on a boundary of the receive mark.
    payload = pattern(MIB + 12345, i)
    r0, h0 = counters()
    c = Conn()
    st, h, _, wait = trickled_put(c, "/%s/%s" % (BUCKET, kind), payload, kind)
    check("a %s body trickled in one segment at a time is 200" % kind, st == 200, st)
    check("and is answered once its last byte is in, not on a timeout (%s)" % kind, wait < 3, "%.2fs" % wait)
    check("with the MD5 of the bytes as its ETag (%s)" % kind,
          h.get("etag", "").strip('"') == hashlib.md5(payload).hexdigest(), h.get("etag"))
    # The same connection is read again at once, so nothing waits for a body's worth of bytes after the body.
    c.s.sendall(request("GET", "/%s/%s" % (BUCKET, kind)))
    t = time.monotonic()
    st, _, got = c.response()
    check("the next request on that connection is answered at once (%s)" % kind,
          st == 200 and time.monotonic() - t < 3, "%s %.2fs" % (st, time.monotonic() - t))
    check("with every byte as it was sent (%s)" % kind, got == payload, "%d bytes" % len(got))
    c.close()
    r1, h1 = counters()
    if r0 is None or r1 is None or h0 is None or h1 is None:
        check("stats reports body_recvs and hash_handoffs", False, "missing")
        continue
    segments = len(payload) // SEG
    # One per segment is what the runtime did before; a few per pace tick is what it should do.
    check("the body was taken in far fewer receives than segments (%s)" % kind,
          r1 - r0 <= segments // 2, "%d receives for %d segments" % (r1 - r0, segments), True)
    check("and its digests were handed to the hashing threads in batches (%s)" % kind,
          h1 - h0 <= 64, "%d handoffs for %d segments" % (h1 - h0, segments), True)

# The checks that sit on the digests still refuse what they refused.
payload = pattern(400 * 1024 + 7, 9)
c = Conn()
st, _, body, _ = trickled_put(c, "/%s/md5-bad" % BUCKET, payload, "unsigned",
                              extra={"content-md5": base64.b64encode(hashlib.md5(b"other").digest()).decode()})
check("a trickled body whose Content-MD5 is wrong is BadDigest", st == 400 and b"BadDigest" in body, st)
c.close()
c = Conn()
st, _, _, _ = trickled_put(c, "/%s/md5-good" % BUCKET, payload, "unsigned",
                           extra={"content-md5": base64.b64encode(hashlib.md5(payload).digest()).decode()})
check("and one whose Content-MD5 is right is 200", st == 200, st)
c.close()
c = Conn()
st, _, body, _ = trickled_put(c, "/%s/crc-bad" % BUCKET, payload, "signed",
                              extra={"x-amz-checksum-crc32": crc32_b64(b"other")})
check("a trickled body whose x-amz-checksum-crc32 is wrong is refused", st == 400, st)
c.close()
c = Conn()
st, h, _, _ = trickled_put(c, "/%s/crc-good" % BUCKET, payload, "signed",
                           extra={"x-amz-checksum-crc32": crc32_b64(payload)})
check("and one whose checksum is right is 200 and says it back",
      st == 200 and h.get("x-amz-checksum-crc32") == crc32_b64(payload), (st, h.get("x-amz-checksum-crc32")))
c.close()

# A signed body that is not what its hash says is refused, and nothing is stored.
c = Conn()
c.trickle(request("PUT", "/%s/sha-bad" % BUCKET, "", sig.sha256hex(b"other"), None, payload))
st, _, body = c.response()
check("a trickled body that is not what x-amz-content-sha256 says is refused",
      st == 400 and b"XAmzContentSHA256Mismatch" in body, (st, body[:120]))
c.close()
status, _, _ = simple("HEAD", "/%s/sha-bad" % BUCKET)
check("and nothing is stored under its key", status == 404, status)

# A part goes through the same path, and the upload made of it reads back whole.
status, _, body = simple("POST", "/%s/mpu" % BUCKET, "uploads")
m = re.search(rb"<UploadId>([^<]+)</UploadId>", body)
check("a multipart upload is begun", status == 200 and m is not None, status)
if m:
    uid = m.group(1).decode()
    part = pattern(5 * MIB + 99, 11)
    c = Conn()
    st, h, _, wait = trickled_put(c, "/%s/mpu" % BUCKET, part, "signed", "partNumber=1&uploadId=" + uid)
    etag = h.get("etag", "")
    check("a part trickled in is 200 with the MD5 of its bytes",
          st == 200 and etag.strip('"') == hashlib.md5(part).hexdigest() and wait < 3, (st, etag, wait))
    c.close()
    xml = ("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part>"
           "</CompleteMultipartUpload>" % etag).encode()
    c = Conn()
    c.s.sendall(request("POST", "/%s/mpu" % BUCKET, "uploadId=" + uid, sig.sha256hex(xml), None, xml))
    st, _, body = c.response()
    check("and the upload completes", st == 200, (st, body[:200]))
    c.close()
    st, _, got = simple("GET", "/%s/mpu" % BUCKET)
    check("and reads back byte for byte", st == 200 and got == part, "%s %d" % (st, len(got)))

print("Results: %d passed, %d failed" % (passed, failed))
sys.exit(failed)
