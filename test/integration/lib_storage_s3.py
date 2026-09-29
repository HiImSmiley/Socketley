#!/usr/bin/env python3
"""The storage runtime's S3 surface, spoken raw and through boto3.

usage: lib_storage_s3.py PORT DATA_DIR

Prints one PASS or FAIL line per assertion and a final "Results:" line, and
exits with the number of failures.  The raw half is there because a client
library hides exactly the bytes a server owes an answer to -- the framing, the
XML, the headers -- and the boto3 half because a library is what people run.
"""
import base64
import hashlib
import http.client
import os
import socket
import sys
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET

PORT = int(sys.argv[1])
DATA = sys.argv[2]
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, detail))


def md5hex(b):
    return hashlib.md5(b).hexdigest()


class Resp:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    def h(self, name):
        return self.headers.get(name.lower())

    def xml(self):
        return ET.fromstring(self.body)

    def code(self):
        try:
            return self.xml().findtext("Code")
        except Exception:
            return None


def request(method, path, body=None, headers=None, conn=None):
    own = conn is None
    if own:
        conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        data = r.read()
        hdrs = {}
        for k, v in r.getheaders():
            hdrs[k.lower()] = v
        return Resp(r.status, hdrs, data)
    finally:
        if own:
            conn.close()


def q(key):
    return urllib.parse.quote(key, safe="/")


def raw_exchange(payload, read_until=None, timeout=10, then=None):
    """A socket of our own, for what http.client refuses to send."""
    s = socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
    s.sendall(payload)
    if then:
        then(s)
    buf = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            if read_until and read_until in buf:
                break
    except socket.timeout:
        pass
    s.close()
    return buf


def status_of(raw):
    return int(raw.split(b" ", 2)[1]) if raw.startswith(b"HTTP/") else -1


# ─── The service and buckets ────────────────────────────────────────────────
print("=== raw HTTP: the service and buckets ===")

r = request("GET", "/")
check("ListBuckets answers 200 with the S3 namespace", r.status == 200 and
      r.body.startswith(b'<?xml version="1.0" encoding="UTF-8"?>') and
      b'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"' in r.body, r.body[:200])
root = r.xml()
check("ListBuckets names an owner and a Buckets element",
      root.find(NS + "Owner") is not None and root.find(NS + "Buckets") is not None)
rid = r.h("x-amz-request-id")
check("every answer carries an x-amz-request-id of sixteen hex digits",
      rid is not None and len(rid) == 16 and all(c in "0123456789ABCDEF" for c in rid), rid)
r2 = request("GET", "/")
check("two requests do not share a request id", r2.h("x-amz-request-id") != rid)
check("ListBuckets is application/xml", (r.h("content-type") or "").startswith("application/xml"))

r = request("PUT", "/alpha-bucket")
check("CreateBucket answers 200 with Location", r.status == 200 and r.h("location") == "/alpha-bucket",
      (r.status, r.headers))
r = request("PUT", "/alpha-bucket")
check("CreateBucket of an existing bucket is BucketAlreadyOwnedByYou 409",
      r.status == 409 and r.code() == "BucketAlreadyOwnedByYou", (r.status, r.body))
for bad in ["ab", "UPPER-case", "under_score", "-leading", "trailing-", "a..b", "192.168.1.1", "xn--thing"]:
    r = request("PUT", "/" + bad)
    check("CreateBucket %r is InvalidBucketName 400" % bad,
          r.status == 400 and r.code() == "InvalidBucketName", (r.status, r.body[:200]))

request("PUT", "/beta-bucket")
r = request("GET", "/")
names = [b.findtext(NS + "Name") for b in r.xml().iter(NS + "Bucket")]
check("ListBuckets lists both buckets, sorted", names == ["alpha-bucket", "beta-bucket"], names)
dates = [b.findtext(NS + "CreationDate") for b in r.xml().iter(NS + "Bucket")]
check("bucket creation dates are ISO 8601 with milliseconds",
      all(len(d) == 24 and d.endswith("Z") and d[10] == "T" for d in dates), dates)

r = request("HEAD", "/alpha-bucket")
check("HeadBucket of a bucket is 200 with no body", r.status == 200 and r.body == b"", (r.status, r.body))
r = request("HEAD", "/nosuch-bucket")
check("HeadBucket of a missing bucket is 404 with no body", r.status == 404 and r.body == b"", (r.status, r.body))
r = request("GET", "/nosuch-bucket?list-type=2")
check("ListObjectsV2 of a missing bucket is NoSuchBucket 404 naming the bucket",
      r.status == 404 and r.code() == "NoSuchBucket" and r.xml().findtext("BucketName") == "nosuch-bucket", r.body)
r = request("GET", "/alpha-bucket?location")
check("GetBucketLocation answers a LocationConstraint", r.status == 200 and b"LocationConstraint" in r.body, r.body)
r = request("DELETE", "/nosuch-bucket")
check("DeleteBucket of a missing bucket is NoSuchBucket 404", r.status == 404 and r.code() == "NoSuchBucket")

# ─── PutObject and GetObject ────────────────────────────────────────────────
print("=== raw HTTP: objects ===")
B = "/alpha-bucket/"

body = os.urandom(70000)
r = request("PUT", B + "plain.bin", body=body, headers={"Content-Type": "application/x-thing"})
check("PutObject answers 200 with the MD5 ETag", r.status == 200 and r.h("etag") == '"%s"' % md5hex(body),
      (r.status, r.headers))
check("PutObject's answer has one Content-Length", r.h("content-length") == "0", r.headers)

r = request("GET", B + "plain.bin")
check("GetObject returns the bytes", r.status == 200 and r.body == body)
check("GetObject returns ETag, Content-Type, Last-Modified, Accept-Ranges and Content-Length",
      r.h("etag") == '"%s"' % md5hex(body) and r.h("content-type") == "application/x-thing" and
      r.h("accept-ranges") == "bytes" and r.h("content-length") == str(len(body)) and
      (r.h("last-modified") or "").endswith("GMT"), r.headers)
r = request("HEAD", B + "plain.bin")
check("HeadObject returns the same headers and no body",
      r.status == 200 and r.body == b"" and r.h("content-length") == str(len(body)) and
      r.h("etag") == '"%s"' % md5hex(body), (r.status, r.headers))

# Metadata and the stored content headers.
r = request("PUT", B + "meta.txt", body=b"metadata please", headers={
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "max-age=60, public",
    "Content-Disposition": 'attachment; filename="m.txt"',
    "Content-Encoding": "identity",
    "Content-Language": "en-GB",
    "x-amz-meta-owner": "somebody",
    "x-amz-meta-Mixed-Case": "Value",
})
check("PutObject with metadata answers 200", r.status == 200)
for verb in ("GET", "HEAD"):
    r = request(verb, B + "meta.txt")
    check("%s returns Cache-Control, Content-Disposition, Content-Encoding and Content-Language" % verb,
          r.h("cache-control") == "max-age=60, public" and
          r.h("content-disposition") == 'attachment; filename="m.txt"' and
          r.h("content-encoding") == "identity" and r.h("content-language") == "en-GB", r.headers)
    check("%s returns user metadata, lowercased" % verb,
          r.h("x-amz-meta-owner") == "somebody" and r.h("x-amz-meta-mixed-case") == "Value", r.headers)
check("Content-Type is kept with its parameters", r.h("content-type") == "text/plain; charset=utf-8", r.headers)

r = request("PUT", B + "notype", body=b"x")
r = request("HEAD", B + "notype")
check("an object stored with no Content-Type is binary/octet-stream",
      r.h("content-type") in ("binary/octet-stream", "application/octet-stream"), r.headers)

r = request("PUT", B + "empty", body=b"")
check("an empty object is stored", r.status == 200 and r.h("etag") == '"d41d8cd98f00b204e9800998ecf8427e"', r.headers)
r = request("GET", B + "empty")
check("an empty object reads back empty", r.status == 200 and r.body == b"" and r.h("content-length") == "0")

# Content-MD5.
good = base64.b64encode(hashlib.md5(b"digest body").digest()).decode()
r = request("PUT", B + "md5good", body=b"digest body", headers={"Content-MD5": good})
check("PutObject with a correct Content-MD5 succeeds", r.status == 200, (r.status, r.body))
wrong = base64.b64encode(hashlib.md5(b"other").digest()).decode()
r = request("PUT", B + "md5bad", body=b"digest body", headers={"Content-MD5": wrong})
check("PutObject with the wrong Content-MD5 is BadDigest 400", r.status == 400 and r.code() == "BadDigest",
      (r.status, r.body))
r = request("GET", B + "md5bad")
check("a body that failed its digest was not stored", r.status == 404, r.status)
r = request("PUT", B + "md5junk", body=b"x", headers={"Content-MD5": "not*base64"})
check("PutObject with a malformed Content-MD5 is InvalidDigest 400", r.status == 400 and r.code() == "InvalidDigest",
      (r.status, r.body))

# Keys.
odd = ["with space", "plus+sign", "percent%25", "uni-é中", "a/b/c/d", "trailing/", "q?mark", "amp&ersand=eq", "dot.", "..dots"]
for k in odd:
    p = B + q(k)
    v = ("value of " + k).encode()
    pr = request("PUT", p, body=v)
    gr = request("GET", p)
    check("key %r round-trips" % k, pr.status == 200 and gr.status == 200 and gr.body == v, (pr.status, gr.status))
r = request("PUT", B + "k" * 1024, body=b"x")
check("a key of 1024 bytes is accepted", r.status == 200, r.status)
r = request("PUT", B + "k" * 1025, body=b"x")
check("a key of 1025 bytes is KeyTooLongError 400", r.status == 400 and r.code() == "KeyTooLongError",
      (r.status, r.body[:200]))

# Limits, refused before a byte of the body is read.
raw = raw_exchange(b"PUT /alpha-bucket/too-big HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % ((5 << 30) + 1),
                   read_until=b"</Error>", timeout=5)
check("a single put over 5 GiB is EntityTooLarge 400 before its body is sent",
      status_of(raw) == 400 and b"<Code>EntityTooLarge</Code>" in raw, raw[:200])
r = request("PUT", B + "big-meta", body=b"x", headers={"x-amz-meta-big": "v" * 2100})
check("user metadata over 2 KB is MetadataTooLarge 400", r.status == 400 and r.code() == "MetadataTooLarge",
      (r.status, r.body[:200]))
check("and nothing was stored", request("GET", B + "big-meta").status == 404)

r = request("PUT", "/nosuch-bucket/key", body=b"x")
check("PutObject into a missing bucket is NoSuchBucket 404", r.status == 404 and r.code() == "NoSuchBucket")
r = request("GET", B + "missing-key")
check("GetObject of a missing key is NoSuchKey 404 naming the key",
      r.status == 404 and r.code() == "NoSuchKey" and r.xml().findtext("Key") == "missing-key", r.body)
check("the error carries a RequestId matching the header",
      r.xml().findtext("RequestId") == r.h("x-amz-request-id"), r.body)
r = request("HEAD", B + "missing-key")
check("HeadObject of a missing key is 404 with no body", r.status == 404 and r.body == b"")
r = request("GET", "/nosuch-bucket/key")
check("GetObject in a missing bucket is NoSuchBucket 404", r.status == 404 and r.code() == "NoSuchBucket")

# Overwrite.
request("PUT", B + "over", body=b"first")
request("PUT", B + "over", body=b"second, longer")
r = request("GET", B + "over")
check("an overwrite replaces the object", r.body == b"second, longer")

# Range.
rng = os.urandom(300000)
request("PUT", B + "range.bin", body=rng)
for spec, want in [("bytes=0-99", rng[0:100]), ("bytes=1000-", rng[1000:]), ("bytes=-500", rng[-500:]),
                   ("bytes=299999-299999", rng[299999:]), ("bytes=290000-999999", rng[290000:]),
                   ("bytes=0-0", rng[0:1]), ("bytes=70000-200000", rng[70000:200001])]:
    r = request("GET", B + "range.bin", headers={"Range": spec})
    total = len(rng)
    check("Range %s answers 206 with the bytes" % spec, r.status == 206 and r.body == want, (r.status, len(r.body)))
    if r.status == 206:
        cr = r.h("content-range") or ""
        check("Range %s answers Content-Range and Content-Length" % spec,
              cr.endswith("/%d" % total) and r.h("content-length") == str(len(want)), r.headers)
r = request("GET", B + "range.bin", headers={"Range": "bytes=999999-"})
check("a Range past the end is InvalidRange 416 with Content-Range */total",
      r.status == 416 and r.code() == "InvalidRange" and r.h("content-range") == "bytes */300000", (r.status, r.headers, r.body))
r = request("GET", B + "range.bin", headers={"Range": "bytes=0-1,5-9"})
check("a multi-range request is answered whole", r.status == 200 and r.body == rng, r.status)
r = request("GET", B + "range.bin", headers={"Range": "bytes=5-2"})
check("an inverted range is ignored", r.status == 200 and r.body == rng, r.status)
r = request("GET", B + "empty", headers={"Range": "bytes=0-"})
check("a Range on an empty object is InvalidRange 416", r.status == 416, r.status)
r = request("HEAD", B + "range.bin", headers={"Range": "bytes=10-19"})
check("HeadObject with a Range answers 206 and the slice's length", r.status == 206 and r.h("content-length") == "10",
      (r.status, r.headers))

# Conditionals.
etag = r.h("etag") or '"%s"' % md5hex(rng)
r = request("GET", B + "range.bin")
etag = r.h("etag")
lm = r.h("last-modified")
r = request("GET", B + "range.bin", headers={"If-None-Match": etag})
check("If-None-Match with the ETag is 304 with no body", r.status == 304 and r.body == b"", (r.status, len(r.body)))
check("a 304 carries the ETag", r.h("etag") == etag, r.headers)
r = request("GET", B + "range.bin", headers={"If-None-Match": '"nope"'})
check("If-None-Match with another ETag is 200", r.status == 200 and r.body == rng)
r = request("GET", B + "range.bin", headers={"If-Match": '"nope"'})
check("If-Match with another ETag is PreconditionFailed 412", r.status == 412 and r.code() == "PreconditionFailed",
      (r.status, r.body))
r = request("GET", B + "range.bin", headers={"If-Match": etag})
check("If-Match with the ETag is 200", r.status == 200)
r = request("GET", B + "range.bin", headers={"If-Modified-Since": lm})
check("If-Modified-Since the object's own date is 304", r.status == 304, r.status)
r = request("GET", B + "range.bin", headers={"If-Modified-Since": "Thu, 01 Jan 2015 00:00:00 GMT"})
check("If-Modified-Since long ago is 200", r.status == 200)
r = request("GET", B + "range.bin", headers={"If-Unmodified-Since": "Thu, 01 Jan 2015 00:00:00 GMT"})
check("If-Unmodified-Since before the object is PreconditionFailed 412", r.status == 412, r.status)
r = request("HEAD", B + "range.bin", headers={"If-None-Match": etag})
check("HEAD with If-None-Match is 304", r.status == 304)

# Response header overrides.
r = request("GET", B + "plain.bin?response-content-type=text%2Fhtml&response-content-disposition=inline")
check("response-content-type and response-content-disposition override the stored headers",
      r.h("content-type") == "text/html" and r.h("content-disposition") == "inline", r.headers)

# If-None-Match: * on a PUT.
r = request("PUT", B + "plain.bin", body=b"x", headers={"If-None-Match": "*"})
check("PUT with If-None-Match: * on an existing key is PreconditionFailed 412", r.status == 412, r.status)
r = request("PUT", B + "fresh-key", body=b"x", headers={"If-None-Match": "*"})
check("PUT with If-None-Match: * on a new key succeeds", r.status == 200, r.status)

# ─── Framing ────────────────────────────────────────────────────────────────
print("=== raw HTTP: framing ===")
# Expect: 100-continue.
def expect_flow(s):
    s.settimeout(5)
    got = b""
    while b"\r\n\r\n" not in got:
        got += s.recv(4096)
    check("Expect: 100-continue is answered with 100 before the body", got.startswith(b"HTTP/1.1 100 Continue"), got[:80])
    s.sendall(b"the body after the 100")
raw = raw_exchange(b"PUT /alpha-bucket/expect HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 22\r\n\r\n",
                   read_until=b"ETag", then=expect_flow, timeout=5)
check("the PUT after 100-continue is stored", request("GET", B + "expect").body == b"the body after the 100")

# Chunked request body.
chunked = b"5\r\nhello\r\n7\r\n, world\r\n0\r\n\r\n"
raw = raw_exchange(b"PUT /alpha-bucket/chunked HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked,
                   read_until=b"\r\n\r\n")
check("a chunked PUT is answered 200", status_of(raw) == 200, raw[:100])
check("a chunked PUT stores the decoded body", request("GET", B + "chunked").body == b"hello, world")

# Pipelining and keep-alive.
two = (b"GET /alpha-bucket/plain.bin HTTP/1.1\r\nHost: x\r\n\r\n" +
       b"HEAD /alpha-bucket/plain.bin HTTP/1.1\r\nHost: x\r\n\r\n" +
       b"GET /alpha-bucket/missing HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
raw = raw_exchange(two, timeout=5)
check("three pipelined requests get three answers in order",
      raw.count(b"HTTP/1.1 200 OK") == 2 and raw.count(b"HTTP/1.1 404") == 1 and
      raw.index(b"HTTP/1.1 200 OK") < raw.index(b"HTTP/1.1 404"), raw[:200])
check("the pipelined GET's body is intact", body in raw)

conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
ok = True
for i in range(200):
    rr = request("PUT", B + "ka-%d" % (i % 5), body=b"v%d" % i, conn=conn)
    ok = ok and rr.status == 200
    rr = request("GET", B + "ka-%d" % (i % 5), conn=conn)
    ok = ok and rr.body == b"v%d" % i
conn.close()
check("400 requests on one keep-alive connection", ok)

raw = raw_exchange(b"GET /alpha-bucket/plain.bin HTTP/1.0\r\n\r\n", timeout=5)
check("HTTP/1.0 is answered and the connection closed", status_of(raw) == 200 and body in raw)

raw = raw_exchange(b"GET /alpha-bucket/plain.bin HTTP/1.1\r\nBadHeaderNoColon\r\n\r\n", timeout=5)
check("a header line with no colon is refused with 400", status_of(raw) == 400, raw[:100])
raw = raw_exchange(b"GET /alpha-bucket/plain.bin HTTP/1.1\r\nHost: x\r\nX: " + b"a" * 40000 + b"\r\n\r\n", timeout=5)
check("a head of 40 KB is refused", status_of(raw) in (400, 431), raw[:100])
raw = raw_exchange(b"GET /alpha-bucket/x HTTP/2.0\r\n\r\n", timeout=5)
check("an HTTP version that is not 1.x is refused with 505", status_of(raw) == 505, raw[:100])
raw = raw_exchange(b"PUT /alpha-bucket/nolen HTTP/1.1\r\nHost: x\r\n\r\n", timeout=5)
check("a PUT with no length is MissingContentLength 411", status_of(raw) == 411, raw[:100])
raw = raw_exchange(b"PUT /alpha-bucket/both HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n", timeout=5)
check("a request with both Content-Length and Transfer-Encoding is refused", status_of(raw) == 400, raw[:100])

# A body that stops short leaves nothing behind.
s = socket.create_connection(("127.0.0.1", PORT))
s.sendall(b"PUT /alpha-bucket/truncated HTTP/1.1\r\nHost: x\r\nContent-Length: 3000000\r\n\r\n" + os.urandom(100000))
time.sleep(0.3)
s.close()
time.sleep(0.5)
check("a body that stopped short was not stored", request("GET", B + "truncated").status == 404)
tmpdir = os.path.join(DATA, "alpha-bucket", "tmp")
check("and its temporary file is gone", os.path.isdir(tmpdir) and os.listdir(tmpdir) == [], os.listdir(tmpdir))

# A client that leaves in the middle of a download does not hurt the server.
big = os.urandom(3000000)
request("PUT", B + "big3m", body=big)
s = socket.create_connection(("127.0.0.1", PORT))
s.sendall(b"GET /alpha-bucket/big3m HTTP/1.1\r\nHost: x\r\n\r\n")
s.recv(1000)
s.close()
time.sleep(0.2)
check("the server answers after a client abandoned a download", request("GET", B + "big3m").body == big)

# Unsupported operations are refused as such.
r = request("GET", B + "plain.bin?acl")
check("?acl is NotImplemented 501", r.status == 501 and r.code() == "NotImplemented", (r.status, r.body[:200]))
r = request("POST", B + "plain.bin?uploads")
check("POST ?uploads is NotImplemented 501 until multipart exists", r.status == 501, r.status)
r = request("PUT", B + "chunkedsigned", body=b"x", headers={"x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"})
check("an aws-chunked upload is refused rather than stored as framing", r.status == 501 and r.code() == "NotImplemented",
      (r.status, r.body[:200]))
check("and nothing was stored for it", request("GET", B + "chunkedsigned").status == 404)
r = request("PATCH", B + "plain.bin")
check("an unknown method is 405 MethodNotAllowed", r.status == 405, r.status)

# ─── DeleteObject ───────────────────────────────────────────────────────────
print("=== raw HTTP: delete ===")
request("PUT", B + "victim", body=b"v")
r = request("DELETE", B + "victim")
check("DeleteObject answers 204 with no body", r.status == 204 and r.body == b"", (r.status, r.body))
check("the object is gone", request("GET", B + "victim").status == 404)
r = request("DELETE", B + "victim")
check("DeleteObject of a missing key is 204 too", r.status == 204, r.status)
r = request("DELETE", "/nosuch-bucket/key")
check("DeleteObject in a missing bucket is NoSuchBucket 404", r.status == 404 and r.code() == "NoSuchBucket")

# ─── DeleteObjects ──────────────────────────────────────────────────────────
def delete_xml(keys, quiet=False):
    parts = ['<?xml version="1.0" encoding="UTF-8"?><Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">']
    if quiet:
        parts.append("<Quiet>true</Quiet>")
    for k in keys:
        parts.append("<Object><Key>%s</Key></Object>" % k.replace("&", "&amp;").replace("<", "&lt;"))
    parts.append("</Delete>")
    return "".join(parts).encode()


for i in range(6):
    request("PUT", B + "batch/k%d" % i, body=b"x")
request("PUT", B + "batch/a&b<c", body=b"x")
xml = delete_xml(["batch/k0", "batch/k1", "batch/missing", "batch/a&b<c"])
md5h = base64.b64encode(hashlib.md5(xml).digest()).decode()
r = request("POST", "/alpha-bucket?delete", body=xml, headers={"Content-MD5": md5h, "Content-Type": "application/xml"})
check("DeleteObjects answers 200 and a DeleteResult", r.status == 200 and r.xml().tag == NS + "DeleteResult",
      (r.status, r.body[:300]))
deleted = sorted(d.findtext(NS + "Key") for d in r.xml().iter(NS + "Deleted"))
check("DeleteObjects reports every key deleted, the missing one too, escapes decoded",
      deleted == ["batch/a&b<c", "batch/k0", "batch/k1", "batch/missing"], deleted)
check("DeleteObjects removed them", request("GET", B + "batch/k0").status == 404 and
      request("GET", B + "batch/a%26b%3Cc").status == 404)
check("and left the others", request("GET", B + "batch/k2").status == 200)
xml = delete_xml(["batch/k2", "batch/k3"], quiet=True)
r = request("POST", "/alpha-bucket?delete", body=xml)
check("a Quiet DeleteObjects answers an empty DeleteResult", r.status == 200 and b"<Deleted>" not in r.body, r.body)
check("and removed the keys", request("GET", B + "batch/k2").status == 404)
r = request("POST", "/alpha-bucket?delete", body=b"<Delete><Object></Delete>")
check("malformed XML is MalformedXML 400", r.status == 400 and r.code() == "MalformedXML", (r.status, r.body[:200]))
r = request("POST", "/alpha-bucket?delete", body=delete_xml(["a"]), headers={"Content-MD5": md5h})
check("a wrong Content-MD5 is BadDigest 400", r.status == 400 and r.code() == "BadDigest", (r.status, r.body[:200]))
r = request("POST", "/alpha-bucket?delete", body=delete_xml(["k%d" % i for i in range(1001)]))
check("more than 1000 keys is MalformedXML 400", r.status == 400 and r.code() == "MalformedXML", (r.status, r.body[:200]))
many = ["many/k%04d" % i for i in range(300)]
for k in many:
    request("PUT", B + k, body=b"m")
r = request("POST", "/alpha-bucket?delete", body=delete_xml(many))
check("DeleteObjects of 300 keys deletes them all", r.status == 200 and len(list(r.xml().iter(NS + "Deleted"))) == 300)
r = request("GET", "/alpha-bucket?list-type=2&prefix=many/")
check("and the listing agrees", r.xml().findtext(NS + "KeyCount") == "0", r.body[:300])
r = request("POST", "/nosuch-bucket?delete", body=delete_xml(["a"]))
check("DeleteObjects in a missing bucket is NoSuchBucket 404", r.status == 404 and r.code() == "NoSuchBucket")

# ─── CopyObject ─────────────────────────────────────────────────────────────
print("=== raw HTTP: copy ===")
csrc = os.urandom(5 * 1024 * 1024 + 17)
request("PUT", B + "copy/src", body=csrc, headers={"Content-Type": "text/x-source", "x-amz-meta-origin": "src"})
r = request("PUT", B + "copy/dst", headers={"x-amz-copy-source": "/alpha-bucket/copy/src"})
check("CopyObject answers 200 and a CopyObjectResult with the ETag", r.status == 200 and
      r.xml().tag == NS + "CopyObjectResult" and r.xml().findtext(NS + "ETag") == '"%s"' % md5hex(csrc),
      (r.status, r.body[:300]))
check("CopyObjectResult has a LastModified", (r.xml().findtext(NS + "LastModified") or "").endswith("Z"))
r = request("GET", B + "copy/dst")
check("the copy has the bytes", r.body == csrc)
check("the default directive COPY keeps the metadata",
      r.h("content-type") == "text/x-source" and r.h("x-amz-meta-origin") == "src", r.headers)
r = request("PUT", B + "copy/dst2", headers={"x-amz-copy-source": "alpha-bucket/copy/src",
                                              "x-amz-metadata-directive": "REPLACE",
                                              "Content-Type": "text/x-replaced", "x-amz-meta-new": "yes"})
r = request("HEAD", B + "copy/dst2")
check("directive REPLACE takes the new metadata and drops the old",
      r.h("content-type") == "text/x-replaced" and r.h("x-amz-meta-new") == "yes" and r.h("x-amz-meta-origin") is None,
      r.headers)
request("PUT", "/beta-bucket")
r = request("PUT", "/beta-bucket/other/place", headers={"x-amz-copy-source": "/alpha-bucket/" + q("copy/src")})
check("CopyObject across buckets", r.status == 200 and request("GET", "/beta-bucket/other/place").body == csrc)
request("PUT", B + q("sp ace+plus"), body=b"encoded source")
r = request("PUT", B + "copy/enc", headers={"x-amz-copy-source": "/alpha-bucket/" + q("sp ace+plus")})
check("a percent-encoded copy source is decoded", r.status == 200 and request("GET", B + "copy/enc").body == b"encoded source",
      (r.status, r.body[:200]))
r = request("PUT", B + "copy/src", headers={"x-amz-copy-source": "/alpha-bucket/copy/src"})
check("copying an object onto itself unchanged is InvalidRequest 400", r.status == 400 and r.code() == "InvalidRequest",
      (r.status, r.body[:200]))
r = request("PUT", B + "copy/src", headers={"x-amz-copy-source": "/alpha-bucket/copy/src",
                                             "x-amz-metadata-directive": "REPLACE", "Content-Type": "text/self"})
check("copying an object onto itself with REPLACE updates it in place",
      r.status == 200 and request("HEAD", B + "copy/src").h("content-type") == "text/self" and
      request("GET", B + "copy/src").body == csrc)
r = request("PUT", B + "copy/x", headers={"x-amz-copy-source": "/alpha-bucket/no-such-source"})
check("a missing copy source key is NoSuchKey 404", r.status == 404 and r.code() == "NoSuchKey", (r.status, r.body[:200]))
r = request("PUT", B + "copy/x", headers={"x-amz-copy-source": "/no-such-bucket/k"})
check("a missing copy source bucket is NoSuchBucket 404", r.status == 404 and r.code() == "NoSuchBucket")
r = request("PUT", B + "copy/x", headers={"x-amz-copy-source": "nonsense"})
check("a copy source with no key is InvalidArgument 400", r.status == 400 and r.code() == "InvalidArgument",
      (r.status, r.body[:200]))
r = request("PUT", "/nosuch-bucket/x", headers={"x-amz-copy-source": "/alpha-bucket/copy/src"})
check("CopyObject into a missing bucket is NoSuchBucket 404", r.status == 404 and r.code() == "NoSuchBucket")

# ─── Listing ────────────────────────────────────────────────────────────────
print("=== raw HTTP: listing ===")
request("PUT", "/list-bucket")
L = "/list-bucket/"
keys = ["a", "b/1", "b/2", "b/sub/x", "c", "d/1", "e", "photos/2020/a.jpg", "photos/2020/b.jpg",
        "photos/2021/c.jpg", "photos/index.html", "zeta"]
for k in keys:
    request("PUT", L + k, body=k.encode())


def listing(query):
    r = request("GET", "/list-bucket?" + query)
    root = r.xml()
    return r, root, [c.findtext(NS + "Key") for c in root.iter(NS + "Contents")], \
        [c.findtext(NS + "Prefix") for c in root.iter(NS + "CommonPrefixes")]


r, root, ks, ps = listing("list-type=2")
check("ListObjectsV2 lists every key in order", ks == sorted(keys), ks)
check("ListObjectsV2 answers Name, KeyCount, MaxKeys and IsTruncated",
      root.findtext(NS + "Name") == "list-bucket" and root.findtext(NS + "KeyCount") == str(len(keys)) and
      root.findtext(NS + "MaxKeys") == "1000" and root.findtext(NS + "IsTruncated") == "false", r.body[:300])
c0 = list(root.iter(NS + "Contents"))[0]
check("each Contents has LastModified, ETag, Size and StorageClass",
      all(c0.find(NS + t) is not None for t in ("Key", "LastModified", "ETag", "Size", "StorageClass")) and
      c0.findtext(NS + "ETag") == '"%s"' % md5hex(b"a") and c0.findtext(NS + "Size") == "1", r.body[:400])
r, root, ks, ps = listing("list-type=2&delimiter=/")
check("a delimiter rolls keys up into CommonPrefixes",
      ks == ["a", "c", "e", "zeta"] and ps == ["b/", "d/", "photos/"], (ks, ps))
check("KeyCount counts keys and prefixes together", root.findtext(NS + "KeyCount") == "7")
check("Delimiter is echoed", root.findtext(NS + "Delimiter") == "/")
r, root, ks, ps = listing("list-type=2&delimiter=/&prefix=photos/")
check("prefix and delimiter together", ks == ["photos/index.html"] and ps == ["photos/2020/", "photos/2021/"], (ks, ps))
r, root, ks, ps = listing("list-type=2&prefix=photos/2020/")
check("a prefix alone", ks == ["photos/2020/a.jpg", "photos/2020/b.jpg"], ks)
r, root, ks, ps = listing("list-type=2&start-after=c")
check("start-after is exclusive", ks == ["d/1", "e", "photos/2020/a.jpg", "photos/2020/b.jpg", "photos/2021/c.jpg",
                                         "photos/index.html", "zeta"], ks)
check("StartAfter is echoed", root.findtext(NS + "StartAfter") == "c")

# Pagination.
seen, tokens, pages = [], [], 0
token = None
while True:
    qs = "list-type=2&max-keys=5&delimiter=/"
    if token:
        qs += "&continuation-token=" + urllib.parse.quote(token)
    r, root, ks, ps = listing(qs)
    pages += 1
    seen += ks + ps
    check("a page holds at most max-keys entries", len(ks) + len(ps) <= 5)
    if root.findtext(NS + "IsTruncated") == "true":
        token = root.findtext(NS + "NextContinuationToken")
        check("a truncated page names NextContinuationToken", bool(token))
        check("and echoes the token that produced it", pages == 1 or root.findtext(NS + "ContinuationToken") is not None)
    else:
        break
    if pages > 20:
        break
check("paging through with delimiter sees each entry exactly once",
      sorted(seen) == sorted(["a", "c", "e", "zeta", "b/", "d/", "photos/"]), seen)
r, root, ks, ps = listing("list-type=2&max-keys=0")
check("max-keys=0 is an empty, untruncated page", ks == [] and root.findtext(NS + "IsTruncated") == "false", r.body[:300])
r, root, ks, ps = listing("list-type=2&max-keys=100000")
check("max-keys above 1000 is clamped", root.findtext(NS + "MaxKeys") == "1000")
r = request("GET", "/list-bucket?list-type=2&max-keys=abc")
check("a max-keys that is not a number is InvalidArgument 400", r.status == 400 and r.code() == "InvalidArgument", r.body[:200])
r = request("GET", "/list-bucket?list-type=2&continuation-token=%21%21bad")
check("a continuation token that is not one is InvalidArgument 400", r.status == 400 and r.code() == "InvalidArgument", r.body[:200])
r = request("GET", "/list-bucket?list-type=3")
check("list-type=3 is InvalidArgument 400", r.status == 400 and r.code() == "InvalidArgument", r.body[:200])

# encoding-type=url.
request("PUT", L + q("enc/with space+plus&amp"), body=b"e")
r, root, ks, ps = listing("list-type=2&encoding-type=url&prefix=enc/")
check("encoding-type=url percent-encodes keys and says so",
      root.findtext(NS + "EncodingType") == "url" and ks == ["enc/with%20space%2Bplus%26amp"], (ks, r.body[:300]))
r, root, ks, ps = listing("list-type=2&prefix=enc/")
check("without it the key is XML-escaped and otherwise as stored", ks == ["enc/with space+plus&amp"], ks)
r = request("GET", "/list-bucket?list-type=2&encoding-type=bogus")
check("an encoding-type other than url is InvalidArgument 400", r.status == 400 and r.code() == "InvalidArgument")

# V1.
r, root, ks, ps = listing("delimiter=/&max-keys=3")
check("ListObjects V1 answers Marker and NextMarker when truncated",
      root.find(NS + "Marker") is not None and root.findtext(NS + "IsTruncated") == "true" and
      root.findtext(NS + "NextMarker") is not None, r.body[:400])
seen = ks + ps
marker = root.findtext(NS + "NextMarker")
for _ in range(10):
    r, root, ks, ps = listing("delimiter=/&max-keys=3&marker=" + urllib.parse.quote(marker))
    seen += ks + ps
    if root.findtext(NS + "IsTruncated") != "true":
        break
    marker = root.findtext(NS + "NextMarker")
check("ListObjects V1 paged by marker sees every entry once",
      sorted(seen) == sorted(["a", "c", "e", "zeta", "b/", "d/", "photos/", "enc/"]), sorted(seen))
r = request("GET", "/list-bucket")
check("a bare GET of a bucket is a V1 listing", r.status == 200 and r.xml().find(NS + "Marker") is not None)

# ─── DeleteBucket ───────────────────────────────────────────────────────────
print("=== raw HTTP: buckets, again ===")
r = request("DELETE", "/list-bucket")
check("DeleteBucket of a bucket with objects is BucketNotEmpty 409", r.status == 409 and r.code() == "BucketNotEmpty",
      (r.status, r.body[:200]))
r = request("POST", "/list-bucket?delete", body=delete_xml(keys + ["enc/with space+plus&amp"]))
r = request("DELETE", "/list-bucket")
check("DeleteBucket of an emptied bucket is 204", r.status == 204, (r.status, r.body[:200]))
check("and the bucket is gone", request("HEAD", "/list-bucket").status == 404)
r = request("PUT", "/list-bucket")
check("the name can be made again", r.status == 200)
r = request("GET", "/list-bucket?list-type=2")
check("and the new bucket is empty", r.xml().findtext(NS + "KeyCount") == "0")
request("DELETE", "/list-bucket")

# ─── Concurrency ────────────────────────────────────────────────────────────
print("=== raw HTTP: concurrent clients ===")
request("PUT", "/conc-bucket")
errors = []


def worker(n):
    try:
        conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
        for i in range(25):
            data = os.urandom(1000 + (n * 37 + i * 911) % 200000)
            key = "/conc-bucket/w%d/k%d" % (n, i)
            r = request("PUT", key, body=data, conn=conn)
            if r.status != 200 or r.h("etag") != '"%s"' % md5hex(data):
                errors.append(("put", n, i, r.status))
                return
            r = request("GET", key, conn=conn)
            if r.body != data:
                errors.append(("get", n, i))
                return
        conn.close()
    except Exception as e:
        errors.append(("exc", n, repr(e)))


threads = [threading.Thread(target=worker, args=(n,)) for n in range(16)]
for t in threads:
    t.start()
for t in threads:
    t.join()
check("16 clients each put and read back 25 objects intact", errors == [], errors[:3])
r = request("GET", "/conc-bucket?list-type=2&max-keys=1000")
check("the listing counts all 400", r.xml().findtext(NS + "KeyCount") == "400", r.body[:200])

# Racing writers of one key end with one whole winner.
contenders = [os.urandom(50000 + i * 1000) for i in range(12)]
race_errors = []


def racer(i):
    r = request("PUT", "/conc-bucket/race", body=contenders[i])
    if r.status != 200:
        race_errors.append(r.status)


threads = [threading.Thread(target=racer, args=(i,)) for i in range(12)]
for t in threads:
    t.start()
for t in threads:
    t.join()
r = request("GET", "/conc-bucket/race")
check("racing puts of one key all succeed", race_errors == [], race_errors)
check("and the survivor is exactly one of the bodies", r.body in contenders)
check("with the ETag of that body", r.h("etag") == '"%s"' % md5hex(r.body))
h = request("HEAD", "/conc-bucket/race")
check("and HEAD agrees with GET", h.h("etag") == r.h("etag") and h.h("content-length") == str(len(r.body)))

# ─── boto3 ──────────────────────────────────────────────────────────────────
print("=== boto3 against --anonymous ===")
try:
    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config
    from botocore.exceptions import ClientError
    from boto3.s3.transfer import TransferConfig
except ImportError:
    print("  SKIP: boto3 is not installed")
    boto3 = None

if boto3:
    s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % PORT, region_name="us-east-1",
                      config=Config(signature_version=UNSIGNED, s3={"addressing_style": "path"},
                                    retries={"max_attempts": 1}))

    def code_of(fn):
        try:
            fn()
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["ResponseMetadata"]["HTTPStatusCode"]
        return None, None

    check("boto3 create_bucket", s3.create_bucket(Bucket="boto-bucket")["ResponseMetadata"]["HTTPStatusCode"] == 200)
    check("boto3 create_bucket again is BucketAlreadyOwnedByYou",
          code_of(lambda: s3.create_bucket(Bucket="boto-bucket")) == ("BucketAlreadyOwnedByYou", 409))
    check("boto3 list_buckets", "boto-bucket" in [b["Name"] for b in s3.list_buckets()["Buckets"]])
    check("boto3 head_bucket", s3.head_bucket(Bucket="boto-bucket")["ResponseMetadata"]["HTTPStatusCode"] == 200)
    check("boto3 head_bucket of a missing bucket is 404",
          code_of(lambda: s3.head_bucket(Bucket="boto-missing")) == ("404", 404))
    check("boto3 get_bucket_location", "LocationConstraint" in s3.get_bucket_location(Bucket="boto-bucket"))

    data = os.urandom(2_500_000)
    r = s3.put_object(Bucket="boto-bucket", Key="dir/obj 1+2.bin", Body=data, ContentType="application/x-boto",
                      Metadata={"alpha": "1", "beta": "two"}, CacheControl="no-store", ContentDisposition="inline",
                      ContentEncoding="identity", ContentLanguage="fr")
    check("boto3 put_object returns the MD5 ETag", r["ETag"] == '"%s"' % md5hex(data), r["ETag"])
    g = s3.get_object(Bucket="boto-bucket", Key="dir/obj 1+2.bin")
    body_read = g["Body"].read()
    check("boto3 get_object returns the bytes", body_read == data)
    check("boto3 get_object returns the bytes and every stored header",
          g["ContentType"] == "application/x-boto" and g["Metadata"] == {"alpha": "1", "beta": "two"}
          and g["CacheControl"] == "no-store" and g["ContentDisposition"] == "inline" and g["ContentLanguage"] == "fr"
          and g["ContentLength"] == len(data) and g["ETag"] == '"%s"' % md5hex(data), dict(g))
    h = s3.head_object(Bucket="boto-bucket", Key="dir/obj 1+2.bin")
    check("boto3 head_object", h["ContentLength"] == len(data) and h["Metadata"]["beta"] == "two")
    g = s3.get_object(Bucket="boto-bucket", Key="dir/obj 1+2.bin", Range="bytes=100-199")
    check("boto3 ranged get_object", g["Body"].read() == data[100:200] and g["ContentRange"] == "bytes 100-199/%d" % len(data)
          and g["ResponseMetadata"]["HTTPStatusCode"] == 206)
    check("boto3 get_object of a missing key is NoSuchKey",
          code_of(lambda: s3.get_object(Bucket="boto-bucket", Key="nope")) == ("NoSuchKey", 404))
    check("boto3 head_object of a missing key is 404",
          code_of(lambda: s3.head_object(Bucket="boto-bucket", Key="nope")) == ("404", 404))
    check("boto3 get_object in a missing bucket is NoSuchBucket",
          code_of(lambda: s3.get_object(Bucket="boto-missing", Key="k")) == ("NoSuchBucket", 404))
    check("boto3 get_object past the end is InvalidRange",
          code_of(lambda: s3.get_object(Bucket="boto-bucket", Key="dir/obj 1+2.bin", Range="bytes=99999999-")) == ("InvalidRange", 416))
    check("boto3 conditional get is 304",
          code_of(lambda: s3.get_object(Bucket="boto-bucket", Key="dir/obj 1+2.bin", IfNoneMatch=r["ETag"]))[1] == 304)
    check("boto3 precondition failed is PreconditionFailed",
          code_of(lambda: s3.get_object(Bucket="boto-bucket", Key="dir/obj 1+2.bin", IfMatch='"x"')) == ("PreconditionFailed", 412))

    for i in range(120):
        s3.put_object(Bucket="boto-bucket", Key="list/%04d" % i, Body=b"%d" % i)
    for i in range(3):
        s3.put_object(Bucket="boto-bucket", Key="list/sub%d/x" % i, Body=b"s")
    pag = s3.get_paginator("list_objects_v2")
    got = [o["Key"] for pg in pag.paginate(Bucket="boto-bucket", Prefix="list/", PaginationConfig={"PageSize": 25})
           for o in pg.get("Contents", [])]
    check("boto3 list_objects_v2 paginator lists every key once, in order", got == sorted(got) and len(got) == 123 and len(set(got)) == 123, len(got))
    resp = s3.list_objects_v2(Bucket="boto-bucket", Prefix="list/", Delimiter="/")
    check("boto3 list_objects_v2 with a delimiter", len(resp["Contents"]) == 120 and
          [c["Prefix"] for c in resp["CommonPrefixes"]] == ["list/sub0/", "list/sub1/", "list/sub2/"], resp.get("CommonPrefixes"))
    resp = s3.list_objects_v2(Bucket="boto-bucket", Prefix="dir/")
    check("boto3 list_objects_v2 decodes url-encoded keys", [o["Key"] for o in resp["Contents"]] == ["dir/obj 1+2.bin"], resp.get("Contents"))
    resp = s3.list_objects_v2(Bucket="boto-bucket", Prefix="list/", StartAfter="list/0117")
    check("boto3 StartAfter", [o["Key"] for o in resp["Contents"]][:2] == ["list/0118", "list/0119"], resp["KeyCount"])
    pag1 = s3.get_paginator("list_objects")
    got1 = [o["Key"] for pg in pag1.paginate(Bucket="boto-bucket", Prefix="list/", Delimiter="/", PaginationConfig={"PageSize": 40})
            for o in pg.get("Contents", [])]
    check("boto3 list_objects (V1) paginator", len(got1) == 120, len(got1))

    c = s3.copy_object(Bucket="boto-bucket", Key="copied/obj", CopySource={"Bucket": "boto-bucket", "Key": "dir/obj 1+2.bin"})
    check("boto3 copy_object", c["CopyObjectResult"]["ETag"] == '"%s"' % md5hex(data))
    check("boto3 the copy has the bytes and the source's metadata",
          s3.get_object(Bucket="boto-bucket", Key="copied/obj")["Body"].read() == data and
          s3.head_object(Bucket="boto-bucket", Key="copied/obj")["Metadata"] == {"alpha": "1", "beta": "two"})
    s3.copy_object(Bucket="boto-bucket", Key="copied/replaced", CopySource="boto-bucket/dir/obj 1+2.bin",
                   MetadataDirective="REPLACE", Metadata={"only": "this"}, ContentType="text/replaced")
    hh = s3.head_object(Bucket="boto-bucket", Key="copied/replaced")
    check("boto3 copy_object with REPLACE and a string source", hh["Metadata"] == {"only": "this"} and hh["ContentType"] == "text/replaced", hh)

    d = s3.delete_objects(Bucket="boto-bucket", Delete={"Objects": [{"Key": "list/%04d" % i} for i in range(120)]})
    check("boto3 delete_objects deletes 120 keys", len(d.get("Deleted", [])) == 120 and not d.get("Errors"))
    d = s3.delete_objects(Bucket="boto-bucket", Delete={"Objects": [{"Key": "list/sub%d/x" % i} for i in range(3)], "Quiet": True})
    check("boto3 quiet delete_objects", not d.get("Deleted") and not d.get("Errors"))
    check("boto3 delete_object answers 204", s3.delete_object(Bucket="boto-bucket", Key="copied/obj")["ResponseMetadata"]["HTTPStatusCode"] == 204)
    check("boto3 delete_bucket of a non-empty bucket is BucketNotEmpty",
          code_of(lambda: s3.delete_bucket(Bucket="boto-bucket")) == ("BucketNotEmpty", 409))

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "up.bin")
        blob = os.urandom(6_000_000)
        with open(src, "wb") as f:
            f.write(blob)
        s3.upload_file(src, "boto-bucket", "uploaded/up.bin", Config=TransferConfig(multipart_threshold=1 << 30))
        dst = os.path.join(td, "down.bin")
        s3.download_file("boto-bucket", "uploaded/up.bin", dst)
        check("boto3 upload_file then download_file round-trips", open(dst, "rb").read() == blob)
        big = os.urandom(20_000_000)
        s3.put_object(Bucket="boto-bucket", Key="uploaded/big.bin", Body=big)
        dst2 = os.path.join(td, "big-down.bin")
        s3.download_file("boto-bucket", "uploaded/big.bin", dst2, Config=TransferConfig(multipart_chunksize=5_000_000,
                                                                                      multipart_threshold=6_000_000))
        check("boto3 download_file of 20 MB in parallel ranged gets", hashlib.md5(open(dst2, "rb").read()).hexdigest() == md5hex(big))
        with open(src, "rb") as f:
            s3.upload_fileobj(f, "boto-bucket", "uploaded/fileobj.bin", Config=TransferConfig(multipart_threshold=1 << 30))
        check("boto3 upload_fileobj", s3.get_object(Bucket="boto-bucket", Key="uploaded/fileobj.bin")["Body"].read() == blob)

    check("boto3 create_multipart_upload is NotImplemented until multipart lands",
          code_of(lambda: s3.create_multipart_upload(Bucket="boto-bucket", Key="mp"))[1] == 501)

    resp = s3.list_objects_v2(Bucket="boto-bucket")
    for o in resp.get("Contents", []):
        s3.delete_object(Bucket="boto-bucket", Key=o["Key"])
    check("boto3 delete_bucket of an emptied bucket", s3.delete_bucket(Bucket="boto-bucket")["ResponseMetadata"]["HTTPStatusCode"] == 204)
    check("boto3 delete_bucket of a missing bucket is NoSuchBucket",
          code_of(lambda: s3.delete_bucket(Bucket="boto-bucket")) == ("NoSuchBucket", 404))

total = passed + failed
print("  Results: %d/%d passed (%d failed)" % (passed, total, failed))
sys.exit(min(failed, 100))
