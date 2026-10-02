#!/usr/bin/env python3
"""Server-side encryption on the storage runtime.

usage: lib_storage_sse.py MODE ARGS...

  main PORT DATA            a cleartext runtime with a master key: SSE-S3 PUT, GET, HEAD, ranges,
                            partNumber, multipart in place and copied, UploadPartCopy, CopyObject
                            in every direction, a bucket's default, versioning, tags, the refusals,
                            and the bytes on disk
  recovery PORT DATA        what main left, after a clean restart and after a SIGKILL with every
                            journal removed, read back byte for byte
  tls PORT CERT DATA        a TLS runtime with a master key: SSE-C with the right, a wrong and no
                            key, ranges, multipart, copies between SSE-C and SSE-S3, nothing held;
                            an SSE-C upload's part list bound by its key or by the master key's MAC,
                            and a header that drops the last part of either reads nothing
  tlsnokey PORT CERT DATA   a TLS runtime without a master key refuses an SSE-C completion that does
                            not carry the key, leaves the upload open, and completes it with the key
  nokey PORT                a runtime without a master key refuses SSE-S3 and a bucket default
  shards NODE0 NODE1 DATA   two shards, one unix node each: a default set through one is honoured
                            by both, and every object reads alike through the owner and the other
  tamper PORT DATA          object files rewritten as someone who can write the disk would: a header
                            cut to a chunk boundary or to empty, two parts' chunks swapped, a part
                            dropped from the header, a record set back to format 1; none reads
  layout PORT DATA          an encrypted upload whose part list is too long for the header
                            (SOCKETLEY_STORAGE_PART_LIST_MAX) completes, reads by range and
                            partNumber before and after a restart, and a bent list reads nothing
  pool PORT DATA            small SSE-S3 puts take a pooled file and sync as plain ones do; one killed
                            after its rename (SOCKETLEY_STORAGE_KILL_AFTER_RENAME=killme/) whose rename
                            is then lost is rolled forward, and a torn one is not
  policy PORT               a bucket policy requiring AES256 through s3:x-amz-server-side-encryption

Prints one PASS or FAIL line per assertion and exits with the number of failures.
"""
import base64
import hashlib
import http.client
import json
import os
import re
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zlib

import lib_s3_signing as sig

MODE = sys.argv[1]
BIN = os.environ.get("BIN", "")
RUNTIME = os.environ.get("RUNTIME", "sse")
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
B = "sseb"
STATE = "sse-expected.json"
DEFAULTS_STATE = "sse-defaults.json"
MARK = b"PLAINTEXT-MARKER-0123456789-"
MIB = 1 << 20

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, detail))


def wait_for(fn, timeout):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.2)
    return fn()


class UnixConn(http.client.HTTPConnection):
    def __init__(self, path, timeout=60):
        super().__init__("localhost", timeout=timeout)
        self.unix_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.unix_path)


NODE = None
CERT = None


def conn(node):
    if isinstance(node, str):
        return UnixConn(node)
    if CERT:
        return http.client.HTTPSConnection("localhost", node, timeout=60,
                                           context=ssl.create_default_context(cafile=CERT))
    return http.client.HTTPConnection("127.0.0.1", node, timeout=60)


def req(method, path, body=None, headers=None, node=None):
    c = conn(node or NODE)
    try:
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data
    finally:
        c.close()


def xml_code(body):
    m = re.search(rb"<Code>([^<]*)</Code>", body or b"")
    return m.group(1).decode() if m else ""


def md5(b):
    return hashlib.md5(b).hexdigest()


def blob(n, seed):
    out = bytearray()
    x = hashlib.sha256(seed.encode()).digest()
    while len(out) < n:
        x = hashlib.sha256(x).digest()
        out += x
    return bytes(out[:n])


def marked(n, seed):
    """Random bytes with the marker every 4 KiB, so a body stored in the clear is found by a search."""
    b = bytearray(blob(n, seed))
    for at in range(0, n - len(MARK), 4096):
        b[at:at + len(MARK)] = MARK
    return bytes(b)


def obj_file(data, key, bucket=B):
    h = hashlib.sha256(key.encode()).hexdigest()
    return os.path.join(data, bucket, "data", h[:2], h)


def on_disk(data, key, bucket=B):
    with open(obj_file(data, key, bucket), "rb") as f:
        return f.read()


def sealed_len(n, version=2):
    """Version 2: whole chunks, then the short one that ends the stream; version 1 had no chunk for the end."""
    return n + ((n // 65536 + 1) if version == 2 else (n + 65535) // 65536) * 28


def boto(port, https=False):
    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config
    scheme = "https://localhost" if https else "http://127.0.0.1"
    return boto3.client("s3", endpoint_url="%s:%d" % (scheme, port), region_name="us-east-1",
                        verify=CERT if https else None,
                        config=Config(signature_version=UNSIGNED, s3={"addressing_style": "path"},
                                      retries={"max_attempts": 1}))


def err_code(fn):
    from botocore.exceptions import ClientError
    try:
        fn()
        return None
    except ClientError as e:
        return (e.response.get("ResponseMetadata", {}).get("HTTPStatusCode"), e.response.get("Error", {}).get("Code"))


def stats():
    out = subprocess.run([BIN, "stats", RUNTIME], capture_output=True, text=True).stdout
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d


def stat_int(name):
    try:
        return int(stats().get(name, "0"))
    except ValueError:
        return 0


def wait_stat(name, at_least, timeout=5):
    return wait_for(lambda: stat_int(name) >= at_least, timeout)


def ranges_ok(s3, key, body, extra=None):
    """Every range that touches a chunk boundary, a part boundary, the ends and the middle reads exactly."""
    n = len(body)
    picks = [(0, 0), (0, 65535), (65535, 65536), (65534, 65537), (n - 1, n - 1), (n // 2, n // 2 + 100000),
             (65536 * 3 - 5, 65536 * 5 + 5)]
    picks += extra or []
    bad = []
    for lo, hi in picks:
        if lo >= n or hi >= n or lo > hi:
            continue
        got = s3.get_object(Bucket=B, Key=key, Range="bytes=%d-%d" % (lo, hi), **(KEYARGS or {}))["Body"].read()
        if got != body[lo:hi + 1]:
            bad.append((lo, hi, len(got)))
    for suffix in ["bytes=-100", "bytes=%d-" % (n - 70000 if n > 70000 else 1)]:
        got = s3.get_object(Bucket=B, Key=key, Range=suffix, **(KEYARGS or {}))["Body"].read()
        want = body[-100:] if suffix == "bytes=-100" else body[n - 70000 if n > 70000 else 1:]
        if got != want:
            bad.append((suffix, len(got)))
    return bad


KEYARGS = None


def mpu(s3, key, parts, create=None, part_args=None, bucket=None):
    create = create or {}
    part_args = part_args or {}
    bucket = bucket or B
    up = s3.create_multipart_upload(Bucket=bucket, Key=key, **create)
    uid = up["UploadId"]
    done = []
    for i, p in enumerate(parts, 1):
        r = s3.upload_part(Bucket=bucket, Key=key, UploadId=uid, PartNumber=i, Body=p, **part_args)
        done.append({"PartNumber": i, "ETag": r["ETag"]})
    r = s3.complete_multipart_upload(Bucket=bucket, Key=key, UploadId=uid, MultipartUpload={"Parts": done})
    return up, r


def write_bytes():
    """What the worker has written to its files, counted as it dirties pages."""
    with open("/proc/%s/io" % stats().get("pid")) as f:
        for line in f:
            if line.startswith("write_bytes:"):
                return int(line.split()[1])
    return 0


def save_expect(data, expect):
    with open(os.path.join(data, STATE), "w") as f:
        json.dump(expect, f)


def default_sums_wrong(want):
    """How HEAD and GET with x-amz-checksum-mode differ, for each key, from its CRC64NVME FULL_OBJECT and no other."""
    wrong = []
    for key, crc in want.items():
        for method in ("HEAD", "GET"):
            st, h, _ = req(method, "/%s/%s" % (B, key), headers={"x-amz-checksum-mode": "ENABLED"})
            got = (st, h.get("x-amz-checksum-crc64nvme"), h.get("x-amz-checksum-type"),
                   sorted(n for n in h if n.startswith("x-amz-checksum-")))
            if got != (200, crc, "FULL_OBJECT", ["x-amz-checksum-crc64nvme", "x-amz-checksum-type"]):
                wrong.append((key, method, got, crc))
    return wrong


# ─── main ───────────────────────────────────────────────────────────────────

def mode_main(port, data):
    global NODE
    NODE = port
    s3 = boto(port)
    s3.create_bucket(Bucket=B)
    expect = {}

    # ── SSE-S3 on a PUT ─────────────────────────────────────────────────────
    big = marked(3 * MIB + 12345, "big")
    r = s3.put_object(Bucket=B, Key="big", Body=big, ServerSideEncryption="AES256")
    check("a PUT with AES256 is answered with AES256", r.get("ServerSideEncryption") == "AES256", r)
    check("and its ETag is the MD5 of the plaintext", r["ETag"].strip('"') == md5(big), r["ETag"])
    g = s3.get_object(Bucket=B, Key="big")
    body = g["Body"].read()
    check("a GET returns the plaintext", body == big, (len(body), len(big)))
    check("and says AES256", g.get("ServerSideEncryption") == "AES256", g.get("ServerSideEncryption"))
    check("with the plaintext's length", g["ContentLength"] == len(big), g["ContentLength"])
    h = s3.head_object(Bucket=B, Key="big")
    check("a HEAD says AES256, the length and the ETag",
          (h.get("ServerSideEncryption"), h["ContentLength"], h["ETag"].strip('"')) == ("AES256", len(big), md5(big)),
          h)
    bad = ranges_ok(s3, "big", big)
    check("every range read is exact, across chunk boundaries and at both ends", not bad, bad)
    expect["big"] = md5(big)

    raw = on_disk(data, "big")
    check("the object's file does not hold its plaintext", MARK not in raw, raw.count(MARK))
    check("and holds the sealed chunks behind its header", len(raw) - sealed_len(len(big)) in (4096, 8192, 12288),
          (len(raw), sealed_len(len(big))))
    clear = marked(200000, "clear")
    r = s3.put_object(Bucket=B, Key="clear", Body=clear)
    check("a PUT that asks for nothing is answered without SSE", "ServerSideEncryption" not in r, r)
    check("and its file does hold its plaintext, so the search above can fail", MARK in on_disk(data, "clear"))
    check("a GET of it says nothing of SSE",
          "ServerSideEncryption" not in s3.get_object(Bucket=B, Key="clear"))
    expect["clear"] = md5(clear)

    # A small object is opened once and then answered from memory, still as AES256.
    small = marked(3000, "small")
    s3.put_object(Bucket=B, Key="small", Body=small, ServerSideEncryption="AES256")
    hot0 = stat_int("hot_gets")
    first = s3.get_object(Bucket=B, Key="small")
    second = s3.get_object(Bucket=B, Key="small")
    check("a small encrypted object reads back twice",
          first["Body"].read() == small and second["Body"].read() == small)
    check("the second GET says AES256 too", second.get("ServerSideEncryption") == "AES256", second)
    check("and is answered from the held copy", wait_stat("hot_gets", hot0 + 1), (hot0, stat_int("hot_gets")))
    check("its file does not hold its plaintext", MARK not in on_disk(data, "small"))
    expect["small"] = md5(small)
    empty = s3.put_object(Bucket=B, Key="empty", Body=b"", ServerSideEncryption="AES256")
    g = s3.get_object(Bucket=B, Key="empty")
    check("an empty encrypted object reads back empty",
          (g["Body"].read(), g["ContentLength"], empty["ETag"].strip('"')) == (b"", 0, md5(b"")))
    expect["empty"] = md5(b"")
    exact = marked(2 * 65536, "exact")
    s3.put_object(Bucket=B, Key="exact", Body=exact, ServerSideEncryption="AES256")
    check("an object of exactly two chunks reads back", s3.get_object(Bucket=B, Key="exact")["Body"].read() == exact)
    expect["exact"] = md5(exact)
    # A body of unknown length, sent chunked, is sealed as it comes.
    chunked = marked(1500000, "chunked")
    c = conn(port)
    c.putrequest("PUT", "/%s/chunked" % B)
    c.putheader("Transfer-Encoding", "chunked")
    c.putheader("x-amz-server-side-encryption", "AES256")
    c.endheaders()
    for at in range(0, len(chunked), 300000):
        piece = chunked[at:at + 300000]
        c.send(b"%x\r\n" % len(piece) + piece + b"\r\n")
    c.send(b"0\r\n\r\n")
    cr = c.getresponse()
    cr.read()
    c.close()
    check("a chunked PUT is encrypted", (cr.status, cr.getheader("x-amz-server-side-encryption")) == (200, "AES256"),
          cr.status)
    check("and reads back", s3.get_object(Bucket=B, Key="chunked")["Body"].read() == chunked)
    expect["chunked"] = md5(chunked)

    # ── multipart ───────────────────────────────────────────────────────────
    p = [marked(5 * MIB, "p1"), marked(5 * MIB, "p2"), marked(MIB + 777, "p3")]
    whole = b"".join(p)
    w0 = write_bytes()
    up, r = mpu(s3, "mp", p, create={"ServerSideEncryption": "AES256"})
    ratio = (write_bytes() - w0) / len(whole)
    check("an encrypted upload of equal parts is sealed where the object needs it, written once (%.3fx)" % ratio,
          0.95 <= ratio <= 1.10, ratio)
    check("CreateMultipartUpload with AES256 is answered with it", up.get("ServerSideEncryption") == "AES256", up)
    check("CompleteMultipartUpload says AES256", r.get("ServerSideEncryption") == "AES256", r)
    g = s3.get_object(Bucket=B, Key="mp")
    check("an encrypted multipart object reads back whole", g["Body"].read() == whole)
    check("with a three-part ETag", g["ETag"].strip('"').endswith("-3"), g["ETag"])
    for n in (1, 2, 3):
        got = s3.get_object(Bucket=B, Key="mp", PartNumber=n)
        check("partNumber=%d reads its part" % n, got["Body"].read() == p[n - 1])
    h = s3.head_object(Bucket=B, Key="mp", PartNumber=2)
    check("a HEAD of partNumber=2 gives its length", h["ContentLength"] == len(p[1]), h["ContentLength"])
    bad = ranges_ok(s3, "mp", whole, [(5 * MIB - 10, 5 * MIB + 10), (10 * MIB - 1, 10 * MIB + 65536)])
    check("ranges across its part boundaries are exact", not bad, bad)
    check("its file does not hold its plaintext", MARK not in on_disk(data, "mp"))
    expect["mp"] = md5(whole)
    # Parts of different sizes are copied into the object rather than left in place.
    q = [marked(5 * MIB, "q1"), marked(6 * MIB, "q2"), marked(123457, "q3")]
    w0 = write_bytes()
    mpu(s3, "mpcopy", q, create={"ServerSideEncryption": "AES256"})
    wq = b"".join(q)
    ratio = (write_bytes() - w0) / len(wq)
    check("and one of unequal parts is copied, sealed bytes as they are (%.3fx)" % ratio, 1.8 <= ratio <= 2.2, ratio)
    check("an encrypted upload of unequal parts reads back whole",
          s3.get_object(Bucket=B, Key="mpcopy")["Body"].read() == wq)
    check("and its second part by number", s3.get_object(Bucket=B, Key="mpcopy", PartNumber=2)["Body"].read() == q[1])
    bad = ranges_ok(s3, "mpcopy", wq, [(5 * MIB - 3, 5 * MIB + 3), (11 * MIB - 70000, 11 * MIB + 70000)])
    check("and its ranges", not bad, bad)
    expect["mpcopy"] = md5(wq)
    # A part sent twice is the second one's bytes.
    up = s3.create_multipart_upload(Bucket=B, Key="mptwice", ServerSideEncryption="AES256")
    uid = up["UploadId"]
    a = s3.upload_part(Bucket=B, Key="mptwice", UploadId=uid, PartNumber=1, Body=marked(5 * MIB, "t1"))
    a2 = s3.upload_part(Bucket=B, Key="mptwice", UploadId=uid, PartNumber=1, Body=marked(5 * MIB, "t1b"))
    b2 = s3.upload_part(Bucket=B, Key="mptwice", UploadId=uid, PartNumber=2, Body=marked(4000, "t2"))
    check("an UploadPart of an encrypted upload says AES256", a.get("ServerSideEncryption") == "AES256", a)
    s3.complete_multipart_upload(Bucket=B, Key="mptwice", UploadId=uid, MultipartUpload={"Parts": [
        {"PartNumber": 1, "ETag": a2["ETag"]}, {"PartNumber": 2, "ETag": b2["ETag"]}]})
    wt = marked(5 * MIB, "t1b") + marked(4000, "t2")
    check("a part uploaded twice reads as its second body", s3.get_object(Bucket=B, Key="mptwice")["Body"].read() == wt)
    expect["mptwice"] = md5(wt)
    # UploadPartCopy from an encrypted source, into an encrypted upload and into a clear one.
    for label, create in (("an encrypted", {"ServerSideEncryption": "AES256"}), ("a clear", {})):
        key = "pc-" + ("enc" if create else "clear")
        up = s3.create_multipart_upload(Bucket=B, Key=key, **create)
        uid = up["UploadId"]
        r1 = s3.upload_part_copy(Bucket=B, Key=key, UploadId=uid, PartNumber=1,
                                 CopySource={"Bucket": B, "Key": "mp"}, CopySourceRange="bytes=3-%d" % (5 * MIB + 2))
        r2 = s3.upload_part_copy(Bucket=B, Key=key, UploadId=uid, PartNumber=2,
                                 CopySource={"Bucket": B, "Key": "big"}, CopySourceRange="bytes=100-70099")
        s3.complete_multipart_upload(Bucket=B, Key=key, UploadId=uid, MultipartUpload={"Parts": [
            {"PartNumber": 1, "ETag": r1["CopyPartResult"]["ETag"]},
            {"PartNumber": 2, "ETag": r2["CopyPartResult"]["ETag"]}]})
        want = whole[3:5 * MIB + 3] + big[100:70100]
        got = s3.get_object(Bucket=B, Key=key)
        check("UploadPartCopy from encrypted sources into %s upload reads back" % label,
              got["Body"].read() == want, key)
        check("and the object is %s" % ("encrypted" if create else "in the clear"),
              (got.get("ServerSideEncryption") == "AES256") == bool(create) and
              (MARK in on_disk(data, key)) != bool(create))
        expect[key] = md5(want)

    # ── CopyObject in every direction ───────────────────────────────────────
    r = s3.copy_object(Bucket=B, Key="c-enc2clear", CopySource={"Bucket": B, "Key": "big"})
    g = s3.get_object(Bucket=B, Key="c-enc2clear")
    check("a copy of an encrypted object with no SSE asked is in the clear",
          g["Body"].read() == big and "ServerSideEncryption" not in g and MARK in on_disk(data, "c-enc2clear"))
    check("with the plaintext's MD5 as its ETag", r["CopyObjectResult"]["ETag"].strip('"') == md5(big), r)
    expect["c-enc2clear"] = md5(big)
    r = s3.copy_object(Bucket=B, Key="c-clear2enc", CopySource={"Bucket": B, "Key": "clear"},
                       ServerSideEncryption="AES256")
    g = s3.get_object(Bucket=B, Key="c-clear2enc")
    check("a copy of a clear object asked AES256 is encrypted",
          g["Body"].read() == clear and g.get("ServerSideEncryption") == "AES256" and
          MARK not in on_disk(data, "c-clear2enc") and r.get("ServerSideEncryption") == "AES256", r)
    expect["c-clear2enc"] = md5(clear)
    r = s3.copy_object(Bucket=B, Key="c-mp", CopySource={"Bucket": B, "Key": "mp"}, ServerSideEncryption="AES256")
    check("a copy of an encrypted multipart object is one part, its ETag the MD5",
          r["CopyObjectResult"]["ETag"].strip('"') == md5(whole), r["CopyObjectResult"]["ETag"])
    check("and reads back", s3.get_object(Bucket=B, Key="c-mp")["Body"].read() == whole)
    check("and by partNumber=1 is all of it", s3.get_object(Bucket=B, Key="c-mp", PartNumber=1)["Body"].read() == whole)
    expect["c-mp"] = md5(whole)
    # A copy's checksum is of its own plaintext, whichever way it is sealed, and not its source's composite.
    ck = {"ChecksumAlgorithm": "SHA256"}
    mpu(s3, "ck-mp", p, create=dict(ck, ServerSideEncryption="AES256"), part_args=ck)
    mpu(s3, "ck-clear", q, create={"ChecksumAlgorithm": "SHA1"}, part_args={"ChecksumAlgorithm": "SHA1"})
    sha = lambda algo, b: base64.b64encode(hashlib.new(algo, b).digest()).decode()
    crc = lambda b: base64.b64encode(struct.pack(">I", zlib.crc32(b))).decode()
    for dst, src, args, algo, want in (
            ("ck-enc2enc", "ck-mp", {"ServerSideEncryption": "AES256"}, "SHA256", sha("sha256", whole)),
            ("ck-enc2clear", "ck-mp", {"ChecksumAlgorithm": "CRC32"}, "CRC32", crc(whole)),
            ("ck-clear2enc", "ck-clear", {"ServerSideEncryption": "AES256"}, "SHA1", sha("sha1", wq))):
        r = s3.copy_object(Bucket=B, Key=dst, CopySource={"Bucket": B, "Key": src}, **args)
        h = s3.head_object(Bucket=B, Key=dst, ChecksumMode="ENABLED")
        st, hh, _ = req("HEAD", "/%s/%s" % (B, dst), headers={"x-amz-checksum-mode": "ENABLED"})
        got = (r["CopyObjectResult"].get("Checksum" + algo), h.get("Checksum" + algo), hh.get("x-amz-checksum-type"),
               sorted(n for n in hh if n.startswith("x-amz-checksum-")))
        check("a copy %s of %s has the %s of its whole plaintext, FULL_OBJECT, in its answer and its HEAD" %
              (dst, src, algo), got == (want, want, "FULL_OBJECT",
                                        sorted(["x-amz-checksum-" + algo.lower(), "x-amz-checksum-type"])), got)
        check("and is sealed as it asked", (h.get("ServerSideEncryption") == "AES256") ==
              ("ServerSideEncryption" in args), h.get("ServerSideEncryption"))
    expect["ck-mp"] = md5(whole)
    expect["ck-clear"] = md5(wq)
    expect["ck-enc2enc"] = md5(whole)
    expect["ck-enc2clear"] = md5(whole)
    expect["ck-clear2enc"] = md5(wq)
    s3.put_object(Bucket=B, Key="self", Body=clear)
    r = s3.copy_object(Bucket=B, Key="self", CopySource={"Bucket": B, "Key": "self"}, ServerSideEncryption="AES256")
    g = s3.get_object(Bucket=B, Key="self")
    check("a copy of an object onto itself that names AES256 encrypts it in place",
          g["Body"].read() == clear and g.get("ServerSideEncryption") == "AES256" and MARK not in on_disk(data, "self"))
    expect["self"] = md5(clear)
    code = err_code(lambda: s3.copy_object(Bucket=B, Key="self", CopySource={"Bucket": B, "Key": "self"}))
    check("one that names nothing new is still refused", code == (400, "InvalidRequest"), code)

    # S3's default checksum of an object sent without one is of its plaintext, whichever way it is sealed or copied.
    defaults = {}
    dp = [marked(5 * MIB, "dp1"), marked(MIB + 3, "dp2")]
    for key, body in (("d-small", marked(3000, "dsmall")), ("d-big", marked(2 * MIB + 99, "dbig"))):
        st, h, _ = req("PUT", "/%s/%s" % (B, key), body, headers={"x-amz-server-side-encryption": "AES256"})
        check("%s: an SSE-S3 PutObject with no checksum answers the CRC64NVME of its plaintext" % key,
              (st, h.get("x-amz-checksum-crc64nvme"), h.get("x-amz-server-side-encryption")) ==
              (200, sig.crc64nvme_b64(body), "AES256"), (st, h))
        defaults[key] = body
        expect[key] = md5(body)
    mpu(s3, "d-mp", dp, create={"ServerSideEncryption": "AES256"})
    defaults["d-mp"] = b"".join(dp)
    expect["d-mp"] = md5(b"".join(dp))
    # The clear source was given the default when it was put, which every copy of it, sealed or not, keeps.
    for key, body in (("clear", clear), ("big", big), ("c-clear2enc", clear), ("c-enc2clear", big)):
        defaults[key] = body
    defaults = {k: sig.crc64nvme_b64(v) for k, v in defaults.items()}
    wrong = default_sums_wrong(defaults)
    check("each answers it to a HEAD and a GET with x-amz-checksum-mode, FULL_OBJECT and no other: an SSE-S3 upload "
          "with no algorithm and copies into and out of a sealed body included", not wrong, wrong[:2])
    with open(os.path.join(data, DEFAULTS_STATE), "w") as f:
        json.dump(defaults, f)

    # ── refusals ────────────────────────────────────────────────────────────
    st, _, b = req("PUT", "/%s/kms" % B, b"x", {"x-amz-server-side-encryption": "aws:kms"})
    check("aws:kms is refused as not implemented", (st, xml_code(b)) == (501, "NotImplemented"), (st, b[:200]))
    st, _, b = req("PUT", "/%s/bogus" % B, b"x", {"x-amz-server-side-encryption": "ROT13"})
    check("an unknown algorithm is refused", (st, xml_code(b)) == (400, "InvalidArgument"), (st, b[:200]))
    key = base64.b64encode(b"k" * 32).decode()
    kmd5 = base64.b64encode(hashlib.md5(b"k" * 32).digest()).decode()
    ssec = {"x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key,
            "x-amz-server-side-encryption-customer-key-MD5": kmd5}
    st, _, b = req("PUT", "/%s/ssec-plain" % B, b"secret", ssec)
    check("SSE-C over plain HTTP is refused", (st, xml_code(b)) == (400, "InvalidRequest"), (st, b[:300]))
    check("and nothing was stored", req("HEAD", "/%s/ssec-plain" % B)[0] == 404)
    st, _, b = req("GET", "/%s/big" % B, None, ssec)
    check("a GET with SSE-C headers over plain HTTP is refused", st == 400, (st, b[:200]))
    st, _, b = req("GET", "/%s/big" % B, None, {"x-amz-server-side-encryption": "AES256"})
    check("a GET that names an encryption is refused", (st, xml_code(b)) == (400, "InvalidArgument"), (st, b[:200]))

    # ── a bucket's default ──────────────────────────────────────────────────
    code = err_code(lambda: s3.get_bucket_encryption(Bucket=B))
    check("GetBucketEncryption of a bucket with none is ServerSideEncryptionConfigurationNotFoundError",
          code == (404, "ServerSideEncryptionConfigurationNotFoundError"), code)
    s3.create_bucket(Bucket="dflt")
    kms = {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]}
    code = err_code(lambda: s3.put_bucket_encryption(Bucket="dflt", ServerSideEncryptionConfiguration=kms))
    check("a default of aws:kms is refused", code == (501, "NotImplemented"), code)
    st, _, b = req("PUT", "/dflt?encryption", b"<ServerSideEncryptionConfiguration><Rule/></ServerSideEncryptionConfiguration>")
    check("a default with no algorithm is malformed", (st, xml_code(b)) == (400, "MalformedXML"), (st, b[:200]))
    cfg = {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
    s3.put_bucket_encryption(Bucket="dflt", ServerSideEncryptionConfiguration=cfg)
    got = s3.get_bucket_encryption(Bucket="dflt")["ServerSideEncryptionConfiguration"]["Rules"][0]
    check("GetBucketEncryption reads AES256 back",
          got["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256", got)
    st, _, _ = req("GET", "/dflt/x?encryption")
    check("encryption is a bucket's and not an object's", st == 501, st)
    dflt = marked(100000, "dflt")
    r = s3.put_object(Bucket="dflt", Key="d", Body=dflt)
    g = s3.get_object(Bucket="dflt", Key="d")
    check("a PUT that asks nothing of a bucket with a default is encrypted",
          r.get("ServerSideEncryption") == "AES256" and g["Body"].read() == dflt and
          MARK not in on_disk(data, "d", "dflt"), r)
    up = s3.create_multipart_upload(Bucket="dflt", Key="dmp")
    check("an upload begun in a bucket with a default is encrypted", up.get("ServerSideEncryption") == "AES256", up)
    s3.abort_multipart_upload(Bucket="dflt", Key="dmp", UploadId=up["UploadId"])
    r = s3.copy_object(Bucket="dflt", Key="dcopy", CopySource={"Bucket": B, "Key": "clear"})
    check("a copy into a bucket with a default is encrypted",
          r.get("ServerSideEncryption") == "AES256" and MARK not in on_disk(data, "dcopy", "dflt"), r)
    s3.delete_bucket_encryption(Bucket="dflt")
    code = err_code(lambda: s3.get_bucket_encryption(Bucket="dflt"))
    check("DeleteBucketEncryption removes it", code == (404, "ServerSideEncryptionConfigurationNotFoundError"), code)
    r = s3.put_object(Bucket="dflt", Key="after", Body=dflt)
    check("and the next PUT is in the clear", "ServerSideEncryption" not in r and MARK in on_disk(data, "after", "dflt"))
    check("while what it encrypted before still reads", s3.get_object(Bucket="dflt", Key="d")["Body"].read() == dflt)
    s3.put_bucket_encryption(Bucket="dflt", ServerSideEncryptionConfiguration=cfg)

    # ── versioning ──────────────────────────────────────────────────────────
    s3.create_bucket(Bucket="vers")
    s3.put_bucket_encryption(Bucket="vers", ServerSideEncryptionConfiguration=cfg)
    s3.put_bucket_versioning(Bucket="vers", VersioningConfiguration={"Status": "Enabled"})
    v1b, v2b = marked(300000, "v1"), marked(200000, "v2")
    v1 = s3.put_object(Bucket="vers", Key="k", Body=v1b)["VersionId"]
    v2 = s3.put_object(Bucket="vers", Key="k", Body=v2b)["VersionId"]
    g1 = s3.get_object(Bucket="vers", Key="k", VersionId=v1)
    check("an older encrypted version reads back by its id",
          g1["Body"].read() == v1b and g1.get("ServerSideEncryption") == "AES256")
    check("and the latest is the newer one", s3.get_object(Bucket="vers", Key="k")["Body"].read() == v2b)
    check("a ranged read of the older version is exact",
          s3.get_object(Bucket="vers", Key="k", VersionId=v1, Range="bytes=65530-65545")["Body"].read() ==
          v1b[65530:65546])
    s3.delete_object(Bucket="vers", Key="k")
    check("behind a delete marker the versions still read",
          s3.get_object(Bucket="vers", Key="k", VersionId=v2)["Body"].read() == v2b)
    r = s3.copy_object(Bucket="vers", Key="k2", CopySource={"Bucket": "vers", "Key": "k", "VersionId": v1})
    check("a copy of an encrypted version is encrypted and reads back",
          r.get("ServerSideEncryption") == "AES256" and
          s3.get_object(Bucket="vers", Key="k2")["Body"].read() == v1b, r)
    lv = s3.list_object_versions(Bucket="vers", Prefix="k")
    etags = {v["VersionId"]: v["ETag"].strip('"') for v in lv.get("Versions", [])}
    check("ListObjectVersions gives each encrypted version its plaintext MD5",
          etags.get(v1) == md5(v1b) and etags.get(v2) == md5(v2b), etags)
    vdir = os.path.join(data, "vers", "versions")
    leaked = [f for root, _, files in os.walk(vdir) for f in files
              if MARK in open(os.path.join(root, f), "rb").read()]
    check("no noncurrent version's file holds its plaintext", not leaked, leaked)

    # ── tags written into, and around, an encrypted object ──────────────────
    rw0 = stat_int("tag_rewrites")
    tags = [{"Key": "t%02d" % i, "Value": "v" * 250} for i in range(10)]
    s3.put_object_tagging(Bucket=B, Key="big", Tagging={"TagSet": tags})
    check("tags that do not fit the header's slot rewrite the encrypted object", wait_stat("tag_rewrites", rw0 + 1),
          (rw0, stat_int("tag_rewrites")))
    g = s3.get_object(Bucket=B, Key="big")
    check("which then still reads back and says AES256",
          g["Body"].read() == big and g.get("ServerSideEncryption") == "AES256")
    check("a range of it too", s3.get_object(Bucket=B, Key="big", Range="bytes=65530-200000")["Body"].read() ==
          big[65530:200001])

    check("the counters saw the encrypted puts and gets", stat_int("sse_puts") > 0 and stat_int("sse_gets") > 0,
          (stat_int("sse_puts"), stat_int("sse_gets")))
    save_expect(data, expect)


# ─── recovery ───────────────────────────────────────────────────────────────

def remove_journals(data):
    removed = 0
    for root, _, files in os.walk(data):
        for f in files:
            if f.startswith("index.") or f.startswith(".clean."):
                os.unlink(os.path.join(root, f))
                removed += 1
    return removed


def probe(port):
    try:
        return req("GET", "/", node=port)[0] == 200
    except OSError:
        return False


def read_all(s3, expect):
    wrong = []
    for key, want in expect.items():
        try:
            got = md5(s3.get_object(Bucket=B, Key=key)["Body"].read())
        except Exception as e:  # noqa: BLE001
            got = repr(e)[:80]
        if got != want:
            wrong.append((key, got, want))
    return wrong


def mode_recovery(port, data):
    global NODE
    NODE = port
    s3 = boto(port)
    with open(os.path.join(data, STATE)) as f:
        expect = json.load(f)
    check("every object reads back before a restart", not read_all(s3, expect), read_all(s3, expect))
    subprocess.run([BIN, "stop", RUNTIME], capture_output=True)
    time.sleep(0.5)
    subprocess.run([BIN, "start", RUNTIME], capture_output=True)
    check("it starts again", wait_for(lambda: probe(port), 30))
    wrong = read_all(s3, expect)
    check("after a clean restart every encrypted object reads back", not wrong, wrong[:3])
    check("and partNumber still finds a part", s3.get_object(Bucket=B, Key="mp", PartNumber=3)["ContentLength"] ==
          MIB + 777)
    check("the bucket's default survives the restart",
          s3.get_bucket_encryption(Bucket="dflt")["ServerSideEncryptionConfiguration"]["Rules"][0]
          ["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256")

    # A crash with every journal gone: the headers, read at their sealed lengths, are all there is.
    late = marked(700000, "late")
    s3.put_object(Bucket=B, Key="late", Body=late, ServerSideEncryption="AES256")
    expect["late"] = md5(late)
    up = s3.create_multipart_upload(Bucket=B, Key="openmp", ServerSideEncryption="AES256")
    p1 = s3.upload_part(Bucket=B, Key="openmp", UploadId=up["UploadId"], PartNumber=1, Body=marked(5 * MIB, "o1"))
    pid = stats().get("pid")
    removed = remove_journals(data)
    os.kill(int(pid), signal.SIGKILL)
    newpid = wait_for(lambda: (lambda p: p if p and p != pid and probe(port) else None)(stats().get("pid")), 40)
    check("a SIGKILL with %d journal files removed is restarted" % removed, newpid and removed > 0, (pid, newpid))
    wrong = read_all(s3, expect)
    check("after it every encrypted object is found from its file and reads back", not wrong, wrong[:3])
    listed = {o["Key"] for o in s3.list_objects_v2(Bucket=B).get("Contents", [])}
    check("and is listed", set(expect) <= listed, set(expect) - listed)
    check("no object file was set aside as corrupt", "corrupt" not in subprocess.run(
        [BIN, "stats", RUNTIME], capture_output=True, text=True).stdout)
    with open(os.path.join(data, DEFAULTS_STATE)) as f:
        wrong = default_sums_wrong(json.load(f))
    check("and every default checksum is read back from its sealed object's header", not wrong, wrong[:2])
    os.unlink(os.path.join(data, DEFAULTS_STATE))
    # The upload open across the crash keeps its sealed part, and completes into an object that opens.
    p2 = s3.upload_part(Bucket=B, Key="openmp", UploadId=up["UploadId"], PartNumber=2, Body=marked(9999, "o2"))
    s3.complete_multipart_upload(Bucket=B, Key="openmp", UploadId=up["UploadId"], MultipartUpload={"Parts": [
        {"PartNumber": 1, "ETag": p1["ETag"]}, {"PartNumber": 2, "ETag": p2["ETag"]}]})
    check("an encrypted upload open across the crash completes and reads back",
          s3.get_object(Bucket=B, Key="openmp")["Body"].read() == marked(5 * MIB, "o1") + marked(9999, "o2"))
    os.unlink(os.path.join(data, STATE))


# ─── TLS: SSE-C ─────────────────────────────────────────────────────────────

def mode_tls(port, cert, data):
    global NODE, CERT, KEYARGS
    NODE, CERT = port, cert
    s3 = boto(port, https=True)
    s3.create_bucket(Bucket=B)
    key = os.urandom(32)
    other = os.urandom(32)
    ka = {"SSECustomerAlgorithm": "AES256", "SSECustomerKey": key}
    wrong = {"SSECustomerAlgorithm": "AES256", "SSECustomerKey": other}
    kmd5 = base64.b64encode(hashlib.md5(key).digest()).decode()

    body = marked(2 * MIB + 333, "c")
    r = s3.put_object(Bucket=B, Key="c", Body=body, **ka)
    check("an SSE-C PUT is answered with the algorithm and the key's MD5",
          (r.get("SSECustomerAlgorithm"), r.get("SSECustomerKeyMD5")) == ("AES256", kmd5), r)
    etag = r["ETag"].strip('"')
    check("its ETag is not the MD5 of the plaintext", re.fullmatch("[0-9a-f]{32}", etag) and etag != md5(body), etag)
    g = s3.get_object(Bucket=B, Key="c", **ka)
    check("a GET with the key reads the plaintext", g["Body"].read() == body)
    check("and echoes the algorithm and the key's MD5",
          (g.get("SSECustomerAlgorithm"), g.get("SSECustomerKeyMD5"), g["ETag"].strip('"')) == ("AES256", kmd5, etag), g)
    h = s3.head_object(Bucket=B, Key="c", **ka)
    check("a HEAD with the key gives the length", h["ContentLength"] == len(body), h)
    KEYARGS = ka
    bad = ranges_ok(s3, "c", body)
    KEYARGS = None
    check("every range with the key is exact", not bad, bad)
    code = err_code(lambda: s3.get_object(Bucket=B, Key="c"))
    check("a GET without the key is refused", code == (400, "InvalidRequest"), code)
    code = err_code(lambda: s3.head_object(Bucket=B, Key="c"))
    check("a HEAD without the key is refused", code is not None and code[0] == 400, code)
    code = err_code(lambda: s3.get_object(Bucket=B, Key="c", **wrong))
    check("a GET with another key is refused as access denied", code == (403, "AccessDenied"), code)
    code = err_code(lambda: s3.head_object(Bucket=B, Key="c", **wrong))
    check("a HEAD with another key is refused", code is not None and code[0] == 403, code)
    st, _, b = req("GET", "/%s/c" % B, None, {
        "x-amz-server-side-encryption-customer-algorithm": "AES256",
        "x-amz-server-side-encryption-customer-key": base64.b64encode(key).decode(),
        "x-amz-server-side-encryption-customer-key-MD5": base64.b64encode(hashlib.md5(other).digest()).decode()})
    check("a key whose MD5 header does not match it is refused", (st, xml_code(b)) == (400, "InvalidArgument"),
          (st, b[:200]))
    st, _, b = req("GET", "/%s/c" % B, None, {"x-amz-server-side-encryption-customer-algorithm": "AES256"})
    check("an algorithm with no key is refused", (st, xml_code(b)) == (400, "InvalidArgument"), (st, b[:200]))
    st, _, b = req("PUT", "/%s/both" % B, b"x", {
        "x-amz-server-side-encryption": "AES256",
        "x-amz-server-side-encryption-customer-algorithm": "AES256",
        "x-amz-server-side-encryption-customer-key": base64.b64encode(key).decode(),
        "x-amz-server-side-encryption-customer-key-MD5": kmd5})
    check("SSE-S3 and SSE-C together are refused", (st, xml_code(b)) == (400, "InvalidArgument"), (st, b[:200]))
    raw = on_disk(data, "c")
    check("the SSE-C object's file holds no plaintext", MARK not in raw)
    check("and not the key", key not in raw and base64.b64encode(key) not in raw)
    lst = {o["Key"]: o["ETag"].strip('"') for o in s3.list_objects_v2(Bucket=B).get("Contents", [])}
    check("a listing gives the same opaque ETag", lst.get("c") == etag, lst.get("c"))
    st, hh, _ = req("HEAD", "/%s/c" % B, headers=dict(c_headers(key), **{"x-amz-checksum-mode": "ENABLED"}))
    check("the SSE-C object sent without a checksum has S3's default, the CRC64NVME of its plaintext",
          (st, hh.get("x-amz-checksum-crc64nvme"), hh.get("x-amz-checksum-type")) ==
          (200, sig.crc64nvme_b64(body), "FULL_OBJECT"), (st, hh))

    # A small SSE-C object is never held, so every read asks for the key again.
    small = marked(4000, "cs")
    s3.put_object(Bucket=B, Key="cs", Body=small, **ka)
    hb0 = stat_int("hot_bytes")
    hot0 = stat_int("hot_gets")
    for _ in range(3):
        check("a small SSE-C object reads with the key", s3.get_object(Bucket=B, Key="cs", **ka)["Body"].read() == small)
    code = err_code(lambda: s3.get_object(Bucket=B, Key="cs"))
    check("and is refused without it after being read", code == (400, "InvalidRequest"), code)
    time.sleep(1.2)
    check("nothing of it was held in memory", stat_int("hot_gets") == hot0 and stat_int("hot_bytes") == hb0,
          (hot0, stat_int("hot_gets"), hb0, stat_int("hot_bytes")))

    # ── multipart under a client's key ──────────────────────────────────────
    p = [marked(5 * MIB, "cp1"), marked(2 * MIB + 5, "cp2")]
    up = s3.create_multipart_upload(Bucket=B, Key="cmp", **ka)
    uid = up["UploadId"]
    check("an SSE-C upload is answered with its algorithm", up.get("SSECustomerAlgorithm") == "AES256", up)
    code = err_code(lambda: s3.upload_part(Bucket=B, Key="cmp", UploadId=uid, PartNumber=1, Body=p[0]))
    check("a part of it without the key is refused", code is not None and code[0] == 400, code)
    code = err_code(lambda: s3.upload_part(Bucket=B, Key="cmp", UploadId=uid, PartNumber=1, Body=p[0], **wrong))
    check("a part of it with another key is refused", code is not None and code[0] == 403, code)
    parts = []
    for i, part in enumerate(p, 1):
        r = s3.upload_part(Bucket=B, Key="cmp", UploadId=uid, PartNumber=i, Body=part, **ka)
        parts.append({"PartNumber": i, "ETag": r["ETag"]})
    check("a part's ETag is not its MD5", parts[0]["ETag"].strip('"') != md5(p[0]), parts[0])
    s3.complete_multipart_upload(Bucket=B, Key="cmp", UploadId=uid, MultipartUpload={"Parts": parts})
    check("the SSE-C multipart object reads back with the key",
          s3.get_object(Bucket=B, Key="cmp", **ka)["Body"].read() == b"".join(p))
    check("and its second part by number", s3.get_object(Bucket=B, Key="cmp", PartNumber=2, **ka)["Body"].read() == p[1])
    code = err_code(lambda: s3.get_object(Bucket=B, Key="cmp"))
    check("and is refused without it", code == (400, "InvalidRequest"), code)
    # Completed without the key, so the master key's MAC binds a part list that carries the parts' checksums.
    up = s3.create_multipart_upload(Bucket=B, Key="cmpck", ChecksumAlgorithm="SHA256", **ka)
    parts = []
    for i, part in enumerate(p, 1):
        # The upload's algorithm is what the part is checksummed with, which over TLS boto3 would send in a trailer.
        r = s3.upload_part(Bucket=B, Key="cmpck", UploadId=up["UploadId"], PartNumber=i, Body=part, **ka)
        parts.append({"PartNumber": i, "ETag": r["ETag"], "ChecksumSHA256": r["ChecksumSHA256"]})
    s3.complete_multipart_upload(Bucket=B, Key="cmpck", UploadId=up["UploadId"], MultipartUpload={"Parts": parts})
    want = [base64.b64encode(hashlib.sha256(part).digest()).decode() for part in p]
    got = [s3.get_object(Bucket=B, Key="cmpck", PartNumber=i, ChecksumMode="ENABLED", **ka) for i in (1, 2)]
    check("an SSE-C upload's parts read by number with their own SHA-256, its list bound by a MAC",
          [(g.get("ChecksumSHA256"), g["Body"].read()) for g in got] == list(zip(want, p)),
          [g.get("ChecksumSHA256") for g in got])
    st, got = fetch("/%s/cmpck?attributes" % B, dict(c_headers(key), **{"x-amz-object-attributes": "ObjectParts"}))
    listed = re.findall(rb"<ChecksumSHA256>([^<]*)</ChecksumSHA256>", got) if st == 200 else got
    check("and are listed with them by GetObjectAttributes", listed == [w.encode() for w in want], (st, listed))
    h = read_header(obj_file(data, "cmpck"))
    check("whose list follows the body, under the MAC",
          (extra_of(h, b"x-socketley-part-layout") or b"").endswith(b";32") and
          extra_of(h, b"x-socketley-sse-parts") is not None, h and h["extra"])

    # ── copies across the two kinds ─────────────────────────────────────────
    code = err_code(lambda: s3.copy_object(Bucket=B, Key="x", CopySource={"Bucket": B, "Key": "c"}))
    check("a copy of an SSE-C object without the source's key is refused", code == (400, "InvalidRequest"), code)
    r = s3.copy_object(Bucket=B, Key="c2s3", CopySource={"Bucket": B, "Key": "c"},
                       CopySourceSSECustomerAlgorithm="AES256", CopySourceSSECustomerKey=key,
                       ServerSideEncryption="AES256")
    g = s3.get_object(Bucket=B, Key="c2s3")
    check("an SSE-C object copied with its key into AES256 reads without one",
          g["Body"].read() == body and g.get("ServerSideEncryption") == "AES256" and
          r["CopyObjectResult"]["ETag"].strip('"') == md5(body), r)
    r = s3.copy_object(Bucket=B, Key="s32c", CopySource={"Bucket": B, "Key": "c2s3"}, **ka)
    check("and copied back under a client's key needs it again",
          s3.get_object(Bucket=B, Key="s32c", **ka)["Body"].read() == body and
          err_code(lambda: s3.get_object(Bucket=B, Key="s32c")) == (400, "InvalidRequest"))
    r = s3.copy_object(Bucket=B, Key="c2c", CopySource={"Bucket": B, "Key": "c"},
                       CopySourceSSECustomerAlgorithm="AES256", CopySourceSSECustomerKey=key, **wrong)
    check("an SSE-C object copied to another key opens only with the new one",
          s3.get_object(Bucket=B, Key="c2c", **wrong)["Body"].read() == body and
          err_code(lambda: s3.get_object(Bucket=B, Key="c2c", **ka)) == (403, "AccessDenied"))
    up = s3.create_multipart_upload(Bucket=B, Key="cpc", **ka)
    r1 = s3.upload_part_copy(Bucket=B, Key="cpc", UploadId=up["UploadId"], PartNumber=1,
                             CopySource={"Bucket": B, "Key": "c"}, CopySourceRange="bytes=1000-70999",
                             CopySourceSSECustomerAlgorithm="AES256", CopySourceSSECustomerKey=key, **ka)
    s3.complete_multipart_upload(Bucket=B, Key="cpc", UploadId=up["UploadId"], MultipartUpload={"Parts": [
        {"PartNumber": 1, "ETag": r1["CopyPartResult"]["ETag"]}]})
    check("UploadPartCopy from an SSE-C source into an SSE-C upload reads back",
          s3.get_object(Bucket=B, Key="cpc", **ka)["Body"].read() == body[1000:71000])
    s3.put_object(Bucket=B, Key="s3tls", Body=body, ServerSideEncryption="AES256")
    check("SSE-S3 works over TLS as well", s3.get_object(Bucket=B, Key="s3tls")["Body"].read() == body)

    bound_parts(s3, data, key, other)


# ─── an SSE-C upload's part list, bound at completion ───────────────────────

PARTS_MAC = b"x-socketley-sse-parts"
UPLOAD_WRAP = b"x-socketley-sse-wrap"
# Two parts of one size and a shorter last one, so the header's part sizes stay one number with the last dropped.
BOUND_SIZES = [5 * MIB, 5 * MIB, MIB + 7]


def c_args(key):
    return {"SSECustomerAlgorithm": "AES256", "SSECustomerKey": key}


def c_headers(key):
    return {"x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": base64.b64encode(key).decode(),
            "x-amz-server-side-encryption-customer-key-MD5": base64.b64encode(hashlib.md5(key).digest()).decode()}


def c_upload(s3, name, key, seed, create=None):
    """An SSE-C upload of BOUND_SIZES left open: its id, its completion list and its parts."""
    p = [marked(n, "%s%d" % (seed, i)) for i, n in enumerate(BOUND_SIZES)]
    uid = s3.create_multipart_upload(Bucket=B, Key=name, **c_args(key), **(create or {}))["UploadId"]
    done = []
    for i, part in enumerate(p, 1):
        r = s3.upload_part(Bucket=B, Key=name, UploadId=uid, PartNumber=i, Body=part, **c_args(key))
        done.append({"PartNumber": i, "ETag": r["ETag"]})
    return uid, done, p


def drop_last_part(path, h):
    """Rewrites the header as one that names the object's parts but the last, its sizes and checksum agreeing."""
    t = dict(h)
    t["parts"] = h["parts"] - 1
    t["size"] = h["size"] - BOUND_SIZES[-1]
    write_header(path, t)


def as_before_binding(h, key):
    """`h` with its key wrapped as before part lists were bound: a plain wrap, no MAC and no upload's mark."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    rec = extra_of(h, b"x-socketley-sse").split(b";")
    w = base64.b64decode(rec[5])
    data_key = AESGCM(key).decrypt(w[:12], w[12:], b"socketley-sse-key-v2/upload")
    nonce = os.urandom(12)
    rec[5] = base64.b64encode(nonce + AESGCM(key).encrypt(nonce, data_key, b"socketley-sse-key-v2"))
    t = dict(h)
    t["extra"] = [(n, b";".join(rec) if n == b"x-socketley-sse" else v) for n, v in h["extra"]
                  if n not in (PARTS_MAC, UPLOAD_WRAP)]
    return t


def bound_parts(s3, data, key, other):
    ka = c_args(key)
    hdrs = c_headers(key)

    # Bound by the key a completion carries, as boto3 and the AWS CLI can send it.
    uid, done, p = c_upload(s3, "bykey", key, "bk")
    code = err_code(lambda: s3.complete_multipart_upload(Bucket=B, Key="bykey", UploadId=uid,
                                                         MultipartUpload={"Parts": done}, **c_args(other)))
    check("a completion carrying another key than the upload's is refused", code == (403, "AccessDenied"), code)
    s3.complete_multipart_upload(Bucket=B, Key="bykey", UploadId=uid, MultipartUpload={"Parts": done}, **ka)
    check("the upload completes with its own key after that",
          s3.get_object(Bucket=B, Key="bykey", **ka)["Body"].read() == b"".join(p))
    path = obj_file(data, "bykey")
    h = read_header(path)
    check("a list bound by the key needs no MAC", h and h["crc_ok"] and extra_of(h, PARTS_MAC) is None,
          h and h["extra"])
    drop_last_part(path, h)
    st, got = fetch("/%s/bykey" % B, hdrs)
    check("a key-bound object whose header drops its last part does not open",
          (st, xml_code(got)) == (403, "AccessDenied"), (st, got[:200]))
    st, got = fetch("/%s/bykey?partNumber=1" % B, hdrs)
    check("and nor does its first part by number", st == 403, (st, got[:200]))

    # Bound by a MAC under the master key, when the completion does not carry the client's key.
    uid, done, p = c_upload(s3, "bymaster", key, "bm")
    s3.complete_multipart_upload(Bucket=B, Key="bymaster", UploadId=uid, MultipartUpload={"Parts": done})
    check("an upload completed without its key reads back whole with the key",
          s3.get_object(Bucket=B, Key="bymaster", **ka)["Body"].read() == b"".join(p))
    check("and its last part by number",
          s3.get_object(Bucket=B, Key="bymaster", PartNumber=3, **ka)["Body"].read() == p[2])
    code = err_code(lambda: s3.get_object(Bucket=B, Key="bymaster", **c_args(other)))
    check("while another key is still refused", code == (403, "AccessDenied"), code)
    path = obj_file(data, "bymaster")
    h = read_header(path)
    mac = extra_of(h, PARTS_MAC) if h else None
    check("its header carries the part list's MAC, and not the upload's mark",
          mac is not None and re.fullmatch(rb"[0-9a-f]{8};[0-9a-f]{64}", mac) and extra_of(h, UPLOAD_WRAP) is None,
          h and h["extra"])

    # Tags that bring the header's room to within a MAC of its 4 KiB edge: the upload kept room for one.
    mac_entry = 8 + len(PARTS_MAC) + len(mac or b"")
    sizes_room = 20 - len(extra_of(h, b"x-socketley-part-sizes") or b"")
    want = 4096 - mac_entry // 2 - (24 + len(header_body(h)) - mac_entry + sizes_room) - (8 + len(b"x-amz-tagging"))
    tags = []
    for i in range(10):
        # A tag takes its key, its value and a NUL after each, up to 128 + 256 + 2 bytes.
        n = min(386, want)
        if n < 4:
            break
        k = ("k%d" % i + "k" * 128)[:min(128, n - 2)]
        v = "v" * (n - 2 - len(k))
        want -= n
        tags.append("%s=%s" % (k, v))
    uid, done, pe = c_upload(s3, "edge", key, "edge", {"Tagging": "&".join(tags)})
    w0 = write_bytes()
    s3.complete_multipart_upload(Bucket=B, Key="edge", UploadId=uid, MultipartUpload={"Parts": done})
    written = write_bytes() - w0
    e = read_header(obj_file(data, "edge"))
    used = 24 + len(header_body(e)) if e else 0
    check("an upload whose header would cross 4 KiB only with its MAC is answered from a header past it",
          want == 0 and 4096 < used <= 4096 + mac_entry and e["header_len"] == 8192, (want, used, e and e["header_len"]))
    check("and is still linked in place, its parts not copied", written < MIB, written)
    check("and reads back whole", s3.get_object(Bucket=B, Key="edge", **ka)["Body"].read() == b"".join(pe))
    drop_last_part(path, h)
    st, got = fetch("/%s/bymaster" % B, hdrs)
    check("a MAC-bound object whose header drops its last part is a 500, not the first two parts",
          (st, xml_code(got)) == (500, "InternalError"), (st, got[:200]))
    st, got = fetch("/%s/bymaster?partNumber=1" % B, hdrs)
    check("and nor does its first part read by number", st == 500, (st, got[:200]))
    write_header(path, h)
    st, got = fetch("/%s/bymaster" % B, hdrs)
    check("the header as written reads again, so the refusals were the dropped part's",
          (st, got) == (200, b"".join(p)), st)
    t = dict(h)
    t["extra"] = [(n, v) for n, v in h["extra"] if n != PARTS_MAC]
    write_header(path, t)
    st, got = fetch("/%s/bymaster" % B, hdrs)
    check("an object of an upload begun now with its MAC removed is a 500, never read unbound",
          (st, xml_code(got)) == (500, "InternalError"), (st, got[:200]))
    t["parts"], t["size"] = h["parts"] - 1, h["size"] - BOUND_SIZES[-1]
    write_header(path, t)
    st, got = fetch("/%s/bymaster" % B, hdrs)
    check("and so is one with its MAC and its last part both removed",
          (st, xml_code(got)) == (500, "InternalError"), (st, got[:200]))
    try:
        legacy = as_before_binding(h, key)
    except ImportError:
        legacy = None
        print("  SKIP: python3-cryptography is needed to write an object as before part lists were bound")
    if legacy:
        write_header(path, legacy)
        st, got = fetch("/%s/bymaster" % B, hdrs)
        check("an SSE-C object completed unbound before this change still reads",
              (st, got) == (200, b"".join(p)), (st, got[:200]))
        t = dict(legacy)
        t["extra"] = legacy["extra"] + [(PARTS_MAC, b"0" * 8 + b";" + b"0" * 64)]
        write_header(path, t)
        st, got = fetch("/%s/bymaster" % B, hdrs)
        check("unless it carries a MAC that does not hold", st == 500, st)

    # A completion naming the customer key of an upload that has none is refused.
    up = s3.create_multipart_upload(Bucket=B, Key="s3mpu", ServerSideEncryption="AES256")
    r = s3.upload_part(Bucket=B, Key="s3mpu", UploadId=up["UploadId"], PartNumber=1, Body=b"x" * 1000)
    code = err_code(lambda: s3.complete_multipart_upload(
        Bucket=B, Key="s3mpu", UploadId=up["UploadId"],
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": r["ETag"]}]}, **ka))
    check("SSE-C headers on the completion of an SSE-S3 upload are refused", code == (400, "InvalidRequest"), code)

    # An upload begun before part lists were bound, its meta file rewritten as that runtime wrote it.
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
    except ImportError:
        print("  SKIP: python3-cryptography is needed to write an upload as before part lists were bound")
        return
    uid, done, p = c_upload(s3, "oldform", key, "of")
    meta = os.path.join(data, B, "mpu", uid, "meta")
    h = read_header(meta)
    check("a new SSE-C upload's meta file carries the upload's mark", h and extra_of(h, UPLOAD_WRAP) == b"upload",
          h and h["extra"])
    ok, _ = restart_runtime(NODE, None, lambda: write_header(meta, as_before_binding(h, key)))
    check("the runtime starts again with the upload rewritten", ok)
    doc = "<CompleteMultipartUpload>" + "".join(
        "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>" % (d["PartNumber"], d["ETag"]) for d in done) + \
        "</CompleteMultipartUpload>"
    st, _, b = req("POST", "/%s/oldform?uploadId=%s" % (B, uid), doc.encode())
    check("an upload begun before binding is refused a completion without its key, though a master key is at hand",
          (st, xml_code(b)) == (400, "InvalidRequest") and b"begun before" in b and
          b"x-amz-server-side-encryption-customer" in b, (st, b[:400]))
    check("and nothing is completed", req("HEAD", "/%s/oldform" % B, headers=hdrs)[0] == 404)
    s3.complete_multipart_upload(Bucket=B, Key="oldform", UploadId=uid, MultipartUpload={"Parts": done}, **ka)
    check("it completes with its key", s3.get_object(Bucket=B, Key="oldform", **ka)["Body"].read() == b"".join(p))
    path = obj_file(data, "oldform")
    h = read_header(path)
    check("bound by the key, with no MAC", h and extra_of(h, PARTS_MAC) is None and extra_of(h, UPLOAD_WRAP) is None,
          h and h["extra"])
    drop_last_part(path, h)
    st, got = fetch("/%s/oldform" % B, hdrs)
    check("so a header that drops its last part does not open", (st, xml_code(got)) == (403, "AccessDenied"),
          (st, got[:200]))


def mode_tlsnokey(port, cert, data):
    global NODE, CERT
    NODE, CERT = port, cert
    s3 = boto(port, https=True)
    s3.create_bucket(Bucket=B)
    key = os.urandom(32)
    ka = c_args(key)
    uid, done, p = c_upload(s3, "nomaster", key, "nm")
    doc = "<CompleteMultipartUpload>" + "".join(
        "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>" % (d["PartNumber"], d["ETag"]) for d in done) + \
        "</CompleteMultipartUpload>"
    st, _, b = req("POST", "/%s/nomaster?uploadId=%s" % (B, uid), doc.encode())
    check("without a master key an SSE-C completion that does not carry the key is a 400 InvalidRequest",
          (st, xml_code(b)) == (400, "InvalidRequest"), (st, b[:300]))
    check("which names both ways out", b"x-amz-server-side-encryption-customer" in b and b"--sse-key-file" in b,
          b[:400])
    check("and completes nothing", req("HEAD", "/%s/nomaster" % B, headers=c_headers(key))[0] == 404)
    lp = s3.list_parts(Bucket=B, Key="nomaster", UploadId=uid)
    check("the upload stays open with its parts", len(lp.get("Parts", [])) == 3, lp.get("Parts"))
    s3.complete_multipart_upload(Bucket=B, Key="nomaster", UploadId=uid, MultipartUpload={"Parts": done}, **ka)
    check("and completes when the key is sent",
          s3.get_object(Bucket=B, Key="nomaster", **ka)["Body"].read() == b"".join(p))
    path = obj_file(data, "nomaster")
    h = read_header(path)
    check("bound by that key alone", h and h["crc_ok"] and extra_of(h, PARTS_MAC) is None, h and h["extra"])
    drop_last_part(path, h)
    st, got = fetch("/%s/nomaster" % B, c_headers(key))
    check("so a header that drops its last part does not open", (st, xml_code(got)) == (403, "AccessDenied"),
          (st, got[:200]))
    uid = s3.create_multipart_upload(Bucket=B, Key="plainmpu")["UploadId"]
    r = s3.upload_part(Bucket=B, Key="plainmpu", UploadId=uid, PartNumber=1, Body=b"y" * 1000)
    s3.complete_multipart_upload(Bucket=B, Key="plainmpu", UploadId=uid,
                                 MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": r["ETag"]}]})
    check("while a plain upload completes as before",
          s3.get_object(Bucket=B, Key="plainmpu")["Body"].read() == b"y" * 1000)


# ─── no master key ──────────────────────────────────────────────────────────

def mode_nokey(port):
    global NODE
    NODE = port
    s3 = boto(port)
    s3.create_bucket(Bucket=B)
    code = err_code(lambda: s3.put_object(Bucket=B, Key="k", Body=b"x", ServerSideEncryption="AES256"))
    check("without a master key an AES256 PUT is refused", code == (501, "NotImplemented"), code)
    st, _, b = req("PUT", "/%s/k" % B, b"x", {"x-amz-server-side-encryption": "AES256"})
    check("and says why", b"sse-key-file" in b, b[:300])
    check("and nothing was stored in its place", req("HEAD", "/%s/k" % B)[0] == 404)
    cfg = {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
    code = err_code(lambda: s3.put_bucket_encryption(Bucket=B, ServerSideEncryptionConfiguration=cfg))
    check("and a bucket default is refused too", code == (501, "NotImplemented"), code)
    s3.put_object(Bucket=B, Key="plain", Body=b"plain")
    check("while a plain PUT goes on as before", s3.get_object(Bucket=B, Key="plain")["Body"].read() == b"plain")


# ─── two shards ─────────────────────────────────────────────────────────────

def mode_shards(nodes, data):
    global NODE
    NODE = nodes[0]
    st, _, _ = req("PUT", "/" + B, node=nodes[1])
    check("a bucket is made through shard 1", st == 200, st)
    doc = (b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault>"
           b"<SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule>"
           b"</ServerSideEncryptionConfiguration>")
    st, _, b = req("PUT", "/%s?encryption" % B, doc, node=nodes[1])
    check("PutBucketEncryption through shard 1 is taken", st == 200, (st, b[:200]))
    for i, n in enumerate(nodes):
        st, _, b = req("GET", "/%s?encryption" % B, node=n)
        check("GetBucketEncryption through node %d reads AES256" % i, st == 200 and b"AES256" in b, (st, b[:200]))
    bodies = {}
    for i in range(16):
        key = "k%02d" % i
        bodies[key] = marked(1000 + i * 9000 if i % 4 else 300000 + i, key)
        st, h, _ = req("PUT", "/%s/%s" % (B, key), bodies[key], node=nodes[i % 2])
        if st != 200 or h.get("x-amz-server-side-encryption") != "AES256":
            check("every PUT through either node is encrypted by the default", False, (key, st, h))
            break
    else:
        check("every PUT through either node is encrypted by the default", True)
    wrong = []
    for rnd in range(2):
        for key, want in bodies.items():
            for n in nodes:
                st, h, got = req("GET", "/%s/%s" % (B, key), node=n)
                if st != 200 or got != want or h.get("x-amz-server-side-encryption") != "AES256":
                    wrong.append((rnd, key, n, st, len(got)))
    check("every object reads alike through its owner and the other shard, twice", not wrong, wrong[:4])
    for key in bodies:
        st, h, _ = req("HEAD", "/%s/%s" % (B, key), node=nodes[1])
        if st != 200 or int(h.get("content-length", -1)) != len(bodies[key]):
            check("a HEAD through shard 1 gives every plaintext length", False, (key, st, h))
            break
    else:
        check("a HEAD through shard 1 gives every plaintext length", True)
    leaked = [k for k in bodies if MARK in on_disk(data, k)]
    check("no object's file holds its plaintext", not leaked, leaked)
    # A multipart upload begun on one node and fed on the other.
    st, _, b = req("POST", "/%s/smp?uploads" % B, node=nodes[0])
    uid = ET.fromstring(b).findtext(NS + "UploadId")
    p = [marked(5 * MIB, "s1"), marked(70000, "s2")]
    tags = []
    for i, part in enumerate(p, 1):
        st, h, _ = req("PUT", "/%s/smp?partNumber=%d&uploadId=%s" % (B, i, uid), part, node=nodes[i % 2])
        tags.append(h.get("etag"))
    xml = "<CompleteMultipartUpload>" + "".join(
        "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>" % (i, e) for i, e in enumerate(tags, 1)) + \
        "</CompleteMultipartUpload>"
    st, h, b = req("POST", "/%s/smp?uploadId=%s" % (B, uid), xml.encode(), node=nodes[1])
    check("an encrypted upload fed through both nodes completes", st == 200 and
          h.get("x-amz-server-side-encryption") == "AES256", (st, b[:200]))
    for i, n in enumerate(nodes):
        st, _, got = req("GET", "/%s/smp" % B, node=n)
        check("and reads back whole through node %d" % i, st == 200 and got == b"".join(p), (st, len(got)))
        st, _, got = req("GET", "/%s/smp?partNumber=2" % B, node=n)
        check("and its part 2 through node %d" % i, st == 206 and got == p[1], (st, len(got)))
    st, _, _ = req("DELETE", "/%s?encryption" % B, node=nodes[0])
    check("DeleteBucketEncryption through shard 0 is taken", st == 204, st)
    for i, n in enumerate(nodes):
        st, h, _ = req("PUT", "/%s/after%d" % (B, i), MARK * 10, node=n)
        check("and node %d stores the next PUT in the clear" % i,
              st == 200 and "x-amz-server-side-encryption" not in h, (st, h))


# ─── an object header as object_format.cpp writes it ────────────────────────

def crc32c(data, crc=0):
    global CRC_TABLE
    try:
        CRC_TABLE
    except NameError:
        CRC_TABLE = []
        for i in range(256):
            c = i
            for _ in range(8):
                c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
            CRC_TABLE.append(c)
    crc ^= 0xFFFFFFFF
    for b in data:
        crc = CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def read_header(path):
    with open(path, "rb") as f:
        head = f.read(65536)
    if head[:8] != b"SKLOBJ\x01\x00":
        return None
    _, header_len, body_len, crc = struct.unpack_from("<IIII", head, 8)
    body = head[24:24 + body_len]
    r = 0
    size, mtime = struct.unpack_from("<QQ", body, r)
    r += 16
    md5d = body[r:r + 16]
    r += 16
    parts, = struct.unpack_from("<I", body, r)
    r += 4

    def s():
        nonlocal r
        n, = struct.unpack_from("<I", body, r)
        v = body[r + 4:r + 4 + n]
        r += 4 + n
        return v
    key = s()
    ctype = s()
    n, = struct.unpack_from("<I", body, r)
    r += 4
    extra = [(s(), s()) for _ in range(n)]
    return dict(header_len=header_len, crc_ok=crc32c(head[:20] + body) == crc, size=size, mtime=mtime, md5=md5d,
                parts=parts, key=key, ctype=ctype, extra=extra)


def header_body(h):
    def s(v):
        return struct.pack("<I", len(v)) + v
    return struct.pack("<QQ", h["size"], h["mtime"]) + h["md5"] + struct.pack("<I", h["parts"]) + s(h["key"]) + \
        s(h["ctype"]) + struct.pack("<I", len(h["extra"])) + b"".join(s(n) + s(v) for n, v in h["extra"])


def write_header(path, h):
    """Writes `h` over the header of the file at `path`, its checksum made again, as someone who can write the disk can."""
    body = header_body(h)
    pre = b"SKLOBJ\x01\x00" + struct.pack("<III", 1, h["header_len"], len(body))
    out = pre + struct.pack("<I", crc32c(pre + body)) + body
    out += b"\0" * (h["header_len"] - len(out))
    with open(path, "r+b") as f:
        f.write(out)
        f.flush()
        os.fsync(f.fileno())


def extra_of(h, name):
    return dict(h["extra"]).get(name)


def set_extra(h, name, value):
    h["extra"] = [(n, value if n == name else v) for n, v in h["extra"]]


def fetch(path, headers=None):
    """A GET's status and body, or "cut" when the connection ends inside a body its headers promised."""
    try:
        st, _, body = req("GET", path, headers=headers)
        return st, body
    except (http.client.IncompleteRead, http.client.RemoteDisconnected, ConnectionError) as e:
        return "cut", type(e).__name__


def swap(path, a, b, n):
    with open(path, "r+b") as f:
        f.seek(a)
        x = f.read(n)
        f.seek(b)
        y = f.read(n)
        f.seek(a)
        f.write(y)
        f.seek(b)
        f.write(x)
        f.flush()
        os.fsync(f.fileno())


def flip(path, at):
    with open(path, "r+b") as f:
        f.seek(at)
        c = f.read(1)
        f.seek(at)
        f.write(bytes([c[0] ^ 1]))
        f.flush()
        os.fsync(f.fileno())


def restart_runtime(port, data=None, between=None):
    """Stops and starts the runtime, every journal removed in between when `data` is given, `between` run there."""
    subprocess.run([BIN, "stop", RUNTIME], capture_output=True)
    time.sleep(0.5)
    removed = remove_journals(data) if data else 0
    if between:
        between()
    subprocess.run([BIN, "start", RUNTIME], capture_output=True)
    return wait_for(lambda: probe(port), 30), removed


# ─── tampering with what is on the disk ─────────────────────────────────────

TB = "ssetamper"


def mode_tamper(port, data):
    global NODE
    NODE = port
    s3 = boto(port)
    s3.create_bucket(Bucket=TB)
    aes = {"ServerSideEncryption": "AES256"}

    # A header cut back to a chunk boundary: every chunk before it still opens, and none of them ends the stream.
    body = marked(3 * 65536 + 100, "cut")
    s3.put_object(Bucket=TB, Key="cut", Body=body, **aes)
    path = obj_file(data, "cut", TB)
    h = read_header(path)
    check("the header this test rewrites is the one the runtime wrote", h and h["crc_ok"] and h["size"] == len(body))
    h["size"] = 2 * 65536
    write_header(path, h)
    st, got = fetch("/%s/cut" % TB)
    check("an object whose header was cut to a chunk boundary does not read as the shorter object",
          st != 200 and got != body[:2 * 65536], (st, len(got) if isinstance(got, bytes) else got))
    st, got = fetch("/%s/cut" % TB, {"Range": "bytes=131000-131071"})
    check("and nor does a range read to its claimed end", st not in (200, 206), (st, got[:80]))
    st, got = fetch("/%s/cut" % TB, {"Range": "bytes=0-99"})
    check("while a range inside it is still the object's own bytes", (st, got) == (206, body[:100]), st)

    # A small object, read whole with its header, is refused before a header is sent: cut to empty, it is a 500.
    small = marked(3000, "smallcut")
    s3.put_object(Bucket=TB, Key="small", Body=small, **aes)
    path = obj_file(data, "small", TB)
    h = read_header(path)
    h["size"] = 0
    write_header(path, h)
    st, got = fetch("/%s/small" % TB)
    check("a small object whose header says it is empty is a 500, not an empty object",
          (st, xml_code(got)) == (500, "InternalError"), (st, got[:200]))

    # Two parts of one upload share its data key, so their chunks at one index were interchangeable.
    p = [marked(5 * MIB, "sp1"), marked(5 * MIB + 1000, "sp2")]
    mpu(s3, "spliced", p, create=aes, bucket=TB)
    path = obj_file(data, "spliced", TB)
    h = read_header(path)
    hl = h["header_len"]
    # Where part 2's stream begins depends on the format the record names, so the swap is exact for either.
    swap(path, hl, hl + sealed_len(len(p[0]), int(extra_of(h, b"x-socketley-sse")[:1])), 65536 + 28)
    st, got = fetch("/%s/spliced" % TB, {"Range": "bytes=0-99"})
    check("chunk 0 of part 2 put in the place of chunk 0 of part 1 does not open there",
          st not in (200, 206) and got != p[1][:100], (st, got[:40]))
    st, got = fetch("/%s/spliced" % TB, {"Range": "bytes=%d-%d" % (len(p[0]), len(p[0]) + 99)})
    check("and nor does chunk 0 of part 1 in part 2's place", st not in (200, 206), (st, got[:40]))
    st, got = fetch("/%s/spliced" % TB)
    check("so the whole object does not read as a mix of both", st != 200, st)

    # A header that names fewer parts than were completed: the data key is wrapped with the list it had.
    p = [marked(5 * MIB, "dp1"), marked(5 * MIB, "dp2"), marked(MIB + 7, "dp3")]
    mpu(s3, "dropped", p, create=aes, bucket=TB)
    path = obj_file(data, "dropped", TB)
    h = read_header(path)
    check("a completed upload's header records its part sizes", extra_of(h, b"x-socketley-part-sizes") is not None,
          h["extra"])
    h["parts"] = 2
    h["size"] = 2 * 5 * MIB
    set_extra(h, b"x-socketley-part-sizes", str(5 * MIB).encode())
    write_header(path, h)
    st, got = fetch("/%s/dropped" % TB)
    check("a header that drops the last part is a 500, not the first two parts",
          (st, xml_code(got)) == (500, "InternalError"), (st, got[:200]))
    st, got = fetch("/%s/dropped?partNumber=1" % TB)
    check("and nor does partNumber read a part of it", st == 500, (st, got[:200]))

    # A record set back to format 1, whose chunks were bound to their index alone.
    body = marked(200000, "downgrade")
    s3.put_object(Bucket=TB, Key="downgrade", Body=body, **aes)
    path = obj_file(data, "downgrade", TB)
    h = read_header(path)
    rec = extra_of(h, b"x-socketley-sse")
    check("a new object is written in format 2", rec is not None and rec.startswith(b"2;"), rec)
    set_extra(h, b"x-socketley-sse", b"1" + rec[1:])
    write_header(path, h)
    st, got = fetch("/%s/downgrade" % TB)
    check("a record set back to format 1 opens nothing", st != 200, st)


# ─── a part list too long for the header ────────────────────────────────────

LB = "sselayout"
# Part numbers with gaps, and every size its own, so the list is long and the numbers have to be kept.
LAYOUT_NUMBERS = [1, 2, 4, 5, 7, 8, 10, 11, 13]


def layout_parts():
    return [marked(5 * MIB + 4099 * i + 1, "lay%d" % n) for i, n in enumerate(LAYOUT_NUMBERS[:-1])] + \
        [marked(12345, "laylast")]


def mode_layout(port, data):
    global NODE
    NODE = port
    s3 = boto(port)
    s3.create_bucket(Bucket=LB)
    parts = layout_parts()
    whole = b"".join(parts)
    trailers = stat_int("multipart_list_trailers")
    up = s3.create_multipart_upload(Bucket=LB, Key="varied", ServerSideEncryption="AES256")
    done = []
    for n, p in zip(LAYOUT_NUMBERS, parts):
        r = s3.upload_part(Bucket=LB, Key="varied", UploadId=up["UploadId"], PartNumber=n, Body=p)
        done.append({"PartNumber": n, "ETag": r["ETag"]})
    r = s3.complete_multipart_upload(Bucket=LB, Key="varied", UploadId=up["UploadId"], MultipartUpload={"Parts": done})
    check("an encrypted upload of %d parts, each its own size and numbered with gaps, completes" % len(parts),
          r.get("ServerSideEncryption") == "AES256" and r["ETag"].strip('"').endswith("-%d" % len(parts)), r)
    path = obj_file(data, "varied", LB)
    h = read_header(path)
    check("its part list is kept after the body, its header naming where and its digest",
          extra_of(h, b"x-socketley-part-layout") is not None and extra_of(h, b"x-socketley-part-sizes") is None,
          h["extra"])
    check("which the stats count", wait_stat("multipart_list_trailers", trailers + 1),
          (trailers, stat_int("multipart_list_trailers")))
    with open(path, "rb") as f:
        raw = f.read()
    check("the file does not hold its plaintext", MARK not in raw, raw.count(MARK))
    check("and is the header, every part's sealed stream and the list",
          len(raw) == h["header_len"] + sum(sealed_len(len(p)) for p in parts) + 20 + 12 * len(parts),
          len(raw))

    def reads(label):
        g = s3.get_object(Bucket=LB, Key="varied")
        check("%s: it reads back whole" % label, g["Body"].read() == whole)
        bad = []
        at = 0
        for i, p in enumerate(parts):
            if i:
                got = s3.get_object(Bucket=LB, Key="varied", Range="bytes=%d-%d" % (at - 50, at + 49))["Body"].read()
                if got != whole[at - 50:at + 50]:
                    bad.append(("across", i))
            got = s3.get_object(Bucket=LB, Key="varied", PartNumber=i + 1)
            if got["Body"].read() != p or got["ContentLength"] != len(p):
                bad.append(("part", i + 1))
            hd = s3.head_object(Bucket=LB, Key="varied", PartNumber=i + 1)
            if hd["ContentLength"] != len(p) or hd.get("PartsCount") != len(parts):
                bad.append(("head", i + 1, hd["ContentLength"]))
            at += len(p)
        check("%s: every part by partNumber, GET and HEAD, and every range across a part boundary" % label, not bad, bad)

    # Each part's SHA-256 kept after a sealed body, of parts copied into it and of parts sealed where they lie.
    ck_objects = {"ck-varied": parts, "ck-equal": [marked(5 * MIB, "cke%d" % i) for i in range(3)] + [marked(777, "ckl")]}
    for key, ps in ck_objects.items():
        up = s3.create_multipart_upload(Bucket=LB, Key=key, ServerSideEncryption="AES256", ChecksumAlgorithm="SHA256")
        done = []
        for i, p in enumerate(ps, 1):
            r = s3.upload_part(Bucket=LB, Key=key, UploadId=up["UploadId"], PartNumber=i, Body=p,
                               ChecksumAlgorithm="SHA256")
            done.append({"PartNumber": i, "ETag": r["ETag"], "ChecksumSHA256": r["ChecksumSHA256"]})
        w0 = write_bytes()
        s3.complete_multipart_upload(Bucket=LB, Key=key, UploadId=up["UploadId"], MultipartUpload={"Parts": done})
        written = write_bytes() - w0
        h = read_header(obj_file(data, key, LB))
        with open(obj_file(data, key, LB), "rb") as f:
            size = os.fstat(f.fileno()).st_size
        check("%s: an encrypted upload's SHA-256 part checksums follow its sealed body, the header naming their width"
              % key, (extra_of(h, b"x-socketley-part-layout") or b"").endswith(b";32") and
              size == h["header_len"] + sum(sealed_len(len(p)) for p in ps) + 24 + 44 * len(ps), (h["extra"], size))
        if key == "ck-equal":
            check("ck-equal: and its parts were sealed where they lie, the list written after them, not copied",
                  written < MIB, written)

    def ck_reads(label):
        bad = []
        for key, ps in ck_objects.items():
            for i, p in enumerate(ps, 1):
                want = base64.b64encode(hashlib.sha256(p).digest()).decode()
                g = s3.get_object(Bucket=LB, Key=key, PartNumber=i, ChecksumMode="ENABLED")
                if (g.get("ChecksumSHA256"), g["Body"].read() == p) != (want, True):
                    bad.append((key, "get", i, g.get("ChecksumSHA256")))
                hd = s3.head_object(Bucket=LB, Key=key, PartNumber=i, ChecksumMode="ENABLED")
                if hd.get("ChecksumSHA256") != want:
                    bad.append((key, "head", i, hd.get("ChecksumSHA256")))
            a = s3.get_object_attributes(Bucket=LB, Key=key, ObjectAttributes=["ObjectParts"])
            got = [(q["PartNumber"], q["Size"], q.get("ChecksumSHA256")) for q in a["ObjectParts"]["Parts"]]
            if got != [(i, len(p), base64.b64encode(hashlib.sha256(p).digest()).decode()) for i, p in enumerate(ps, 1)]:
                bad.append((key, "attributes", got[:2]))
        check("%s: each encrypted part's own SHA-256 by GET, HEAD and GetObjectAttributes" % label, not bad, bad[:3])

    reads("before a restart")
    ck_reads("before a restart")
    ok, removed = restart_runtime(port, data)
    check("it starts again with %d journal files removed" % removed, ok and removed > 0, (ok, removed))
    reads("after it, from the header and the list in the file")
    ck_reads("after it, from the list in the file")

    # The list is checked against its digest, so one bent by a byte places nothing.
    flip(path, len(raw) - 5)
    st, got = fetch("/%s/varied?partNumber=2" % LB)
    check("a list bent by a byte is a 500 for a partNumber read", (st, xml_code(got)) == (500, "InternalError"),
          (st, got[:200]))
    st, got = fetch("/%s/varied" % LB)
    check("and the whole object is not read through it", st != 200, st)


# ─── encrypted puts through a pooled file ───────────────────────────────────

PB = "ssepool"


def mode_pool(port, data):
    global NODE
    NODE = port
    s3 = boto(port)
    s3.create_bucket(Bucket=PB)

    def puts(n, sse):
        extra = {"ServerSideEncryption": "AES256"} if sse else {}
        s3.put_object(Bucket=PB, Key="warm%d" % sse, Body=b"w", **extra)
        time.sleep(0.3)
        f0 = stat_int("fsyncs")
        t0 = time.time()
        for i in range(n):
            s3.put_object(Bucket=PB, Key="f%d/%d" % (sse, i), Body=marked(4096, "f%d%d" % (sse, i)), **extra)
        took = (time.time() - t0) / n
        time.sleep(0.5)
        return (stat_int("fsyncs") - f0) / n, took

    plain_syncs, plain_ms = puts(40, False)
    sse_syncs, sse_ms = puts(40, True)
    pooled = 0
    for i in range(40):
        h = read_header(obj_file(data, "f1/%d" % i, PB))
        digest = extra_of(h, b"x-socketley-stored-md5")
        with open(obj_file(data, "f1/%d" % i, PB), "rb") as f:
            f.seek(h["header_len"])
            stored = f.read()
        pooled += 1 if digest == md5(stored).encode() else 0
    # A pool refilled behind a slow sync of pool/ can run dry for a put or two, which then take the long way.
    check("small SSE-S3 puts go through a pooled file, each naming the digest of its sealed bytes (%d of 40)" % pooled,
          pooled >= 30, pooled)
    check("and sync as plain ones do: %.2f fsyncs and %.2f ms a put against %.2f and %.2f in the clear" %
          (sse_syncs, sse_ms * 1000, plain_syncs, plain_ms * 1000), abs(sse_syncs - plain_syncs) < 0.5,
          (sse_syncs, plain_syncs))

    # SOCKETLEY_STORAGE_KILL_AFTER_RENAME=killme/ kills the worker right after the rename that answers a pooled put.
    def killed_put(key, body):
        pid = stats().get("pid")
        # Sent once: botocore retries a cut connection, and a retry the respawned worker takes is a second put.
        try:
            req("PUT", "/%s/%s" % (PB, key), body, {"x-amz-server-side-encryption": "AES256"})
            answered = True
        except (http.client.HTTPException, OSError):
            answered = False
        back = wait_for(lambda: (lambda p: p if p and p != pid and probe(port) else None)(stats().get("pid")), 40)
        return answered, back

    pool_dir = os.path.join(data, PB, "pool")
    # The descriptors every bucket's pool holds are bounded together, so the kills begin from a start, with every pool empty.
    restart_runtime(port)
    for key, torn in (("killme/whole", False), ("killme/torn", True)):
        body = marked(100000, key)
        # A start leaves the pool empty and its first put asks for a refill, which is ready once pool/ is synced;
        # a snapshot counting exactly that one put is this worker's and was taken after the put looked in the pool.
        s3.put_object(Bucket=PB, Key="warm/" + key, Body=b"w", ServerSideEncryption="AES256")

        def pool_ready():
            st = stats()
            return st.get("puts") == "1" and int(st.get("pool_ready", "0")) >= 1
        check("%s: the pool is filled again" % key, wait_for(pool_ready, 20), stats().get("pool_ready"))
        answered, back = killed_put(key, body)
        check("%s: the worker is killed after the rename, before it answers, and comes back" % key,
              not answered and back, (answered, back))
        path = obj_file(data, key, PB)
        h = read_header(path) if path and os.path.exists(path) else None
        check("%s: its file names the digest of its sealed bytes" % key,
              h is not None and extra_of(h, b"x-socketley-stored-md5") is not None, h and h["extra"])
        # A process killed keeps its renames; a crash of the machine may not, which leaves the file in pool/.
        subprocess.run([BIN, "stop", RUNTIME], capture_output=True)
        time.sleep(0.5)
        lost = os.path.join(pool_dir, "0.000000000000000000000000000000%02d" % (77 + torn))
        os.rename(path, lost)
        if torn:
            flip(lost, os.path.getsize(lost) - 1000)
        remove_journals(data)
        subprocess.run([BIN, "start", RUNTIME], capture_output=True)
        check("%s: it starts again" % key, wait_for(lambda: probe(port), 30))
        st, got = fetch("/%s/%s" % (PB, key))
        if torn:
            check("a sealed pooled file with a page lost is not rolled forward", st == 404, (st, got[:120]))
        else:
            check("a whole sealed pooled file is rolled forward with no key at hand, and reads back",
                  (st, got) == (200, body), (st, len(got)))
        check("%s: and the pool holds no file it left" % key, not os.path.exists(lost), os.listdir(pool_dir))


# ─── a bucket policy that requires encryption ───────────────────────────────

YB = "ssepolicy"


def mode_policy(port):
    global NODE
    NODE = port
    s3 = boto(port)
    s3.create_bucket(Bucket=YB)
    res = "arn:aws:s3:::%s/*" % YB
    # The policy S3's documentation gives for requiring SSE-S3 on every upload.
    pol = {"Version": "2012-10-17", "Statement": [
        {"Sid": "DenyIncorrectEncryptionHeader", "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
         "Resource": res, "Condition": {"StringNotEquals": {"s3:x-amz-server-side-encryption": "AES256"}}},
        {"Sid": "DenyUnencryptedObjectUploads", "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
         "Resource": res, "Condition": {"Null": {"s3:x-amz-server-side-encryption": "true"}}}]}
    st, _, body = req("PUT", "/%s?policy" % YB, json.dumps(pol).encode())
    check("a policy conditioned on s3:x-amz-server-side-encryption is taken", st == 204, (st, body[:300]))
    aes = {"x-amz-server-side-encryption": "AES256"}
    st, _, body = req("PUT", "/%s/clear" % YB, b"x")
    check("a PUT that does not ask for encryption is refused by it", (st, xml_code(body)) == (403, "AccessDenied"),
          (st, body[:200]))
    st, _, _ = req("PUT", "/%s/sealed" % YB, b"x", aes)
    check("one that asks for AES256 is not", st == 200, st)
    st, _, body = req("PUT", "/%s/kms" % YB, b"x", {"x-amz-server-side-encryption": "aws:kms"})
    check("one that asks for another method is refused by it", (st, xml_code(body)) == (403, "AccessDenied"), st)
    st, _, body = req("PUT", "/%s/copy" % YB, b"", {"x-amz-copy-source": "/%s/sealed" % YB})
    check("a copy that does not ask is refused", (st, xml_code(body)) == (403, "AccessDenied"), st)
    st, _, _ = req("PUT", "/%s/copy" % YB, b"", dict(aes, **{"x-amz-copy-source": "/%s/sealed" % YB}))
    check("and one that does is not", st == 200, st)
    st, _, body = req("POST", "/%s/mp?uploads" % YB)
    check("an upload begun without it is refused", (st, xml_code(body)) == (403, "AccessDenied"), st)
    # The parts and the completion carry no header: the encryption was chosen, and judged, at the creation.
    part = marked(5 * MIB, "polpart")
    r = s3.create_multipart_upload(Bucket=YB, Key="mp", ServerSideEncryption="AES256")
    p1 = s3.upload_part(Bucket=YB, Key="mp", UploadId=r["UploadId"], PartNumber=1, Body=part)
    p2 = s3.upload_part(Bucket=YB, Key="mp", UploadId=r["UploadId"], PartNumber=2, Body=b"tail")
    c = s3.complete_multipart_upload(Bucket=YB, Key="mp", UploadId=r["UploadId"], MultipartUpload={"Parts": [
        {"PartNumber": 1, "ETag": p1["ETag"]}, {"PartNumber": 2, "ETag": p2["ETag"]}]})
    check("one begun with it takes its parts and completes", c.get("ServerSideEncryption") == "AES256", c)
    check("and the policy says nothing of reads", s3.get_object(Bucket=YB, Key="mp")["Body"].read() == part + b"tail")
    st, _, body = req("PUT", "/%s?policy" % YB, json.dumps({"Statement": [dict(pol["Statement"][0], Condition={
        "StringEquals": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "k"}})]}).encode())
    check("a condition on a key it cannot honour is still refused", (st, xml_code(body)) == (400, "MalformedPolicy"),
          (st, body[:200]))
    st, _, _ = req("DELETE", "/%s?policy" % YB)
    check("the policy is removed", st == 204, st)
    st, _, _ = req("PUT", "/%s/clear" % YB, b"x")
    check("after which a PUT in the clear is taken", st == 200, st)


def main():
    if MODE == "main":
        mode_main(int(sys.argv[2]), sys.argv[3])
    elif MODE == "recovery":
        mode_recovery(int(sys.argv[2]), sys.argv[3])
    elif MODE == "tls":
        mode_tls(int(sys.argv[2]), sys.argv[3], sys.argv[4])
    elif MODE == "tlsnokey":
        mode_tlsnokey(int(sys.argv[2]), sys.argv[3], sys.argv[4])
    elif MODE == "nokey":
        mode_nokey(int(sys.argv[2]))
    elif MODE == "shards":
        mode_shards(sys.argv[2:4], sys.argv[4])
    elif MODE == "tamper":
        mode_tamper(int(sys.argv[2]), sys.argv[3])
    elif MODE == "layout":
        mode_layout(int(sys.argv[2]), sys.argv[3])
    elif MODE == "pool":
        mode_pool(int(sys.argv[2]), sys.argv[3])
    elif MODE == "policy":
        mode_policy(int(sys.argv[2]))
    print("  %d passed, %d failed" % (passed, failed))
    sys.exit(min(failed, 100))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        check("the %s half ran to its end" % MODE, False, repr(e)[:300])
        sys.exit(min(failed, 100))
