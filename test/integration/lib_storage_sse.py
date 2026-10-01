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
                            key, ranges, multipart, copies between SSE-C and SSE-S3, nothing held
  nokey PORT                a runtime without a master key refuses SSE-S3 and a bucket default
  shards NODE0 NODE1 DATA   two shards, one unix node each: a default set through one is honoured
                            by both, and every object reads alike through the owner and the other

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
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

MODE = sys.argv[1]
BIN = os.environ.get("BIN", "")
RUNTIME = os.environ.get("RUNTIME", "sse")
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
B = "sseb"
STATE = "sse-expected.json"
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


def sealed_len(n):
    return n + (n + 65535) // 65536 * 28


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


def mpu(s3, key, parts, create=None, part_args=None):
    create = create or {}
    part_args = part_args or {}
    up = s3.create_multipart_upload(Bucket=B, Key=key, **create)
    uid = up["UploadId"]
    done = []
    for i, p in enumerate(parts, 1):
        r = s3.upload_part(Bucket=B, Key=key, UploadId=uid, PartNumber=i, Body=p, **part_args)
        done.append({"PartNumber": i, "ETag": r["ETag"]})
    r = s3.complete_multipart_upload(Bucket=B, Key=key, UploadId=uid, MultipartUpload={"Parts": done})
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
    s3.put_object(Bucket=B, Key="self", Body=clear)
    r = s3.copy_object(Bucket=B, Key="self", CopySource={"Bucket": B, "Key": "self"}, ServerSideEncryption="AES256")
    g = s3.get_object(Bucket=B, Key="self")
    check("a copy of an object onto itself that names AES256 encrypts it in place",
          g["Body"].read() == clear and g.get("ServerSideEncryption") == "AES256" and MARK not in on_disk(data, "self"))
    expect["self"] = md5(clear)
    code = err_code(lambda: s3.copy_object(Bucket=B, Key="self", CopySource={"Bucket": B, "Key": "self"}))
    check("one that names nothing new is still refused", code == (400, "InvalidRequest"), code)

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


def main():
    if MODE == "main":
        mode_main(int(sys.argv[2]), sys.argv[3])
    elif MODE == "recovery":
        mode_recovery(int(sys.argv[2]), sys.argv[3])
    elif MODE == "tls":
        mode_tls(int(sys.argv[2]), sys.argv[3], sys.argv[4])
    elif MODE == "nokey":
        mode_nokey(int(sys.argv[2]))
    elif MODE == "shards":
        mode_shards(sys.argv[2:4], sys.argv[4])
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
