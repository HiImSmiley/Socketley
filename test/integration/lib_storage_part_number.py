#!/usr/bin/env python3
"""GetObject and HeadObject by partNumber on the storage runtime.

usage: lib_storage_part_number.py MODE ARGS...

  main PORT DATA       an anonymous runtime over TCP: parts of equal size (written in
                       place), of unequal size (assembled by copying), a single-part
                       object, an empty one, a copy, the refusals, HEAD, conditional
                       headers, boto3; and an object whose header carries no part sizes,
                       as one completed before they were recorded does
  restart PORT DATA    after a stop and a start, and then after a start with every
                       journal removed: the part boundaries come back from the headers
  shards NODE0 NODE1   two shards, one unix node each: every part through both nodes,
                       one of which does not own the key

Prints one PASS or FAIL line per assertion and exits with the number of failures.
"""
import base64
import hashlib
import http.client
import os
import socket
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zlib

MODE = sys.argv[1]
BIN = os.environ.get("BIN", "")
RUNTIME = os.environ.get("RUNTIME", "pn")
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
MiB = 1 << 20
B = "pnb"

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
        if fn():
            return True
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


def req(method, path, body=None, headers=None, node=None):
    node = node or NODE
    c = UnixConn(node) if isinstance(node, str) else http.client.HTTPConnection("127.0.0.1", node, timeout=60)
    try:
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
    finally:
        c.close()


def xml_code(body):
    try:
        return ET.fromstring(body).findtext("Code")
    except Exception:
        return None


def md5(b):
    return hashlib.md5(b).hexdigest()


def mp_etag(parts):
    return "%s-%d" % (hashlib.md5(b"".join(hashlib.md5(p).digest() for p in parts)).hexdigest(), len(parts))


def upload(key, parts, node=None, data=None):
    """Uploads `parts` as one multipart object; returns the ETag and whether its data file became the object."""
    st, _, body = req("POST", "/%s/%s?uploads" % (B, key), node=node)
    if st != 200:
        raise RuntimeError("create %s: %d %r" % (key, st, body[:200]))
    uid = ET.fromstring(body).findtext(NS + "UploadId")
    etags = []
    for i, p in enumerate(parts):
        st, h, body = req("PUT", "/%s/%s?partNumber=%d&uploadId=%s" % (B, key, i + 1, uid), p, node=node)
        if st != 200:
            raise RuntimeError("part %d of %s: %d %r" % (i + 1, key, st, body[:200]))
        etags.append(h["etag"].strip('"'))
    ino = None
    if data:
        try:
            ino = os.stat(os.path.join(data, B, "mpu", uid, "data")).st_ino
        except OSError:
            ino = None
    x = "<CompleteMultipartUpload>" + "".join(
        "<Part><PartNumber>%d</PartNumber><ETag>\"%s\"</ETag></Part>" % (i + 1, e) for i, e in enumerate(etags)) + \
        "</CompleteMultipartUpload>"
    st, _, body = req("POST", "/%s/%s?uploadId=%s" % (B, key, uid), x.encode(), node=node)
    if st != 200:
        raise RuntimeError("complete %s: %d %r" % (key, st, body[:200]))
    etag = ET.fromstring(body).findtext(NS + "ETag").strip('"')
    in_place = ino is not None and object_file(data, key) is not None and \
        os.stat(object_file(data, key)).st_ino == ino
    return etag, in_place


def part_answers(key, parts, method="GET", node=None):
    """Every way the answer for each part of `key` differs from S3's, as a list."""
    whole = b"".join(parts)
    multi = MULTI.get(key, True)
    etag = mp_etag(parts) if multi else md5(whole)
    wrong = []
    at = 0
    for i, p in enumerate(parts):
        st, h, body = req(method, "/%s/%s?partNumber=%d" % (B, key, i + 1), node=node)
        want_range = "bytes %d-%d/%d" % (at, at + len(p) - 1, len(whole))
        got = (st, h.get("content-range"), h.get("content-length"), h.get("etag"), h.get("x-amz-mp-parts-count"))
        want = (206, want_range, str(len(p)), '"%s"' % etag, str(len(parts)) if multi else None)
        if got != want:
            wrong.append((i + 1, got, want))
        if method == "GET" and body != p:
            wrong.append((i + 1, "body", len(body), md5(body), md5(p)))
        if method == "HEAD" and body:
            wrong.append((i + 1, "a HEAD has a body", len(body)))
        at += len(p)
    return wrong


MULTI = {}


# ── each part's own checksum, kept after completion ─────────────────────────
def b64_sum(algo, data):
    if algo == "CRC32":
        raw = struct.pack(">I", zlib.crc32(data))
    else:
        raw = hashlib.new(algo.lower(), data).digest()
    return base64.b64encode(raw).decode()


def upload_ck(key, parts, algo, full=False, node=None, data=None):
    """Uploads `parts` with `algo`; returns whether the data file became the object and the parts' checksums."""
    h = {"x-amz-checksum-algorithm": algo}
    if full:
        h["x-amz-checksum-type"] = "FULL_OBJECT"
    st, _, body = req("POST", "/%s/%s?uploads" % (B, key), headers=h, node=node)
    if st != 200:
        raise RuntimeError("create %s: %d %r" % (key, st, body[:200]))
    uid = ET.fromstring(body).findtext(NS + "UploadId")
    etags, sums = [], []
    for i, p in enumerate(parts):
        st, h, body = req("PUT", "/%s/%s?partNumber=%d&uploadId=%s" % (B, key, i + 1, uid), p, node=node)
        if st != 200:
            raise RuntimeError("part %d of %s: %d %r" % (i + 1, key, st, body[:200]))
        etags.append(h["etag"].strip('"'))
        sums.append(h.get("x-amz-checksum-" + algo.lower()))
    ino = os.stat(os.path.join(data, B, "mpu", uid, "data")).st_ino if data else None
    x = "<CompleteMultipartUpload>" + "".join(
        "<Part><PartNumber>%d</PartNumber><ETag>\"%s\"</ETag></Part>" % (i + 1, e) for i, e in enumerate(etags)) + \
        "</CompleteMultipartUpload>"
    st, _, body = req("POST", "/%s/%s?uploadId=%s" % (B, key, uid), x.encode(), node=node)
    if st != 200:
        raise RuntimeError("complete %s: %d %r" % (key, st, body[:200]))
    in_place = ino is not None and os.stat(object_file(data, key)).st_ino == ino
    return in_place, sums


def part_sums_wrong(key, parts, algo, typ, method="GET", node=None):
    """Every way a part read with x-amz-checksum-mode differs from its own checksum, or one without it shows one."""
    name = "x-amz-checksum-" + algo.lower()
    wrong = []
    for i, p in enumerate(parts):
        path = "/%s/%s?partNumber=%d" % (B, key, i + 1)
        st, h, body = req(method, path, headers={"x-amz-checksum-mode": "ENABLED"}, node=node)
        got = (st, h.get(name), h.get("x-amz-checksum-type"))
        want = (206, b64_sum(algo, p), typ)
        if got != want:
            wrong.append((i + 1, got, want))
        if method == "GET" and body != p:
            wrong.append((i + 1, "body", len(body)))
        st, h, _ = req(method, path, node=node)
        if name in h:
            wrong.append((i + 1, "a checksum not asked for", h[name]))
    return wrong


def attr_parts(key, node=None, max_parts=None, marker=None):
    """GetObjectAttributes' ObjectParts of `key`: (number, size, checksum or None) per part, and NextPartNumberMarker."""
    h = {"x-amz-object-attributes": "ObjectParts,Checksum"}
    if max_parts:
        h["x-amz-max-parts"] = str(max_parts)
    if marker:
        h["x-amz-part-number-marker"] = str(marker)
    st, _, body = req("GET", "/%s/%s?attributes" % (B, key), headers=h, node=node)
    if st != 200:
        return st, body[:200]
    x = ET.fromstring(body)
    rows = []
    for p in x.iter(NS + "Part"):
        ck = [c.text for c in p if c.tag.startswith(NS + "Checksum")]
        rows.append((int(p.findtext(NS + "PartNumber")), int(p.findtext(NS + "Size")), ck[0] if ck else None))
    return rows, x.findtext(NS + "ObjectParts/" + NS + "NextPartNumberMarker")


def attrs_wrong(key, parts, algo, node=None):
    """How the parts GetObjectAttributes lists for `key`, in full and two at a time, differ from their checksums."""
    want = [(i + 1, len(p), b64_sum(algo, p)) for i, p in enumerate(parts)]
    got, _ = attr_parts(key, node)
    wrong = [] if got == want else [("all", got, want)]
    paged, marker = [], None
    while True:
        rows, marker = attr_parts(key, node, 2, marker)
        if not isinstance(rows, list):
            return wrong + [("page", rows, marker)]
        paged += rows
        if not marker:
            break
    if paged != want:
        wrong.append(("paged", paged, want))
    return wrong


def ck_wrong(key, parts, algo, typ, node=None):
    return part_sums_wrong(key, parts, algo, typ, node=node) + \
        part_sums_wrong(key, parts, algo, typ, "HEAD", node=node) + attrs_wrong(key, parts, algo, node)


def blob(n, seed):
    out = bytearray()
    h = hashlib.sha256(seed.encode()).digest()
    while len(out) < n:
        h = hashlib.sha256(h).digest()
        out += h * 64
    return bytes(out[:n])


EQUAL = [blob(5 * MiB, "e1"), blob(5 * MiB, "e2"), blob(5 * MiB, "e3"), blob(MiB + 7, "e4")]
UNEQUAL = [blob(6 * MiB, "u1"), blob(5 * MiB, "u2"), blob(7 * MiB + 3, "u3"), blob(100, "u4")]
SINGLE = blob(10000, "s")
# Every size its own, so the list is longer than the 48 bytes SOCKETLEY_STORAGE_PART_LIST_MAX leaves it in the header.
VARIED = [blob(5 * MiB + 4099 * i + 1, "v%d" % i) for i in range(8)] + [blob(100, "vlast")]

# Uploaded with a checksum algorithm: the algorithm, the object's checksum type, its parts, and whether its
# data file becomes the object.  Against the 48 bytes the header may give a list here, 4 SHA-256 checksums
# (172 bytes of base64) follow the body even in place, 4 CRC32 ones (24) stay in the header in place and copied,
# and nine SHA-1 ones follow a copied body with the sizes.
CK = {
    "ck-equal": ("SHA256", "COMPOSITE", EQUAL, True),
    "ck-crc": ("CRC32", "FULL_OBJECT", EQUAL, True),
    "ck-unequal": ("CRC32", "COMPOSITE", UNEQUAL, False),
    "ck-varied": ("SHA1", "COMPOSITE", VARIED, False),
}


# ── an object header as object_format.cpp writes it ─────────────────────────
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
    size, mtime = struct.unpack_from("<QQ", body, r); r += 16
    md5d = body[r:r + 16]; r += 16
    parts, = struct.unpack_from("<I", body, r); r += 4

    def s():
        nonlocal r
        n, = struct.unpack_from("<I", body, r)
        v = body[r + 4:r + 4 + n]
        r += 4 + n
        return v
    key = s()
    ctype = s()
    n, = struct.unpack_from("<I", body, r); r += 4
    extra = [(s(), s()) for _ in range(n)]
    return dict(header_len=header_len, crc=crc, crc_ok=crc32c(head[:20] + body) == crc, size=size, mtime=mtime,
                md5=md5d, parts=parts, key=key, ctype=ctype, extra=extra)


def write_header(path, h):
    def s(v):
        return struct.pack("<I", len(v)) + v
    body = struct.pack("<QQ", h["size"], h["mtime"]) + h["md5"] + struct.pack("<I", h["parts"]) + s(h["key"]) + \
        s(h["ctype"]) + struct.pack("<I", len(h["extra"])) + b"".join(s(n) + s(v) for n, v in h["extra"])
    pre = b"SKLOBJ\x01\x00" + struct.pack("<III", 1, h["header_len"], len(body))
    out = pre + struct.pack("<I", crc32c(pre + body)) + body
    out += b"\0" * (h["header_len"] - len(out))
    with open(path, "r+b") as f:
        f.write(out)
        f.flush()
        os.fsync(f.fileno())


def object_file(data, key):
    for root, dirs, files in os.walk(os.path.join(data, B)):
        dirs[:] = [d for d in dirs if d not in ("mpu", "tmp")]
        for f in files:
            p = os.path.join(root, f)
            try:
                h = read_header(p)
            except (OSError, struct.error):
                h = None
            if h and h["key"] == key.encode():
                return p
    return None


def remove_journals(data):
    removed = 0
    for root, _, files in os.walk(data):
        for f in files:
            if f.startswith("index.") or f.startswith(".clean."):
                os.unlink(os.path.join(root, f))
                removed += 1
    return removed


def restart(port, data=None):
    subprocess.run([BIN, "stop", RUNTIME], capture_output=True)
    time.sleep(0.5)
    removed = remove_journals(data) if data else 0
    subprocess.run([BIN, "start", RUNTIME], capture_output=True)
    ok = wait_for(lambda: probe(port), 30)
    return ok, removed


def probe(port):
    try:
        return req("GET", "/", node=port)[0] == 200
    except OSError:
        return False


def mode_main(port, data):
    global NODE
    NODE = port
    st, _, _ = req("PUT", "/" + B)
    check("the bucket is made", st == 200, st)

    etag, in_place = upload("equal", EQUAL, data=data)
    check("parts of one size complete with the multipart ETag", etag == mp_etag(EQUAL), etag)
    check("and their data file became the object, so this is the in-place layout", in_place)
    wrong = part_answers("equal", EQUAL)
    check("each part of equal size is a 206 of its bytes, Content-Range, Content-Length, ETag and parts count",
          not wrong, wrong[:2])
    wrong = part_answers("equal", EQUAL, "HEAD")
    check("and a HEAD of each says the same with no body", not wrong, wrong[:2])

    etag, in_place = upload("unequal", UNEQUAL, data=data)
    check("parts of unequal size complete", etag == mp_etag(UNEQUAL), etag)
    check("by copying them, as they cannot sit in place", not in_place)
    wrong = part_answers("unequal", UNEQUAL)
    check("each part of unequal size is answered with its own bytes and boundaries", not wrong, wrong[:2])
    wrong = part_answers("unequal", UNEQUAL, "HEAD")
    check("and by a HEAD", not wrong, wrong[:2])
    h = read_header(object_file(data, "unequal"))
    sizes = dict(h["extra"]).get(b"x-socketley-part-sizes")
    check("its header lists the four sizes", sizes == b",".join(str(len(p)).encode() for p in UNEQUAL), sizes)
    h = read_header(object_file(data, "equal"))
    sizes = dict(h["extra"]).get(b"x-socketley-part-sizes")
    check("and the equal one's header the one size", sizes == str(5 * MiB).encode(), sizes)
    st, hd, _ = req("GET", "/%s/equal" % B)
    check("which is no response header", not any("socketley" in k for k in hd), list(hd))

    # ── a part list too long for the header follows the body ──
    etag, _ = upload("varied", VARIED, data=data)
    check("parts of nine sizes complete", etag == mp_etag(VARIED), etag)
    h = read_header(object_file(data, "varied"))
    extra = dict(h["extra"])
    check("their list is kept after the body, which the header names, and not in it",
          b"x-socketley-part-layout" in extra and b"x-socketley-part-sizes" not in extra, h["extra"])
    with open(object_file(data, "varied"), "rb") as f:
        size = os.fstat(f.fileno()).st_size
    check("the file is the header, the body and the list",
          size == h["header_len"] + sum(len(p) for p in VARIED) + 20 + 12 * len(VARIED), size)
    wrong = part_answers("varied", VARIED) + part_answers("varied", VARIED, "HEAD")
    check("each of its parts is answered by GET and HEAD from the list", not wrong, wrong[:2])
    st, h2, body = req("GET", "/%s/varied" % B)
    check("and a plain GET of it is the body without the list", (st, body == b"".join(VARIED)) == (200, True), st)
    st, _, body = req("GET", "/%s/varied?partNumber=10" % B)
    check("partNumber=10 of its nine is 416", (st, xml_code(body)) == (416, "InvalidPartNumber"), (st, body[:200]))

    # ── a single-part object is its own part 1 ──
    req("PUT", "/%s/single" % B, SINGLE)
    MULTI["single"] = False
    wrong = part_answers("single", [SINGLE])
    check("partNumber=1 of a single-part object is a 206 of all of it, with no parts count", not wrong, wrong)
    st, _, body = req("GET", "/%s/single?partNumber=2" % B)
    check("and partNumber=2 of it is 416 InvalidPartNumber", (st, xml_code(body)) == (416, "InvalidPartNumber"),
          (st, body[:200]))
    req("PUT", "/%s/empty" % B, b"")
    st, h, body = req("GET", "/%s/empty?partNumber=1" % B)
    check("partNumber=1 of an empty object is a 200 of nothing",
          (st, body, h.get("content-length"), h.get("content-range")) == (200, b"", "0", None), (st, h))

    # ── refusals ──
    for method in ("GET", "HEAD"):
        st, h, body = req(method, "/%s/equal?partNumber=5" % B)
        want = (416, "InvalidPartNumber") if method == "GET" else (416, None)
        check("%s of part 5 of 4 is 416 InvalidPartNumber" % method, (st, xml_code(body)) == want, (st, body[:200]))
    for bad in ("0", "10001", "x", "-1", ""):
        st, _, body = req("GET", "/%s/equal?partNumber=%s" % (B, bad))
        check("partNumber=%r is 400 InvalidArgument" % bad, (st, xml_code(body)) == (400, "InvalidArgument"),
              (st, body[:200]))
    st, _, body = req("GET", "/%s/equal?partNumber=1" % B, headers={"Range": "bytes=0-9"})
    check("partNumber with a Range is 400 InvalidRequest", (st, xml_code(body)) == (400, "InvalidRequest"),
          (st, body[:200]))
    st, _, _ = req("HEAD", "/%s/equal?partNumber=1" % B, headers={"Range": "bytes=0-9"})
    check("and so is a HEAD with both", st == 400, st)
    st, _, body = req("GET", "/%s/missing?partNumber=1" % B)
    check("a missing key is NoSuchKey", (st, xml_code(body)) == (404, "NoSuchKey"), (st, body[:200]))
    st, _, body = req("PUT", "/%s/x?partNumber=1" % B, b"abc")
    check("a PUT with partNumber and no uploadId is still NotImplemented",
          (st, xml_code(body)) == (501, "NotImplemented"), (st, body[:200]))

    # ── conditional headers ──
    good, other = '"%s"' % mp_etag(EQUAL), '"%s"' % md5(b"other")
    st, h, body = req("GET", "/%s/equal?partNumber=2" % B, headers={"If-Match": good})
    check("If-Match of the object's ETag gives the part", (st, body == EQUAL[1]) == (206, True), st)
    st, _, body = req("GET", "/%s/equal?partNumber=2" % B, headers={"If-Match": other})
    check("If-Match of another is 412", (st, xml_code(body)) == (412, "PreconditionFailed"), (st, body[:200]))
    st, _, body = req("GET", "/%s/equal?partNumber=2" % B, headers={"If-None-Match": good})
    check("If-None-Match of the object's ETag is 304", (st, body) == (304, b""), (st, body[:200]))
    st, _, _ = req("HEAD", "/%s/equal?partNumber=9" % B, headers={"If-Match": other})
    check("a failed condition comes before the part number", st == 412, st)
    st, _, _ = req("GET", "/%s/equal?partNumber=3" % B,
                   headers={"If-Modified-Since": "Sat, 01 Jan 2000 00:00:00 GMT"})
    check("If-Modified-Since in the past gives the part", st == 206, st)

    # ── a copy is one part, as S3 makes it ──
    for directive in ("COPY", "REPLACE"):
        dst = "copy-" + directive.lower()
        st, _, body = req("PUT", "/%s/%s" % (B, dst),
                          headers={"x-amz-copy-source": "/%s/unequal" % B, "x-amz-metadata-directive": directive})
        got = (ET.fromstring(body).findtext(NS + "ETag") or "").strip('"') if st == 200 else body[:200]
        whole = b"".join(UNEQUAL)
        check("a copy (%s) of a multipart object has the MD5 of its bytes as ETag" % directive, got == md5(whole),
              (st, got))
        st, h, _ = req("HEAD", "/%s/%s" % (B, dst))
        check("and says so on a HEAD, with no parts count",
              (h.get("etag"), h.get("x-amz-mp-parts-count")) == ('"%s"' % md5(whole), None), h)
        MULTI[dst] = False
        wrong = part_answers(dst, [whole])
        check("its partNumber=1 is the whole object", not wrong, wrong)
        st, _, body = req("GET", "/%s/%s?partNumber=2" % (B, dst))
        check("and its partNumber=2 is 416", (st, xml_code(body)) == (416, "InvalidPartNumber"), (st, body[:200]))
        h = read_header(object_file(data, dst))
        check("and its header holds no part sizes", b"x-socketley-part-sizes" not in dict(h["extra"]), h["extra"])
    st, _, body = req("PUT", "/%s/copy-single" % B, headers={"x-amz-copy-source": "/%s/single" % B})
    check("a copy of a single-part object keeps its ETag",
          st == 200 and (ET.fromstring(body).findtext(NS + "ETag") or "").strip('"') == md5(SINGLE), (st, body[:200]))

    # ── an SDK reading the parts ──
    try:
        import boto3
        from botocore import UNSIGNED
        from botocore.config import Config
        c = boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % port, region_name="us-east-1",
                         config=Config(signature_version=UNSIGNED, s3={"addressing_style": "path"},
                                       retries={"max_attempts": 1}))
        h = c.head_object(Bucket=B, Key="unequal", PartNumber=1)
        n = h.get("PartsCount")
        got = b"".join(c.get_object(Bucket=B, Key="unequal", PartNumber=i)["Body"].read() for i in range(1, n + 1))
        check("boto3 reads PartsCount from a HEAD of part 1 and the object part by part",
              (n, got == b"".join(UNEQUAL), h.get("ContentLength")) == (4, True, len(UNEQUAL[0])),
              (n, h.get("ContentLength")))
        g = c.get_object(Bucket=B, Key="equal", PartNumber=4)
        check("and sees part 4's ContentRange",
              g.get("ContentRange") == "bytes %d-%d/%d" % (15 * MiB, 16 * MiB + 6, 16 * MiB + 7), g.get("ContentRange"))
    except ImportError:
        print("  SKIP: boto3 is not installed")

    # ── each part's own checksum, kept after completion ──
    for key, (algo, typ, parts, place) in CK.items():
        in_place, sums = upload_ck(key, parts, algo, typ == "FULL_OBJECT", data=data)
        want = [b64_sum(algo, p) for p in parts]
        check("%s: each UploadPart answers its part's %s" % (key, algo), sums == want, (sums, want))
        check("%s: the data file %s the object" % (key, "became" if place else "did not become"), in_place == place)
        wrong = ck_wrong(key, parts, algo, typ)
        check("%s: GET and HEAD of each part with x-amz-checksum-mode give its own %s as %s, and GetObjectAttributes "
              "lists it beside each part, whole and two at a time" % (key, algo, typ), not wrong, wrong[:2])
        wrong = part_answers(key, parts)
        check("%s: and the parts' bytes and boundaries are as without checksums" % key, not wrong, wrong[:2])
    extra = dict(read_header(object_file(data, "ck-equal"))["extra"])
    layout = extra.get(b"x-socketley-part-layout", b"")
    check("in place, SHA-256 checksums too long for the header follow the body, the header naming their width",
          layout.endswith(b";32") and b"x-socketley-part-checksums" not in extra and
          extra.get(b"x-socketley-part-sizes") is None, list(extra))
    with open(object_file(data, "ck-equal"), "rb") as f:
        size = os.fstat(f.fileno()).st_size
    check("and the file is the header, the body and a list of number, size and checksum per part",
          size == read_header(object_file(data, "ck-equal"))["header_len"] + sum(map(len, EQUAL)) + 24 + 44 * 4, size)
    for key in ("ck-crc", "ck-unequal"):
        extra = dict(read_header(object_file(data, key))["extra"])
        want = base64.b64encode(b"".join(base64.b64decode(b64_sum("CRC32", p)) for p in CK[key][2]))
        check("%s: its CRC32 checksums are kept in its header" % key,
              extra.get(b"x-socketley-part-checksums") == want and b"x-socketley-part-layout" not in extra, list(extra))
    st, h, _ = req("GET", "/%s/ck-equal?partNumber=2" % B,
                   headers={"x-amz-checksum-mode": "ENABLED", "Range": "bytes=0-9"})
    check("a Range beside partNumber is still refused before any checksum", st == 400, st)
    st, h, _ = req("GET", "/%s/ck-equal" % B, headers={"x-amz-checksum-mode": "ENABLED", "Range": "bytes=0-9"})
    check("and a ranged GET carries no checksum, as the bytes are no part's",
          st == 206 and "x-amz-checksum-sha256" not in h, (st, h.get("x-amz-checksum-sha256")))
    st, h, _ = req("GET", "/%s/ck-equal" % B, headers={"x-amz-checksum-mode": "ENABLED"})
    check("while the whole object's GET carries the composite one",
          h.get("x-amz-checksum-sha256", "").endswith("-4") and h.get("x-amz-checksum-type") == "COMPOSITE", h)

    # A single-part object is its own part 1, with its own checksum.
    one = blob(70000, "ck1")
    req("PUT", "/%s/ck-single" % B, one, headers={"x-amz-checksum-sha256": b64_sum("SHA256", one)})
    MULTI["ck-single"] = False
    wrong = part_sums_wrong("ck-single", [one], "SHA256", "FULL_OBJECT") + \
        part_sums_wrong("ck-single", [one], "SHA256", "FULL_OBJECT", "HEAD")
    check("partNumber=1 of a single-part object with x-amz-checksum-mode gives its checksum", not wrong, wrong)

    # A copy is one part, so it keeps none of its source's part checksums.
    for src, dst in (("ck-equal", "ck-copy"), ("ck-crc", "ck-crc-copy")):
        st, _, body = req("PUT", "/%s/%s" % (B, dst), headers={"x-amz-copy-source": "/%s/%s" % (B, src)})
        check("%s is copied" % src, st == 200, (st, body[:200]))
        MULTI[dst] = False
        extra = dict(read_header(object_file(data, dst))["extra"])
        check("%s: its header keeps no part list or part checksum" % dst,
              not any(n.startswith(b"x-socketley-part") for n in extra), list(extra))
        rows = attr_parts(dst)
        check("%s: GetObjectAttributes lists no parts of it" % dst, rows[0] == [], rows)
        st, h, body = req("GET", "/%s/%s?partNumber=1" % (B, dst), headers={"x-amz-checksum-mode": "ENABLED"})
        algo = CK[src][0]
        got = h.get("x-amz-checksum-" + algo.lower())
        whole = b"".join(CK[src][2])
        check("%s: its partNumber=1 is all of it, with no checksum of its source's part 1" % dst,
              st == 206 and body == whole and got != b64_sum(algo, CK[src][2][0]), (st, got))
    st, h, _ = req("GET", "/%s/ck-crc-copy?partNumber=1" % B, headers={"x-amz-checksum-mode": "ENABLED"})
    check("the copy of a FULL_OBJECT CRC32 object gives that CRC32 for its one part",
          h.get("x-amz-checksum-crc32") == b64_sum("CRC32", b"".join(EQUAL)), h.get("x-amz-checksum-crc32"))
    st, h, _ = req("GET", "/%s/ck-copy?partNumber=1" % B, headers={"x-amz-checksum-mode": "ENABLED"})
    check("and the copy of a COMPOSITE one gives none, its value being of parts the copy does not have",
          "x-amz-checksum-sha256" not in h, h.get("x-amz-checksum-sha256"))

    try:
        import boto3
        from botocore import UNSIGNED
        from botocore.config import Config
        c = boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % port, region_name="us-east-1",
                         config=Config(signature_version=UNSIGNED, s3={"addressing_style": "path"},
                                       retries={"max_attempts": 1}))
        a = c.get_object_attributes(Bucket=B, Key="ck-varied", ObjectAttributes=["ObjectParts"])
        got = [(p["PartNumber"], p.get("ChecksumSHA1")) for p in a["ObjectParts"]["Parts"]]
        check("boto3 reads each part's ChecksumSHA1 from GetObjectAttributes",
              got == [(i + 1, b64_sum("SHA1", p)) for i, p in enumerate(VARIED)], got[:2])
        g = c.get_object(Bucket=B, Key="ck-equal", PartNumber=3, ChecksumMode="ENABLED")
        check("and part 3's ChecksumSHA256 from a GET, validating the body against it",
              (g.get("ChecksumSHA256"), g["Body"].read() == EQUAL[2]) == (b64_sum("SHA256", EQUAL[2]), True),
              g.get("ChecksumSHA256"))
    except ImportError:
        print("  SKIP: boto3 is not installed")

    # ── an object completed before part sizes were recorded ──
    upload("legacy", EQUAL, data=data)
    path = object_file(data, "legacy")
    h = read_header(path)
    check("the header this test reads is the one the runtime wrote, its checksum included", h["crc_ok"])
    h["extra"] = [(n, v) for n, v in h["extra"] if n != b"x-socketley-part-sizes"]
    write_header(path, h)
    check("and the legacy header written in its place reads back sound", read_header(path)["crc_ok"])
    # And one completed before part checksums were kept.
    upload_ck("ck-legacy", EQUAL, "CRC32", data=data)
    lpath = object_file(data, "ck-legacy")
    h = read_header(lpath)
    h["extra"] = [(n, v) for n, v in h["extra"] if n != b"x-socketley-part-checksums"]
    write_header(lpath, h)
    ok, removed = restart(port, data)
    check("a start with the journals removed reads it from the file", ok and removed > 0, (ok, removed))
    for n in (1, 2, 4):
        st, _, body = req("GET", "/%s/legacy?partNumber=%d" % (B, n))
        check("partNumber=%d of it is 501 NotImplemented, not a guess" % n,
              (st, xml_code(body)) == (501, "NotImplemented") and b"part sizes" in body, (st, body[:300]))
    st, _, body = req("GET", "/%s/legacy?partNumber=5" % B)
    check("partNumber=5 of it is still 416", (st, xml_code(body)) == (416, "InvalidPartNumber"), (st, body[:200]))
    st, h, body = req("GET", "/%s/legacy" % B)
    check("and a plain GET of it is whole, with its multipart ETag",
          (st, body == b"".join(EQUAL), h.get("etag")) == (200, True, '"%s"' % mp_etag(EQUAL)), (st, h.get("etag")))
    wrong = part_answers("equal", EQUAL) + part_answers("unequal", UNEQUAL, "HEAD")
    check("while the others are still answered from their headers", not wrong, wrong[:2])
    got = [req("GET", "/%s/ck-legacy?partNumber=%d" % (B, n), headers={"x-amz-checksum-mode": "ENABLED"})
           for n in (1, 4)]
    check("parts of an object completed before their checksums were kept are read with none",
          [(st, body == EQUAL[n], "x-amz-checksum-crc32" in h) for (st, h, body), n in zip(got, (0, 3))] ==
          [(206, True, False)] * 2, [(st, h.get("x-amz-checksum-crc32")) for st, h, _ in got])
    rows, _ = attr_parts("ck-legacy")
    check("and listed by GetObjectAttributes with their sizes and no checksum",
          rows == [(i + 1, len(p), None) for i, p in enumerate(EQUAL)], rows)


def mode_restart(port, data):
    global NODE
    NODE = port
    MULTI["single"] = False
    ok, _ = restart(port)
    check("it starts again", ok)
    wrong = part_answers("equal", EQUAL) + part_answers("unequal", UNEQUAL) + part_answers("single", [SINGLE]) + \
        part_answers("varied", VARIED)
    check("after a restart every part is answered as before", not wrong, wrong[:2])
    wrong = []
    for key, (algo, typ, parts, _) in CK.items():
        wrong += [(key, w) for w in ck_wrong(key, parts, algo, typ)]
    check("and with its own checksum, from the journal", not wrong, wrong[:2])
    ok, removed = restart(port, data)
    check("and again with every journal removed", ok and removed > 0, (ok, removed))
    wrong = part_answers("equal", EQUAL) + part_answers("unequal", UNEQUAL, "HEAD") + \
        part_answers("varied", VARIED, "HEAD")
    check("after which the boundaries come from the object headers and the list after a body", not wrong, wrong[:2])
    wrong = []
    for key, (algo, typ, parts, _) in CK.items():
        wrong += [(key, w) for w in ck_wrong(key, parts, algo, typ)]
    check("and every part's checksum comes back from the header or the list after the body", not wrong, wrong[:2])


def mode_shards(nodes):
    global NODE
    NODE = nodes[0]
    st, _, _ = req("PUT", "/" + B)
    check("the bucket is made", st == 200, st)
    shapes = {"s-eq": EQUAL[:2] + [EQUAL[3]], "s-uneq": UNEQUAL}
    keys = []
    for i in range(3):
        for name, parts in shapes.items():
            key = "%s-%d" % (name, i)
            upload(key, parts, node=nodes[i % 2])
            keys.append((key, parts))
    wrong = []
    for key, parts in keys:
        for node in nodes:
            wrong += [(key, node, w) for w in part_answers(key, parts, node=node)]
            wrong += [(key, node, w) for w in part_answers(key, parts, "HEAD", node=node)]
    check("every part of every object is answered alike by both shards, owner or not", not wrong, wrong[:3])
    upload("s-var", VARIED, node=nodes[1])
    wrong = []
    for node in nodes:
        wrong += [(node, w) for w in part_answers("s-var", VARIED, node=node)]
        wrong += [(node, w) for w in part_answers("s-var", VARIED, "HEAD", node=node)]
    check("and an object whose list follows its body is answered alike by both", not wrong, wrong[:3])
    wrong = []
    for i, key in enumerate(("ck-equal", "ck-unequal")):
        algo, typ, parts, _ = CK[key]
        upload_ck("s-" + key, parts, algo, node=nodes[i])
        for node in nodes:
            wrong += [(key, node, w) for w in ck_wrong("s-" + key, parts, algo, typ, node=node)]
    check("each part's checksum, after the body or in the header, is answered alike by both shards", not wrong, wrong[:3])
    for node in nodes:
        st, _, body = req("GET", "/%s/s-eq-0?partNumber=4" % B, node=node)
        check("part 4 of 3 is 416 on %s" % os.path.basename(node), (st, xml_code(body)) == (416, "InvalidPartNumber"),
              (st, body[:200]))
    MULTI["s-small"] = False
    req("PUT", "/%s/s-small" % B, SINGLE, node=nodes[1])
    for node in nodes:
        # Three times, so the later ones are served from the copy the first left in memory.
        got = [req("GET", "/%s/s-small?partNumber=1" % B, node=node) for _ in range(3)]
        check("partNumber=1 of a small object held in memory is a 206 on %s" % os.path.basename(node),
              all((st, h.get("content-range"), body) == (206, "bytes 0-9999/10000", SINGLE) for st, h, body in got),
              [(st, h.get("content-range"), len(body)) for st, h, body in got])


if MODE == "main":
    mode_main(int(sys.argv[2]), sys.argv[3])
elif MODE == "restart":
    mode_restart(int(sys.argv[2]), sys.argv[3])
elif MODE == "shards":
    mode_shards(sys.argv[2:])
else:
    print("unknown mode " + MODE)
    sys.exit(2)
print("  Results: %d passed, %d failed" % (passed, failed))
sys.exit(failed)
