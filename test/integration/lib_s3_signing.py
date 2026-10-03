"""A SigV4 signer of our own for the storage tests, so a test can sign at a date
it picks, with a payload hash it names, in chunks of its own, and then break the
signature in a way a client library would never.

It is the reference implementation test/unit/gen_s3_sigv4_cases.py checks the
runtime's verifier against, reduced to what these tests need.  Requests made
through boto3 are signed by boto3; this is for the ones boto3 will not send.
"""
import base64
import datetime
import hashlib
import hmac
import struct
import urllib.parse
import zlib

EMPTY = hashlib.sha256(b"").hexdigest()


def sha256hex(b):
    return hashlib.sha256(b).hexdigest()


def _hm(k, m):
    return hmac.new(k, m.encode() if isinstance(m, str) else m, hashlib.sha256).digest()


def signing_key(secret, date, region="us-east-1", service="s3"):
    return _hm(_hm(_hm(_hm(("AWS4" + secret).encode(), date), region), service), "aws4_request")


def _enc(s):
    return urllib.parse.quote(s, safe="-_.~")


def canonical_query(query):
    items = []
    for part in query.split("&") if query else []:
        if not part:
            continue
        n, _, v = part.partition("=")
        items.append((_enc(urllib.parse.unquote_plus(n)), _enc(urllib.parse.unquote_plus(v))))
    items.sort()
    return "&".join("%s=%s" % (n, v) for n, v in items)


def amz_now(offset_seconds=0):
    t = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=offset_seconds)
    return t.strftime("%Y%m%dT%H%M%SZ")


class Signed:
    """The headers of a signed request and what a chunk signature needs after them."""

    def __init__(self, headers, signature, key, amzdate, scope):
        self.headers = headers
        self.signature = signature
        self.key = key
        self.amzdate = amzdate
        self.scope = scope


def sign(method, path, query, host, access, secret, payload_hash, extra_headers=None, amzdate=None,
         region="us-east-1"):
    """Signs host, x-amz-date, x-amz-content-sha256 and every header in extra_headers."""
    amzdate = amzdate or amz_now()
    date = amzdate[:8]
    hdrs = {"host": host, "x-amz-date": amzdate, "x-amz-content-sha256": payload_hash}
    for k, v in (extra_headers or {}).items():
        hdrs[k.lower()] = v
    names = sorted(hdrs)
    canonical_headers = "".join("%s:%s\n" % (n, " ".join(str(hdrs[n]).split())) for n in names)
    creq = "\n".join([method, path, canonical_query(query), canonical_headers, ";".join(names), payload_hash])
    scope = "%s/%s/s3/aws4_request" % (date, region)
    sts = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope, sha256hex(creq.encode())])
    key = signing_key(secret, date, region)
    sig = _hm(key, sts).hex()
    out = dict(hdrs)
    out["Authorization"] = "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" % (
        access, scope, ";".join(names), sig)
    del out["host"]
    return Signed(out, sig, key, amzdate, scope)


def chunk_signature(key, amzdate, scope, prev, data):
    return _hm(key, "\n".join(["AWS4-HMAC-SHA256-PAYLOAD", amzdate, scope, prev, EMPTY, sha256hex(data)])).hex()


def signed_chunks(s, pieces, trailers=None):
    """The body of STREAMING-AWS4-HMAC-SHA256-PAYLOAD, or with trailers the -TRAILER variant."""
    out = b""
    prev = s.signature
    for p in list(pieces) + [b""]:
        prev = chunk_signature(s.key, s.amzdate, s.scope, prev, p)
        out += ("%x;chunk-signature=%s\r\n" % (len(p), prev)).encode() + p + (b"\r\n" if p else b"")
    if trailers is None:
        return out + b"\r\n"
    text = "".join("%s:%s\n" % (n, v) for n, v in trailers)
    tsig = _hm(s.key, "\n".join(["AWS4-HMAC-SHA256-TRAILER", s.amzdate, s.scope, prev, sha256hex(text.encode())])).hex()
    return (out + "".join("%s:%s\r\n" % (n, v) for n, v in trailers).encode() +
            ("x-amz-trailer-signature:%s\r\n\r\n" % tsig).encode())


def unsigned_chunks(pieces, trailers):
    """The body of STREAMING-UNSIGNED-PAYLOAD-TRAILER, framed as botocore frames it."""
    out = b"".join(("%x\r\n" % len(p)).encode() + p + b"\r\n" for p in pieces if p)
    return out + b"0\r\n" + "".join("%s:%s\r\n" % (n, v) for n, v in trailers).encode() + b"\r\n"


def crc32_b64(data):
    return base64.b64encode(zlib.crc32(data).to_bytes(4, "big")).decode()


def sha256_b64(data):
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


_CRC32C_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0x82F63B78 if _c & 1 else _c >> 1
    _CRC32C_TABLE.append(_c)


def crc32c(data, crc=0):
    crc = ~crc & 0xFFFFFFFF
    for b in data:
        crc = _CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return ~crc & 0xFFFFFFFF


def crc32c_b64(data):
    return base64.b64encode(crc32c(data).to_bytes(4, "big")).decode()


# CRC-64/NVME, S3's default checksum, eight bytes a step through eight tables since Python has none of its own.
_CRC64_TABLES = [[]]
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0x9A6C9329AC4BC9B5 if _c & 1 else _c >> 1
    _CRC64_TABLES[0].append(_c)
for _k in range(1, 8):
    _CRC64_TABLES.append([(_v >> 8) ^ _CRC64_TABLES[0][_v & 0xFF] for _v in _CRC64_TABLES[_k - 1]])
_CRC64_SEEN = {}


def crc64nvme(data):
    t0, t1, t2, t3, t4, t5, t6, t7 = _CRC64_TABLES
    crc = 0xFFFFFFFFFFFFFFFF
    n8 = len(data) // 8 * 8
    for (v,) in struct.iter_unpack("<Q", data[:n8]):
        crc ^= v
        crc = t7[crc & 0xFF] ^ t6[(crc >> 8) & 0xFF] ^ t5[(crc >> 16) & 0xFF] ^ t4[(crc >> 24) & 0xFF] ^ \
            t3[(crc >> 32) & 0xFF] ^ t2[(crc >> 40) & 0xFF] ^ t1[(crc >> 48) & 0xFF] ^ t0[crc >> 56]
    for b in data[n8:]:
        crc = t0[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFFFFFFFFFF


def crc64nvme_b64(data):
    # Remembered by digest, since a test asks for the same large body more than once and each takes Python a second.
    k = hashlib.sha1(data).digest()
    if k not in _CRC64_SEEN:
        _CRC64_SEEN[k] = base64.b64encode(crc64nvme(data).to_bytes(8, "big")).decode()
    return _CRC64_SEEN[k]


def wait_released(data, timeout=30.0):
    """Waits until no stopping worker holds a shard of the runtime whose directory is `data`, so its files are the test's to change."""
    import fcntl
    import os
    import time
    give_up = time.monotonic() + timeout
    for name in sorted(n for n in os.listdir(data) if n.startswith(".lock.")):
        with open(os.path.join(data, name), "rb") as f:
            while True:
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(f, fcntl.LOCK_UN)
                    break
                except BlockingIOError:
                    if time.monotonic() > give_up:
                        return False
                    time.sleep(0.05)
    return True
