#!/usr/bin/env python3
"""SigV4 against the storage runtime: header and presigned authentication,
every x-amz-content-sha256 mode, aws-chunked bodies, checksums, and the S3
error codes each failure is answered with.

usage: lib_storage_auth.py PORT DATA_DIR WORKER_PID MODE

MODE is one of
  signed    a runtime with --access-key/--secret-key and no --anonymous
  credfile  a runtime with --credentials FILE; the file is rewritten under it
  both      a runtime with credentials and --anonymous

The credentials are in AK, SK and, for credfile, CREDFILE.  Prints one PASS or
FAIL line per assertion and a final "Results:" line, and exits with the number
of failures.
"""
import hashlib
import http.client
import os
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET

import boto3
import botocore.exceptions
import requests
from botocore.config import Config

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib_s3_signing as sig  # noqa: E402

PORT = int(sys.argv[1])
DATA = sys.argv[2]
PID = int(sys.argv[3])
MODE = sys.argv[4]
AK = os.environ.get("AK", "AKIATESTACCESSKEY01")
SK = os.environ.get("SK", "test/secret+key/for.storage.sigv4")
HOST = "127.0.0.1:%d" % PORT
URL = "http://" + HOST

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, detail))


class Resp:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    def h(self, name):
        return self.headers.get(name.lower())

    def code(self):
        try:
            return ET.fromstring(self.body).findtext("Code")
        except Exception:
            return None


def raw(method, target, headers=None, body=b"", pieces=None):
    """One request as given.  `pieces` sends the body with Transfer-Encoding: chunked, cut as listed."""
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
    try:
        hdrs = dict(headers or {})
        if pieces is not None:
            hdrs["Transfer-Encoding"] = "chunked"
            conn.request(method, target, body=iter(pieces), headers=hdrs, encode_chunked=True)
        else:
            conn.request(method, target, body=body, headers=hdrs)
        r = conn.getresponse()
        data = r.read()
        return Resp(r.status, {k.lower(): v for k, v in r.getheaders()}, data)
    except (ConnectionError, http.client.HTTPException) as e:
        return Resp(0, {}, repr(e).encode())
    finally:
        conn.close()


def signed(method, path, query="", body=b"", payload_hash=None, extra=None, amzdate=None,
           access=None, secret=None, pieces=None, tamper=None, send_body=None):
    """A request signed with the runtime's key unless told otherwise."""
    ph = payload_hash if payload_hash is not None else sig.sha256hex(body)
    s = sig.sign(method, path, query, HOST, access or AK, secret or SK, ph, extra, amzdate)
    hdrs = dict(s.headers)
    if extra:
        hdrs.update(extra)
    if tamper:
        tamper(hdrs)
    target = path + ("?" + query if query else "")
    return raw(method, target, hdrs, body if send_body is None else send_body, pieces), s


def client(access=None, secret=None, **s3cfg):
    cfg = dict(s3cfg)
    cfg["addressing_style"] = "path"
    return boto3.client("s3", endpoint_url=URL, aws_access_key_id=access or AK,
                        aws_secret_access_key=secret or SK, region_name="us-east-1",
                        config=Config(signature_version="s3v4", s3=cfg, retries={"max_attempts": 1}))


def code_of(fn):
    try:
        fn()
    except botocore.exceptions.ClientError as e:
        return e.response["Error"].get("Code"), e.response["ResponseMetadata"]["HTTPStatusCode"]
    return None, 200


def list_keys(c, bucket):
    r = c.list_objects_v2(Bucket=bucket)
    return [o["Key"] for o in r.get("Contents", [])]


def worker_hwm_kib():
    with open("/proc/%d/status" % PID) as f:
        for line in f:
            if line.startswith("VmHWM:"):
                return int(line.split()[1])
    return -1


def object_file_count(bucket):
    n = 0
    for root, _, files in os.walk(os.path.join(DATA, bucket, "data")):
        n += len(files)
    return n


B = "authb"


# ─── credentials file: the file is rewritten under a running runtime ─────────

def credfile_mode():
    path = os.environ["CREDFILE"]

    def write(text):
        tmp = path + ".new"
        with open(tmp, "w") as f:
            f.write(text)
        os.replace(tmp, path)

    def works(access, secret):
        return code_of(lambda: client(access, secret).list_buckets())[0] is None

    def wait_for(fn, timeout=8.0):
        end = time.time() + timeout
        while time.time() < end:
            if fn():
                return True
            time.sleep(0.25)
        return fn()

    check("credentials file: the first pair signs", works("AKA", "secretA"))
    check("credentials file: the second pair signs", works("AKB", "secretB"))
    check("credentials file: a secret holding ':' is the whole rest of the line", works("AKC", "sec:ret:c"))
    check("credentials file: a key that is not listed is InvalidAccessKeyId",
          code_of(lambda: client("AKZ", "secretZ").list_buckets()) == ("InvalidAccessKeyId", 403))
    check("credentials file: a listed key with another key's secret is SignatureDoesNotMatch",
          code_of(lambda: client("AKA", "secretB").list_buckets()) == ("SignatureDoesNotMatch", 403))

    write("# rotated\nAKA:secretA\nAKE:secretE\n")
    check("credentials file: a key added to the file works without a restart",
          wait_for(lambda: works("AKE", "secretE")))
    check("credentials file: a key taken out of the file stops working",
          wait_for(lambda: not works("AKB", "secretB")))
    check("credentials file: a key left in the file goes on working", works("AKA", "secretA"))

    write("this is not a credential line\n")
    time.sleep(2.5)
    check("credentials file: a file that does not parse leaves the old keys in force",
          works("AKA", "secretA") and works("AKE", "secretE"))
    write("")
    time.sleep(2.5)
    check("credentials file: an empty file leaves the old keys in force", works("AKA", "secretA"))

    write("AKF:secretF\n")
    check("credentials file: a repaired file is picked up", wait_for(lambda: works("AKF", "secretF")))
    check("credentials file: and the keys it no longer lists stop working",
          wait_for(lambda: not works("AKA", "secretA")))

    os.unlink(path)
    time.sleep(2.5)
    check("credentials file: a file that has gone leaves the keys in force", works("AKF", "secretF"))


# ─── the boto3 half: real botocore signing ───────────────────────────────────

def boto3_half():
    seen = set()

    def note(request, **kw):
        h = request.headers.get("x-amz-content-sha256")
        if h:
            seen.add(h if not isinstance(h, bytes) else h.decode())

    c = client()
    c.meta.events.register("request-created.s3", note)
    c.create_bucket(Bucket=B)
    body = os.urandom(300_000)
    c.put_object(Bucket=B, Key="hex.bin", Body=body)
    check("boto3 signs a PutObject over http with the hash of the payload",
          any(len(h) == 64 and all(ch in "0123456789abcdef" for ch in h) for h in seen), seen)
    check("boto3 a signed PutObject round-trips", c.get_object(Bucket=B, Key="hex.bin")["Body"].read() == body)
    check("boto3 head_object, list_objects_v2 and delete_object are signed and answered",
          c.head_object(Bucket=B, Key="hex.bin")["ContentLength"] == len(body) and list_keys(c, B) == ["hex.bin"] and
          c.delete_object(Bucket=B, Key="hex.bin")["ResponseMetadata"]["HTTPStatusCode"] == 204)

    unsigned = client(payload_signing_enabled=False)
    unsigned.meta.events.register("request-created.s3", note)
    blob = os.urandom(3_000_000)
    unsigned.put_object(Bucket=B, Key="unsigned.bin", Body=blob)
    check("boto3 with payload signing off sends UNSIGNED-PAYLOAD", "UNSIGNED-PAYLOAD" in seen, seen)
    check("boto3 an UNSIGNED-PAYLOAD PutObject round-trips", c.get_object(Bucket=B, Key="unsigned.bin")["Body"].read() == blob)

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "up.bin")
        with open(src, "wb") as f:
            f.write(blob)
        c.upload_file(src, B, "file.bin")
        dst = os.path.join(td, "down.bin")
        c.download_file(B, "file.bin", dst)
        check("boto3 upload_file and download_file with signed requests", open(dst, "rb").read() == blob)

    # Wrong secrets, unknown keys, and a signature that is one character off.
    check("boto3 a wrong secret is SignatureDoesNotMatch 403",
          code_of(lambda: client(secret="not-the-secret").list_buckets()) == ("SignatureDoesNotMatch", 403))
    check("boto3 an unknown access key is InvalidAccessKeyId 403",
          code_of(lambda: client(access="AKIANOTAKEYATALL").list_buckets()) == ("InvalidAccessKeyId", 403))
    r = raw("GET", "/")
    check("a request with no credentials is AccessDenied 403", r.status == 403 and r.code() == "AccessDenied", (r.status, r.body[:200]))
    r = raw("GET", "/", {"Authorization": "AWS4-HMAC-SHA256 Credential=oops"})
    check("a malformed Authorization is AuthorizationHeaderMalformed 400",
          r.status == 400 and r.code() == "AuthorizationHeaderMalformed", (r.status, r.body[:200]))
    r = raw("GET", "/", {"Authorization": "Basic Zm9vOmJhcg=="})
    check("a scheme that is not AWS4-HMAC-SHA256 is refused", r.status == 400, (r.status, r.body[:200]))

    # Checksums as boto3 sends them over http: in a header.
    for algo, key in (("CRC32", "crc32"), ("SHA256", "sha256"), ("SHA1", "sha1")):
        data = os.urandom(70_000)
        c.put_object(Bucket=B, Key="ck-" + key, Body=data, ChecksumAlgorithm=algo)
        h = c.head_object(Bucket=B, Key="ck-" + key, ChecksumMode="ENABLED")
        want = {"CRC32": sig.crc32_b64, "SHA256": sig.sha256_b64,
                "SHA1": lambda d: __import__("base64").b64encode(hashlib.sha1(d).digest()).decode()}[algo](data)
        check("boto3 put_object with ChecksumAlgorithm=%s stores the checksum and head_object returns it" % algo,
              h.get("Checksum" + algo) == want, (h.get("Checksum" + algo), want))
    plain = c.head_object(Bucket=B, Key="ck-crc32")
    check("a stored checksum is left off a head_object that did not ask for it", "ChecksumCRC32" not in plain, plain)
    g = c.get_object(Bucket=B, Key="ck-sha256", ChecksumMode="ENABLED", Range="bytes=0-9")
    check("a ranged get does not carry the checksum of the whole object", "ChecksumSHA256" not in g, g.keys())

    # A checksum that is not the body's.
    data = os.urandom(5000)
    ck_bad = sig.crc32_b64(b"something else")
    s, _ = signed("PUT", "/%s/ck-bad" % B, body=data, extra={"x-amz-checksum-crc32": ck_bad})
    check("a wrong x-amz-checksum-crc32 is BadDigest 400", s.status == 400 and s.code() == "BadDigest", (s.status, s.body[:200]))
    check("and the object was not stored", code_of(lambda: c.head_object(Bucket=B, Key="ck-bad"))[1] == 404)
    s, _ = signed("PUT", "/%s/ck-bad" % B, body=data, extra={"x-amz-checksum-sha256": sig.sha256_b64(b"another body")})
    check("a wrong x-amz-checksum-sha256 is BadDigest 400", s.status == 400 and s.code() == "BadDigest", (s.status, s.body[:200]))
    s, _ = signed("PUT", "/%s/ck-c32c" % B, body=data, extra={"x-amz-checksum-crc32c": sig.crc32c_b64(data)})
    check("a right x-amz-checksum-crc32c is stored and echoed",
          s.status == 200 and s.h("x-amz-checksum-crc32c") == sig.crc32c_b64(data), (s.status, s.headers))
    s, _ = signed("PUT", "/%s/ck-c32c2" % B, body=data, extra={"x-amz-checksum-crc32c": sig.crc32c_b64(b"other")})
    check("a wrong x-amz-checksum-crc32c is BadDigest", s.status == 400 and s.code() == "BadDigest", (s.status, s.body[:200]))
    s, _ = signed("PUT", "/%s/ck-bad" % B, body=data, extra={"x-amz-checksum-crc32": "not base64!"})
    check("a checksum that is not base64 is InvalidRequest 400", s.status == 400 and s.code() == "InvalidRequest", (s.status, s.body[:200]))
    s, _ = signed("PUT", "/%s/ck-bad" % B, body=data,
                  extra={"x-amz-checksum-crc32": sig.crc32_b64(data), "x-amz-checksum-sha256": sig.sha256_b64(data)})
    check("two checksum algorithms at once are InvalidRequest 400", s.status == 400 and s.code() == "InvalidRequest", (s.status, s.body[:200]))
    s, _ = signed("PUT", "/%s/ck-bad" % B, body=data, extra={"x-amz-checksum-crc32": sig.crc32_b64(data)[:6]})
    check("a checksum of the wrong length is InvalidRequest 400", s.status == 400 and s.code() == "InvalidRequest", (s.status, s.body[:200]))


# ─── presigned URLs ──────────────────────────────────────────────────────────

def presigned_half():
    c = client()
    data = os.urandom(50_000)
    c.put_object(Bucket=B, Key="pre/obj.bin", Body=data, ContentType="application/x-pre")

    url = c.generate_presigned_url("get_object", Params={"Bucket": B, "Key": "pre/obj.bin"}, ExpiresIn=300)
    r = requests.get(url)
    check("presigned GET returns the object", r.status_code == 200 and r.content == data, r.status_code)
    check("presigned GET keeps the stored content type", r.headers.get("Content-Type") == "application/x-pre")
    r = requests.get(url, headers={"Range": "bytes=10-19"})
    check("presigned GET with a Range header the URL did not sign", r.status_code == 206 and r.content == data[10:20], r.status_code)

    r = requests.head(c.generate_presigned_url("head_object", Params={"Bucket": B, "Key": "pre/obj.bin"}, ExpiresIn=300))
    check("presigned HEAD", r.status_code == 200 and int(r.headers["Content-Length"]) == len(data), r.status_code)

    put_url = c.generate_presigned_url("put_object", Params={"Bucket": B, "Key": "pre/put.bin"}, ExpiresIn=300)
    up = os.urandom(200_000)
    r = requests.put(put_url, data=up)
    check("presigned PUT stores the body", r.status_code == 200 and c.get_object(Bucket=B, Key="pre/put.bin")["Body"].read() == up, r.status_code)
    put_url2 = c.generate_presigned_url("put_object", Params={"Bucket": B, "Key": "pre/ct.bin", "ContentType": "text/pre"}, ExpiresIn=300)
    r = requests.put(put_url2, data=b"typed", headers={"Content-Type": "text/pre"})
    check("presigned PUT with a signed Content-Type", r.status_code == 200 and c.head_object(Bucket=B, Key="pre/ct.bin")["ContentType"] == "text/pre", r.status_code)
    r = requests.put(put_url2, data=b"typed", headers={"Content-Type": "text/other"})
    check("presigned PUT whose signed Content-Type is changed is SignatureDoesNotMatch",
          r.status_code == 403 and "SignatureDoesNotMatch" in r.text, (r.status_code, r.text[:200]))

    r = requests.delete(c.generate_presigned_url("delete_object", Params={"Bucket": B, "Key": "pre/put.bin"}, ExpiresIn=300))
    check("presigned DELETE", r.status_code == 204 and code_of(lambda: c.head_object(Bucket=B, Key="pre/put.bin"))[1] == 404, r.status_code)

    # Tampering.
    def flip(u, param):
        parts = urllib.parse.urlsplit(u)
        q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        out = []
        for k, v in q:
            if k == param:
                v = v[:-1] + ("0" if v[-1] != "0" else "1")
            out.append((k, v))
        return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(out)))

    r = requests.get(flip(url, "X-Amz-Signature"))
    check("presigned GET with one character of the signature changed is SignatureDoesNotMatch",
          r.status_code == 403 and "SignatureDoesNotMatch" in r.text, (r.status_code, r.text[:200]))
    r = requests.get(url.replace("pre/obj.bin", "pre/put.bin"))
    check("presigned GET for another key is SignatureDoesNotMatch", r.status_code == 403 and "SignatureDoesNotMatch" in r.text, (r.status_code, r.text[:200]))
    r = requests.put(url, data=b"x")
    check("a presigned GET URL does not authorise a PUT", r.status_code == 403 and "SignatureDoesNotMatch" in r.text, (r.status_code, r.text[:200]))
    r = requests.get(flip(url, "X-Amz-Expires"))
    check("presigned GET with X-Amz-Expires changed is SignatureDoesNotMatch", r.status_code == 403, r.status_code)
    r = requests.get(client(secret="wrong-secret-entirely").generate_presigned_url(
        "get_object", Params={"Bucket": B, "Key": "pre/obj.bin"}, ExpiresIn=300))
    check("presigned GET signed with the wrong secret is SignatureDoesNotMatch", r.status_code == 403 and "SignatureDoesNotMatch" in r.text, (r.status_code, r.text[:200]))
    r = requests.get(client(access="AKIANOTAKEYATALL").generate_presigned_url(
        "get_object", Params={"Bucket": B, "Key": "pre/obj.bin"}, ExpiresIn=300))
    check("presigned GET with an unknown access key is InvalidAccessKeyId", r.status_code == 403 and "InvalidAccessKeyId" in r.text, (r.status_code, r.text[:200]))

    # Expiry, and a clock that is off.
    short = c.generate_presigned_url("get_object", Params={"Bucket": B, "Key": "pre/obj.bin"}, ExpiresIn=1)
    check("presigned GET is good inside its lifetime", requests.get(short).status_code == 200)
    time.sleep(2.2)
    r = requests.get(short)
    check("an expired presigned GET is AccessDenied 403 (Request has expired)",
          r.status_code == 403 and "AccessDenied" in r.text and "expired" in r.text, (r.status_code, r.text[:200]))

    def presign_at(offset_seconds, expires):
        amz = sig.amz_now(offset_seconds)
        date = amz[:8]
        scope = "%s/us-east-1/s3/aws4_request" % date
        q = {"X-Amz-Algorithm": "AWS4-HMAC-SHA256", "X-Amz-Credential": "%s/%s" % (AK, scope),
             "X-Amz-Date": amz, "X-Amz-Expires": str(expires), "X-Amz-SignedHeaders": "host"}
        query = "&".join("%s=%s" % (k, urllib.parse.quote(v, safe="-_.~")) for k, v in q.items())
        path = "/%s/pre/obj.bin" % B
        creq = "\n".join(["GET", path, sig.canonical_query(query), "host:%s\n" % HOST, "host", "UNSIGNED-PAYLOAD"])
        sts = "\n".join(["AWS4-HMAC-SHA256", amz, scope, sig.sha256hex(creq.encode())])
        s = sig._hm(sig.signing_key(SK, date), sts).hex()
        return raw("GET", path + "?" + query + "&X-Amz-Signature=" + s)

    r = presign_at(0, 60)
    check("a presigned URL of our own making is accepted (the control for the two below)", r.status == 200, (r.status, r.body[:200]))
    r = presign_at(-3600, 60)
    check("a presigned URL that expired an hour ago is AccessDenied", r.status == 403 and r.code() == "AccessDenied", (r.status, r.body[:200]))
    r = presign_at(1800, 3600)
    check("a presigned URL dated half an hour ahead is RequestTimeTooSkewed",
          r.status == 403 and r.code() == "RequestTimeTooSkewed", (r.status, r.body[:200]))


# ─── every payload mode, hand-signed ─────────────────────────────────────────

def payload_half():
    c = client()
    path = lambda k: "/%s/%s" % (B, k)  # noqa: E731

    # The hash of the payload, verified against the streamed body.
    body = os.urandom(3 * 1024 * 1024 + 17)
    r, _ = signed("PUT", path("hex-ok"), body=body)
    check("a hex payload hash is verified against a body of several reads and stored",
          r.status == 200 and c.get_object(Bucket=B, Key="hex-ok")["Body"].read() == body, (r.status, r.body[:200]))
    r, _ = signed("PUT", path("hex-bad"), body=body, payload_hash=sig.sha256hex(b"not the body"))
    check("a hex payload hash that is not the body's is XAmzContentSHA256Mismatch 400",
          r.status == 400 and r.code() == "XAmzContentSHA256Mismatch", (r.status, r.body[:200]))
    check("and nothing was stored under that key", code_of(lambda: c.head_object(Bucket=B, Key="hex-bad"))[1] == 404)
    corrupt = bytearray(body)
    corrupt[len(corrupt) // 2] ^= 1
    r, _ = signed("PUT", path("hex-bad2"), body=body, send_body=bytes(corrupt))
    check("one flipped byte in the middle of the body is XAmzContentSHA256Mismatch",
          r.status == 400 and r.code() == "XAmzContentSHA256Mismatch", (r.status, r.body[:200]))
    r, _ = signed("PUT", path("hex-empty"), body=b"")
    check("an empty body with the hash of nothing is stored", r.status == 200 and c.head_object(Bucket=B, Key="hex-empty")["ContentLength"] == 0, (r.status, r.body[:200]))
    r, _ = signed("PUT", path("hex-empty2"), body=b"", payload_hash=sig.sha256hex(b"x"))
    check("an empty body whose hash is another body's is XAmzContentSHA256Mismatch", r.status == 400 and r.code() == "XAmzContentSHA256Mismatch", (r.status, r.body[:200]))
    r, _ = signed("GET", path("hex-ok"), payload_hash=sig.sha256hex(b"x"))
    check("a GET whose declared hash is not that of its empty body is refused too", r.status == 400 and r.code() == "XAmzContentSHA256Mismatch", (r.status, r.body[:200]))

    r, _ = signed("PUT", path("unsigned"), body=body, payload_hash="UNSIGNED-PAYLOAD")
    check("UNSIGNED-PAYLOAD is stored without a hash to check", r.status == 200 and c.get_object(Bucket=B, Key="unsigned")["Body"].read() == body, (r.status, r.body[:200]))

    # aws-chunked with signatures on every chunk.
    pieces = [os.urandom(100_000), os.urandom(100_000), os.urandom(12_345)]
    data = b"".join(pieces)
    S = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
    ex = {"x-amz-decoded-content-length": str(len(data)), "content-encoding": "aws-chunked"}

    def put_chunks(key, mutate=None):
        # Signed for this key, so that whatever fails is what `mutate` did to the body.
        s = sig.sign("PUT", path(key), "", HOST, AK, SK, S, ex)
        wire = sig.signed_chunks(s, pieces)
        return raw("PUT", path(key), dict(s.headers, **ex), mutate(wire) if mutate else wire)

    r = put_chunks("chunks")
    check("aws-chunked with signed chunks is decoded and stored",
          r.status == 200 and c.get_object(Bucket=B, Key="chunks")["Body"].read() == data, (r.status, r.body[:200]))
    check("and the framing's Content-Encoding is not stored with the object",
          "ContentEncoding" not in c.head_object(Bucket=B, Key="chunks"), c.head_object(Bucket=B, Key="chunks"))

    def flip_second_chunk(wire):
        bad = bytearray(wire)
        # Inside the second chunk's data, which is signed by the signature that follows.
        bad[wire.find(pieces[1][:16]) + 3] ^= 1
        return bytes(bad)

    r = put_chunks("chunks-bad", flip_second_chunk)
    check("a flipped byte inside a signed chunk is SignatureDoesNotMatch 403",
          r.status == 403 and r.code() == "SignatureDoesNotMatch", (r.status, r.body[:200]))
    check("and nothing was stored under that key", code_of(lambda: c.head_object(Bucket=B, Key="chunks-bad"))[1] == 404)

    r = put_chunks("chunks-bad2", lambda w: w.replace(b"chunk-signature=", b"chunk-signature=0", 1))
    check("a chunk signature of the wrong length is refused", r.status in (400, 403), (r.status, r.body[:200]))
    r = put_chunks("chunks-bad3", lambda w: w.replace(b"chunk-signature=", b"chunk-signature=" + b"0" * 64 + b";x=", 1))
    check("a chunk signature that is not the chunk's is refused", r.status in (400, 403), (r.status, r.body[:200]))

    short_ex = dict(ex, **{"x-amz-decoded-content-length": str(len(data) + 5)})
    s2 = sig.sign("PUT", path("chunks-short"), "", HOST, AK, SK, S, short_ex)
    r = raw("PUT", path("chunks-short"), dict(s2.headers, **short_ex), sig.signed_chunks(s2, pieces))
    check("a body that decodes to fewer bytes than x-amz-decoded-content-length says is refused",
          r.status == 400, (r.status, r.body[:200]))
    check("and nothing was stored for it", code_of(lambda: c.head_object(Bucket=B, Key="chunks-short"))[1] == 404)

    # A body that stops inside a chunk, and one that stops between them.
    r = put_chunks("chunks-cut", lambda w: w[:len(w) - 300])
    check("a signed stream that ends inside its last chunk is IncompleteBody 400", r.status == 400 and r.code() == "IncompleteBody", (r.status, r.body[:200]))
    check("and nothing was stored for a cut stream", code_of(lambda: c.head_object(Bucket=B, Key="chunks-cut"))[1] == 404)
    r = put_chunks("chunks-nofinal", lambda w: w[:w.rfind(b"0;chunk-signature=")])
    check("a signed stream that ends before its zero-length chunk is refused", r.status == 400, (r.status, r.body[:200]))
    check("and nothing was stored for it", code_of(lambda: c.head_object(Bucket=B, Key="chunks-nofinal"))[1] == 404)

    # aws-chunked with a checksum in the trailer, unsigned and signed.
    text = os.urandom(4000)
    crc = sig.crc32c_b64(text)
    UT = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
    ex2 = {"x-amz-decoded-content-length": str(len(text)), "content-encoding": "aws-chunked",
           "x-amz-trailer": "x-amz-checksum-crc32c", "x-amz-sdk-checksum-algorithm": "CRC32C"}
    s3 = sig.sign("PUT", path("trailer"), "", HOST, AK, SK, UT, ex2)
    r = raw("PUT", path("trailer"), dict(s3.headers, **ex2),
            sig.unsigned_chunks([text[:1500], text[1500:]], [("x-amz-checksum-crc32c", crc)]))
    h = c.head_object(Bucket=B, Key="trailer", ChecksumMode="ENABLED")
    check("an unsigned-trailer body with a right crc32c is stored and the checksum kept",
          r.status == 200 and h.get("ChecksumCRC32C") == crc and r.h("x-amz-checksum-crc32c") == crc, (r.status, r.body[:200], h))
    check("and its bytes are the decoded payload", c.get_object(Bucket=B, Key="trailer")["Body"].read() == text)
    r = raw("PUT", path("trailer-bad"), dict(sig.sign("PUT", path("trailer-bad"), "", HOST, AK, SK, UT, ex2).headers, **ex2),
            sig.unsigned_chunks([text[:1500], text[1500:]], [("x-amz-checksum-crc32c", sig.crc32c_b64(b"other"))]))
    check("an unsigned-trailer body whose crc32c is not the body's is BadDigest 400", r.status == 400 and r.code() == "BadDigest", (r.status, r.body[:200]))
    check("and nothing was stored for a wrong trailer checksum", code_of(lambda: c.head_object(Bucket=B, Key="trailer-bad"))[1] == 404)

    ex3 = {"x-amz-decoded-content-length": str(len(text)), "content-encoding": "aws-chunked",
           "x-amz-trailer": "x-amz-checksum-sha256"}
    s4 = sig.sign("PUT", path("trailer-sha"), "", HOST, AK, SK, UT, ex3)
    r = raw("PUT", path("trailer-sha"), dict(s4.headers, **ex3),
            sig.unsigned_chunks([text], [("x-amz-checksum-sha256", sig.sha256_b64(text))]))
    check("an unsigned-trailer body with a right sha256", r.status == 200 and r.h("x-amz-checksum-sha256") == sig.sha256_b64(text), (r.status, r.body[:200]))

    ST = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
    s5 = sig.sign("PUT", path("strailer"), "", HOST, AK, SK, ST, ex2)
    r = raw("PUT", path("strailer"), dict(s5.headers, **ex2),
            sig.signed_chunks(s5, [text[:1000], text[1000:]], [("x-amz-checksum-crc32c", crc)]))
    check("a signed-chunk body with a signed trailer is stored",
          r.status == 200 and c.get_object(Bucket=B, Key="strailer")["Body"].read() == text, (r.status, r.body[:200]))
    r = raw("PUT", path("strailer-bad"), dict(sig.sign("PUT", path("strailer-bad"), "", HOST, AK, SK, ST, ex2).headers, **ex2),
            sig.signed_chunks(s5, [text[:1000], text[1000:]], [("x-amz-checksum-crc32c", crc)]))
    check("a signed trailer signed for another request is SignatureDoesNotMatch", r.status == 403, (r.status, r.body[:200]))
    s6 = sig.sign("PUT", path("strailer-wrong"), "", HOST, AK, SK, ST, ex2)
    r = raw("PUT", path("strailer-wrong"), dict(s6.headers, **ex2),
            sig.signed_chunks(s6, [text[:1000], text[1000:]], [("x-amz-checksum-crc32c", sig.crc32c_b64(b"other"))]))
    check("a correctly signed trailer that carries a wrong checksum is BadDigest", r.status == 400 and r.code() == "BadDigest", (r.status, r.body[:200]))

    # Both framings at once, as boto3 over https sends a checksum: the aws-chunked
    # body itself carried in Transfer-Encoding: chunked, cut where it likes.
    s7 = sig.sign("PUT", path("both"), "", HOST, AK, SK, UT, ex2)
    inner = sig.unsigned_chunks([text[:1500], text[1500:]], [("x-amz-checksum-crc32c", crc)])
    cuts = [inner[:7], inner[7:1000], inner[1000:1600], inner[1600:]]
    r = raw("PUT", path("both"), dict(s7.headers, **ex2), pieces=cuts)
    check("aws-chunked inside Transfer-Encoding: chunked is undone, decoded and verified",
          r.status == 200 and c.get_object(Bucket=B, Key="both")["Body"].read() == text and r.h("x-amz-checksum-crc32c") == crc, (r.status, r.body[:200]))
    s8 = sig.sign("PUT", path("both-bad"), "", HOST, AK, SK, UT, ex2)
    inner_bad = sig.unsigned_chunks([text[:1500], text[1500:]], [("x-amz-checksum-crc32c", sig.crc32c_b64(b"other"))])
    r = raw("PUT", path("both-bad"), dict(s8.headers, **ex2), pieces=[inner_bad[:100], inner_bad[100:]])
    check("and a wrong trailer checksum inside it is BadDigest", r.status == 400 and r.code() == "BadDigest", (r.status, r.body[:200]))
    s9 = sig.sign("PUT", path("both-signed"), "", HOST, AK, SK, S, ex)
    w = sig.signed_chunks(s9, pieces)
    r = raw("PUT", path("both-signed"), dict(s9.headers, **ex), pieces=[w[:333], w[333:150000], w[150000:]])
    check("signed chunks inside Transfer-Encoding: chunked are verified across the outer cuts",
          r.status == 200 and c.get_object(Bucket=B, Key="both-signed")["Body"].read() == data, (r.status, r.body[:200]))

    # A clock that is off.
    r, _ = signed("GET", "/", amzdate=sig.amz_now(-20 * 60))
    check("a request dated twenty minutes ago is RequestTimeTooSkewed 403", r.status == 403 and r.code() == "RequestTimeTooSkewed", (r.status, r.body[:200]))
    r, _ = signed("GET", "/", amzdate=sig.amz_now(20 * 60))
    check("a request dated twenty minutes ahead is RequestTimeTooSkewed 403", r.status == 403 and r.code() == "RequestTimeTooSkewed", (r.status, r.body[:200]))
    r, _ = signed("GET", "/", amzdate=sig.amz_now(-10 * 60))
    check("a request dated ten minutes ago is inside the window", r.status == 200, (r.status, r.body[:200]))

    # The same request with its signature changed.
    def flip_sig(h):
        a = h["Authorization"]
        h["Authorization"] = a[:-1] + ("0" if a[-1] != "0" else "1")
    r, _ = signed("GET", "/", tamper=flip_sig)
    check("one character of the signature changed is SignatureDoesNotMatch", r.status == 403 and r.code() == "SignatureDoesNotMatch", (r.status, r.body[:200]))
    r, _ = signed("GET", "/", secret="another-secret")
    check("a wrong secret is SignatureDoesNotMatch", r.status == 403 and r.code() == "SignatureDoesNotMatch", (r.status, r.body[:200]))
    r, _ = signed("GET", "/", access="AKIANOTAKEYATALL")
    check("an unknown access key is InvalidAccessKeyId", r.status == 403 and r.code() == "InvalidAccessKeyId", (r.status, r.body[:200]))
    r, _ = signed("GET", "/%s/hex-ok" % B, tamper=lambda h: h.update({"x-amz-date": sig.amz_now(5)}))
    check("a date header changed after signing is SignatureDoesNotMatch", r.status == 403 and r.code() == "SignatureDoesNotMatch", (r.status, r.body[:200]))
    r, _ = signed("GET", "/%s/hex-ok" % B, extra={"x-amz-meta-mine": "a"}, tamper=lambda h: h.update({"x-amz-meta-mine": "b"}))
    check("a signed header changed after signing is SignatureDoesNotMatch", r.status == 403 and r.code() == "SignatureDoesNotMatch", (r.status, r.body[:200]))
    r, _ = signed("GET", "/%s/hex-ok" % B)
    check("the same request untouched is served (the control for the ones above)", r.status == 200 and r.body == body, r.status)

    # A denied request is answered before its body is read, and the connection closes.
    r, _ = signed("PUT", path("denied"), body=b"x" * 1000, secret="another-secret")
    check("a denied PUT stores nothing", r.status == 403 and code_of(lambda: c.head_object(Bucket=B, Key="denied"))[1] == 404, r.status)
    r, _ = signed("PUT", path("denied-big"), body=os.urandom(8 << 20), secret="another-secret")
    check("a denied PUT with several megabytes of body is answered 403 and not reset",
          r.status == 403 and r.code() == "SignatureDoesNotMatch", (r.status, r.body[:200]))
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
    body_ = os.urandom(3 << 20)
    s_ = sig.sign("PUT", path("denied-keepalive"), "", HOST, AK, "another-secret", sig.sha256hex(body_))
    conn.request("PUT", path("denied-keepalive"), body=body_, headers=s_.headers)
    first = conn.getresponse()
    first.read()
    s2_ = sig.sign("GET", "/", "", HOST, AK, SK, sig.EMPTY)
    conn.request("GET", "/", headers=s2_.headers)
    second = conn.getresponse()
    second.read()
    conn.close()
    check("and the connection that was denied serves the next request", first.status == 403 and second.status == 200, (first.status, second.status))


# ─── a large body with signatures, and the worker's memory ───────────────────

def large_half():
    c = client()
    mib = int(os.environ.get("SOCKETLEY_STORAGE_AUTH_MIB", "256"))
    block = os.urandom(1 << 20)
    total = mib << 20
    before = worker_hwm_kib()

    # Hex hash over a body sent in pieces.
    h = hashlib.sha256()
    for _ in range(mib):
        h.update(block)

    def send_plain(key, payload_hash):
        path = "/%s/%s" % (B, key)
        s = sig.sign("PUT", path, "", HOST, AK, SK, payload_hash)
        conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=300)
        conn.putrequest("PUT", path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", HOST)
        conn.putheader("Content-Length", str(total))
        for k, v in s.headers.items():
            conn.putheader(k, v)
        conn.endheaders()
        t0 = time.time()
        for _ in range(mib):
            conn.send(block)
        r = conn.getresponse()
        r.read()
        conn.close()
        return r.status, time.time() - t0

    status, took = send_plain("big-unsigned", "UNSIGNED-PAYLOAD")
    check("a %d MiB body with UNSIGNED-PAYLOAD is stored" % mib, status == 200, status)
    print("  info: %d MiB unsigned in %.2fs (%.0f MB/s)" % (mib, took, mib / took))
    status, took = send_plain("big-hex", h.hexdigest())
    print("  info: %d MiB with a hex payload hash in %.2fs (%.0f MB/s)" % (mib, took, mib / took))
    check("a %d MiB body with a hex payload hash is stored" % mib, status == 200 and
          c.head_object(Bucket=B, Key="big-hex")["ContentLength"] == total, status)
    # Signed chunks of a megabyte.
    S = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
    path = "/%s/big-chunks" % B
    ex = {"x-amz-decoded-content-length": str(total), "content-encoding": "aws-chunked"}
    s = sig.sign("PUT", path, "", HOST, AK, SK, S, ex)
    framed = 0
    prev = s.signature
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=300)
    conn.putrequest("PUT", path, skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", HOST)
    # The length of the framing is known ahead: one header line per chunk and the last.
    line_len = len(("%x;chunk-signature=%s\r\n" % (1 << 20, "0" * 64)))
    final_len = len("0;chunk-signature=%s\r\n\r\n" % ("0" * 64))
    conn.putheader("Content-Length", str(mib * (line_len + (1 << 20) + 2) + final_len))
    for k, v in dict(s.headers, **ex).items():
        conn.putheader(k, v)
    conn.endheaders()
    t0 = time.time()
    for _ in range(mib):
        prev = sig.chunk_signature(s.key, s.amzdate, s.scope, prev, block)
        conn.send(("%x;chunk-signature=%s\r\n" % (len(block), prev)).encode() + block + b"\r\n")
    prev = sig.chunk_signature(s.key, s.amzdate, s.scope, prev, b"")
    conn.send(("0;chunk-signature=%s\r\n\r\n" % prev).encode())
    r = conn.getresponse()
    r.read()
    conn.close()
    took = time.time() - t0
    print("  info: %d MiB in signed chunks in %.2fs (%.0f MB/s, the client signs each chunk)" % (mib, took, mib / took))
    check("a %d MiB body in signed chunks is stored" % mib, r.status == 200 and
          c.head_object(Bucket=B, Key="big-chunks")["ContentLength"] == total, r.status)
    g = hashlib.md5()
    for chunk in c.get_object(Bucket=B, Key="big-chunks")["Body"].iter_chunks(1 << 20):
        g.update(chunk)
    want = hashlib.md5()
    for _ in range(mib):
        want.update(block)
    check("and the bytes that were stored are the decoded ones", g.hexdigest() == want.hexdigest())

    after = worker_hwm_kib()
    limit_kib = int(os.environ.get("SOCKETLEY_STORAGE_AUTH_RSS_MIB", "64")) * 1024
    check("the worker's peak resident set stays bounded through both (%d -> %d KiB, limit %d)" % (before, after, limit_kib),
          0 < after <= limit_kib, (before, after))


# ─── credentials and --anonymous together ────────────────────────────────────

def both_half():
    c = client()
    r = raw("GET", "/")
    check("with --anonymous a request with no credentials is served", r.status == 200, (r.status, r.body[:200]))
    check("and a request with the right credentials is served too", code_of(lambda: c.list_buckets())[0] is None)
    check("but a wrong signature is refused and not taken for an anonymous request",
          code_of(lambda: client(secret="wrong-secret-entirely").list_buckets()) == ("SignatureDoesNotMatch", 403))
    r = raw("PUT", "/anon-bucket")
    check("an anonymous CreateBucket", r.status == 200, (r.status, r.body[:200]))
    text = os.urandom(3000)
    crc = sig.crc32c_b64(text)
    hdrs = {"x-amz-content-sha256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER", "content-encoding": "aws-chunked",
            "x-amz-decoded-content-length": str(len(text)), "x-amz-trailer": "x-amz-checksum-crc32c"}
    r = raw("PUT", "/anon-bucket/trailer", hdrs, sig.unsigned_chunks([text], [("x-amz-checksum-crc32c", crc)]))
    check("an anonymous unsigned-trailer body is decoded and its checksum checked",
          r.status == 200 and raw("GET", "/anon-bucket/trailer").body == text, (r.status, r.body[:200]))
    r = raw("PUT", "/anon-bucket/trailer-bad", hdrs, sig.unsigned_chunks([text], [("x-amz-checksum-crc32c", sig.crc32c_b64(b"other"))]))
    check("and a wrong one is BadDigest", r.status == 400 and r.code() == "BadDigest", (r.status, r.body[:200]))
    r = raw("PUT", "/anon-bucket/signed-chunks", {"x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
                                                  "x-amz-decoded-content-length": "3", "content-encoding": "aws-chunked"}, b"3;chunk-signature=" + b"0" * 64 + b"\r\nabc\r\n")
    check("an anonymous request cannot use signed chunks, which nobody is there to verify", r.status == 501, (r.status, r.body[:200]))


def main():
    if MODE == "credfile":
        credfile_mode()
    elif MODE == "signed":
        boto3_half()
        presigned_half()
        payload_half()
        large_half()
    elif MODE == "both":
        client().create_bucket(Bucket=B)
        both_half()
    else:
        print("unknown mode " + MODE)
        sys.exit(2)
    total = passed + failed
    print("  Results: %d/%d passed (%d failed)" % (passed, total, failed))
    sys.exit(min(failed, 100))


main()
