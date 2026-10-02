#!/usr/bin/env python3
"""The storage runtime measured against what S3 clients expect, through boto3.

usage: lib_storage_compat.py PORT DATA_DIR

Prints one PASS or FAIL line per assertion and a final "Results:" line, and
exits with the number of failures (at most 100).  The credentials come from
S3_TEST_ACCESS_KEY and S3_TEST_SECRET_KEY when set, and are otherwise the
anonymous client of a runtime made with --anonymous.

lib_storage_s3.py holds down what each operation answers; this file asks the
questions a client library asks of a whole service: every error code with the
body and headers around it, every shape of Range against objects on both sides
of the splice threshold, a listing of ten thousand keys paged by every size and
compared with a model of S3's own ordering, the round trip of every header,
CopyObject's directives, DeleteObjects that half fails, keys of every spelling,
and writers racing readers on one key.
"""
import base64
import datetime
import hashlib
import http.client
import os
import re
import sys
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET

PORT = int(sys.argv[1])
DATA = sys.argv[2]
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
ACCESS = os.environ.get("S3_TEST_ACCESS_KEY")
SECRET = os.environ.get("S3_TEST_SECRET_KEY")

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, str(detail)[:400]))


def md5hex(b):
    return hashlib.md5(b).hexdigest()


try:
    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config
    from botocore.exceptions import ClientError
except ImportError:
    print("  SKIP: boto3 is not installed")
    sys.exit(0)


def make_client():
    cfg = dict(s3={"addressing_style": "path"}, retries={"max_attempts": 1})
    if ACCESS:
        return boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % PORT, region_name="us-east-1",
                            aws_access_key_id=ACCESS, aws_secret_access_key=SECRET, config=Config(**cfg))
    return boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % PORT, region_name="us-east-1",
                        config=Config(signature_version=UNSIGNED, **cfg))


s3 = make_client()


def err_of(fn):
    """(code, http status, the whole error dict) of a call that must fail, or (None, None, None)."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["ResponseMetadata"]["HTTPStatusCode"], e.response
    return None, None, None


def expect_err(name, fn, code, status):
    c, st, resp = err_of(fn)
    check(name, c == code and st == status, "got %s %s, want %s %s" % (c, st, code, status))
    return resp


# A raw exchange, for what boto3 will not send or hides.
def raw(method, path, body=None, headers=None, conn=None):
    own = conn is None
    if own:
        conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        data = r.read()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data
    finally:
        if own:
            conn.close()


def q(key):
    return urllib.parse.quote(key, safe="/")


def put(bucket, key, body=b"", **kw):
    return s3.put_object(Bucket=bucket, Key=key, Body=body, **kw)


def get(bucket, key, **kw):
    r = s3.get_object(Bucket=bucket, Key=key, **kw)
    return r, r["Body"].read()


# ─── Every error code, with the shape S3 clients parse ──────────────────────
print("=== boto3: error codes and the error document ===")
s3.create_bucket(Bucket="err-bucket")
put("err-bucket", "present", b"0123456789")

resp = expect_err("GetObject of a missing key is NoSuchKey 404",
                  lambda: s3.get_object(Bucket="err-bucket", Key="absent"), "NoSuchKey", 404)
check("the error names the key and carries a request id and a message",
      resp is not None and resp["Error"].get("Key") == "absent" and resp["Error"].get("Message") and
      resp["ResponseMetadata"].get("RequestId"), resp and resp["Error"])
resp = expect_err("GetObject in a missing bucket is NoSuchBucket 404",
                  lambda: s3.get_object(Bucket="nobucket-here", Key="k"), "NoSuchBucket", 404)
check("the error names the bucket", resp is not None and resp["Error"].get("BucketName") == "nobucket-here",
      resp and resp["Error"])
expect_err("PutObject in a missing bucket is NoSuchBucket 404",
           lambda: put("nobucket-here", "k", b"x"), "NoSuchBucket", 404)
expect_err("DeleteObject in a missing bucket is NoSuchBucket 404",
           lambda: s3.delete_object(Bucket="nobucket-here", Key="k"), "NoSuchBucket", 404)
expect_err("ListObjectsV2 in a missing bucket is NoSuchBucket 404",
           lambda: s3.list_objects_v2(Bucket="nobucket-here"), "NoSuchBucket", 404)
expect_err("DeleteObjects in a missing bucket is NoSuchBucket 404",
           lambda: s3.delete_objects(Bucket="nobucket-here", Delete={"Objects": [{"Key": "k"}]}),
           "NoSuchBucket", 404)
expect_err("DeleteBucket of a missing bucket is NoSuchBucket 404",
           lambda: s3.delete_bucket(Bucket="nobucket-here"), "NoSuchBucket", 404)
expect_err("CopyObject into a missing bucket is NoSuchBucket 404",
           lambda: s3.copy_object(Bucket="nobucket-here", Key="k",
                                  CopySource={"Bucket": "err-bucket", "Key": "present"}), "NoSuchBucket", 404)
expect_err("CopyObject from a missing bucket is NoSuchBucket 404",
           lambda: s3.copy_object(Bucket="err-bucket", Key="k",
                                  CopySource={"Bucket": "nobucket-here", "Key": "present"}), "NoSuchBucket", 404)
expect_err("CopyObject of a missing key is NoSuchKey 404",
           lambda: s3.copy_object(Bucket="err-bucket", Key="k",
                                  CopySource={"Bucket": "err-bucket", "Key": "absent"}), "NoSuchKey", 404)
c, st, _ = err_of(lambda: s3.head_object(Bucket="err-bucket", Key="absent"))
check("HeadObject of a missing key is 404 (no body, so the code is the status)", st == 404 and c == "404", (c, st))
c, st, _ = err_of(lambda: s3.head_bucket(Bucket="nobucket-here"))
check("HeadBucket of a missing bucket is 404", st == 404 and c == "404", (c, st))
expect_err("CreateBucket of one's own bucket is BucketAlreadyOwnedByYou 409",
           lambda: s3.create_bucket(Bucket="err-bucket"), "BucketAlreadyOwnedByYou", 409)
expect_err("DeleteBucket of a bucket with an object is BucketNotEmpty 409",
           lambda: s3.delete_bucket(Bucket="err-bucket"), "BucketNotEmpty", 409)
for bad in ["ab", "with_under", "UPPER", "-lead", "a" * 64, "1.2.3.4", "dou..ble"]:
    c, st, _ = err_of(lambda: s3.create_bucket(Bucket=bad))
    check("CreateBucket %r is InvalidBucketName 400" % bad[:20], st == 400 and c == "InvalidBucketName", (c, st))
expect_err("a key of 1025 bytes is KeyTooLongError 400",
           lambda: put("err-bucket", "k" * 1025, b"x"), "KeyTooLongError", 400)
expect_err("a key of 1025 bytes of two-byte characters is KeyTooLongError 400",
           lambda: put("err-bucket", "é" * 513, b"x"), "KeyTooLongError", 400)
expect_err("a Content-MD5 that is not the body's is BadDigest 400",
                  lambda: put("err-bucket", "bad-md5", b"body",
                              ContentMD5=base64.b64encode(hashlib.md5(b"other").digest()).decode()),
                  "BadDigest", 400)
expect_err("a body refused by BadDigest was not stored",
           lambda: s3.head_object(Bucket="err-bucket", Key="bad-md5"), "404", 404)
st_, hd_, body_ = raw("PUT", "/err-bucket/junk-md5", body=b"x", headers={"Content-MD5": "%%%"})
check("a Content-MD5 that is not base64 is InvalidDigest 400", st_ == 400 and b"<Code>InvalidDigest</Code>" in body_,
      (st_, body_[:200]))
expect_err("a Range past the end is InvalidRange 416",
           lambda: s3.get_object(Bucket="err-bucket", Key="present", Range="bytes=10-"), "InvalidRange", 416)
check("PutObjectAcl of the ACL every object has is taken",
      err_of(lambda: s3.put_object_acl(Bucket="err-bucket", Key="present", ACL="private"))[0] is None)
resp = expect_err("PutObjectAcl of any other is AccessControlListNotSupported 400, as with ACLs disabled",
                  lambda: s3.put_object_acl(Bucket="err-bucket", Key="present", ACL="public-read"),
                  "AccessControlListNotSupported", 400)
expect_err("and so is a put that asks for one",
           lambda: s3.put_object(Bucket="err-bucket", Key="acl-put", Body=b"x", ACL="public-read"),
           "AccessControlListNotSupported", 400)
expect_err("which stored nothing", lambda: s3.head_object(Bucket="err-bucket", Key="acl-put"), "404", 404)
expect_err("GetBucketPolicy on a bucket without one is NoSuchBucketPolicy 404",
           lambda: s3.get_bucket_policy(Bucket="err-bucket"), "NoSuchBucketPolicy", 404)
st_, hd_, body_ = raw("PUT", "/err-bucket/present", body=b"x", headers={"If-None-Match": "*"})
check("PutObject with If-None-Match: * on an existing key is PreconditionFailed 412",
      st_ == 412 and b"<Code>PreconditionFailed</Code>" in body_, (st_, body_[:200]))
expect_err("GetObject with a stale If-Match is PreconditionFailed 412",
           lambda: s3.get_object(Bucket="err-bucket", Key="present", IfMatch='"deadbeef"'),
           "PreconditionFailed", 412)
etag = s3.head_object(Bucket="err-bucket", Key="present")["ETag"]
c, st, _ = err_of(lambda: s3.get_object(Bucket="err-bucket", Key="present", IfNoneMatch=etag))
check("GetObject with a fresh If-None-Match is 304", st == 304, (c, st))
expect_err("a copy whose x-amz-copy-source-if-match is stale is PreconditionFailed 412",
           lambda: s3.copy_object(Bucket="err-bucket", Key="cp", CopySource={"Bucket": "err-bucket", "Key": "present"},
                                  CopySourceIfMatch='"deadbeef"'), "PreconditionFailed", 412)
expect_err("a copy of an object onto itself is InvalidRequest 400",
           lambda: s3.copy_object(Bucket="err-bucket", Key="present",
                                  CopySource={"Bucket": "err-bucket", "Key": "present"}), "InvalidRequest", 400)
st_, hd_, body_ = raw("GET", "/err-bucket?list-type=2&max-keys=abc")
check("a listing with max-keys=abc is InvalidArgument 400", st_ == 400 and b"<Code>InvalidArgument</Code>" in body_,
      (st_, body_[:200]))
expect_err("a listing with a garbage continuation token is InvalidArgument 400",
           lambda: s3.list_objects_v2(Bucket="err-bucket", ContinuationToken="!!not-a-token!!"),
           "InvalidArgument", 400)
expect_err("3 KiB of user metadata is MetadataTooLarge 400",
           lambda: put("err-bucket", "meta-big", b"x", Metadata={"big": "v" * 3000}), "MetadataTooLarge", 400)

st_, hd_, body_ = raw("POST", "/err-bucket/present", body=b"")
check("a POST of an object is refused, not crashed on (405 or 501)", st_ in (405, 501), (st_, body_[:200]))
st_, hd_, body_ = raw("PATCH", "/err-bucket/present", body=b"")
check("an unknown method is MethodNotAllowed 405", st_ == 405 and b"<Code>MethodNotAllowed</Code>" in body_,
      (st_, body_[:200]))
st_, hd_, body_ = raw("PUT", "/err-bucket/nolen", body=None, headers={"Content-Length": "0"})
check("a PUT of a zero-length body is fine", st_ == 200, (st_, body_[:200]))
st_, hd_, body_ = raw("POST", "/err-bucket?delete", body=b"<Delete><Object></Object></Delete>")
check("a DeleteObjects body with an Object and no Key is MalformedXML 400",
      st_ == 400 and b"<Code>MalformedXML</Code>" in body_, (st_, body_[:200]))

st_, hd_, body_ = raw("GET", "/err-bucket/absent")
root = ET.fromstring(body_)
check("an error document is <Error> with Code, Message, Resource and RequestId, as application/xml",
      root.tag == "Error" and all(root.findtext(t) for t in ("Code", "Message", "Resource", "RequestId")) and
      hd_.get("content-type", "").startswith("application/xml") and
      root.findtext("RequestId") == hd_.get("x-amz-request-id"), (hd_, body_[:300]))
check("Resource is the path asked for", root.findtext("Resource") == "/err-bucket/absent", body_[:300])

if ACCESS:
    bad = boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % PORT, region_name="us-east-1",
                       aws_access_key_id=ACCESS, aws_secret_access_key=SECRET + "x",
                       config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}))
    expect_err("a wrong secret is SignatureDoesNotMatch 403",
               lambda: bad.list_buckets(), "SignatureDoesNotMatch", 403)
    unknown = boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % PORT, region_name="us-east-1",
                           aws_access_key_id="NOSUCHKEYID", aws_secret_access_key="x",
                           config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}))
    expect_err("an unknown access key is InvalidAccessKeyId 403",
               lambda: unknown.list_buckets(), "InvalidAccessKeyId", 403)
    anon = boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % PORT, region_name="us-east-1",
                        config=Config(signature_version=UNSIGNED, s3={"addressing_style": "path"},
                                      retries={"max_attempts": 1}))
    expect_err("an unsigned request is AccessDenied 403", lambda: anon.list_buckets(), "AccessDenied", 403)

# ─── Range: every shape, both sides of the splice threshold ─────────────────
print("=== boto3: ranges ===")
s3.create_bucket(Bucket="range-bucket")


def expected_range(spec, size):
    """RFC 7233 as S3 applies it: ('whole'|'slice'|'unsat', first, last)."""
    m = re.fullmatch(r"bytes=(\d*)-(\d*)", spec)
    if not m or (m.group(1) == "" and m.group(2) == ""):
        return ("whole", 0, size - 1)
    a, b = m.group(1), m.group(2)
    if a == "":
        n = int(b)
        if n == 0 or size == 0:
            return ("unsat", 0, 0)
        return ("slice", max(0, size - n), size - 1)
    a = int(a)
    if b != "" and int(b) < a:
        return ("whole", 0, size - 1)
    if a >= size:
        return ("unsat", 0, 0)
    return ("slice", a, size - 1 if b == "" else min(int(b), size - 1))


sizes = [0, 1, 2, 100, 4096, 65535, 65536, 65537, 300001]
specs = ["bytes=0-0", "bytes=0-", "bytes=0-99", "bytes=1-1", "bytes=1-", "bytes=-1", "bytes=-2", "bytes=-100",
         "bytes=-65536", "bytes=-65537", "bytes=-999999999", "bytes=-0", "bytes=99-99", "bytes=100-", "bytes=100-100",
         "bytes=65535-65536", "bytes=65536-", "bytes=65535-", "bytes=300000-", "bytes=300001-", "bytes=300000-999999999",
         "bytes=5-2", "bytes=1-1000000000000", "bytes=18446744073709551615-", "bytes=abc", "bytes=-", "bytes=",
         "items=0-5", "0-5", "bytes=0-5,7-9", "bytes=1--2"]
range_bad = []
range_n = 0
for size in sizes:
    data = os.urandom(size)
    key = "r%d" % size
    put("range-bucket", key, data)
    for spec in specs:
        want = expected_range(spec, size)
        if spec.startswith("bytes=0-5,"):
            want = ("whole", 0, size - 1)          # S3 answers a multi-range whole
        st_, hd_, body_ = raw("GET", "/range-bucket/" + key, headers={"Range": spec})
        range_n += 1
        if want[0] == "whole":
            ok = st_ == 200 and body_ == data and "content-range" not in hd_
        elif want[0] == "unsat":
            ok = st_ == 416 and b"<Code>InvalidRange</Code>" in body_ and hd_.get("content-range") == "bytes */%d" % size
        else:
            f, l = want[1], want[2]
            ok = (st_ == 206 and body_ == data[f:l + 1] and hd_.get("content-range") == "bytes %d-%d/%d" % (f, l, size)
                  and hd_.get("content-length") == str(l - f + 1) and hd_.get("etag") == '"%s"' % md5hex(data)
                  and hd_.get("accept-ranges") == "bytes")
        if not ok:
            range_bad.append((size, spec, st_, len(body_), hd_.get("content-range")))
        # HEAD must agree with GET on status and length.
        hst, hhd, hbody = raw("HEAD", "/range-bucket/" + key, headers={"Range": spec})
        if hst != st_ or hbody != b"" or (st_ == 206 and hhd.get("content-length") != hd_.get("content-length")):
            range_bad.append(("HEAD", size, spec, hst))
check("%d Range shapes over %d object sizes answer as RFC 7233 and S3 do" % (len(specs), len(sizes)),
      not range_bad, range_bad[:6])

data = os.urandom(200000)
put("range-bucket", "conn", data)
r, body = get("range-bucket", "conn", Range="bytes=10-19")
check("boto3 ranged get_object gives ContentRange and the slice",
      body == data[10:20] and r["ContentRange"] == "bytes 10-19/200000" and r["ContentLength"] == 10 and
      r["ResponseMetadata"]["HTTPStatusCode"] == 206, r.get("ContentRange"))
r, body = get("range-bucket", "conn", Range="bytes=-7")
check("boto3 suffix range", body == data[-7:] and r["ContentRange"] == "bytes 199993-199999/200000")
expect_err("boto3 range beyond the end is InvalidRange 416",
           lambda: s3.get_object(Bucket="range-bucket", Key="conn", Range="bytes=200000-"), "InvalidRange", 416)

# One connection carrying a run of ranges of one object, spliced and small, in turn.
conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
seq_ok = True
for i in range(60):
    f = (i * 3331) % 190000
    l = f + (i * 977) % 9000
    st_, hd_, body_ = raw("GET", "/range-bucket/conn", headers={"Range": "bytes=%d-%d" % (f, l)}, conn=conn)
    if st_ != 206 or body_ != data[f:l + 1]:
        seq_ok = False
        break
conn.close()
check("60 ranged GETs of varied lengths on one keep-alive connection", seq_ok, (i, st_))

# ─── Keys of every spelling ─────────────────────────────────────────────────
print("=== boto3: keys ===")
s3.create_bucket(Bucket="key-bucket")
odd = [
    "plain", "with space", "  leading and trailing  ", "plus+sign", "a+b c", "percent%25", "%", "%zz", "100%",
    "uni-é", "中文/路径/文件.txt", "emoji-😀-key", "Ünïcödé/ñ", "ﬃ-ligature", "é-combining", "é-precomposed",
    "double//slash", "//leading-double", "/leading-single", "trailing/", "trailing//", "a/./b", "a/../b", "..", ".", "...",
    "q?mark", "hash#tag", "amp&ersand=eq", "semi;colon", "colon:", "at@sign", "comma,comma", "star*", "paren(s)",
    "bang!", "tilde~", "quote'single", 'quote"double', "back\\slash", "pipe|", "less<than>greater", "brace{}", "caret^",
    "tab\there", "new\nline", "cr\rreturn", "nul-free\x01ctl", "x" * 1024, "é" * 512, "a/" * 500 + "z",
    "UPPER", "upper", "Mixed", "a", "a/", "a/b", "a-b", "a.b", "a b",
]
made = {}
for k in odd:
    body = ("value of %r" % k).encode()
    try:
        r = put("key-bucket", k, body)
        made[k] = body
        if r["ETag"] != '"%s"' % md5hex(body):
            check("put of key %r returns the MD5" % k[:40], False, r["ETag"])
    except Exception as e:
        check("put of key %r" % k[:40], False, repr(e))
bad_get = []
for k, body in made.items():
    try:
        r, got = get("key-bucket", k)
        if got != body:
            bad_get.append(k)
    except Exception as e:
        bad_get.append((k, repr(e)[:80]))
check("%d oddly spelled keys each put and read back their own bytes" % len(odd),
      len(made) == len(odd) and not bad_get, bad_get[:4])
bad_head = [k for k in made if s3.head_object(Bucket="key-bucket", Key=k)["ContentLength"] != len(made[k])]
check("and each answers HEAD with its own length", not bad_head, bad_head[:4])
listed = []
for page in s3.get_paginator("list_objects_v2").paginate(Bucket="key-bucket"):
    listed += [o["Key"] for o in page.get("Contents", [])]
check("a listing (boto3 asks for encoding-type=url) returns every key exactly as put",
      sorted(listed) == sorted(made) and listed == sorted(listed, key=lambda s: s.encode()),
      (set(made) ^ set(listed), len(listed)))
listed = []
for page in s3.get_paginator("list_objects_v2").paginate(Bucket="key-bucket", PaginationConfig={"PageSize": 7}):
    listed += [o["Key"] for o in page.get("Contents", [])]
check("and pages of seven return each of them once, in UTF-8 byte order",
      listed == sorted(made, key=lambda s: s.encode()), (len(listed), len(made)))
# Without encoding-type=url the XML has to carry the awkward ones escaped or refuse them, never garble them.
st_, hd_, body_ = raw("GET", "/key-bucket?list-type=2&prefix=" + q("less<"))
check("a listing without encoding-type escapes < and > and parses as XML",
      st_ == 200 and b"less&lt;than&gt;greater" in body_ and ET.fromstring(body_) is not None, body_[:300])
st_, hd_, body_ = raw("GET", "/key-bucket?list-type=2&prefix=" + q("amp&") + "&encoding-type=url")
check("a prefix with an ampersand, percent-encoded in the query, finds its key",
      st_ == 200 and b"amp%26ersand%3Deq" in body_, body_[:300])
st_, hd_, body_ = raw("GET", "/key-bucket?list-type=2&prefix=" + urllib.parse.quote("é", safe="") + "&delimiter=/")
check("a UTF-8 prefix in the query matches", st_ == 200 and "é-precomposed".encode() in body_ or
      b"%C3%A9-precomposed" in body_, body_[:300])
check("NFC and NFD spellings are different keys, as S3 has them",
      get("key-bucket", "é-precomposed")[1] != get("key-bucket", "é-combining")[1])
check("a key with a trailing slash is an object with its own bytes",
      get("key-bucket", "trailing/")[1] == made["trailing/"] and get("key-bucket", "a")[1] == made["a"] and
      get("key-bucket", "a/")[1] == made["a/"] and get("key-bucket", "a/b")[1] == made["a/b"])
r = s3.list_objects_v2(Bucket="key-bucket", Prefix="double/", Delimiter="/")
check("keys with // roll up at the first delimiter after the prefix",
      [c["Prefix"] for c in r.get("CommonPrefixes", [])] == ["double//"], r.get("CommonPrefixes"))
# Deleting them all leaves the bucket removable.
# A control character other than tab and newline cannot be written into an XML 1.0 answer (S3 has the
# same limit, which is why listings offer encoding-type=url), so those two go one at a time.
ctl = [k for k in made if any(ord(ch) < 0x20 and ch not in "\t\n" for ch in k)]
for k in ctl:
    s3.delete_object(Bucket="key-bucket", Key=k)
batch = [k for k in made if k not in ctl]
d = s3.delete_objects(Bucket="key-bucket", Delete={"Objects": [{"Key": k} for k in batch][:1000]})
check("DeleteObjects removes every other oddly spelled key by name",
      sorted(x["Key"] for x in d.get("Deleted", [])) == sorted(batch) and not d.get("Errors"),
      (len(d.get("Deleted", [])), len(batch), d.get("Errors")))
check("and the bucket is then empty", s3.list_objects_v2(Bucket="key-bucket")["KeyCount"] == 0)
# Raw path spellings the client libraries normalise away.
st_, _, _ = raw("PUT", "/key-bucket//two-slashes", body=b"s")
check("a raw path /bucket//key stores the key '/key'", st_ == 200 and get("key-bucket", "/two-slashes")[1] == b"s")
st_, _, _ = raw("PUT", "/key-bucket/a%2Fb", body=b"encoded slash")
check("a %2F in the path is the same key as a /", st_ == 200 and get("key-bucket", "a/b")[1] == b"encoded slash")
st_, _, _ = raw("PUT", "/key-bucket/plus+literal", body=b"plus")
check("a literal + in a path stays a plus, not a space",
      st_ == 200 and get("key-bucket", "plus+literal")[1] == b"plus")
st_, _, body_ = raw("PUT", "/key-bucket/bad%zzescape", body=b"x")
check("a malformed percent escape in a path is refused with a 4xx", 400 <= st_ < 500, (st_, body_[:200]))
st_, _, body_ = raw("GET", "/key-bucket/", )
check("a GET of /bucket/ is a listing", st_ == 200 and b"ListBucketResult" in body_, (st_, body_[:200]))

# ─── Empty objects ──────────────────────────────────────────────────────────
print("=== boto3: empty objects ===")
s3.create_bucket(Bucket="empty-bucket")
r = put("empty-bucket", "e", b"")
check("an empty put returns the MD5 of nothing", r["ETag"] == '"d41d8cd98f00b204e9800998ecf8427e"', r["ETag"])
r, body = get("empty-bucket", "e")
check("an empty object reads back empty with Content-Length 0", body == b"" and r["ContentLength"] == 0)
check("HeadObject of it says 0", s3.head_object(Bucket="empty-bucket", Key="e")["ContentLength"] == 0)
expect_err("any Range on an empty object is InvalidRange 416",
           lambda: s3.get_object(Bucket="empty-bucket", Key="e", Range="bytes=0-0"), "InvalidRange", 416)
c = s3.copy_object(Bucket="empty-bucket", Key="e2", CopySource={"Bucket": "empty-bucket", "Key": "e"})
check("an empty object copies", c["CopyObjectResult"]["ETag"] == '"d41d8cd98f00b204e9800998ecf8427e"' and
      get("empty-bucket", "e2")[1] == b"")
put("empty-bucket", "e", b"now not empty")
check("an empty object is overwritten by a full one", get("empty-bucket", "e")[1] == b"now not empty")
put("empty-bucket", "e", b"")
check("and a full object by an empty one", get("empty-bucket", "e")[1] == b"")
put("empty-bucket", "folder/", b"")
r = s3.list_objects_v2(Bucket="empty-bucket", Delimiter="/")
check("an empty 'folder/' object is listed as a prefix and not as a key",
      [c["Prefix"] for c in r.get("CommonPrefixes", [])] == ["folder/"] and
      [o["Key"] for o in r.get("Contents", [])] == ["e", "e2"], (r.get("CommonPrefixes"), r.get("Contents")))
r = s3.list_objects_v2(Bucket="empty-bucket", Prefix="folder/")
check("and listed under its own prefix with Size 0",
      [(o["Key"], o["Size"]) for o in r.get("Contents", [])] == [("folder/", 0)], r.get("Contents"))
s3.delete_objects(Bucket="empty-bucket", Delete={"Objects": [{"Key": "e"}, {"Key": "e2"}, {"Key": "folder/"}]})
s3.delete_bucket(Bucket="empty-bucket")

# ─── Metadata round trip ────────────────────────────────────────────────────
print("=== boto3: headers that come back ===")
s3.create_bucket(Bucket="meta-bucket")
put("meta-bucket", "m", b"meta body", ContentType="text/x-special; charset=iso-8859-1", CacheControl="no-cache, private",
    ContentDisposition='attachment; filename="na me.txt"', ContentEncoding="gzip", ContentLanguage="de, en-GB",
    Expires=datetime.datetime(2030, 1, 1, 12, 0, 0),
    Metadata={"a": "1", "b-c": "two words", "UPPER": "Value", "empty": "", "spaced": "  inner  spaces  ", "long": "L" * 1500})
for label, fn in (("GetObject", lambda: s3.get_object(Bucket="meta-bucket", Key="m")),
                  ("HeadObject", lambda: s3.head_object(Bucket="meta-bucket", Key="m"))):
    r = fn()
    check("%s returns ContentType with its parameters" % label, r["ContentType"] == "text/x-special; charset=iso-8859-1",
          r["ContentType"])
    check("%s returns CacheControl, ContentDisposition, ContentEncoding, ContentLanguage" % label,
          r["CacheControl"] == "no-cache, private" and r["ContentDisposition"] == 'attachment; filename="na me.txt"'
          and r["ContentEncoding"] == "gzip" and r["ContentLanguage"] == "de, en-GB",
          {k: r.get(k) for k in ("CacheControl", "ContentDisposition", "ContentEncoding", "ContentLanguage")})
    check("%s returns Expires" % label, "Expires" in r or "ExpiresString" in r, list(r))
    check("%s returns user metadata with names lowercased and values intact" % label,
          r["Metadata"] == {"a": "1", "b-c": "two words", "upper": "Value", "empty": "", "spaced": "inner  spaces",
                            "long": "L" * 1500}, r["Metadata"])
    check("%s returns Content-Length, ETag and Last-Modified" % label,
          r["ContentLength"] == 9 and r["ETag"] == '"%s"' % md5hex(b"meta body") and r["LastModified"].year >= 2026)
lm1 = s3.head_object(Bucket="meta-bucket", Key="m")["LastModified"]
time.sleep(1.1)
put("meta-bucket", "m", b"meta body")
r = s3.head_object(Bucket="meta-bucket", Key="m")
check("a second put with no headers replaces every one of them, not merges",
      r["Metadata"] == {} and "CacheControl" not in r and "ContentEncoding" not in r and
      r["ContentType"] in ("binary/octet-stream", "application/octet-stream"), r)
check("and moves Last-Modified forward", r["LastModified"] > lm1, (lm1, r["LastModified"]))
r = s3.list_objects_v2(Bucket="meta-bucket")["Contents"][0]
check("a listing's LastModified (to the millisecond) and ETag are the object's, HEAD's to the second",
      r["LastModified"].replace(microsecond=0) == s3.head_object(Bucket="meta-bucket", Key="m")["LastModified"]
      and r["ETag"] == '"%s"' % md5hex(b"meta body"), r)
# A metadata name that is not lowercase on the wire, and duplicates.
st_, hd_, _ = raw("PUT", "/meta-bucket/raw-meta", body=b"x",
                  headers={"X-Amz-Meta-Mixed-CASE": "v", "Content-Type": "application/json"})
st_, hd_, _ = raw("HEAD", "/meta-bucket/raw-meta")
check("raw metadata names come back lowercase", hd_.get("x-amz-meta-mixed-case") == "v", hd_)
check("a response header override on GET reads back", s3.get_object(
    Bucket="meta-bucket", Key="m", ResponseContentType="text/plain", ResponseCacheControl="max-age=1",
    ResponseContentDisposition="inline", ResponseContentLanguage="fr", ResponseContentEncoding="br")["ContentType"]
      == "text/plain")

# ─── CopyObject and its directives ──────────────────────────────────────────
print("=== boto3: CopyObject ===")
put("meta-bucket", "src", b"source bytes " * 1000, ContentType="text/src", CacheControl="max-age=9",
    Metadata={"origin": "source", "keep": "yes"})
src_etag = s3.head_object(Bucket="meta-bucket", Key="src")["ETag"]
s3.copy_object(Bucket="meta-bucket", Key="cp-default", CopySource={"Bucket": "meta-bucket", "Key": "src"})
r = s3.head_object(Bucket="meta-bucket", Key="cp-default")
check("the default directive is COPY: type, cache-control and metadata follow the source",
      r["ContentType"] == "text/src" and r["CacheControl"] == "max-age=9" and r["Metadata"] == {"origin": "source", "keep": "yes"}
      and r["ETag"] == src_etag, r)
s3.copy_object(Bucket="meta-bucket", Key="cp-copy", CopySource={"Bucket": "meta-bucket", "Key": "src"},
               MetadataDirective="COPY", ContentType="text/ignored", Metadata={"ignored": "yes"})
r = s3.head_object(Bucket="meta-bucket", Key="cp-copy")
check("directive COPY ignores the metadata and type sent with the request",
      r["ContentType"] == "text/src" and r["Metadata"] == {"origin": "source", "keep": "yes"}, r)
s3.copy_object(Bucket="meta-bucket", Key="cp-replace", CopySource={"Bucket": "meta-bucket", "Key": "src"},
               MetadataDirective="REPLACE", ContentType="text/replaced", Metadata={"fresh": "new"})
r = s3.head_object(Bucket="meta-bucket", Key="cp-replace")
check("directive REPLACE takes the request's type and metadata and none of the source's",
      r["ContentType"] == "text/replaced" and r["Metadata"] == {"fresh": "new"} and "CacheControl" not in r, r)
s3.copy_object(Bucket="meta-bucket", Key="cp-bare", CopySource={"Bucket": "meta-bucket", "Key": "src"},
               MetadataDirective="REPLACE")
r = s3.head_object(Bucket="meta-bucket", Key="cp-bare")
check("directive REPLACE with nothing sent leaves a default type and no metadata",
      r["ContentType"] in ("binary/octet-stream", "application/octet-stream") and r["Metadata"] == {} and
      "CacheControl" not in r, r)
check("every copy has the source's bytes",
      all(get("meta-bucket", k)[1] == b"source bytes " * 1000 for k in ("cp-default", "cp-copy", "cp-replace", "cp-bare")))
s3.copy_object(Bucket="meta-bucket", Key="src", CopySource={"Bucket": "meta-bucket", "Key": "src"},
               MetadataDirective="REPLACE", Metadata={"origin": "rewritten"}, ContentType="text/src")
r = s3.head_object(Bucket="meta-bucket", Key="src")
check("a REPLACE copy onto itself rewrites the metadata and keeps the bytes",
      r["Metadata"] == {"origin": "rewritten"} and r["ETag"] == src_etag and r["ContentLength"] == 13000, r)
s3.create_bucket(Bucket="meta-other")
s3.copy_object(Bucket="meta-other", Key="dir/x y+z", CopySource={"Bucket": "meta-bucket", "Key": "cp-default"})
check("a copy across buckets, to a key that needs escaping",
      get("meta-other", "dir/x y+z")[1] == b"source bytes " * 1000)
put("meta-bucket", "src sp+ace/é", b"odd source", Metadata={"m": "v"})
s3.copy_object(Bucket="meta-bucket", Key="cp-odd", CopySource={"Bucket": "meta-bucket", "Key": "src sp+ace/é"})
check("a copy from a key that needs escaping (boto3 percent-encodes the source)",
      get("meta-bucket", "cp-odd")[1] == b"odd source" and
      s3.head_object(Bucket="meta-bucket", Key="cp-odd")["Metadata"] == {"m": "v"})
c = s3.copy_object(Bucket="meta-bucket", Key="cp-if", CopySource={"Bucket": "meta-bucket", "Key": "cp-odd"},
                   CopySourceIfNoneMatch='"deadbeef"')
check("a copy with a CopySourceIfNoneMatch that does not match goes through",
      c["ResponseMetadata"]["HTTPStatusCode"] == 200)
expect_err("a copy with CopySourceIfNoneMatch that matches is PreconditionFailed 412",
           lambda: s3.copy_object(Bucket="meta-bucket", Key="cp-if2", CopySource={"Bucket": "meta-bucket", "Key": "cp-odd"},
                                  CopySourceIfNoneMatch=s3.head_object(Bucket="meta-bucket", Key="cp-odd")["ETag"]),
           "PreconditionFailed", 412)
expect_err("and left no object", lambda: s3.head_object(Bucket="meta-bucket", Key="cp-if2"), "404", 404)
expect_err("a copy with CopySourceIfUnmodifiedSince before the source is PreconditionFailed 412",
           lambda: s3.copy_object(Bucket="meta-bucket", Key="cp-if3", CopySource={"Bucket": "meta-bucket", "Key": "cp-odd"},
                                  CopySourceIfUnmodifiedSince=datetime.datetime(2015, 1, 1)),
           "PreconditionFailed", 412)
c = s3.copy_object(Bucket="meta-bucket", Key="cp-if4", CopySource={"Bucket": "meta-bucket", "Key": "cp-odd"},
                   CopySourceIfModifiedSince=datetime.datetime(2015, 1, 1))
check("a copy with CopySourceIfModifiedSince long ago goes through", c["ResponseMetadata"]["HTTPStatusCode"] == 200)
big = os.urandom(5 << 20)
put("meta-bucket", "big-src", big)
s3.copy_object(Bucket="meta-bucket", Key="big-dst", CopySource={"Bucket": "meta-bucket", "Key": "big-src"})
check("a 5 MiB copy has the bytes", get("meta-bucket", "big-dst")[1] == big)
put("meta-bucket", "over-src", b"before")
s3.copy_object(Bucket="meta-bucket", Key="over-dst", CopySource={"Bucket": "meta-bucket", "Key": "over-src"})
put("meta-bucket", "over-src", b"after")
check("a copy is a copy: overwriting the source afterwards leaves it alone", get("meta-bucket", "over-dst")[1] == b"before")
s3.delete_object(Bucket="meta-bucket", Key="over-src")
check("and so is deleting it", get("meta-bucket", "over-dst")[1] == b"before")
expect_err("a copy to a key of 1025 bytes is KeyTooLongError 400",
           lambda: s3.copy_object(Bucket="meta-bucket", Key="k" * 1025, CopySource={"Bucket": "meta-bucket", "Key": "big-src"}),
           "KeyTooLongError", 400)

# ─── DeleteObjects that partly fails ────────────────────────────────────────
print("=== boto3: DeleteObjects ===")
s3.create_bucket(Bucket="del-bucket")
for k in ("d1", "d2", "d3"):
    put("del-bucket", k, k.encode())
d = s3.delete_objects(Bucket="del-bucket", Delete={"Objects": [
    {"Key": "d1"}, {"Key": "never-existed"}, {"Key": "k" * 1025}, {"Key": "d2"}, {"Key": "d1"}]})
deleted = sorted(x["Key"] for x in d.get("Deleted", []))
errors = d.get("Errors", [])
check("a batch with a missing key, a duplicate and a key too long: the good ones and the missing one are Deleted",
      "d1" in deleted and "d2" in deleted and "never-existed" in deleted, d)
check("and the too-long key is an Error entry with a Code and a Message, not a failed call",
      len(errors) == 1 and errors[0]["Key"] == "k" * 1025 and errors[0]["Code"] == "KeyTooLongError" and
      errors[0].get("Message"), errors)
check("the objects named by the batch are gone and the others are not",
      err_of(lambda: s3.head_object(Bucket="del-bucket", Key="d1"))[1] == 404 and
      err_of(lambda: s3.head_object(Bucket="del-bucket", Key="d2"))[1] == 404 and
      s3.head_object(Bucket="del-bucket", Key="d3")["ContentLength"] == 2)
d = s3.delete_objects(Bucket="del-bucket", Delete={"Objects": [{"Key": "d3"}, {"Key": "k" * 1025}], "Quiet": True})
check("a Quiet batch reports only its errors", not d.get("Deleted") and len(d.get("Errors", [])) == 1, d)
check("and still deleted the good key", err_of(lambda: s3.head_object(Bucket="del-bucket", Key="d3"))[1] == 404)
for label, body in (("an empty Delete", b"<Delete></Delete>"),
                    ("a Delete with only Quiet", b"<Delete><Quiet>true</Quiet></Delete>"),
                    ("garbage", b"not xml at all"), ("an empty body", b""),
                    ("an unclosed Delete", b"<Delete><Object><Key>x</Key></Object>")):
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    try:
        conn.request("POST", "/del-bucket?delete", body=body,
                     headers={"Content-MD5": base64.b64encode(hashlib.md5(body).digest()).decode()})
        r = conn.getresponse()
        rb = r.read()
        check("DeleteObjects with %s is answered (200 empty result or 400 MalformedXML), not left hanging" % label,
              r.status == 400 and b"MalformedXML" in rb or r.status == 200 and b"DeleteResult" in rb, (r.status, rb[:200]))
    except Exception as e:
        check("DeleteObjects with %s is answered, not left hanging" % label, False, repr(e))
    finally:
        conn.close()
check("the runtime serves after those", s3.list_buckets()["ResponseMetadata"]["HTTPStatusCode"] == 200)

# ─── A listing of ten thousand keys ─────────────────────────────────────────
print("=== boto3: listing pagination over 10000 keys ===")
s3.create_bucket(Bucket="big-list")
keys = []
for month in range(1, 13):
    for day in range(1, 26):
        for n in range(33):
            keys.append("logs/2024/%02d/%02d/f%02d.log" % (month, day, n))
keys += ["logs/2024/01", "logs/2024/010", "logs/2024/01-x", "logs/2024/01.y", "logs/2024/%02d/" % 1, "logs/", "logs",
         "logs-old/a", "logs.txt", "a", "a-b", "a.b", "a/b", "a/b/c", "a/b-c", "a b", "b//c", "b/c", "é/1", "é/2", "中/x",
         "z"]
keys += ["root%03d" % i for i in range(100)]
keys += ["idx/%05d" % i for i in range(10000 - len(keys) + 0)] if len(keys) < 10000 else []
keys = sorted(set(keys), key=lambda s: s.encode())
print("  %d keys" % len(keys))
todo = list(keys)
todo_lock = threading.Lock()
put_errors = []


def populator():
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
    while True:
        with todo_lock:
            if not todo:
                break
            k = todo.pop()
        try:
            st, hd, body = raw("PUT", "/big-list/" + q(k), body=k.encode(), conn=conn)
            if st != 200:
                put_errors.append((k, st))
        except Exception as e:
            put_errors.append((k, repr(e)))
            conn.close()
            conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
    conn.close()


t0 = time.time()
threads = [threading.Thread(target=populator) for _ in range(16)]
for t in threads:
    t.start()
for t in threads:
    t.join()
print("  %d puts in %.1f s" % (len(keys), time.time() - t0))
check("10000 keys put by 16 clients", not put_errors, put_errors[:3])


def model_items(prefix="", delimiter="", start_after=""):
    items = []
    last = None
    for k in keys:
        if k <= start_after or not k.startswith(prefix):
            continue
        if delimiter:
            i = k.find(delimiter, len(prefix))
            if i >= 0:
                cp = k[:i + len(delimiter)]
                if cp != last:
                    items.append(("P", cp))
                    last = cp
                continue
        items.append(("K", k))
    return items


def list_all(page, **kw):
    """Every page of a listing as [(kind, name)] per page, following the continuation token."""
    pages = []
    token = None
    while True:
        args = dict(Bucket="big-list", MaxKeys=page, **kw)
        if token:
            args["ContinuationToken"] = token
        r = s3.list_objects_v2(**args)
        items = [("K", o["Key"]) for o in r.get("Contents", [])] + [("P", c["Prefix"]) for c in r.get("CommonPrefixes", [])]
        pages.append((items, r["IsTruncated"], r["KeyCount"], r.get("NextContinuationToken")))
        if not r["IsTruncated"]:
            return pages
        token = r["NextContinuationToken"]
        if len(pages) > 20000:
            return pages


def merge_page(items):
    return sorted(items, key=lambda it: it[1].encode())


for label, kw in (("no prefix, no delimiter", {}),
                  ("delimiter /", {"Delimiter": "/"}),
                  ("prefix logs/2024/ and delimiter /", {"Prefix": "logs/2024/", "Delimiter": "/"}),
                  ("prefix logs/2024/03/ and delimiter /", {"Prefix": "logs/2024/03/", "Delimiter": "/"}),
                  ("prefix logs/2024/03/07/f1 without a delimiter", {"Prefix": "logs/2024/03/07/f1"}),
                  ("delimiter 2 (a character inside names)", {"Delimiter": "2"}),
                  ("a two-character delimiter //", {"Delimiter": "//"}),
                  ("prefix a and delimiter /", {"Prefix": "a", "Delimiter": "/"}),
                  ("StartAfter at a key with no delimiter", {"StartAfter": "logs/2024/05/10/f10.log"}),
                  ("StartAfter at a key inside a prefix, a prefix that has nothing after it",
                   {"Prefix": "logs/2024/05/", "Delimiter": "/", "StartAfter": "logs/2024/05/25/f32.log"}),
                  ("a prefix that matches nothing", {"Prefix": "zzz"}),
                  ("prefix é and delimiter /", {"Prefix": "é", "Delimiter": "/"})):
    for page in (1000, 999, 137, 7, 1):
        if page == 1 and len(model_items(kw.get("Prefix", ""), kw.get("Delimiter", ""), kw.get("StartAfter", ""))) > 400:
            continue
        want = model_items(kw.get("Prefix", ""), kw.get("Delimiter", ""), kw.get("StartAfter", ""))
        pages = list_all(page, **kw)
        got = [it for p in pages for it in merge_page(p[0])]
        sizes_ok = all(p[2] == len(p[0]) and len(p[0]) <= page for p in pages)
        trunc_ok = all(p[1] == (i < len(pages) - 1) for i, p in enumerate(pages))
        exact = (len(pages) == max(1, -(-len(want) // page))) or not want
        check("%s, %d per page: %d entries once each in order over %d pages" % (label, page, len(want), len(pages)),
              got == want and sizes_ok and trunc_ok and exact,
              (len(got), len(want), sizes_ok, trunc_ok, len(pages), [x for x in got if x not in want][:2]))

# The whole set through the paginator, and V1 with marker.
seen = []
for page in s3.get_paginator("list_objects_v2").paginate(Bucket="big-list"):
    seen += [o["Key"] for o in page.get("Contents", [])]
check("boto3's paginator sees all %d keys once, sorted" % len(keys), seen == keys, (len(seen), len(keys)))
seen = []
for page in s3.get_paginator("list_objects").paginate(Bucket="big-list", Delimiter="/", PaginationConfig={"PageSize": 3}):
    seen += [o["Key"] for o in page.get("Contents", [])] + [c["Prefix"] for c in page.get("CommonPrefixes", [])]
want = [n for _, n in model_items("", "/")]
check("a V1 listing with a delimiter, 3 per page, sees every entry once", sorted(seen) == sorted(want), (len(seen), len(want)))
r = s3.list_objects_v2(Bucket="big-list", MaxKeys=1000)
check("the first page of 1000 says Size, ETag, LastModified, StorageClass on every key",
      all(o["Size"] == len(o["Key"].encode()) and o["ETag"] == '"%s"' % md5hex(o["Key"].encode()) and o["StorageClass"] == "STANDARD"
          for o in r["Contents"]), r["Contents"][:1])
# A listing while keys are being put and deleted: nothing torn, nothing twice.
churn_stop = threading.Event()


def churn():
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
    i = 0
    while not churn_stop.is_set():
        k = "churn/%05d" % (i % 300)
        raw("PUT", "/big-list/" + k, body=b"c", conn=conn)
        if i % 3 == 0:
            raw("DELETE", "/big-list/churn/%05d" % ((i + 100) % 300), conn=conn)
        i += 1
    conn.close()


ct = threading.Thread(target=churn)
ct.start()
dupes = 0
disorder = 0
for _ in range(6):
    prev = None
    names = []
    token = None
    while True:
        args = dict(Bucket="big-list", MaxKeys=500)
        if token:
            args["ContinuationToken"] = token
        r = s3.list_objects_v2(**args)
        names += [o["Key"] for o in r.get("Contents", [])]
        if not r["IsTruncated"]:
            break
        token = r["NextContinuationToken"]
    dupes += len(names) - len(set(names))
    disorder += sum(1 for a, b in zip(names, names[1:]) if a.encode() >= b.encode())
churn_stop.set()
ct.join()
check("six full listings taken while 300 keys are put and deleted have no duplicate and no disorder",
      dupes == 0 and disorder == 0, (dupes, disorder))
check("and the keys that were never touched were all there each time",
      set(keys) <= set(names), len(set(keys) - set(names)))

# ─── Writers racing readers on one key ──────────────────────────────────────
print("=== boto3: one key, many writers ===")
s3.create_bucket(Bucket="race-bucket")
WRITERS = 12
bodies = [bytes([65 + i]) * (150000 + i * 37003) for i in range(WRITERS)]
etags = {'"%s"' % md5hex(b): b for b in bodies}
torn = []
reader_stop = threading.Event()
reads = [0]
misses = [0]


def reader():
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
    while not reader_stop.is_set():
        try:
            st, hd, body = raw("GET", "/race-bucket/k", conn=conn)
        except Exception as e:
            torn.append(repr(e))
            conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
            continue
        if st == 404:
            misses[0] += 1
            continue
        reads[0] += 1
        if st != 200 or body not in etags.values() or hd.get("etag") not in etags or etags[hd["etag"]] != body:
            torn.append((st, len(body), hd.get("etag")))
    conn.close()


put_status = []


def writer(i):
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
    for _ in range(6):
        st, hd, body = raw("PUT", "/race-bucket/k", body=bodies[i], conn=conn)
        put_status.append(st)
    conn.close()


readers = [threading.Thread(target=reader) for _ in range(4)]
writers = [threading.Thread(target=writer, args=(i,)) for i in range(WRITERS)]
for t in readers + writers:
    t.start()
for t in writers:
    t.join()
reader_stop.set()
for t in readers:
    t.join()
check("%d writers put one key 6 times each, every put is 200" % WRITERS, put_status.count(200) == WRITERS * 6, set(put_status))
check("%d concurrent reads each saw exactly one writer's whole body with its ETag, never a torn one" % reads[0],
      not torn and reads[0] > 20, (torn[:3], reads[0]))
final = get("race-bucket", "k")[1]
check("the survivor is one writer's body", final in bodies)
check("HEAD, GET and the listing agree on it", s3.head_object(Bucket="race-bucket", Key="k")["ETag"] == '"%s"' % md5hex(final)
      and s3.list_objects_v2(Bucket="race-bucket")["Contents"][0]["ETag"] == '"%s"' % md5hex(final) and
      s3.list_objects_v2(Bucket="race-bucket")["Contents"][0]["Size"] == len(final))
check("one object file and no stray temporary file remain",
      len(os.listdir(os.path.join(DATA, "race-bucket", "tmp"))) == 0, os.listdir(os.path.join(DATA, "race-bucket", "tmp")))

# Acknowledged order is commit order: a put acknowledged before the next begins is what the next replaces.
order_ok = True
seq = []
conns = [http.client.HTTPConnection("127.0.0.1", PORT, timeout=60) for _ in range(4)]
for i in range(80):
    body = ("version %03d " % i).encode() * (1 + (i * 7919) % 30000)
    st, hd, _ = raw("PUT", "/race-bucket/seq", body=body, conn=conns[i % 4])
    st2, hd2, got = raw("GET", "/race-bucket/seq", conn=conns[(i + 1) % 4])
    if st != 200 or got != body:
        order_ok = False
        seq.append((i, st, len(got), len(body)))
        break
for c in conns:
    c.close()
check("80 puts, each acknowledged before the next starts on another connection, are each what a GET then reads",
      order_ok, seq)
# A put racing a delete and a get of the same key ends in one of the two states.
mix_stop = threading.Event()
mix_bad = []


def deleter():
    while not mix_stop.is_set():
        raw("DELETE", "/race-bucket/mix")


def putter():
    while not mix_stop.is_set():
        raw("PUT", "/race-bucket/mix", body=b"M" * 300000)


def getter():
    while not mix_stop.is_set():
        st, hd, body = raw("GET", "/race-bucket/mix")
        if st == 200 and body != b"M" * 300000:
            mix_bad.append(len(body))
        elif st not in (200, 404):
            mix_bad.append(st)


mt = [threading.Thread(target=f) for f in (deleter, putter, putter, getter, getter)]
for t in mt:
    t.start()
time.sleep(3)
mix_stop.set()
for t in mt:
    t.join()
st, hd, body = raw("GET", "/race-bucket/mix")
check("a put racing a delete and two readers: every read is 404 or the whole body", not mix_bad, mix_bad[:4])
check("and the last state is consistent between GET and listing",
      (st == 200) == (s3.list_objects_v2(Bucket="race-bucket", Prefix="mix")["KeyCount"] == 1), st)

# ─── The bucket lifecycle ───────────────────────────────────────────────────
print("=== boto3: buckets ===")
names = [b["Name"] for b in s3.list_buckets()["Buckets"]]
check("ListBuckets names every bucket made here, sorted", names == sorted(names) and {"err-bucket", "range-bucket",
      "key-bucket", "meta-bucket", "meta-other", "del-bucket", "big-list", "race-bucket"} <= set(names), names)
s3.create_bucket(Bucket="tmp-bucket")
put("tmp-bucket", "k", b"1")
s3.delete_object(Bucket="tmp-bucket", Key="k")
s3.delete_bucket(Bucket="tmp-bucket")
expect_err("a deleted bucket is NoSuchBucket", lambda: s3.list_objects_v2(Bucket="tmp-bucket"), "NoSuchBucket", 404)
s3.create_bucket(Bucket="tmp-bucket")
check("and can be made again, empty and without the old object", s3.list_objects_v2(Bucket="tmp-bucket")["KeyCount"] == 0
      and err_of(lambda: s3.head_object(Bucket="tmp-bucket", Key="k"))[1] == 404)
s3.delete_bucket(Bucket="tmp-bucket")
check("no bucket directory of a deleted bucket is left behind", not os.path.exists(os.path.join(DATA, "tmp-bucket")),
      os.listdir(DATA))

print("  Results: %d/%d passed (%d failed)" % (passed, passed + failed, failed))
sys.exit(min(failed, 100))
