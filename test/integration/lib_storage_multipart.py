#!/usr/bin/env python3
"""Multipart uploads against the storage runtime, through boto3 with credentials.

usage: lib_storage_multipart.py PORT DATA_DIR MODE

MODE is one of
  main      every operation and every refusal, on a fresh runtime; leaves two
            open uploads described in $MPU_STATE for the restart modes
  resume    after a stop and a start: the two uploads are where they were
  killed    after the worker was killed while a part was arriving
  expire    a runtime with --mpu-expire: an open upload is aborted by itself
  reaped    after a stop, a wait and a start: what expired meanwhile is gone
  quota     a runtime with --max-bytes: parts count against it and give it back
  large     a big object assembled from big parts, with the worker's memory read

Prints one PASS or FAIL line per assertion and a final "Results:" line, and
exits with the number of failures.
"""
import base64
import hashlib
import http.client
import json
import os
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

import boto3
import botocore.exceptions
from boto3.s3.transfer import TransferConfig
from botocore.config import Config

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib_s3_signing as sig  # noqa: E402

PORT = int(sys.argv[1])
DATA = sys.argv[2]
MODE = sys.argv[3]
AK = os.environ.get("AK", "AKIATESTACCESSKEY01")
SK = os.environ.get("SK", "test/secret+key/for.storage.sigv4")
STATE = os.environ.get("MPU_STATE", "")
HOST = "127.0.0.1:%d" % PORT
MiB = 1 << 20
B = "mpb"
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


def client():
    return boto3.client("s3", endpoint_url="http://" + HOST, aws_access_key_id=AK, aws_secret_access_key=SK,
                        region_name="us-east-1",
                        config=Config(signature_version="s3v4", s3={"addressing_style": "path"},
                                      retries={"max_attempts": 1}))


def code_of(fn):
    try:
        fn()
    except botocore.exceptions.ClientError as e:
        return e.response["Error"].get("Code"), e.response["ResponseMetadata"]["HTTPStatusCode"]
    return None, 200


def md5(b):
    return hashlib.md5(b).hexdigest()


def multipart_etag(parts):
    return "%s-%d" % (hashlib.md5(b"".join(hashlib.md5(p).digest() for p in parts)).hexdigest(), len(parts))


def raw_signed(method, path, query="", body=b"", extra=None):
    """A request boto3 would not make, signed with the runtime's key."""
    s = sig.sign(method, path, query, HOST, AK, SK, sig.sha256hex(body), extra)
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
    try:
        conn.request(method, path + ("?" + query if query else ""), body=body, headers=dict(s.headers, **(extra or {})))
        r = conn.getresponse()
        data = r.read()
        return r.status, data
    finally:
        conn.close()


def xml_code(body):
    try:
        return ET.fromstring(body).findtext("Code")
    except Exception:
        return None


def mpu_dir(bucket=B):
    return os.path.join(DATA, bucket, "mpu")


def upload_dirs(bucket=B):
    try:
        return sorted(os.listdir(mpu_dir(bucket)))
    except FileNotFoundError:
        return []


def wait_for(fn, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        if fn():
            return True
        time.sleep(0.1)
    return fn()


def open_uploads(c, **kw):
    return [(u["Key"], u["UploadId"]) for u in c.list_multipart_uploads(Bucket=B, **kw).get("Uploads", [])]


def stats():
    import subprocess
    out = subprocess.run([os.environ["BIN"], "stats", os.environ.get("RUNTIME", "mp")], capture_output=True, text=True).stdout
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d


def upload_all(c, key, parts, **create):
    mp = c.create_multipart_upload(Bucket=B, Key=key, **create)
    etags = []
    for i, p in enumerate(parts, 1):
        etags.append(c.upload_part(Bucket=B, Key=key, UploadId=mp["UploadId"], PartNumber=i, Body=p)["ETag"])
    return mp["UploadId"], etags


def complete(c, key, uid, etags):
    return c.complete_multipart_upload(Bucket=B, Key=key, UploadId=uid,
                                       MultipartUpload={"Parts": [{"PartNumber": i, "ETag": e} for i, e in enumerate(etags, 1)]})


# ─── the main run ────────────────────────────────────────────────────────────

def main_mode():
    c = client()
    c.create_bucket(Bucket=B)

    # boto3's own transfer manager, forced into multipart.
    blob = os.urandom(23 * MiB + 12345)
    tc = TransferConfig(multipart_threshold=5 * MiB, multipart_chunksize=5 * MiB, max_concurrency=8)
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "up.bin")
        with open(src, "wb") as f:
            f.write(blob)
        c.upload_file(src, B, "big/file.bin", Config=tc)
        chunks = [blob[i:i + 5 * MiB] for i in range(0, len(blob), 5 * MiB)]
        h = c.head_object(Bucket=B, Key="big/file.bin")
        check("boto3 upload_file over the multipart threshold: the ETag is md5 of the part md5s and the part count",
              h["ETag"].strip('"') == multipart_etag(chunks) and h["ContentLength"] == len(blob) and h["ETag"].endswith('-5"'),
              (h["ETag"], multipart_etag(chunks)))
        dst = os.path.join(td, "down.bin")
        c.download_file(B, "big/file.bin", dst, Config=tc)
        check("and the object downloaded is the file uploaded", open(dst, "rb").read() == blob)
        check("and the ranged parts of a download line up too",
              c.get_object(Bucket=B, Key="big/file.bin", Range="bytes=5242870-5242890")["Body"].read() == blob[5242870:5242891])
        check("a multipart object reports its part count", c.get_object(Bucket=B, Key="big/file.bin")["ResponseMetadata"]["HTTPHeaders"].get("x-amz-mp-parts-count") == "5")

        # The same with a checksum on every part.
        c.upload_file(src, B, "big/checked.bin", Config=tc, ExtraArgs={"ChecksumAlgorithm": "CRC32"})
        raws = b"".join(sig.zlib.crc32(p).to_bytes(4, "big") for p in chunks)
        want = base64.b64encode(sig.zlib.crc32(raws).to_bytes(4, "big")).decode() + "-%d" % len(chunks)
        h = c.head_object(Bucket=B, Key="big/checked.bin", ChecksumMode="ENABLED")
        check("upload_file with ChecksumAlgorithm=CRC32 stores the composite checksum of the parts (%s)" % want,
              h.get("ChecksumCRC32") == want, h.get("ChecksumCRC32"))
        check("and the bytes are the file's", c.get_object(Bucket=B, Key="big/checked.bin")["Body"].read() == blob)
    check("nothing is left of a completed upload on the disk", wait_for(lambda: upload_dirs() == []), upload_dirs())
    check("and no temporary file", os.listdir(os.path.join(DATA, B, "tmp")) == [], os.listdir(os.path.join(DATA, B, "tmp")))

    # By hand: out of order, a part replaced, listings, metadata.
    p1, p2, p2b, p3 = os.urandom(5 * MiB), os.urandom(5 * MiB), os.urandom(5 * MiB + 7), os.urandom(1234)
    mp = c.create_multipart_upload(Bucket=B, Key="manual/obj", ContentType="text/mp", Metadata={"m": "v"},
                                   CacheControl="max-age=9")
    uid = mp["UploadId"]
    check("create_multipart_upload answers the bucket, key and an id", mp["Bucket"] == B and mp["Key"] == "manual/obj" and len(uid) >= 16, mp)
    e3 = c.upload_part(Bucket=B, Key="manual/obj", UploadId=uid, PartNumber=3, Body=p3)["ETag"]
    e2 = c.upload_part(Bucket=B, Key="manual/obj", UploadId=uid, PartNumber=2, Body=p2)["ETag"]
    e1 = c.upload_part(Bucket=B, Key="manual/obj", UploadId=uid, PartNumber=1, Body=p1)["ETag"]
    check("upload_part answers the md5 of the part as its ETag", e1.strip('"') == md5(p1) and e3.strip('"') == md5(p3), (e1, e3))
    e2b = c.upload_part(Bucket=B, Key="manual/obj", UploadId=uid, PartNumber=2, Body=p2b)["ETag"]
    check("a part uploaded again has the new ETag", e2b != e2 and e2b.strip('"') == md5(p2b))
    lp = c.list_parts(Bucket=B, Key="manual/obj", UploadId=uid)
    check("list_parts lists the parts in order with their sizes and the replaced one's new size",
          [(p["PartNumber"], p["Size"], p["ETag"]) for p in lp["Parts"]] ==
          [(1, len(p1), e1), (2, len(p2b), e2b), (3, len(p3), e3)], lp["Parts"])
    check("list_parts names the bucket, key and upload", lp["Bucket"] == B and lp["Key"] == "manual/obj" and lp["UploadId"] == uid)
    page = c.list_parts(Bucket=B, Key="manual/obj", UploadId=uid, MaxParts=2)
    check("list_parts with MaxParts=2 is truncated and says where to go on",
          page["IsTruncated"] and [p["PartNumber"] for p in page["Parts"]] == [1, 2] and page["NextPartNumberMarker"] == 2, page)
    page2 = c.list_parts(Bucket=B, Key="manual/obj", UploadId=uid, MaxParts=2, PartNumberMarker=2)
    check("and the next page starts after the marker", not page2["IsTruncated"] and [p["PartNumber"] for p in page2["Parts"]] == [3], page2)
    check("open uploads are listed", ("manual/obj", uid) in open_uploads(c))
    check("a prefix that matches lists it and one that does not, does not",
          ("manual/obj", uid) in open_uploads(c, Prefix="manual/") and open_uploads(c, Prefix="other/") == [])
    lu = c.list_multipart_uploads(Bucket=B, Delimiter="/")
    check("a delimiter rolls it up into a common prefix", [p["Prefix"] for p in lu.get("CommonPrefixes", [])] == ["manual/"] and not lu.get("Uploads"), lu)

    done = complete(c, "manual/obj", uid, [e1, e2b, e3])
    want_etag = multipart_etag([p1, p2b, p3])
    check("complete_multipart_upload answers the multipart ETag", done["ETag"].strip('"') == want_etag, (done["ETag"], want_etag))
    got = c.get_object(Bucket=B, Key="manual/obj")
    body = got["Body"].read()
    check("the object is the parts as last uploaded, joined", body == p1 + p2b + p3, (len(body), len(p1 + p2b + p3)))
    check("with the metadata, content type and headers given at create",
          got["Metadata"] == {"m": "v"} and got["ContentType"] == "text/mp" and got["CacheControl"] == "max-age=9", got["Metadata"])
    check("and its ETag is the multipart one", got["ETag"].strip('"') == want_etag)
    check("a completed upload is no longer listed", ("manual/obj", uid) not in open_uploads(c))
    check("list_parts of a completed upload is NoSuchUpload",
          code_of(lambda: c.list_parts(Bucket=B, Key="manual/obj", UploadId=uid)) == ("NoSuchUpload", 404))
    check("and so is completing it a second time",
          code_of(lambda: complete(c, "manual/obj", uid, [e1, e2b, e3])) == ("NoSuchUpload", 404))
    check("the listing of objects shows it once with its size",
          [o["Size"] for o in c.list_objects_v2(Bucket=B, Prefix="manual/")["Contents"]] == [len(p1 + p2b + p3)])

    # A single small part is a whole upload: only the last part may be small.
    uid1, e = upload_all(c, "tiny", [b"just this"])
    complete(c, "tiny", uid1, e)
    check("an upload of one small part completes", c.get_object(Bucket=B, Key="tiny")["Body"].read() == b"just this")
    check("and its ETag is the md5 of one md5 with -1", c.head_object(Bucket=B, Key="tiny")["ETag"].strip('"') == multipart_etag([b"just this"]))

    # Refusals, each on an upload of its own.
    uid, e = upload_all(c, "err/a", [os.urandom(5 * MiB), os.urandom(100)])
    good = [{"PartNumber": 1, "ETag": e[0]}, {"PartNumber": 2, "ETag": e[1]}]
    check("completing with an ETag that is not the part's is InvalidPart",
          code_of(lambda: c.complete_multipart_upload(Bucket=B, Key="err/a", UploadId=uid, MultipartUpload={"Parts": [
              {"PartNumber": 1, "ETag": '"' + "0" * 32 + '"'}, good[1]]})) == ("InvalidPart", 400))
    check("completing with a part that was never uploaded is InvalidPart",
          code_of(lambda: c.complete_multipart_upload(Bucket=B, Key="err/a", UploadId=uid, MultipartUpload={"Parts": [
              good[0], {"PartNumber": 9, "ETag": e[1]}]})) == ("InvalidPart", 400))
    check("completing with the parts out of order is InvalidPartOrder",
          code_of(lambda: c.complete_multipart_upload(Bucket=B, Key="err/a", UploadId=uid, MultipartUpload={"Parts": [
              good[1], good[0]]})) == ("InvalidPartOrder", 400))
    check("completing with the same part twice is InvalidPartOrder",
          code_of(lambda: c.complete_multipart_upload(Bucket=B, Key="err/a", UploadId=uid, MultipartUpload={"Parts": [
              good[0], good[0]]})) == ("InvalidPartOrder", 400))
    check("after those refusals the upload is intact and completes",
          code_of(lambda: c.complete_multipart_upload(Bucket=B, Key="err/a", UploadId=uid, MultipartUpload={"Parts": good}))[0] is None)

    uid, e = upload_all(c, "err/small", [os.urandom(100 * 1024), os.urandom(5 * MiB)])
    check("a part but the last under 5 MiB is EntityTooSmall",
          code_of(lambda: complete(c, "err/small", uid, e)) == ("EntityTooSmall", 400))
    check("and the object was not made", code_of(lambda: c.head_object(Bucket=B, Key="err/small"))[1] == 404)
    check("and the upload is still there to be fixed", ("err/small", uid) in open_uploads(c))
    c.upload_part(Bucket=B, Key="err/small", UploadId=uid, PartNumber=1, Body=os.urandom(5 * MiB))
    e[0] = c.list_parts(Bucket=B, Key="err/small", UploadId=uid)["Parts"][0]["ETag"]
    check("re-uploading the small part makes it complete", code_of(lambda: complete(c, "err/small", uid, e))[0] is None)

    fake = "0" * 32
    check("completing an upload that never was is NoSuchUpload",
          code_of(lambda: complete(c, "err/none", fake, ['"' + "0" * 32 + '"'])) == ("NoSuchUpload", 404))
    check("uploading a part to one is NoSuchUpload",
          code_of(lambda: c.upload_part(Bucket=B, Key="err/none", UploadId=fake, PartNumber=1, Body=b"x")) == ("NoSuchUpload", 404))
    check("aborting one is NoSuchUpload", code_of(lambda: c.abort_multipart_upload(Bucket=B, Key="err/none", UploadId=fake)) == ("NoSuchUpload", 404))
    check("listing the parts of one is NoSuchUpload", code_of(lambda: c.list_parts(Bucket=B, Key="err/none", UploadId=fake)) == ("NoSuchUpload", 404))
    check("an id that is not even the shape of one is NoSuchUpload too",
          code_of(lambda: c.list_parts(Bucket=B, Key="err/none", UploadId="../../etc")) == ("NoSuchUpload", 404))

    uid, e = upload_all(c, "err/b", [b"x" * 10])
    status, body_ = raw_signed("PUT", "/%s/err/b" % B, "partNumber=0&uploadId=" + uid, b"x")
    check("part number 0 is InvalidArgument", status == 400 and xml_code(body_) == "InvalidArgument", (status, body_[:200]))
    status, body_ = raw_signed("PUT", "/%s/err/b" % B, "partNumber=10001&uploadId=" + uid, b"x")
    check("part number 10001 is InvalidArgument", status == 400 and xml_code(body_) == "InvalidArgument", (status, body_[:200]))
    status, body_ = raw_signed("PUT", "/%s/err/b" % B, "partNumber=one&uploadId=" + uid, b"x")
    check("a part number that is not a number is InvalidArgument", status == 400 and xml_code(body_) == "InvalidArgument", (status, body_[:200]))
    status, body_ = raw_signed("PUT", "/%s/err/other-key" % B, "partNumber=1&uploadId=" + uid, b"x")
    check("a part sent for another key than the upload's is NoSuchUpload", status == 404 and xml_code(body_) == "NoSuchUpload", (status, body_[:200]))
    status, body_ = raw_signed("PUT", "/%s/err/b" % B, "partNumber=2&uploadId=" + uid, os.urandom(300),
                               {"content-md5": base64.b64encode(hashlib.md5(b"another").digest()).decode()})
    check("a part with the wrong Content-MD5 is BadDigest", status == 400 and xml_code(body_) == "BadDigest", (status, body_[:200]))
    check("and it was not kept as a part", [p["PartNumber"] for p in c.list_parts(Bucket=B, Key="err/b", UploadId=uid)["Parts"]] == [1])
    status, body_ = raw_signed("POST", "/%s/err/b" % B, "uploadId=" + uid, b"<not xml")
    check("completing with a body that is not XML is MalformedXML", status == 400 and xml_code(body_) == "MalformedXML", (status, body_[:200]))
    status, body_ = raw_signed("POST", "/%s/err/b" % B, "uploadId=" + uid, b"<CompleteMultipartUpload></CompleteMultipartUpload>")
    check("completing with no parts is MalformedXML", status == 400 and xml_code(body_) == "MalformedXML", (status, body_[:200]))
    check("delete_bucket with an open upload is BucketNotEmpty",
          code_of(lambda: c.delete_bucket(Bucket=B)) == ("BucketNotEmpty", 409))
    # A bucket with nothing in it but an upload: only the upload stops the delete.
    c.create_bucket(Bucket="mpempty")
    eu = c.create_multipart_upload(Bucket="mpempty", Key="k")["UploadId"]
    check("an empty bucket with an open upload cannot be deleted",
          code_of(lambda: c.delete_bucket(Bucket="mpempty")) == ("BucketNotEmpty", 409))
    c.abort_multipart_upload(Bucket="mpempty", Key="k", UploadId=eu)
    check("and can once the upload is aborted", code_of(lambda: c.delete_bucket(Bucket="mpempty"))[0] is None)
    c.abort_multipart_upload(Bucket=B, Key="err/b", UploadId=uid)
    check("abort_multipart_upload answers 204 and the upload is gone",
          ("err/b", uid) not in open_uploads(c) and code_of(lambda: c.list_parts(Bucket=B, Key="err/b", UploadId=uid)) == ("NoSuchUpload", 404))
    check("and its files are gone from the disk", wait_for(lambda: uid not in upload_dirs()), upload_dirs())
    check("uploading a part to an aborted upload is NoSuchUpload",
          code_of(lambda: c.upload_part(Bucket=B, Key="err/b", UploadId=uid, PartNumber=1, Body=b"x")) == ("NoSuchUpload", 404))
    check("aborting it twice is NoSuchUpload the second time",
          code_of(lambda: c.abort_multipart_upload(Bucket=B, Key="err/b", UploadId=uid)) == ("NoSuchUpload", 404))

    # UploadPartCopy.
    src = os.urandom(12 * MiB + 99)
    c.put_object(Bucket=B, Key="copy/src", Body=src)
    mp = c.create_multipart_upload(Bucket=B, Key="copy/dst")
    ranges = [(0, 5 * MiB - 1), (5 * MiB, 10 * MiB - 1), (10 * MiB, len(src) - 1)]
    tags = []
    for i, (lo, hi) in enumerate(ranges, 1):
        r = c.upload_part_copy(Bucket=B, Key="copy/dst", UploadId=mp["UploadId"], PartNumber=i,
                               CopySource={"Bucket": B, "Key": "copy/src"}, CopySourceRange="bytes=%d-%d" % (lo, hi))
        tags.append(r["CopyPartResult"]["ETag"])
        check("upload_part_copy of bytes %d-%d has the md5 of that range as its ETag" % (lo, hi),
              r["CopyPartResult"]["ETag"].strip('"') == md5(src[lo:hi + 1]), r["CopyPartResult"])
    complete(c, "copy/dst", mp["UploadId"], tags)
    check("parts copied by range make the source's bytes", c.get_object(Bucket=B, Key="copy/dst")["Body"].read() == src)
    mp = c.create_multipart_upload(Bucket=B, Key="copy/whole")
    r = c.upload_part_copy(Bucket=B, Key="copy/whole", UploadId=mp["UploadId"], PartNumber=1, CopySource={"Bucket": B, "Key": "copy/src"})
    check("upload_part_copy with no range copies the whole source", r["CopyPartResult"]["ETag"].strip('"') == md5(src))
    check("upload_part_copy of a missing source is NoSuchKey",
          code_of(lambda: c.upload_part_copy(Bucket=B, Key="copy/whole", UploadId=mp["UploadId"], PartNumber=2,
                                             CopySource={"Bucket": B, "Key": "copy/none"})) == ("NoSuchKey", 404))
    check("upload_part_copy of a range past the end is InvalidArgument",
          code_of(lambda: c.upload_part_copy(Bucket=B, Key="copy/whole", UploadId=mp["UploadId"], PartNumber=2,
                                             CopySource={"Bucket": B, "Key": "copy/src"}, CopySourceRange="bytes=0-%d" % len(src)))[0] == "InvalidArgument")
    c.abort_multipart_upload(Bucket=B, Key="copy/whole", UploadId=mp["UploadId"])
    c.copy({"Bucket": B, "Key": "copy/src"}, B, "copy/managed", Config=tc)
    check("boto3 copy() of a big object copies it by parts", c.get_object(Bucket=B, Key="copy/managed")["Body"].read() == src)
    check("and the copy is a multipart object", "-" in c.head_object(Bucket=B, Key="copy/managed")["ETag"])

    # Checksums on the parts and on the whole.
    parts = [os.urandom(5 * MiB), os.urandom(5 * MiB), os.urandom(4000)]
    mp = c.create_multipart_upload(Bucket=B, Key="ck/obj", ChecksumAlgorithm="SHA256")
    uid = mp["UploadId"]
    tags, cks = [], []
    for i, p in enumerate(parts, 1):
        want = sig.sha256_b64(p)
        r = c.upload_part(Bucket=B, Key="ck/obj", UploadId=uid, PartNumber=i, Body=p, ChecksumSHA256=want)
        tags.append(r["ETag"])
        cks.append(want)
        check("upload_part %d answers the SHA256 it verified" % i, r.get("ChecksumSHA256") == want, r)
    check("a part with a wrong SHA256 is BadDigest and is not kept",
          code_of(lambda: c.upload_part(Bucket=B, Key="ck/obj", UploadId=uid, PartNumber=4, Body=b"abc",
                                        ChecksumSHA256=sig.sha256_b64(b"abd"))) == ("BadDigest", 400))
    lp = c.list_parts(Bucket=B, Key="ck/obj", UploadId=uid)
    check("list_parts carries each part's checksum and the upload's algorithm",
          [p.get("ChecksumSHA256") for p in lp["Parts"]] == cks and lp.get("ChecksumAlgorithm") == "SHA256", lp)
    bad_cks = [{"PartNumber": i, "ETag": t, "ChecksumSHA256": ck} for i, (t, ck) in enumerate(zip(tags, cks), 1)]
    bad_cks[1]["ChecksumSHA256"] = sig.sha256_b64(b"not part two")
    check("completing with a part checksum that is not the stored one is InvalidPart",
          code_of(lambda: c.complete_multipart_upload(Bucket=B, Key="ck/obj", UploadId=uid, MultipartUpload={"Parts": bad_cks})) == ("InvalidPart", 400))
    good_cks = [{"PartNumber": i, "ETag": t, "ChecksumSHA256": ck} for i, (t, ck) in enumerate(zip(tags, cks), 1)]
    done = c.complete_multipart_upload(Bucket=B, Key="ck/obj", UploadId=uid, MultipartUpload={"Parts": good_cks})
    raws = b"".join(hashlib.sha256(p).digest() for p in parts)
    want = base64.b64encode(hashlib.sha256(raws).digest()).decode() + "-3"
    check("the completed object's checksum is the SHA256 of the part checksums, -3", done.get("ChecksumSHA256") == want, (done.get("ChecksumSHA256"), want))
    check("and head_object returns it on request", c.head_object(Bucket=B, Key="ck/obj", ChecksumMode="ENABLED").get("ChecksumSHA256") == want)
    check("and the bytes are the parts'", c.get_object(Bucket=B, Key="ck/obj")["Body"].read() == b"".join(parts))
    mp = c.create_multipart_upload(Bucket=B, Key="ck/two", ChecksumAlgorithm="CRC32")
    status, body_ = raw_signed("PUT", "/%s/ck/two" % B, "partNumber=1&uploadId=" + mp["UploadId"], b"data",
                               {"x-amz-checksum-sha256": sig.sha256_b64(b"data")})
    check("a part with another algorithm's checksum than the upload's is InvalidRequest", status == 400 and xml_code(body_) == "InvalidRequest", (status, body_[:200]))
    status, body_ = raw_signed("PUT", "/%s/ck/two" % B, "partNumber=1&uploadId=" + mp["UploadId"], b"data")
    check("a part with no checksum still gets the upload's, taken by the runtime", status == 200, (status, body_[:200]))
    lp = c.list_parts(Bucket=B, Key="ck/two", UploadId=mp["UploadId"])
    check("and list_parts shows it", lp["Parts"][0].get("ChecksumCRC32") == sig.crc32_b64(b"data"), lp)
    c.abort_multipart_upload(Bucket=B, Key="ck/two", UploadId=mp["UploadId"])
    status, body_ = raw_signed("POST", "/%s/ck/nope" % B, "uploads", b"", {"x-amz-checksum-algorithm": "MD9"})
    check("create_multipart_upload with an algorithm that is not one is InvalidRequest", status == 400 and xml_code(body_) == "InvalidRequest", (status, body_[:200]))

    # Other things an upload id must not do.
    check("an upload id is not something get_object serves",
          code_of(lambda: c.get_object(Bucket=B, Key="manual/obj", PartNumber=1))[0] == "NotImplemented")

    # Two uploads left open for the restarts.
    u1 = c.create_multipart_upload(Bucket=B, Key="resume/one", ContentType="text/one")["UploadId"]
    a1 = os.urandom(5 * MiB)
    b1 = os.urandom(5 * MiB)
    t1 = [c.upload_part(Bucket=B, Key="resume/one", UploadId=u1, PartNumber=1, Body=a1)["ETag"],
          c.upload_part(Bucket=B, Key="resume/one", UploadId=u1, PartNumber=2, Body=b1)["ETag"]]
    u2 = c.create_multipart_upload(Bucket=B, Key="resume/two")["UploadId"]
    a2 = os.urandom(5 * MiB)
    b2 = os.urandom(5 * MiB)
    t2 = [c.upload_part(Bucket=B, Key="resume/two", UploadId=u2, PartNumber=1, Body=a2)["ETag"],
          c.upload_part(Bucket=B, Key="resume/two", UploadId=u2, PartNumber=2, Body=b2)["ETag"]]
    if STATE:
        with open(STATE, "w") as f:
            json.dump({"u1": u1, "t1": t1, "a1": md5(a1), "b1": md5(b1), "u2": u2, "t2": t2, "a2": md5(a2), "b2": md5(b2)}, f)
        with open(STATE + ".blobs", "wb") as f:
            f.write(a1 + b1 + a2 + b2)

    # The daemon's view of the counters trails the worker's by a moment.
    check("stats counts the uploads, the parts and what is held",
          wait_for(lambda: int(stats().get("multipart_uploads", "-1")) == 2 and int(stats().get("multipart_parts", "-1")) == 4 and
                   int(stats().get("multipart_bytes", "-1")) == 20 * MiB), stats())
    s = stats()
    check("stats counts what was created, completed and aborted",
          int(s.get("multipart_created", "0")) >= 10 and int(s.get("multipart_completed", "0")) >= 6 and int(s.get("multipart_aborted", "0")) >= 3, s)


def state():
    with open(STATE) as f:
        st = json.load(f)
    with open(STATE + ".blobs", "rb") as f:
        blobs = f.read()
    return st, blobs


def resume_mode():
    c = client()
    st, blobs = state()
    ups = dict((k, u) for k, u in open_uploads(c))
    check("after a stop and a start both open uploads are still listed", ups.get("resume/one") == st["u1"] and ups.get("resume/two") == st["u2"], ups)
    lp = c.list_parts(Bucket=B, Key="resume/one", UploadId=st["u1"])
    check("and their parts, with the same ETags", [p["ETag"] for p in lp["Parts"]] == st["t1"] and
          [p["Size"] for p in lp["Parts"]] == [5 * MiB, 5 * MiB], lp["Parts"])
    check("and the runtime counts what they hold again",
          wait_for(lambda: int(stats().get("multipart_uploads", "-1")) == 2 and int(stats().get("multipart_bytes", "-1")) == 20 * MiB), stats())
    last = os.urandom(777)
    t3 = c.upload_part(Bucket=B, Key="resume/one", UploadId=st["u1"], PartNumber=3, Body=last)["ETag"]
    complete(c, "resume/one", st["u1"], st["t1"] + [t3])
    body = c.get_object(Bucket=B, Key="resume/one")["Body"].read()
    check("an upload begun before the restart is completed after it",
          body == blobs[:10 * MiB] + last and c.head_object(Bucket=B, Key="resume/one")["ContentType"] == "text/one", len(body))
    check("and the other is still there", ("resume/two", st["u2"]) in open_uploads(c))


def killed_mode():
    """The worker was killed while a 6 MiB part of the second upload was arriving."""
    c = client()
    st, blobs = state()
    lp = c.list_parts(Bucket=B, Key="resume/two", UploadId=st["u2"])
    check("a part cut by a kill is not a part: only the whole ones are listed", [p["PartNumber"] for p in lp["Parts"]] == [1, 2], lp["Parts"])
    check("and no temporary file of it is left", os.listdir(os.path.join(DATA, B, "tmp")) == [], os.listdir(os.path.join(DATA, B, "tmp")))
    check("and the disk holds exactly the two parts and the meta file",
          sorted(os.listdir(os.path.join(mpu_dir(), st["u2"]))) == ["1", "2", "meta"], os.listdir(os.path.join(mpu_dir(), st["u2"])))
    last = os.urandom(4321)
    t3 = c.upload_part(Bucket=B, Key="resume/two", UploadId=st["u2"], PartNumber=3, Body=last)["ETag"]
    complete(c, "resume/two", st["u2"], st["t2"] + [t3])
    check("the upload is finished after the kill", c.get_object(Bucket=B, Key="resume/two")["Body"].read() == blobs[10 * MiB:20 * MiB] + last)
    check("and nothing is left open", open_uploads(c) == [], open_uploads(c))


def expire_mode():
    c = client()
    c.create_bucket(Bucket=B)
    uid, e = upload_all(c, "exp/a", [os.urandom(1000)])
    check("an upload is open at first", ("exp/a", uid) in open_uploads(c))
    check("and its directory is on the disk", uid in upload_dirs())
    check("an open upload is aborted once it is older than --mpu-expire",
          wait_for(lambda: ("exp/a", uid) not in open_uploads(c), 20.0), open_uploads(c))
    check("and its files are removed", wait_for(lambda: uid not in upload_dirs(), 5.0), upload_dirs())
    check("uploading a part to it is NoSuchUpload",
          code_of(lambda: c.upload_part(Bucket=B, Key="exp/a", UploadId=uid, PartNumber=2, Body=b"x")) == ("NoSuchUpload", 404))
    # One begun now is not expired yet.
    uid2 = c.create_multipart_upload(Bucket=B, Key="exp/b")["UploadId"]
    check("an upload begun a moment ago is not touched", ("exp/b", uid2) in open_uploads(c))
    if STATE:
        with open(STATE, "w") as f:
            json.dump({"u": uid2}, f)


def reaped_mode():
    c = client()
    with open(STATE) as f:
        uid = json.load(f)["u"]
    check("an upload that expired while the runtime was stopped is gone at the next start", ("exp/b", uid) not in open_uploads(c), open_uploads(c))
    check("and its directory", uid not in upload_dirs(), upload_dirs())


def quota_mode():
    c = client()
    c.create_bucket(Bucket=B)
    held = lambda: int(stats().get("multipart_bytes", "-1"))  # noqa: E731
    uid = c.create_multipart_upload(Bucket=B, Key="q/a")["UploadId"]
    c.upload_part(Bucket=B, Key="q/a", UploadId=uid, PartNumber=1, Body=os.urandom(5 * MiB))
    e2 = c.upload_part(Bucket=B, Key="q/a", UploadId=uid, PartNumber=2, Body=os.urandom(5 * MiB))["ETag"]
    check("two parts inside the quota are taken and counted", wait_for(lambda: held() == 10 * MiB), stats())
    check("a third that would pass the quota is StorageFull 507",
          code_of(lambda: c.upload_part(Bucket=B, Key="q/a", UploadId=uid, PartNumber=3, Body=os.urandom(5 * MiB))) == ("StorageFull", 507))
    check("an object that would pass it is refused too",
          code_of(lambda: c.put_object(Bucket=B, Key="q/o", Body=os.urandom(3 * MiB)))[1] == 507)
    check("a part sent again needs room for both copies until the new one lands",
          code_of(lambda: c.upload_part(Bucket=B, Key="q/a", UploadId=uid, PartNumber=2, Body=os.urandom(5 * MiB))) == ("StorageFull", 507))
    check("and the refused one left the old part as it was",
          [p["ETag"] for p in c.list_parts(Bucket=B, Key="q/a", UploadId=uid)["Parts"]][1] == e2 and held() == 10 * MiB)
    c.abort_multipart_upload(Bucket=B, Key="q/a", UploadId=uid)
    check("aborting gives the room back", wait_for(lambda: held() == 0), stats())
    check("and an object that would not fit before is stored now",
          code_of(lambda: c.put_object(Bucket=B, Key="q/o", Body=os.urandom(3 * MiB)))[0] is None)
    c.delete_object(Bucket=B, Key="q/o")
    uid = c.create_multipart_upload(Bucket=B, Key="q/b")["UploadId"]
    c.upload_part(Bucket=B, Key="q/b", UploadId=uid, PartNumber=1, Body=os.urandom(5 * MiB))
    e = c.upload_part(Bucket=B, Key="q/b", UploadId=uid, PartNumber=1, Body=os.urandom(5 * MiB + 100))["ETag"]
    check("a part replaced inside the room costs its new size and gives back its old one",
          wait_for(lambda: held() == 5 * MiB + 100), stats())
    complete(c, "q/b", uid, [e])
    check("completing gives the parts' room back and the object holds its own",
          wait_for(lambda: held() == 0) and c.head_object(Bucket=B, Key="q/b")["ContentLength"] == 5 * MiB + 100, stats())


def large_mode():
    c = client()
    c.create_bucket(Bucket=B)
    nparts = int(os.environ.get("SOCKETLEY_STORAGE_MPU_PARTS", "6"))
    part_mib = int(os.environ.get("SOCKETLEY_STORAGE_MPU_PART_MIB", "64"))
    pid = int(os.environ["WPID"])

    def hwm():
        with open("/proc/%d/status" % pid) as f:
            for line in f:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1])
        return -1

    before = hwm()
    block = os.urandom(MiB)
    uid = c.create_multipart_upload(Bucket=B, Key="large")["UploadId"]
    tags, md5s = [], []
    t0 = time.time()
    for i in range(1, nparts + 1):
        # One part is a block repeated, so the client holds a block and a slice can be checked.
        body = block * part_mib
        tags.append(c.upload_part(Bucket=B, Key="large", UploadId=uid, PartNumber=i, Body=body)["ETag"])
        md5s.append(hashlib.md5(body).digest())
    up = time.time() - t0
    t1 = time.time()
    complete(c, "large", uid, tags)
    took = time.time() - t1
    total = nparts * part_mib
    h = c.head_object(Bucket=B, Key="large")
    check("a %d MiB object is assembled from %d parts of %d MiB" % (total, nparts, part_mib),
          h["ContentLength"] == total * MiB and h["ETag"].strip('"') == "%s-%d" % (hashlib.md5(b"".join(md5s)).hexdigest(), nparts), h)
    print("  info: uploaded %d MiB in %.2fs (%.0f MB/s), assembled in %.2fs (%.0f MB/s)" %
          (total, up, total / up, took, total / took))
    g = hashlib.md5()
    want = hashlib.md5()
    for chunk in c.get_object(Bucket=B, Key="large")["Body"].iter_chunks(MiB):
        g.update(chunk)
    for _ in range(total):
        want.update(block)
    check("and it reads back as the parts, joined", g.hexdigest() == want.hexdigest())
    after = hwm()
    limit = int(os.environ.get("SOCKETLEY_STORAGE_MPU_RSS_MIB", "64")) * 1024
    check("the worker's peak resident set stays bounded through the parts and the assembly (%d -> %d KiB, limit %d)" %
          (before, after, limit), 0 < after <= limit, (before, after))
    check("nothing is left of the upload", wait_for(lambda: upload_dirs() == [], 10.0), upload_dirs())


def main():
    {"main": main_mode, "resume": resume_mode, "killed": killed_mode, "expire": expire_mode,
     "reaped": reaped_mode, "quota": quota_mode, "large": large_mode}[MODE]()
    total = passed + failed
    print("  Results: %d/%d passed (%d failed)" % (passed, total, failed))
    sys.exit(min(failed, 100))


main()
