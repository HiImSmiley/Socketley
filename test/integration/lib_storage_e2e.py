#!/usr/bin/env python3
"""What the storage runtime's features do together, over https with credentials.

usage: lib_storage_e2e.py PORT CERT MODE EXPECT_FILE

MODE is
  main    put_object with every checksum algorithm, upload_file in parts, the
          multipart calls one by one, a signed aws-chunked body inside an outer
          Transfer-Encoding: chunked, and the refusals of a wrong key; the keys
          whose puts committed are written to EXPECT_FILE, one line for each
          on_put a script should have been told of
  rpc     PORT is a server runtime whose script answers text commands with
          socketley.storage calls against a sharded runtime (CERT is that
          runtime's plain http port): put, get, head, list and delete of keys
          owned by every shard, and an object too large to read
  creds   PORT is plain http and CERT is the credentials file the runtime reads:
          keys added to it work and keys taken out stop, on every shard

Prints one PASS or FAIL line per assertion and a final "Results:" line, and
exits with the number of failures.
"""
import base64
import hashlib
import os
import socket
import ssl
import sys
import tempfile
import time
import zlib

import boto3
import botocore.exceptions
from boto3.s3.transfer import TransferConfig
from botocore.config import Config

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib_s3_signing as sig  # noqa: E402

PORT = int(sys.argv[1])
CERT = sys.argv[2]
MODE = sys.argv[3]
EXPECT = sys.argv[4] if len(sys.argv) > 4 else ""
AK = "AKIAE2EACCESSKEY01"
SK = "e2e/secret+key/for.storage.sigv4"
MiB = 1 << 20
B = "e2ebkt"

passed = failed = 0
put_keys = []


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, detail))


def client(access=AK, secret=SK, https=True):
    return boto3.client(
        "s3",
        endpoint_url=("https://localhost:%d" if https else "http://127.0.0.1:%d") % PORT,
        aws_access_key_id=access, aws_secret_access_key=secret, region_name="us-east-1",
        verify=CERT if https else None,
        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}, max_pool_connections=16,
                      connect_timeout=10, read_timeout=60))


def code_of(e):
    return e.response["Error"]["Code"]


def crc32_b64(b):
    return sig.crc32_b64(b)


def sha1_b64(b):
    return base64.b64encode(hashlib.sha1(b).digest()).decode()


# botocore computes CRC32C and CRC64NVME only with the awscrt package, which is not a dependency here.
SUMS = {
    "CRC32": ("ChecksumCRC32", crc32_b64),
    "SHA1": ("ChecksumSHA1", sha1_b64),
    "SHA256": ("ChecksumSHA256", sig.sha256_b64),
}


def body_of(n, seed):
    out = bytearray()
    x = seed * 2654435761 % (1 << 32) or 1
    while len(out) < n:
        x = (x * 1103515245 + 12345) % (1 << 31)
        out += x.to_bytes(4, "little")
    return bytes(out[:n])


def mode_main():
    s3 = client()
    s3.create_bucket(Bucket=B)

    # ── put_object with a checksum, over https ──────────────────────────────
    for algo, (field, fn) in SUMS.items():
        for n in (100, 3 * MiB):
            key = "ck/%s/%d" % (algo, n)
            body = body_of(n, n + len(algo))
            try:
                r = s3.put_object(Bucket=B, Key=key, Body=body, ChecksumAlgorithm=algo)
                ok = r["ETag"].strip('"') == hashlib.md5(body).hexdigest() and r.get(field) == fn(body)
                check("put_object %s of %d bytes over https is stored with its checksum" % (algo, n), ok, r)
                put_keys.append(key)
                g = s3.get_object(Bucket=B, Key=key, ChecksumMode="ENABLED")
                got = g["Body"].read()
                check("and comes back whole with the checksum %s" % algo, got == body and g.get(field) == fn(body),
                      (len(got), g.get(field)))
            except botocore.exceptions.ClientError as e:
                check("put_object %s of %d bytes over https" % (algo, n), False, e.response["Error"])
    # A checksum that is wrong is refused, and nothing is stored under the key.
    try:
        s3.put_object(Bucket=B, Key="ck/bad", Body=b"payload", ChecksumCRC32="AAAAAA==")
        check("a wrong checksum is refused", False, "accepted")
    except botocore.exceptions.ClientError as e:
        check("a wrong checksum is refused as BadDigest", code_of(e) == "BadDigest", e.response["Error"])
    try:
        s3.head_object(Bucket=B, Key="ck/bad")
        check("and nothing is stored", False, "stored")
    except botocore.exceptions.ClientError as e:
        check("and nothing is stored", code_of(e) in ("404", "NoSuchKey"), e.response["Error"])

    # ── a script's on_request refuses the multipart calls too ───────────────
    try:
        s3.create_multipart_upload(Bucket=B, Key="forbid/x")
        check("a multipart upload of a key the script forbids is refused", False, "created")
    except botocore.exceptions.ClientError as e:
        check("a multipart upload of a key the script forbids is AccessDenied", code_of(e) == "AccessDenied",
              e.response["Error"])
    with tempfile.TemporaryDirectory() as td0:
        path0 = os.path.join(td0, "f")
        open(path0, "wb").write(body_of(11 * MiB, 5))
        try:
            s3.upload_file(path0, B, "forbid/file",
                           Config=TransferConfig(multipart_threshold=5 * MiB, multipart_chunksize=5 * MiB))
            check("upload_file of a forbidden key is refused", False, "uploaded")
        except Exception as e:      # noqa: BLE001
            check("upload_file of a forbidden key is refused", "AccessDenied" in repr(e), repr(e))
    check("and leaves no upload behind", not s3.list_multipart_uploads(Bucket=B).get("Uploads"))

    # ── upload_file, in parts, with and without a checksum ─────────────────
    cfg = TransferConfig(multipart_threshold=5 * MiB, multipart_chunksize=5 * MiB, max_concurrency=6)
    with tempfile.TemporaryDirectory() as td:
        for label, extra, key in (("no checksum", None, "mp/plain"), ("CRC32", {"ChecksumAlgorithm": "CRC32"}, "mp/crc32"),
                                  ("SHA256", {"ChecksumAlgorithm": "SHA256"}, "mp/sha256")):
            path = os.path.join(td, "f")
            data = body_of(23 * MiB + 12345, len(label))
            open(path, "wb").write(data)
            try:
                s3.upload_file(path, B, key, Config=cfg, ExtraArgs=extra)
                put_keys.append(key)
                h = s3.head_object(Bucket=B, Key=key, ChecksumMode="ENABLED")
                check("upload_file (%s) in parts over https: the ETag is a multipart one" % label,
                      h["ETag"].strip('"').endswith("-5") and h["ContentLength"] == len(data), h["ETag"])
                if extra:
                    field = SUMS[extra["ChecksumAlgorithm"]][0]
                    check("and carries a composite checksum of its parts", field in h and h[field].endswith("-5"),
                          {k: v for k, v in h.items() if k.startswith("Checksum")})
                back = os.path.join(td, "back")
                s3.download_file(B, key, back, Config=cfg)
                check("upload_file (%s): the object downloads byte for byte" % label,
                      hashlib.md5(open(back, "rb").read()).hexdigest() == hashlib.md5(data).hexdigest())
            except Exception as e:      # noqa: BLE001
                check("upload_file (%s) over https" % label, False, repr(e))

    # ── the multipart calls one by one ──────────────────────────────────────
    try:
        src = body_of(6 * MiB, 77)
        s3.put_object(Bucket=B, Key="src/whole", Body=src)
        put_keys.append("src/whole")
        up = s3.create_multipart_upload(Bucket=B, Key="mp/steps", ContentType="application/x-e2e",
                                        Metadata={"color": "blue"})
        uid = up["UploadId"]
        p1 = body_of(5 * MiB, 1)
        p3 = body_of(1000, 3)
        e1 = s3.upload_part(Bucket=B, Key="mp/steps", UploadId=uid, PartNumber=1, Body=p1)["ETag"]
        # A part copied from a range of an object, and a part uploaded last, out of order.
        e3 = s3.upload_part(Bucket=B, Key="mp/steps", UploadId=uid, PartNumber=3, Body=p3)["ETag"]
        e2 = s3.upload_part_copy(Bucket=B, Key="mp/steps", UploadId=uid, PartNumber=2,
                                 CopySource={"Bucket": B, "Key": "src/whole"},
                                 CopySourceRange="bytes=0-5242879")["CopyPartResult"]["ETag"]
        other = s3.create_multipart_upload(Bucket=B, Key="mp/other")["UploadId"]
        parts = s3.list_parts(Bucket=B, Key="mp/steps", UploadId=uid, MaxParts=2)
        check("list_parts pages: two of three", len(parts["Parts"]) == 2 and parts["IsTruncated"], parts)
        rest = s3.list_parts(Bucket=B, Key="mp/steps", UploadId=uid, PartNumberMarker=parts["NextPartNumberMarker"])
        check("and the rest", [p["PartNumber"] for p in rest["Parts"]] == [3], rest)
        ups = s3.list_multipart_uploads(Bucket=B)
        ids = sorted(u["UploadId"] for u in ups.get("Uploads", []))
        check("list_multipart_uploads names both open uploads", ids == sorted([uid, other]), ups)
        s3.abort_multipart_upload(Bucket=B, Key="mp/other", UploadId=other)
        ids = [u["UploadId"] for u in s3.list_multipart_uploads(Bucket=B).get("Uploads", [])]
        check("abort removes it from the list", ids == [uid], ids)
        try:
            s3.list_parts(Bucket=B, Key="mp/other", UploadId=other)
            check("an aborted upload has no parts", False, "listed")
        except botocore.exceptions.ClientError as e:
            check("an aborted upload is NoSuchUpload", code_of(e) == "NoSuchUpload", e.response["Error"])
        done = s3.complete_multipart_upload(Bucket=B, Key="mp/steps", UploadId=uid, MultipartUpload={"Parts": [
            {"PartNumber": 1, "ETag": e1}, {"PartNumber": 2, "ETag": e2}, {"PartNumber": 3, "ETag": e3}]})
        put_keys.append("mp/steps")
        check("complete_multipart_upload answers with a -3 ETag", done["ETag"].strip('"').endswith("-3"), done)
        g = s3.get_object(Bucket=B, Key="mp/steps")
        got = g["Body"].read()
        check("the assembled object is the parts in order", got == p1 + src[:5 * MiB] + p3, len(got))
        check("with the content type and metadata the upload began with",
              g["ContentType"] == "application/x-e2e" and g["Metadata"].get("color") == "blue", g)
    except botocore.exceptions.ClientError as e:
        check("the multipart calls one by one", False, e.response["Error"])

    # ── a signed body in trailer framing inside an outer Transfer-Encoding: chunked ──
    ctx = ssl.create_default_context(cafile=CERT)

    def raw_put(key, payload_hash, body, headers, outer_piece):
        s = sig.sign("PUT", "/%s/%s" % (B, key), "", "localhost:%d" % PORT, AK, SK, payload_hash, extra_headers=headers)
        # The outer framing cuts the aws-chunked bytes wherever it likes, mid-header included.
        framed = b""
        for i in range(0, len(body), outer_piece):
            piece = body[i:i + outer_piece]
            framed += ("%x\r\n" % len(piece)).encode() + piece + b"\r\n"
        framed += b"0\r\n\r\n"
        lines = ["PUT /%s/%s HTTP/1.1" % (B, key), "Host: localhost:%d" % PORT, "Transfer-Encoding: chunked"]
        lines += ["%s: %s" % (k, v) for k, v in s.headers.items()]
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + framed
        c = socket.create_connection(("localhost", PORT), timeout=30)
        t = ctx.wrap_socket(c, server_hostname="localhost")
        t.sendall(raw)
        data = b""
        while b"\r\n\r\n" not in data:
            d = t.recv(4096)
            if not d:
                break
            data += d
        t.close()
        return data.split(b"\r\n", 1)[0].decode(), s

    payload = body_of(300000, 9)
    cks = crc32_b64(payload)
    pieces = [payload[i:i + 65536] for i in range(0, len(payload), 65536)]
    for label, chunk_size in (("7 bytes", 7), ("a chunk", 65536), ("1 KiB", 1024)):
        key = "raw/unsigned-%d" % chunk_size
        body = sig.unsigned_chunks(pieces, [("x-amz-checksum-crc32", cks)])
        status, _ = raw_put(key, "STREAMING-UNSIGNED-PAYLOAD-TRAILER", body, {
            "content-encoding": "aws-chunked", "x-amz-decoded-content-length": str(len(payload)),
            "x-amz-trailer": "x-amz-checksum-crc32"}, chunk_size)
        check("an unsigned trailer body cut into outer chunks of %s over https is 200" % label, " 200 " in status + " ", status)
        if " 200 " in status + " ":
            put_keys.append(key)
            g = s3.get_object(Bucket=B, Key=key, ChecksumMode="ENABLED")
            got = g["Body"].read()
            check("and stored whole with its checksum (%s)" % label, got == payload and g.get("ChecksumCRC32") == cks,
                  (len(got), g.get("ChecksumCRC32")))
    # The signed variant, where every chunk and the trailer carry a signature.
    key = "raw/signed"
    s = sig.sign("PUT", "/%s/%s" % (B, key), "", "localhost:%d" % PORT, AK, SK,
                 "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", extra_headers={
                     "content-encoding": "aws-chunked", "x-amz-decoded-content-length": str(len(payload)),
                     "x-amz-trailer": "x-amz-checksum-crc32"})
    body = sig.signed_chunks(s, pieces, [("x-amz-checksum-crc32", cks)])
    framed = b"".join(("%x\r\n" % len(body[i:i + 5000])).encode() + body[i:i + 5000] + b"\r\n"
                      for i in range(0, len(body), 5000)) + b"0\r\n\r\n"
    lines = ["PUT /%s/%s HTTP/1.1" % (B, key), "Host: localhost:%d" % PORT, "Transfer-Encoding: chunked"]
    lines += ["%s: %s" % (k, v) for k, v in s.headers.items()]
    c = socket.create_connection(("localhost", PORT), timeout=30)
    t = ctx.wrap_socket(c, server_hostname="localhost")
    t.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + framed)
    data = t.recv(4096)
    t.close()
    status = data.split(b"\r\n", 1)[0].decode()
    check("a signed trailer body inside an outer chunked body over https is 200", " 200 " in status + " ", status)
    if " 200 " in status + " ":
        put_keys.append(key)
        check("and is stored whole", s3.get_object(Bucket=B, Key=key)["Body"].read() == payload)
    # A trailer that is wrong is refused there too, and stores nothing.
    key = "raw/badtrailer"
    body = sig.unsigned_chunks(pieces, [("x-amz-checksum-crc32", "AAAAAA==")])
    status, _ = raw_put(key, "STREAMING-UNSIGNED-PAYLOAD-TRAILER", body, {
        "content-encoding": "aws-chunked", "x-amz-decoded-content-length": str(len(payload)),
        "x-amz-trailer": "x-amz-checksum-crc32"}, 4096)
    check("a wrong trailer checksum is 400 over https", " 400 " in status + " ", status)
    try:
        s3.head_object(Bucket=B, Key=key)
        check("and nothing is stored", False, "stored")
    except botocore.exceptions.ClientError:
        check("and nothing is stored", True)

    # ── credentials are checked wherever the connection lands ──────────────
    bad = 0
    for i in range(24):
        try:
            client(secret="not-the-secret").list_objects_v2(Bucket=B, MaxKeys=1)
        except botocore.exceptions.ClientError as e:
            bad += code_of(e) != "SignatureDoesNotMatch"
        else:
            bad += 1
    check("twenty-four requests signed with a wrong secret are all SignatureDoesNotMatch", bad == 0, bad)
    bad = 0
    for i in range(24):
        try:
            client(access="AKIANOSUCHKEY").list_objects_v2(Bucket=B, MaxKeys=1)
        except botocore.exceptions.ClientError as e:
            bad += code_of(e) != "InvalidAccessKeyId"
        else:
            bad += 1
    check("and twenty-four with an unknown key are all InvalidAccessKeyId", bad == 0, bad)

    # ── a bucket that holds only open uploads is dropped with them, as in S3, wherever the request lands ──
    s3.create_bucket(Bucket="e2edrop")
    held = [("held/upload%d" % i, s3.create_multipart_upload(Bucket="e2edrop", Key="held/upload%d" % i)["UploadId"])
            for i in range(16)]
    s3.upload_part(Bucket="e2edrop", Key=held[0][0], UploadId=held[0][1], PartNumber=1, Body=b"p" * 1000)
    try:
        client().delete_bucket(Bucket="e2edrop")
        check("a bucket that holds sixteen open uploads on every shard is deleted", True)
    except botocore.exceptions.ClientError as e:
        check("a bucket that holds sixteen open uploads on every shard is deleted", False, e.response["Error"])
    gone = 0
    for k, u in held:
        try:
            client().list_parts(Bucket="e2edrop", Key=k, UploadId=u)
        except botocore.exceptions.ClientError as e:
            gone += code_of(e) in ("NoSuchBucket", "NoSuchUpload")
    check("and every upload went with it, on every shard", gone == len(held), gone)
    s3.create_bucket(Bucket="e2edrop")
    left = []
    for _ in range(16):
        left += client().list_multipart_uploads(Bucket="e2edrop").get("Uploads", [])
    check("and a bucket made again under the name has none of them", not left, left[:3])
    s3.delete_bucket(Bucket="e2edrop")

    # Everything begun was completed or aborted, so no upload is left on any shard.
    left = []
    for _ in range(40):
        left = s3.list_multipart_uploads(Bucket=B).get("Uploads", [])
        if not left:
            break
        time.sleep(0.25)
    check("no upload is left open when the tests are done", not left, left)

    open(EXPECT, "w").write("".join(k + "\n" for k in sorted(put_keys)))


def mode_creds():
    """CERT is the credentials file; the runtime reads it again within a second of a change."""
    path = CERT
    pairs = {"AKIAONE": "secret-one", "AKIATWO": "secret-two"}

    def write(p):
        with open(path + ".new", "w") as f:
            f.write("# e2e\n" + "".join("%s:%s\n" % kv for kv in p.items()))
        os.replace(path + ".new", path)

    def works(access, secret, n=16):
        good = 0
        for _ in range(n):
            try:
                client(access, secret, https=False).list_buckets()
                good += 1
            except botocore.exceptions.ClientError:
                pass
        return good

    check("both keys in the file work on every connection", works("AKIAONE", "secret-one") == 16 and
          works("AKIATWO", "secret-two") == 16)
    pairs["AKIATHREE"] = "secret-three"
    del pairs["AKIAONE"]
    write(pairs)
    time.sleep(1.6)
    check("a key added to the file works on every shard once it is read again", works("AKIATHREE", "secret-three") == 16)
    check("a key taken out stops on every shard", works("AKIAONE", "secret-one") == 0)
    check("a key left in the file still works", works("AKIATWO", "secret-two") == 16)
    # A file that no longer parses leaves the keys in force.
    open(path, "w").write("this is not a credentials file\n")
    time.sleep(1.6)
    check("a file that stops parsing leaves the keys in force", works("AKIATWO", "secret-two") == 16)
    write({"AKIAFOUR": "secret-four"})
    time.sleep(1.6)
    check("and the repaired file is read", works("AKIAFOUR", "secret-four") == 16 and works("AKIATWO", "secret-two") == 0)


def mode_rpc():
    import http.client
    backend = int(CERT)
    sock = socket.create_connection(("127.0.0.1", PORT), timeout=30)
    f = sock.makefile("rwb", buffering=0)

    def ask(line):
        f.write((line + "\n").encode())
        return f.readline().decode().strip()

    n = 40
    vals = {"k%02d" % i: (("v%d-" % i) * (i + 1)).encode() for i in range(n)}
    etags = {}
    bad = []
    for k, v in vals.items():
        r = ask("put %s %s" % (k, v.hex())).split()
        if r[:1] != ["ok"] or int(r[2]) != len(v):
            bad.append((k, r))
        else:
            etags[k] = r[1]
    check("forty puts by script, of keys every shard owns, are all stored", not bad, bad[:3])
    c = http.client.HTTPConnection("127.0.0.1", backend, timeout=30)
    wrong = 0
    for k, v in vals.items():
        c.request("GET", "/rpcb/" + k)
        resp = c.getresponse()
        body = resp.read()
        wrong += resp.status != 200 or body != v or resp.getheader("ETag", "").strip('"') != etags.get(k)
    check("and read back through the S3 port, with the ETags the script was given", wrong == 0, wrong)
    bad = []
    for k, v in vals.items():
        r = ask("get %s" % k).split()
        if r[:1] != ["data"] or bytes.fromhex(r[1]) != v or r[2] != etags[k]:
            bad.append((k, r[:1]))
    check("a script's get of each, wherever it lives, is the object", not bad, bad[:3])
    bad = []
    for k, v in vals.items():
        r = ask("head %s" % k).split()
        if r[:1] != ["head"] or int(r[1]) != len(v) or r[2] != etags[k]:
            bad.append((k, r))
    check("a script's head of each is its size and ETag", not bad, bad[:3])
    check("a get of a key that is not there is NoSuchKey", ask("get nothing").split()[:2] == ["err", "NoSuchKey"])
    check("and a head is too", ask("head nothing").split() == ["err", "NoSuchKey"])
    # The listing is every shard's, in pages.
    seen, after, pages = [], "-", 0
    while pages < 40:
        r = ask("list - - 7 %s" % after)
        parts = dict(x.split("=", 1) for x in r.split() if "=" in x)
        keys = [k for k in parts.get("keys", "").split(",") if k]
        seen += keys
        pages += 1
        if parts.get("truncated") != "true":
            break
        after = parts["next"]
    check("a script's listing in pages of seven is all forty, once, in order", seen == sorted(vals) and pages == 6,
          (pages, len(seen)))
    r = ask("list k0 - - -").split()
    check("with a prefix", any(x.startswith("keys=k00,k01") for x in r), r[:3])
    for k in list(vals)[::2]:
        ask("del %s" % k)
    gone = [k for k in list(vals)[::2] if ask("get %s" % k).split()[:2] == ["err", "NoSuchKey"]]
    check("deleted through the script, gone for the script", len(gone) == n // 2, len(gone))
    c.request("GET", "/rpcb?list-type=2")
    body = c.getresponse().read().decode()
    check("and gone from the S3 listing", body.count("<Key>") == n // 2, body.count("<Key>"))
    # An object too large for a script to read is refused, whichever shard holds it.
    refused = 0
    for i in range(8):
        big = os.urandom(1200000)
        c.request("PUT", "/rpcb/big%d" % i, body=big)
        c.getresponse().read()
        r = ask("getlen big%d" % i).split()
        refused += r[:2] == ["err", "EntityTooLarge"]
    check("eight objects over the script's limit are EntityTooLarge whichever shard holds them", refused == 8, refused)


if MODE == "main":
    mode_main()
elif MODE == "rpc":
    mode_rpc()
elif MODE == "creds":
    mode_creds()
else:
    print("unknown mode")
    sys.exit(99)
print("Results: %d passed, %d failed" % (passed, failed))
sys.exit(min(failed, 100))
