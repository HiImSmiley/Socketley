#!/usr/bin/env python3
"""Lifecycle transitions to a tier, with another storage runtime as the tier, driven with boto3.

usage: lib_storage_tiers.py SOURCE:PORT SOURCE_DIR TIER_PORT

The source's --tiers names COLD at http://127.0.0.1:TIER_PORT/cold/arch.  Signed for with ADMIN_AK/ADMIN_SK on both.
Prints one PASS or FAIL line per assertion.
"""
import os
import random
import subprocess
import sys
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

BIN = os.environ["BIN"]
ADMIN = (os.environ["ADMIN_AK"], os.environ["ADMIN_SK"])
NAME, PORT = sys.argv[1].split(":")
DATA, TIER_PORT = sys.argv[2], int(sys.argv[3])
passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name, flush=True)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, str(detail)[:900]), flush=True)


def wait_for(fn, timeout=60):
    end = time.time() + timeout
    v = None
    while time.time() < end:
        try:
            v = fn()
        except Exception:
            v = None
        if v:
            return v
        time.sleep(0.25)
    return v


def stats():
    out = subprocess.run([BIN, "stats", NAME], capture_output=True, text=True).stdout
    total = {}
    for line in out.splitlines():
        if ":" in line and not line.startswith("["):
            k, v = line.split(":", 1)
            try:
                total[k.strip()] = total.get(k.strip(), 0) + int(v.strip())
            except ValueError:
                pass
    return total


def client(port):
    return boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % port, region_name="us-east-1",
                        aws_access_key_id=ADMIN[0], aws_secret_access_key=ADMIN[1],
                        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}))


s, t = client(int(PORT)), client(TIER_PORT)


def get(key, bucket="hot", **kw):
    try:
        return s.get_object(Bucket=bucket, Key=key, **kw)["Body"].read()
    except ClientError as e:
        return e.response["Error"]["Code"]


def code(fn):
    try:
        fn()
        return "ok"
    except ClientError as e:
        return e.response["Error"]["Code"]


def remote_keys(prefix="arch/"):
    out = []
    for page in t.get_paginator("list_objects_v2").paginate(Bucket="cold", Prefix=prefix):
        out += [o["Key"] for o in page.get("Contents", [])]
    return out


def disk_bytes(bucket):
    n = 0
    for d, _, names in os.walk(os.path.join(DATA, bucket, "data")):
        n += sum(os.path.getsize(os.path.join(d, f)) for f in names)
    return n


def rule(rid, body, prefix=""):
    return {"ID": rid, "Status": "Enabled", "Filter": {"Prefix": prefix}, **body}


rnd = random.Random(3)
noise = bytes(rnd.getrandbits(8) for _ in range(2 << 20))
text = b"the quick brown fox jumps over the lazy dog\n" * 300
part = bytes(rnd.getrandbits(8) for _ in range(5 << 20))

t.create_bucket(Bucket="cold")
s.create_bucket(Bucket="hot")
check("a transition to a class that is no tier is refused InvalidStorageClass",
      code(lambda: s.put_bucket_lifecycle_configuration(Bucket="hot", LifecycleConfiguration={"Rules": [
          rule("x", {"Transitions": [{"Days": 1, "StorageClass": "GLACIER"}]})]})) == "InvalidStorageClass")
s.put_bucket_lifecycle_configuration(Bucket="hot", LifecycleConfiguration={"Rules": [
    rule("cold", {"Transitions": [{"Days": 1, "StorageClass": "COLD"}]})]})
got = s.get_bucket_lifecycle_configuration(Bucket="hot")["Rules"]
check("the rule reads back with its transition",
      got[0].get("Transitions") == [{"Days": 1, "StorageClass": "COLD"}], got)

etag = s.put_object(Bucket="hot", Key="a", Body=noise)["ETag"]
s.put_object(Bucket="hot", Key="b", Body=text, ContentType="text/plain")
s.put_object(Bucket="hot", Key="empty", Body=b"")
up = s.create_multipart_upload(Bucket="hot", Key="m")
pt = [s.upload_part(Bucket="hot", Key="m", UploadId=up["UploadId"], PartNumber=n, Body=part)["ETag"] for n in (1, 2)]
s.complete_multipart_upload(Bucket="hot", Key="m", UploadId=up["UploadId"],
                            MultipartUpload={"Parts": [{"ETag": e, "PartNumber": i + 1} for i, e in enumerate(pt)]})
before = disk_bytes("hot")

check("every version due moves to the tier", wait_for(lambda: stats().get("tier_moved", 0) >= 4, 90), stats())
h = s.head_object(Bucket="hot", Key="a")
check("a moved object is answered with the tier as its class, its ETag and size as they were",
      h.get("StorageClass") == "COLD" and h["ETag"] == etag and h["ContentLength"] == len(noise), h)
listed = {o["Key"]: o["StorageClass"] for o in s.list_objects_v2(Bucket="hot")["Contents"]}
check("and is listed so", listed == {"a": "COLD", "b": "COLD", "empty": "COLD", "m": "COLD"}, listed)
check("its bytes read back from the tier", get("a") == noise and get("b") == text and get("empty") == b"")
check("so does a range across the tier's windows", get("a", Range="bytes=100000-1500000") == noise[100000:1500001])
check("and a part of a multipart object", get("m", PartNumber=2) == part)
check("a GET was read from the tier",
      wait_for(lambda: stats().get("tier_gets", 0) >= 1 and stats().get("tier_reads", 0) >= 1, 10), stats())
keys = remote_keys("arch/hot/")
check("the tier holds each under the bucket, the version's time and MD5, and the key",
      len(keys) == 4 and all(k.startswith("arch/hot/") for k in keys) and any(k.endswith("/a") for k in keys), keys)
check("the files here keep their headers alone", disk_bytes("hot") < 64 * 1024, (before, disk_bytes("hot")))
check("a copy of a moved object is refused InvalidObjectState",
      code(lambda: s.copy_object(Bucket="hot", Key="a2", CopySource={"Bucket": "hot", "Key": "a"})) ==
      "InvalidObjectState")

s.delete_object(Bucket="hot", Key="b")
check("what a version deleted here left at the tier is swept",
      wait_for(lambda: not any(k.endswith("/b") for k in remote_keys("arch/hot/")), 60), remote_keys())
s.put_object(Bucket="hot", Key="a", Body=text)
check("an object written over a moved one reads as the new bytes, in STANDARD",
      get("a") == text and s.head_object(Bucket="hot", Key="a").get("StorageClass") in (None, "STANDARD"))

s.create_bucket(Bucket="ver")
s.put_bucket_versioning(Bucket="ver", VersioningConfiguration={"Status": "Enabled"})
s.put_bucket_lifecycle_configuration(Bucket="ver", LifecycleConfiguration={"Rules": [
    rule("nc", {"NoncurrentVersionTransitions": [{"NoncurrentDays": 1, "StorageClass": "COLD"}]})]})
v1 = s.put_object(Bucket="ver", Key="k", Body=noise[:300000])["VersionId"]
v2 = s.put_object(Bucket="ver", Key="k", Body=text)["VersionId"]
# Asked of the version itself: the counter also moves for anything else the hot bucket's rule is still taking.
ver_classes = lambda: {v["VersionId"]: v["StorageClass"] for v in s.list_object_versions(Bucket="ver")["Versions"]}
check("a noncurrent version moves", wait_for(lambda: ver_classes().get(v1) == "COLD", 60), ver_classes())
vers = ver_classes()
check("the versions are listed with their classes", vers == {v1: "COLD", v2: "STANDARD"}, vers)
check("and the moved one reads back by its id", get("k", "ver", VersionId=v1) == noise[:300000])
check("while the latest stays here", get("k", "ver") == text)
print("  tiers: PASS=%d FAIL=%d" % (passed, failed))
sys.exit(failed)
