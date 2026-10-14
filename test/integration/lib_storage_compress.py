#!/usr/bin/env python3
"""--compress on a storage runtime, driven with boto3.

usage: lib_storage_compress.py NAME PORT DIR

Writes compressible, incompressible, small, multipart and versioned objects, waits for the shard passes to compress
what they take, and reads everything back whole, in ranges across chunks and windows, copied, and after a byte of a
compressed file is changed.  Signed for with ADMIN_AK/ADMIN_SK; one PASS or FAIL line per assertion.
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
NAME, PORT, DATA = sys.argv[1], int(sys.argv[2]), sys.argv[3]
passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name, flush=True)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, str(detail)[:900]), flush=True)


def wait_for(fn, timeout=40):
    end = time.time() + timeout
    v = None
    while time.time() < end:
        try:
            v = fn()
        except Exception:
            v = None
        if v:
            return v
        time.sleep(0.2)
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


def disk_bytes(bucket):
    n = 0
    for d, _, names in os.walk(os.path.join(DATA, bucket, "data")):
        for f in names:
            n += os.path.getsize(os.path.join(d, f))
    return n


def files_with(root, needle):
    found = []
    for d, _, names in os.walk(root):
        for n in names:
            p = os.path.join(d, n)
            try:
                with open(p, "rb") as f:
                    if needle in f.read():
                        found.append(p)
            except OSError:
                pass
    return found


c = boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % PORT, region_name="us-east-1",
                 aws_access_key_id=ADMIN[0], aws_secret_access_key=ADMIN[1],
                 config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}))


def get(bucket, key, rng=None, version=None):
    kw = {}
    if rng:
        kw["Range"] = rng
    if version:
        kw["VersionId"] = version
    try:
        return c.get_object(Bucket=bucket, Key=key, **kw)["Body"].read()
    except ClientError as e:
        return e.response["Error"]["Code"]
    except Exception as e:
        return repr(e)


rnd = random.Random(7)
lines = b"".join(b'{"ts":%d,"level":"info","msg":"request served","path":"/api/v1/items/%d","ms":%d}\n'
                 % (i, i % 977, i % 13) for i in range(100000))
big = lines[:3 << 20]
mid = lines[:300 << 10]
warm = lines[:50000]
noise = bytes(rnd.getrandbits(8) for _ in range(200 << 10))
small = b"tiny text " * 100

c.create_bucket(Bucket="logs")
etags = {}
for k, v in (("big", big), ("mid", mid), ("warm", warm), ("noise", noise), ("small", small), ("empty", b"")):
    etags[k] = c.put_object(Bucket="logs", Key=k, Body=v)["ETag"]
part = lines[:5 << 20]
up = c.create_multipart_upload(Bucket="logs", Key="multi")
pt = [c.upload_part(Bucket="logs", Key="multi", UploadId=up["UploadId"], PartNumber=n, Body=part)["ETag"]
      for n in (1, 2)]
c.complete_multipart_upload(Bucket="logs", Key="multi", UploadId=up["UploadId"],
                            MultipartUpload={"Parts": [{"ETag": e, "PartNumber": i + 1} for i, e in enumerate(pt)]})
c.create_bucket(Bucket="kept")
c.put_bucket_versioning(Bucket="kept", VersioningConfiguration={"Status": "Enabled"})
v1 = c.put_object(Bucket="kept", Key="k", Body=mid)["VersionId"]
c.put_object(Bucket="kept", Key="k", Body=big)
logical = len(big) + len(mid) + len(noise) + len(small)
before = disk_bytes("logs")

check("the versions that take it are compressed: three latest, two of a versioned key",
      wait_for(lambda: stats().get("compressed_objects", 0) >= 5), stats())
check("and what does not get shorter is read and left",
      wait_for(lambda: stats().get("compressed_skipped", 0) >= 1), stats())
s = stats()
check("what they take on disk is a fraction of their bytes",
      0 < s.get("compressed_bytes_out", 0) < s.get("compressed_bytes_in", 1) // 4, s)
# Waited on the files and not on the counters: compressed_objects and
# compressed_bytes_* count every bucket, and they rise when a version has been
# compressed, not when the file in THIS bucket has been replaced.  So the two
# facts drift apart under load -- measured on a loaded box, before and after
# equal to the byte with five versions already counted, and green on its own.
# From the bytes put and not from a reading after them, which a compaction already done reads as the start:
# measured, before and after equal to the byte when it ran ahead of the reading.
raw = len(big) + len(mid) + len(warm) + len(noise) + len(small) + 2 * len(part)
target = raw - (len(big) + len(mid)) // 2 + (64 << 10)
shrank = wait_for(lambda: disk_bytes("logs") < target)
after = disk_bytes("logs")
check("and the bucket's files shrank by it", shrank, (before, after, raw, target))

check("a compressed object reads back whole", get("logs", "big") == big)
check("so does one read whole with its header, and again from memory",
      get("logs", "warm") == warm and get("logs", "warm") == warm and get("logs", "warm", "bytes=4000-70000") ==
      warm[4000:])
check("and one between the two", get("logs", "mid") == mid)
check("the incompressible, small, empty and multipart ones are as they were",
      get("logs", "noise") == noise and get("logs", "small") == small and get("logs", "empty") == b"" and
      get("logs", "multi") == part + part)
for rng, lo, hi in (("bytes=0-0", 0, 0), ("bytes=65535-65536", 65535, 65536), ("bytes=1048570-1048590", 1048570,
                    1048590), ("bytes=100000-2200000", 100000, 2200000), ("bytes=-100", len(big) - 100, len(big) - 1)):
    check("a range %s reads the bytes it names" % rng, get("logs", "big", rng) == big[lo:hi + 1])
h = c.head_object(Bucket="logs", Key="big")
check("the ETag and size are the bytes'", h["ETag"] == etags["big"] and h["ContentLength"] == len(big), h)
check("a GET past memory opened chunks from the file",
      wait_for(lambda: stats().get("compressed_gets", 0) >= 1, 10), stats())
check("a noncurrent version compressed reads back by its id", get("kept", "k", version=v1) == mid)
check("and the latest", get("kept", "k") == big)

c.copy_object(Bucket="logs", Key="copied", CopySource={"Bucket": "logs", "Key": "big"})
check("a copy of a compressed object holds its bytes", get("logs", "copied") == big)
check("and is compressed in its turn", wait_for(lambda: stats().get("compressed_objects", 0) >= 6), stats())
check("and still reads back", get("logs", "copied") == big)

c.put_object(Bucket="logs", Key="big", Body=mid)
check("an object written over a compressed one reads as the new bytes", get("logs", "big") == mid)
check("and is compressed in its turn", wait_for(lambda: stats().get("compressed_objects", 0) >= 7), stats())

# The largest file that names the record is an object's, where a journal holds the name too.
target = sorted(files_with(os.path.join(DATA, "kept"), b"x-socketley-lz4"), key=os.path.getsize, reverse=True)
check("a compressed file says so in its header", len(target) >= 1 and os.path.getsize(target[0]) > 100000, target)
corrupt_before = stats().get("scrub_corrupt", 0)
with open(target[0], "r+b") as f:
    f.seek(0, 2)
    f.seek(f.tell() - 5000)
    b = f.read(1)
    f.seek(-1, 1)
    f.write(bytes([b[0] ^ 0x5A]))
check("the scrub finds a compressed version whose file changed",
      wait_for(lambda: stats().get("scrub_corrupt", 0) > corrupt_before), stats())
print("  compress: PASS=%d FAIL=%d" % (passed, failed))
sys.exit(failed)
