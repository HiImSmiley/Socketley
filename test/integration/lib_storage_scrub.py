#!/usr/bin/env python3
"""The scrub of a storage runtime, driven with boto3, with bytes changed on the disk under it.

usage: lib_storage_scrub.py MODE ...

  alone NAME:PORT DIR       one runtime: a pass reads every version and finds none corrupt, then finds each of a
                            plain, a multipart, an SSE-S3 and a noncurrent version whose file had a byte changed
  heal  A:PORT DIR B:PORT   two nodes of a cluster: a copy A's disk changed is fetched again from B, in a bucket that
                            keeps no versions and in one that does

Every runtime is signed for with ADMIN_AK/ADMIN_SK.  Prints one PASS or FAIL line per assertion.
"""
import os
import subprocess
import sys
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

BIN = os.environ["BIN"]
ADMIN = (os.environ["ADMIN_AK"], os.environ["ADMIN_SK"])
MODE = sys.argv[1]
passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name, flush=True)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, str(detail)[:900]), flush=True)


def client(port):
    cfg = Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1})
    return boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % port, region_name="us-east-1", config=cfg,
                        aws_access_key_id=ADMIN[0], aws_secret_access_key=ADMIN[1])


def wait_for(fn, timeout=30):
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


def stats(name):
    out = subprocess.run([BIN, "stats", name], capture_output=True, text=True).stdout
    total = {}
    for line in out.splitlines():
        if ":" in line and not line.startswith("["):
            k, v = line.split(":", 1)
            try:
                total[k.strip()] = total.get(k.strip(), 0) + int(v.strip())
            except ValueError:
                pass
    return total


def body(c, bucket, key, version=None):
    kw = {"VersionId": version} if version else {}
    try:
        return c.get_object(Bucket=bucket, Key=key, **kw)["Body"].read()
    except ClientError as e:
        return e.response["Error"]["Code"]


def files_with(root, needle):
    """Every file below `root` holding `needle`."""
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


def flip(path, back=64):
    """Changes one byte of the file, `back` bytes before its end, as a disk that went bad would."""
    with open(path, "r+b") as f:
        f.seek(0, 2)
        f.seek(f.tell() - back)
        b = f.read(1)
        f.seek(-1, 1)
        f.write(bytes([b[0] ^ 0x5A]))


def corrupt_after(name, n, timeout=30):
    return wait_for(lambda: stats(name).get("scrub_corrupt", 0) >= n, timeout)


def alone():
    name, port = sys.argv[2].split(":")
    data = sys.argv[3]
    c = client(int(port))
    c.create_bucket(Bucket="plain")
    c.put_object(Bucket="plain", Key="small", Body=b"SMALLOBJECT" * 100)
    part = b"P" * (5 << 20)
    up = c.create_multipart_upload(Bucket="plain", Key="multi")
    tags = [c.upload_part(Bucket="plain", Key="multi", UploadId=up["UploadId"], PartNumber=n,
                          Body=part[:-1] + bytes([0x30 + n]))["ETag"] for n in (1, 2)]
    c.complete_multipart_upload(Bucket="plain", Key="multi", UploadId=up["UploadId"],
                                MultipartUpload={"Parts": [{"ETag": e, "PartNumber": n + 1} for n, e in enumerate(tags)]})
    c.create_bucket(Bucket="sealed")
    c.put_object(Bucket="sealed", Key="secret", Body=b"S" * 200000, ServerSideEncryption="AES256")
    c.create_bucket(Bucket="kept")
    c.put_bucket_versioning(Bucket="kept", VersioningConfiguration={"Status": "Enabled"})
    old = c.put_object(Bucket="kept", Key="k", Body=b"OLDVERSION" * 50)["VersionId"]
    c.put_object(Bucket="kept", Key="k", Body=b"NEWVERSION" * 50)
    passes = stats(name).get("scrub_passes", 0)
    check("a pass reads every version", wait_for(lambda: stats(name).get("scrub_passes", 0) >= passes + 2, 40) and
          stats(name).get("scrub_objects", 0) >= 5, stats(name))
    s = stats(name)
    check("and finds none corrupt", s.get("scrub_corrupt") == 0 and s.get("scrub_skipped") == 0, s)
    check("having read their bytes", s.get("scrub_bytes", 0) >= (10 << 20) + 200000, s)

    flip(files_with(os.path.join(data, "plain"), b"SMALLOBJECT")[0])
    check("a plain object whose file changed is found", corrupt_after(name, 1), stats(name))
    flip(files_with(os.path.join(data, "plain"), b"PPPPPPPPPP" * 100)[0], back=(5 << 20) + 100)
    check("a multipart object whose first part changed is found", corrupt_after(name, 2), stats(name))
    sealed = [p for p in files_with(os.path.join(data, "sealed"), b"") if "/data/" in p]
    flip(sealed[0], back=1000)
    check("an SSE-S3 object whose sealed bytes changed is found", corrupt_after(name, 3), stats(name))
    flip(files_with(os.path.join(data, "kept"), b"OLDVERSION")[0])
    check("a noncurrent version whose file changed is found", corrupt_after(name, 4), stats(name))
    check("and with no other node it stays, to be restored from a copy", body(c, "kept", "k", old) != "NoSuchVersion")


def heal():
    a_name, a_port = sys.argv[2].split(":")
    data = sys.argv[3]
    b_name, b_port = sys.argv[4].split(":")
    a, b = client(int(a_port)), client(int(b_port))
    a.create_bucket(Bucket="hplain")
    a.put_object(Bucket="hplain", Key="obj", Body=b"HEALPLAIN" * 1000)
    a.create_bucket(Bucket="hkept")
    a.put_bucket_versioning(Bucket="hkept", VersioningConfiguration={"Status": "Enabled"})
    v1 = a.put_object(Bucket="hkept", Key="k", Body=b"HEALOLD" * 1000)["VersionId"]
    v2 = a.put_object(Bucket="hkept", Key="k", Body=b"HEALNEW" * 1000)["VersionId"]
    check("the other node has every copy",
          wait_for(lambda: body(b, "hplain", "obj") == b"HEALPLAIN" * 1000 and
                   body(b, "hkept", "k", v1) == b"HEALOLD" * 1000))
    flip(files_with(os.path.join(data, "hplain"), b"HEALPLAIN")[0])
    flip(files_with(os.path.join(data, "hkept"), b"HEALOLD")[0])
    check("the node finds both copies corrupt", corrupt_after(a_name, 2), stats(a_name))
    check("and has the other node send them again",
          wait_for(lambda: stats(a_name).get("scrub_heals", 0) >= 2), stats(a_name))
    check("an object of a bucket that keeps no versions is whole again",
          wait_for(lambda: body(a, "hplain", "obj") == b"HEALPLAIN" * 1000), body(a, "hplain", "obj")[:40])
    check("and a noncurrent version, under its id, behind the latest",
          wait_for(lambda: body(a, "hkept", "k", v1) == b"HEALOLD" * 1000) and
          body(a, "hkept", "k") == b"HEALNEW" * 1000 and body(a, "hkept", "k", v2) == b"HEALNEW" * 1000)
    seen = stats(a_name).get("scrub_corrupt", 0)
    passes = stats(a_name).get("scrub_passes", 0)
    wait_for(lambda: stats(a_name).get("scrub_passes", 0) >= passes + 2, 30)
    check("and the passes after find nothing more", stats(a_name).get("scrub_corrupt", 0) == seen, stats(a_name))
    check("the other node removed nothing", body(b, "hkept", "k", v1) == b"HEALOLD" * 1000 and
          body(b, "hplain", "obj") == b"HEALPLAIN" * 1000)


{"alone": alone, "heal": heal}[MODE]()
print("  scrub: PASS=%d FAIL=%d" % (passed, failed))
sys.exit(failed)
