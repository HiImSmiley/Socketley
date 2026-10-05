#!/usr/bin/env python3
"""A cluster of three storage runtimes, driven with boto3.

usage: lib_storage_cluster.py A B C

A, B and C are name:port of the three nodes, C with two shards.  Every node is signed for with ADMIN_AK/ADMIN_SK.
Prints one PASS or FAIL line per assertion and exits with the number of failures.
"""
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

BIN = os.environ["BIN"]
ADMIN = (os.environ["ADMIN_AK"], os.environ["ADMIN_SK"])
NODES = [(n.split(":")[0], int(n.split(":")[1])) for n in sys.argv[1:4]]
WAIT = 25

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


A, B, C = (client(p) for _, p in NODES)
ALL = [A, B, C]
NAMES = {id(A): NODES[0][0], id(B): NODES[1][0], id(C): NODES[2][0]}


def call(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except ClientError as e:
        return e.response.get("Error", {}).get("Code") or str(e.response.get("ResponseMetadata", {}).get("HTTPStatusCode"))


def wait_for(fn, timeout=WAIT):
    end = time.time() + timeout
    v = None
    while time.time() < end:
        try:
            v = fn()
        except Exception as e:
            v = None
        if v:
            return v
        time.sleep(0.1)
    return v


def runtime(c, verb):
    subprocess.run([BIN, verb, NAMES[id(c)]], capture_output=True)
    if verb == "start":
        wait_for(lambda: isinstance(call(c.list_buckets), dict), 15)


def body(c, bucket, key):
    r = call(c.get_object, Bucket=bucket, Key=key)
    return r["Body"].read() if isinstance(r, dict) else r


def head(c, bucket, key, **kw):
    return call(c.head_object, Bucket=bucket, Key=key, **kw)


def objects(c, bucket):
    r = call(c.list_objects_v2, Bucket=bucket)
    if not isinstance(r, dict):
        return r
    return sorted((o["Key"], o["ETag"], o["LastModified"].isoformat()) for o in r.get("Contents", []))


def versions(c, bucket):
    r = call(c.list_object_versions, Bucket=bucket)
    if not isinstance(r, dict):
        return r
    v = [(x["Key"], x["VersionId"], x["IsLatest"], x["ETag"], x["LastModified"].isoformat()) for x in r.get("Versions", [])]
    m = [(x["Key"], x["VersionId"], x["IsLatest"], "marker", x["LastModified"].isoformat())
         for x in r.get("DeleteMarkers", [])]
    return sorted(v + m)


def same(fn, nodes=ALL):
    """Waits until every node answers `fn` alike, and returns what they answer."""
    got = wait_for(lambda: (lambda xs: xs if all(x == xs[0] for x in xs) else None)([fn(n) for n in nodes]))
    return got[0] if got else [fn(n) for n in nodes]


def stats(c):
    out = subprocess.run([BIN, "stats", NAMES[id(c)]], capture_output=True, text=True).stdout
    total = {}
    for line in out.splitlines():
        if ":" in line and not line.startswith("["):
            k, v = line.split(":", 1)
            try:
                total[k.strip()] = total.get(k.strip(), 0) + int(v.strip())
            except ValueError:
                pass
    return total


# ── buckets and plain objects ───────────────────────────────────────────────
P = "cl-plain"
check("a bucket made on one node", isinstance(call(A.create_bucket, Bucket=P), dict))
check("is made on the others", wait_for(lambda: all(isinstance(call(c.head_bucket, Bucket=P), dict) for c in [B, C])))

A.put_object(Bucket=P, Key="a.txt", Body=b"made on a", ContentType="text/x-a", Metadata={"who": "a"})
check("an object written on one node is read on every other",
      wait_for(lambda: all(body(c, P, "a.txt") == b"made on a" for c in [B, C])))
ha, hb, hc = (head(c, P, "a.txt") for c in ALL)
check("with its ETag, type, metadata and the time it was written there",
      all(isinstance(h, dict) for h in (hb, hc)) and
      all((h["ETag"], h["ContentType"], h["Metadata"], h["LastModified"]) ==
          (ha["ETag"], ha["ContentType"], ha["Metadata"], ha["LastModified"]) for h in (hb, hc)), (ha, hb, hc))
check("and no replication status", all("ReplicationStatus" not in h for h in (ha, hb, hc)))

B.put_object(Bucket=P, Key="b.txt", Body=b"made on b")
wait_for(lambda: body(C, P, "b.txt") == b"made on b")
C.delete_object(Bucket=P, Key="b.txt")
check("a removal on one node removes the object on every other",
      wait_for(lambda: all(head(c, P, "b.txt") in ("404", "NoSuchKey") for c in ALL)))

part = os.urandom(5 << 20)
up = B.create_multipart_upload(Bucket=P, Key="multi.bin")
etags = [B.upload_part(Bucket=P, Key="multi.bin", UploadId=up["UploadId"], PartNumber=n, Body=part)["ETag"]
         for n in (1, 2)]
B.complete_multipart_upload(Bucket=P, Key="multi.bin", UploadId=up["UploadId"],
                            MultipartUpload={"Parts": [{"ETag": e, "PartNumber": n + 1} for n, e in enumerate(etags)]})
mb = head(B, P, "multi.bin")
check("a multipart object is sent in its parts, with its ETag",
      wait_for(lambda: all(isinstance(h, dict) and h["ETag"] == mb["ETag"] and h["ContentLength"] == 10 << 20
                           for h in (head(A, P, "multi.bin"), head(C, P, "multi.bin")))), mb.get("ETag"))
check("and its bytes", body(C, P, "multi.bin") == part + part)

C.put_object_tagging(Bucket=P, Key="a.txt", Tagging={"TagSet": [{"Key": "t", "Value": "from-c"}]})
check("a tag set on one node is on every other",
      wait_for(lambda: all(call(c.get_object_tagging, Bucket=P, Key="a.txt").get("TagSet") ==
                           [{"Key": "t", "Value": "from-c"}] for c in [A, B])))

check("every node lists the same objects", same(lambda c: objects(c, P)) == objects(A, P), [objects(c, P) for c in ALL])

# ── the later write wins, whichever arrives first ──────────────────────────
# B is down while A writes, then A is down while C writes later: B hears C's write first and A's older one last.
runtime(B, "stop")
A.put_object(Bucket=P, Key="race.txt", Body=b"older, from a")
wait_for(lambda: body(C, P, "race.txt") == b"older, from a")
runtime(A, "stop")
time.sleep(0.05)
C.put_object(Bucket=P, Key="race.txt", Body=b"newer, from c")
runtime(B, "start")
wait_for(lambda: body(B, P, "race.txt") == b"newer, from c")
runtime(A, "start")
check("a node that hears a newer write before an older one keeps the newer",
      same(lambda c: body(c, P, "race.txt")) == b"newer, from c", [body(c, P, "race.txt") for c in ALL])
time.sleep(1.5)
check("and still does once the older one has come", [body(c, P, "race.txt") for c in ALL] == [b"newer, from c"] * 3,
      [body(c, P, "race.txt") for c in ALL])

# B is down while A writes and C removes after: whichever B hears first, the removal wins.
runtime(B, "stop")
A.put_object(Bucket=P, Key="gone.txt", Body=b"written before its removal")
wait_for(lambda: body(C, P, "gone.txt") == b"written before its removal")
runtime(A, "stop")
C.delete_object(Bucket=P, Key="gone.txt")
runtime(B, "start")
time.sleep(1)
runtime(A, "start")
time.sleep(1.5)
check("a removal made after a write wins on a node that hears the write last",
      wait_for(lambda: all(head(c, P, "gone.txt") in ("404", "NoSuchKey") for c in ALL)),
      [head(c, P, "gone.txt") for c in ALL])

# A node removes a key it has not heard of yet: the others, which have it, remove it too.
runtime(B, "stop")
A.put_object(Bucket=P, Key="unheard.txt", Body=b"not on b yet")
wait_for(lambda: body(C, P, "unheard.txt") == b"not on b yet")
runtime(A, "stop")
runtime(B, "start")
check("a node removes a key it has not heard of yet", head(B, P, "unheard.txt") in ("404", "NoSuchKey") and
      isinstance(call(B.delete_object, Bucket=P, Key="unheard.txt"), dict))
runtime(A, "start")
check("and every node that had it removes it, the late write included",
      wait_for(lambda: all(head(c, P, "unheard.txt") in ("404", "NoSuchKey") for c in ALL)),
      [head(c, P, "unheard.txt") for c in ALL])

# ── versions ────────────────────────────────────────────────────────────────
V = "cl-ver"
A.create_bucket(Bucket=V)
wait_for(lambda: isinstance(call(B.head_bucket, Bucket=V), dict) and isinstance(call(C.head_bucket, Bucket=V), dict))
A.put_bucket_versioning(Bucket=V, VersioningConfiguration={"Status": "Enabled"})
check("a bucket's versioning set on one node is every node's",
      wait_for(lambda: all(c.get_bucket_versioning(Bucket=V).get("Status") == "Enabled" for c in [B, C])))
v1 = A.put_object(Bucket=V, Key="k", Body=b"one")["VersionId"]
wait_for(lambda: isinstance(head(B, V, "k", VersionId=v1), dict))
v2 = B.put_object(Bucket=V, Key="k", Body=b"two")["VersionId"]
check("every node keeps every version under the id its node gave it",
      same(lambda c: versions(c, V)) == versions(A, V) and {x[1] for x in versions(A, V)} == {v1, v2},
      [versions(c, V) for c in ALL])
m = C.delete_object(Bucket=V, Key="k")
check("a delete marker made on one node is the latest on every other, under its id",
      wait_for(lambda: all(any(x[1] == m.get("VersionId") and x[2] and x[3] == "marker" for x in versions(c, V))
                           for c in [A, B])), [versions(c, V) for c in ALL])
A.delete_object(Bucket=V, Key="k", VersionId=v1)
check("a version removed for good on one node is gone from every other",
      wait_for(lambda: all(v1 not in {x[1] for x in versions(c, V)} for c in [B, C])))

# An older version heard after a newer one goes behind it, so every node has the same latest.
runtime(B, "stop")
va = A.put_object(Bucket=V, Key="late", Body=b"from a")["VersionId"]
wait_for(lambda: isinstance(head(C, V, "late", VersionId=va), dict))
runtime(A, "stop")
time.sleep(0.05)
vc = C.put_object(Bucket=V, Key="late", Body=b"from c")["VersionId"]
runtime(B, "start")
wait_for(lambda: isinstance(head(B, V, "late", VersionId=vc), dict))
runtime(A, "start")
check("a version older than the latest goes behind it on the node that hears it last",
      wait_for(lambda: isinstance(head(B, V, "late", VersionId=va), dict)) and body(B, V, "late") == b"from c",
      versions(B, V))
check("and every node lists the same versions of every key", same(lambda c: versions(c, V)) == versions(A, V),
      [versions(c, V) for c in ALL])

# ── a bucket's documents and an object's lock ───────────────────────────────
A.put_bucket_tagging(Bucket=P, Tagging={"TagSet": [{"Key": "team", "Value": "x"}]})
check("a bucket's tags set on one node are every node's",
      wait_for(lambda: all(call(c.get_bucket_tagging, Bucket=P).get("TagSet") == [{"Key": "team", "Value": "x"}]
                           for c in [B, C])))
B.put_bucket_cors(Bucket=P, CORSConfiguration={"CORSRules": [{"AllowedMethods": ["GET"], "AllowedOrigins": ["*"]}]})
check("and its CORS rules",
      wait_for(lambda: all(isinstance(call(c.get_bucket_cors, Bucket=P), dict) for c in [A, C])))
B.delete_bucket_cors(Bucket=P)
check("and their removal", wait_for(lambda: all(call(c.get_bucket_cors, Bucket=P) == "NoSuchCORSConfiguration"
                                                for c in [A, C])))

L = "cl-lock"
A.create_bucket(Bucket=L, ObjectLockEnabledForBucket=True)
check("a bucket made with object lock has it on every node",
      wait_for(lambda: all(call(c.get_object_lock_configuration, Bucket=L).get("ObjectLockConfiguration", {})
                           .get("ObjectLockEnabled") == "Enabled" for c in [B, C])))
until = (datetime.now(timezone.utc) + timedelta(days=1)).replace(microsecond=0)
lv = A.put_object(Bucket=L, Key="held", Body=b"x", ObjectLockMode="GOVERNANCE",
                  ObjectLockRetainUntilDate=until)["VersionId"]
check("a version's retention is every node's",
      wait_for(lambda: all(isinstance(h, dict) and h.get("ObjectLockMode") == "GOVERNANCE" and
                           h.get("ObjectLockRetainUntilDate") == until
                           for h in (head(B, L, "held", VersionId=lv), head(C, L, "held", VersionId=lv)))),
      head(B, L, "held", VersionId=lv))
A.put_object_legal_hold(Bucket=L, Key="held", VersionId=lv, LegalHold={"Status": "ON"})
check("and a legal hold set later",
      wait_for(lambda: all(call(c.get_object_legal_hold, Bucket=L, Key="held", VersionId=lv)
                           .get("LegalHold", {}).get("Status") == "ON" for c in [B, C])))
check("which keeps the version on a node it was not set on",
      call(C.delete_object, Bucket=L, Key="held", VersionId=lv) == "AccessDenied")

# ── nothing comes back, and nothing is lost ────────────────────────────────
wait_for(lambda: all(stats(c).get("cluster_pending", 1) == 0 for c in ALL))
before = stats(B).get("cluster_sent", 0)
A.put_object(Bucket=P, Key="once.txt", Body=b"once")
wait_for(lambda: body(B, P, "once.txt") == b"once")
time.sleep(1)
check("a node does not send on another node's write", stats(B).get("cluster_sent", 0) == before,
      (before, stats(B)))
check("every node has sent everything, and nothing was refused",
      wait_for(lambda: all(stats(c).get("cluster_pending", 1) == 0 for c in ALL)) and
      all(stats(c).get("cluster_failed", 1) == 0 for c in ALL), [stats(c) for c in ALL])
check("and took bucket changes from the others", all(stats(c).get("cluster_in", 0) > 0 for c in ALL))

# ── a bucket removed ────────────────────────────────────────────────────────
for o in A.list_objects_v2(Bucket=P).get("Contents", []):
    A.delete_object(Bucket=P, Key=o["Key"])
check("a bucket emptied on one node is empty on every other", same(lambda c: objects(c, P)) == [],
      [objects(c, P) for c in ALL])
check("and removed there", isinstance(call(A.delete_bucket, Bucket=P), dict))
check("is removed on every other", wait_for(lambda: all(call(c.head_bucket, Bucket=P) == "404" for c in [B, C])))

print("  cluster: PASS=%d FAIL=%d" % (passed, failed))
sys.exit(failed)
