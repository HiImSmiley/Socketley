#!/usr/bin/env python3
"""A cluster of storage runtimes, driven with boto3.

usage: lib_storage_cluster.py MODE NODE...

  main A B C      everything made on one node is on the others, in every order of arrival; C has two shards
  join A B C D    D joined a cluster that holds data, and is sent all of it
  same A X        X, which began again empty, holds what A holds
  sync A B C D    the nodes answer a write once the three others have it, or after 2 s

A NODE is name:port.  Every node is signed for with ADMIN_AK/ADMIN_SK.  Prints one PASS or FAIL line per assertion
and exits with the number of failures.
"""
import base64
import json
import os
import subprocess
import urllib.error
import urllib.request
import sys
import time
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

BIN = os.environ["BIN"]
ADMIN = (os.environ["ADMIN_AK"], os.environ["ADMIN_SK"])
MODE = sys.argv[1]
NODES = [(n.split(":")[0], int(n.split(":")[1])) for n in sys.argv[2:]]
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


CLIENTS = [client(p) for _, p in NODES]
NAMES = {id(c): n for c, (n, _) in zip(CLIENTS, NODES)}


def iam(port):
    cfg = Config(retries={"max_attempts": 1})
    return boto3.client("iam", endpoint_url="http://127.0.0.1:%d" % port, region_name="", config=cfg,
                        aws_access_key_id=ADMIN[0], aws_secret_access_key=ADMIN[1])


def as_user(port, key):
    cfg = Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1})
    return boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % port, region_name="us-east-1", config=cfg,
                        aws_access_key_id=key[0], aws_secret_access_key=key[1])


def users(port):
    return sorted(u["UserName"] for u in iam(port).list_users()["Users"])


def share(port, method, path="", body=None):
    """A request to a node's /~share as the admin, its JSON or the status it failed with."""
    auth = "Basic " + base64.b64encode(("%s:%s" % ADMIN).encode()).decode()
    req = urllib.request.Request("http://127.0.0.1:%d/~share%s" % (port, path), method=method,
                                 data=None if body is None else json.dumps(body).encode(), headers={"Authorization": auth})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            text = r.read()
            return json.loads(text) if text.startswith((b"{", b"[")) else r.status
    except urllib.error.HTTPError as e:
        return e.code


def fetch(port, path, method="GET"):
    try:
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), method=method)
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read() if method == "GET" else r.status
    except urllib.error.HTTPError as e:
        return e.code


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


def same(fn, nodes=None):
    """Waits until every node answers `fn` alike, and returns what they answer."""
    nodes = nodes or CLIENTS
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


def main():
    A, B, C = CLIENTS
    ALL = CLIENTS
    P = "cl-plain"
    # ── buckets and plain objects ───────────────────────────────────────────────
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

    # The same, with B started again between hearing the removal and hearing the write: it still knows the removal.
    runtime(B, "stop")
    A.put_object(Bucket=P, Key="gone2.txt", Body=b"written before its removal")
    wait_for(lambda: body(C, P, "gone2.txt") == b"written before its removal")
    runtime(A, "stop")
    C.delete_object(Bucket=P, Key="gone2.txt")
    runtime(B, "start")
    wait_for(lambda: stats(C).get("cluster_pending", 1) <= 1)
    time.sleep(0.5)
    runtime(B, "stop")
    runtime(B, "start")
    runtime(A, "start")
    time.sleep(1.5)
    check("and on one started again after it heard the removal",
          wait_for(lambda: all(head(c, P, "gone2.txt") in ("404", "NoSuchKey") for c in ALL)),
          [head(c, P, "gone2.txt") for c in ALL])

    # A node so far behind that its queue is let go is sent everything, its removals too, once it answers.
    for i in range(6):
        A.put_object(Bucket=P, Key="behind-%d" % i, Body=b"before")
    wait_for(lambda: all(head(c, P, "behind-5") not in ("404", "NoSuchKey") for c in [B, C]))
    runtime(B, "stop")
    for i in range(3):
        A.delete_object(Bucket=P, Key="behind-%d" % i)
    for i in range(60):
        A.put_object(Bucket=P, Key="flood-%02d" % i, Body=b"while b was away")
    check("a node far behind has its queue let go", wait_for(lambda: stats(A).get("cluster_overflows", 0) >= 1),
          {k: v for k, v in stats(A).items() if k.startswith("cluster") or k in ("puts", "deletes")})
    runtime(B, "start")
    check("and is sent everything once it is back, the removals too",
          same(lambda c: objects(c, P), [A, B]) == objects(A, P), (objects(A, P), objects(B, P)))

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

    # ── share links ────────────────────────────────────────────────────────────
    def made(c):
        r = call(c.list_buckets)
        return [x["CreationDate"] for x in (r.get("Buckets", []) if isinstance(r, dict) else []) if x["Name"] == P]
    check("a bucket was made at the same time on every node, which a link of it is bound to",
          len(made(A)) == 1 and made(A) == made(B) == made(C), [made(c) for c in (A, B, C)])
    A.put_object(Bucket=P, Key="shared.txt", Body=b"shared from a")
    wait_for(lambda: body(B, P, "shared.txt") == b"shared from a" and body(C, P, "shared.txt") == b"shared from a")
    link = share(NODES[0][1], "POST", body={"bucket": P, "key": "shared.txt", "max_downloads": 5})
    lid = link.get("id") if isinstance(link, dict) else None
    check("a link made on one node opens on every other",
          lid and wait_for(lambda: all(fetch(p, "/~share/" + lid, "HEAD") == 200 for _, p in NODES[1:])) and
          fetch(NODES[1][1], "/~share/" + lid) == b"shared from a", link)
    fetch(NODES[1][1], "/~share/" + lid)
    fetch(NODES[2][1], "/~share/" + lid)
    counted = lambda port: [x.get("downloads") for x in (share(port, "GET") or []) if x.get("id") == lid]
    check("and every node adds up the downloads all of them counted",
          wait_for(lambda: all(counted(p) == [3] for _, p in NODES)), [counted(p) for _, p in NODES])
    check("a link revoked on one node", share(NODES[2][1], "DELETE", "/" + lid) == 204)
    check("is gone from every other", wait_for(lambda: all(fetch(p, "/~share/" + lid) == 404 for _, p in NODES)))

    # ── the IAM API's users ─────────────────────────────────────────────────────
    iam(NODES[0][1]).create_user(UserName="cl-user")
    k = iam(NODES[0][1]).create_access_key(UserName="cl-user")["AccessKey"]
    check("a user made through IAM on one node is every node's",
          wait_for(lambda: all("cl-user" in users(p) for _, p in NODES[1:])))
    check("and its key signs on every other",
          wait_for(lambda: isinstance(call(as_user(NODES[2][1], (k["AccessKeyId"], k["SecretAccessKey"])).list_buckets),
                                      dict)))
    iam(NODES[1][1]).create_user(UserName="cl-user-b")
    check("and a user made on another node after it joins it there",
          wait_for(lambda: all(users(p) == ["cl-user", "cl-user-b"] for _, p in NODES)), [users(p) for _, p in NODES])

    # ── nothing comes back, and nothing is lost ────────────────────────────────
    # Every node has sent what it made, by stats that held still for a second, which lag the work behind them.
    snap = lambda: [(stats(c).get("cluster_pending", 1), stats(c).get("cluster_seeding", 1),
                     stats(c).get("cluster_sent", 0)) for c in ALL]
    wait_for(lambda: (lambda a: a[0][:2] == (0, 0) and all(x[:2] == (0, 0) for x in a) and
                      (time.sleep(1.2) or snap() == a))(snap()), 40)
    before = stats(B).get("cluster_sent", 0)
    A.put_object(Bucket=P, Key="once.txt", Body=b"once")
    wait_for(lambda: body(B, P, "once.txt") == b"once")
    time.sleep(1)
    check("a node does not send on another node's write", stats(B).get("cluster_sent", 0) == before,
          (before, {k: v for k, v in stats(B).items() if k.startswith("cluster") or k.startswith("replication")}))
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


def doc(fn, **kw):
    r = call(fn, **kw)
    if isinstance(r, dict):
        r = {k: v for k, v in r.items() if k != "ResponseMetadata"}
    return str(r)


def holdings(c):
    """Every bucket of a node with its versioning, lock, tags and every version or object it lists."""
    r = call(c.list_buckets)
    if not isinstance(r, dict):
        return r
    out = []
    for b in sorted(x["Name"] for x in r["Buckets"]):
        out.append((b, doc(c.get_bucket_versioning, Bucket=b), doc(c.get_object_lock_configuration, Bucket=b),
                    doc(c.get_bucket_tagging, Bucket=b), versions(c, b), objects(c, b)))
    return out


def join():
    A, D = CLIENTS[0], CLIENTS[3]
    want = holdings(A)
    check("the nodes had buckets for the new one", len(want) >= 3, want)
    got = wait_for(lambda: holdings(D) == want and holdings(D), 90)
    check("a node that joins a cluster holding data is sent all of it, versions, markers, locks and documents",
          got == want, [x for x in zip(holdings(D) or [], want) if x[0] != x[1]][:2])
    lv = [x for x in versions(A, "cl-lock") if x[0] == "held"]
    check("and a version's retention and legal hold",
          bool(lv) and head(D, "cl-lock", "held", VersionId=lv[0][1]).get("ObjectLockMode") == "GOVERNANCE" and
          call(D.get_object_legal_hold, Bucket="cl-lock", Key="held", VersionId=lv[0][1])
          .get("LegalHold", {}).get("Status") == "ON")
    check("and the bytes of a multipart object", body(D, "cl-keep", "multi.bin") == body(A, "cl-keep", "multi.bin"))
    check("and the IAM API's users", users(NODES[3][1]) == users(NODES[0][1]) == ["cl-user", "cl-user-b"],
          (users(NODES[3][1]), users(NODES[0][1])))
    check("every other node has sent it what it holds",
          wait_for(lambda: all(stats(c).get("cluster_pending", 1) == 0 for c in CLIENTS), 60) and
          all(stats(c).get("cluster_seeds", 0) >= 1 for c in CLIENTS[:3]),
          [{k: v for k, v in stats(c).items() if k.startswith("cluster")} for c in CLIENTS])
    check("and nothing was refused", all(stats(c).get("cluster_failed", 1) == 0 for c in CLIENTS))
    D.put_object(Bucket="cl-keep", Key="from-d", Body=b"written on the new node")
    check("and the new node's own writes reach the others",
          wait_for(lambda: all(body(c, "cl-keep", "from-d") == b"written on the new node" for c in CLIENTS[:3])))


def again():
    A, X = CLIENTS
    want = holdings(A)
    got = wait_for(lambda: holdings(X) == want and holdings(X), 90)
    check("a node that began again empty is sent everything again", got == want,
          [x for x in zip(holdings(X) or [], want) if x[0] != x[1]][:2])


def keep():
    A = CLIENTS[0]
    A.create_bucket(Bucket="cl-keep")
    for i in range(40):
        A.put_object(Bucket="cl-keep", Key="k%02d" % i, Body=b"x" * i)
    part = os.urandom(5 << 20)
    up = A.create_multipart_upload(Bucket="cl-keep", Key="multi.bin")
    tags = [A.upload_part(Bucket="cl-keep", Key="multi.bin", UploadId=up["UploadId"], PartNumber=n, Body=part)["ETag"]
            for n in (1, 2)]
    A.complete_multipart_upload(Bucket="cl-keep", Key="multi.bin", UploadId=up["UploadId"],
                                MultipartUpload={"Parts": [{"ETag": e, "PartNumber": n + 1} for n, e in enumerate(tags)]})
    check("the nodes hold the same before one joins", same(lambda c: holdings(c), CLIENTS) == holdings(A))


def sync():
    A, B, C, D = CLIENTS
    A.create_bucket(Bucket="cl-sync")
    wait_for(lambda: all(isinstance(call(c.head_bucket, Bucket="cl-sync"), dict) for c in CLIENTS[1:]))
    had = []
    for i in range(10):
        t = time.time()
        A.put_object(Bucket="cl-sync", Key="s%d" % i, Body=b"synced")
        took = time.time() - t
        had.append((all(isinstance(head(c, "cl-sync", "s%d" % i), dict) for c in (B, C, D)), round(took, 3),
                    [head(c, "cl-sync", "s%d" % i) if not isinstance(head(c, "cl-sync", "s%d" % i), dict) else 1
                     for c in (B, C, D)]))
    check("with sync, every other node has a write by the time it is answered", all(h[0] for h in had),
          (had, {k: v for k, v in stats(A).items() if k.startswith("cluster")}))
    check("and the writes are counted as synced", wait_for(lambda: stats(A).get("cluster_synced", 0) >= 10),
          {k: v for k, v in stats(A).items() if k.startswith("cluster")})
    runtime(D, "stop")
    t = time.time()
    A.put_object(Bucket="cl-sync", Key="late", Body=b"one node is down")
    took = time.time() - t
    check("a write a node that is down cannot take is answered once its wait of 2 s is over", 1.8 <= took < 6, took)
    check("and counted so", wait_for(lambda: stats(A).get("cluster_sync_timeouts", 0) >= 1),
          {k: v for k, v in stats(A).items() if k.startswith("cluster")})
    check("the nodes that are up have it", all(isinstance(head(c, "cl-sync", "late"), dict) for c in (B, C)))
    runtime(D, "start")
    check("and the one that was down has it once it is back",
          wait_for(lambda: isinstance(head(D, "cl-sync", "late"), dict)))


{"main": main, "join": join, "same": again, "keep": keep, "sync": sync}[MODE]()
print("  cluster: PASS=%d FAIL=%d" % (passed, failed))
sys.exit(failed)
