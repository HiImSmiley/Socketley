#!/usr/bin/env python3
"""S3 bucket replication from one storage runtime to another, driven with boto3 and raw HTTP.

usage: lib_storage_replication.py MODE ARGS...

  main SRC DST          the configuration's put, get and delete and their refusals; versions, overwrites and delete
                        markers copied by prefix and tag rules, and the ones they leave; metadata, tags, checksums,
                        an SSE-S3 object and a multipart object equal on the replica; PENDING, COMPLETED, FAILED and
                        REPLICA; the stats lines
  policy DST            a replication user that may only replicate: its copies land, its own writes do not, and a
                        user that may only read cannot write a replica
  down SRC DST          the destination is stopped while versions are written and started again: they are copied
  crash SRC DST SLOW DATA
                        the source worker is killed with SIGKILL while versions wait for a stopped destination, and
                        again in the middle of a slow copy and of a PUT never answered: everything answered is copied
                        after the restart, and nothing that was not
  shards DST NODE0 NODE1
                        two shards of the source, one node each: every version and delete marker through either is
                        copied once, by the shard that owns its key
  loop SRC DST          two buckets that replicate to each other: a version or a delete marker crosses once and does
                        not come back

SRC and DST are the ports of the source runtime (anonymous) and of the destination (signed, with users).
The destination's keys come from the environment: ADMIN_AK/ADMIN_SK, REPL_AK/REPL_SK (may only replicate) and
READ_AK/READ_SK (may only read).  Prints one PASS or FAIL line per assertion and exits with the number of failures.
"""
import hashlib
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET

import boto3
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

MODE = sys.argv[1]
BIN = os.environ.get("BIN", "")
E = os.environ
ADMIN = (E.get("ADMIN_AK", ""), E.get("ADMIN_SK", ""))
REPL = (E.get("REPL_AK", ""), E.get("REPL_SK", ""))
READ = (E.get("READ_AK", ""), E.get("READ_SK", ""))
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
ROLE = "arn:aws:iam::123456789012:role/"
SB = "rsrc-b"
DB = "rdst-b"

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name, flush=True)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, str(detail)[:800]), flush=True)


def wait_for(fn, timeout, every=0.1):
    end = time.time() + timeout
    while time.time() < end:
        try:
            v = fn()
        except Exception:
            v = None
        if v:
            return v
        time.sleep(every)
    try:
        return fn()
    except Exception:
        return None


def client(port, key=None):
    cfg = Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1},
                 signature_version=UNSIGNED if key is None else "s3v4")
    kw = {} if key is None else {"aws_access_key_id": key[0], "aws_secret_access_key": key[1]}
    return boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % port, region_name="us-east-1", config=cfg, **kw)


def code(e):
    return e.response.get("Error", {}).get("Code") if isinstance(e, ClientError) else repr(e)


def call(fn, *a, **kw):
    """The call's result, or the S3 error code it raised."""
    try:
        return fn(*a, **kw)
    except ClientError as e:
        return code(e)


def status(c, bucket, key, version=None):
    kw = {"Bucket": bucket, "Key": key}
    if version:
        kw["VersionId"] = version
    r = call(c.head_object, **kw)
    return r.get("ReplicationStatus", "") if isinstance(r, dict) else r


def body(c, bucket, key):
    r = call(c.get_object, Bucket=bucket, Key=key)
    return r["Body"].read() if isinstance(r, dict) else r


def versions(c, bucket, prefix):
    r = c.list_object_versions(Bucket=bucket, Prefix=prefix)
    return ([(v["Key"], v["IsLatest"]) for v in r.get("Versions", [])],
            [(m["Key"], m["IsLatest"]) for m in r.get("DeleteMarkers", [])])


def version_ids(c, bucket, key):
    r = c.list_object_versions(Bucket=bucket, Prefix=key)
    return ([v["VersionId"] for v in r.get("Versions", []) if v["Key"] == key],
            [m["VersionId"] for m in r.get("DeleteMarkers", []) if m["Key"] == key])


def stats(runtime):
    out = subprocess.run([BIN, "stats", runtime], capture_output=True, text=True).stdout
    shards, cur = {}, 0
    for line in out.splitlines():
        if line.startswith("[shard "):
            cur = int(line[7:].rstrip("]"))
            shards[cur] = {}
        elif ":" in line:
            k, v = line.split(":", 1)
            shards.setdefault(cur, {})[k.strip()] = v.strip()
    return shards


def stat(runtime, name):
    return sum(int(s.get(name, "0") or 0) for s in stats(runtime).values())


def rstats(runtime):
    return {k: {n: v for n, v in s.items() if n.startswith("replication_")} for k, s in stats(runtime).items()}


def worker_pid(runtime):
    for s in stats(runtime).values():
        if s.get("pid"):
            return s["pid"]
    return None


def rule(rid, prio, dest, prefix=None, tags=None, markers=True, storage_class=None):
    r = {"ID": rid, "Priority": prio, "Status": "Enabled", "Destination": {"Bucket": "arn:aws:s3:::" + dest},
         "DeleteMarkerReplication": {"Status": "Enabled" if markers else "Disabled"}}
    if tags:
        r["Filter"] = {"And": {"Prefix": prefix or "", "Tags": [{"Key": k, "Value": v} for k, v in tags]}}
    else:
        r["Filter"] = {"Prefix": prefix or ""}
    if storage_class:
        r["Destination"]["StorageClass"] = storage_class
    return r


def config(target, *rules):
    return {"Role": ROLE + target, "Rules": list(rules)}


def versioned(c, bucket):
    call(c.create_bucket, Bucket=bucket)
    c.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})


def run(*args):
    return subprocess.run([BIN] + list(args), capture_output=True, text=True)


def wait_up(port, timeout=20):
    def up():
        s = socket.socket()
        s.settimeout(1)
        try:
            s.connect(("127.0.0.1", port))
            return True
        except OSError:
            return False
        finally:
            s.close()
    return wait_for(up, timeout)


# ── main ────────────────────────────────────────────────────────────────────
def mode_main(sp, dp):
    src = client(sp)
    dst = client(dp, ADMIN)
    versioned(src, SB)
    versioned(dst, DB)
    src.create_bucket(Bucket="rsrc-plain")

    # The configuration and its refusals.
    good = config("dst", rule("docs", 1, DB, prefix="docs/"),
                  rule("hot", 2, DB, prefix="img/", tags=[("class", "hot")], markers=False,
                       storage_class="STANDARD_IA"))
    check("a bucket without a configuration answers ReplicationConfigurationNotFoundError",
          call(src.get_bucket_replication, Bucket=SB) == "ReplicationConfigurationNotFoundError")
    check("a bucket that is not versioned is refused a configuration",
          call(src.put_bucket_replication, Bucket="rsrc-plain", ReplicationConfiguration=good) == "InvalidRequest")
    check("a Role that names no target is refused",
          call(src.put_bucket_replication, Bucket=SB,
               ReplicationConfiguration=config("nosuch", rule("r", 1, DB))) == "InvalidArgument")
    check("delete marker replication with a tag filter is refused",
          call(src.put_bucket_replication, Bucket=SB,
               ReplicationConfiguration=config("dst", rule("r", 1, DB, tags=[("a", "b")]))) == "InvalidRequest")
    eor = rule("r", 1, DB)
    eor["ExistingObjectReplication"] = {"Status": "Enabled"}
    check("existing object replication is refused as not implemented",
          call(src.put_bucket_replication, Bucket=SB, ReplicationConfiguration=config("dst", eor)) == "NotImplemented")
    c = http.client.HTTPConnection("127.0.0.1", sp, timeout=30)
    c.request("PUT", "/%s?replication" % SB, body=b"<ReplicationConfiguration><Rule>")
    r = c.getresponse()
    check("a document that is not one is MalformedXML", r.status == 400 and b"MalformedXML" in r.read(), r.status)
    c.close()

    check("a configuration is put", isinstance(call(src.put_bucket_replication, Bucket=SB,
                                                    ReplicationConfiguration=good), dict))
    got = call(src.get_bucket_replication, Bucket=SB)
    rules = got["ReplicationConfiguration"]["Rules"] if isinstance(got, dict) else []
    check("and read back as it was given",
          isinstance(got, dict) and got["ReplicationConfiguration"]["Role"] == ROLE + "dst" and
          [(x["ID"], x["Priority"], x["Status"], x["Destination"]["Bucket"], x["DeleteMarkerReplication"]["Status"])
           for x in rules] == [("docs", 1, "Enabled", "arn:aws:s3:::" + DB, "Enabled"),
                               ("hot", 2, "Enabled", "arn:aws:s3:::" + DB, "Disabled")] and
          rules[0]["Filter"] == {"Prefix": "docs/"} and
          rules[1]["Filter"] == {"And": {"Prefix": "img/", "Tags": [{"Key": "class", "Value": "hot"}]}} and
          rules[1]["Destination"].get("StorageClass") == "STANDARD_IA", got)
    check("versioning cannot be suspended while the bucket replicates",
          call(src.put_bucket_versioning, Bucket=SB, VersioningConfiguration={"Status": "Suspended"})
          == "InvalidBucketState")

    # A version with everything a client can give it.
    data = os.urandom(100 * 1024)
    put = src.put_object(Bucket=SB, Key="docs/a", Body=data, ContentType="text/plain", CacheControl="max-age=60",
                         ContentDisposition="inline", Metadata={"color": "blue", "n": "1"}, Tagging="team=core&level=1",
                         ChecksumAlgorithm="SHA256")
    first = status(src, SB, "docs/a")
    check("a version a rule copies is answered PENDING or already COMPLETED", first in ("PENDING", "COMPLETED"), first)
    check("and becomes COMPLETED", wait_for(lambda: status(src, SB, "docs/a") == "COMPLETED", 20),
          status(src, SB, "docs/a"))
    h = call(dst.head_object, Bucket=DB, Key="docs/a", ChecksumMode="ENABLED")
    hs = call(src.head_object, Bucket=SB, Key="docs/a", ChecksumMode="ENABLED")
    check("the replica says REPLICA", isinstance(h, dict) and h.get("ReplicationStatus") == "REPLICA", h)
    check("with the source's ETag, type, cache control, disposition and user metadata",
          isinstance(h, dict) and h["ETag"] == put["ETag"] and h["ContentType"] == "text/plain" and
          h.get("CacheControl") == "max-age=60" and h.get("ContentDisposition") == "inline" and
          h["Metadata"] == {"color": "blue", "n": "1"}, (h, put))
    check("and its checksum", isinstance(h, dict) and h.get("ChecksumSHA256") and
          h.get("ChecksumSHA256") == hs.get("ChecksumSHA256"), (h.get("ChecksumSHA256") if isinstance(h, dict) else h,
                                                                hs.get("ChecksumSHA256")))
    tags = call(dst.get_object_tagging, Bucket=DB, Key="docs/a")
    check("and its tags", isinstance(tags, dict) and sorted((t["Key"], t["Value"]) for t in tags["TagSet"]) ==
          [("level", "1"), ("team", "core")], tags)
    check("and its bytes", body(dst, DB, "docs/a") == data)

    # A later tag change of a copied version follows it to the same version id there.
    def dst_tags():
        r = call(dst.get_object_tagging, Bucket=DB, Key="docs/a", VersionId=put["VersionId"])
        return sorted((t["Key"], t["Value"]) for t in r["TagSet"]) if isinstance(r, dict) else r
    call(src.put_object_tagging, Bucket=SB, Key="docs/a", VersionId=put["VersionId"],
         Tagging={"TagSet": [{"Key": "team", "Value": "ops"}]})
    check("a tag change of a copied version is copied", wait_for(lambda: dst_tags() == [("team", "ops")], 20),
          dst_tags())
    call(src.delete_object_tagging, Bucket=SB, Key="docs/a", VersionId=put["VersionId"])
    check("and so is the removal of its tags", wait_for(lambda: dst_tags() == [], 20), dst_tags())
    check("which leaves the version's status as it was", status(src, SB, "docs/a") == "COMPLETED",
          status(src, SB, "docs/a"))

    # The tag rule, and what no rule names.
    src.put_object(Bucket=SB, Key="img/x", Body=b"hot image", Tagging="class=hot")
    src.put_object(Bucket=SB, Key="img/y", Body=b"cold image", Tagging="class=cold")
    src.put_object(Bucket=SB, Key="misc/z", Body=b"nobody's")
    check("a version the tag rule names is copied", wait_for(lambda: status(src, SB, "img/x") == "COMPLETED", 20) and
          body(dst, DB, "img/x") == b"hot image", status(src, SB, "img/x"))
    check("one whose tag differs has no status", status(src, SB, "img/y") == "", status(src, SB, "img/y"))
    hx = call(dst.head_object, Bucket=DB, Key="img/x")
    check("a replica is of the class its rule names", isinstance(hx, dict) and hx.get("StorageClass") == "STANDARD_IA", hx)
    src.put_object(Bucket=SB, Key="docs/rr", Body=b"rr", StorageClass="REDUCED_REDUNDANCY")
    hr = call(dst.head_object, Bucket=DB, Key="docs/rr") if wait_for(
        lambda: status(src, SB, "docs/rr") == "COMPLETED", 20) else None
    check("and of its source's where the rule names none",
          isinstance(hr, dict) and hr.get("StorageClass") == "REDUCED_REDUNDANCY", hr)
    check("nor one no rule's prefix names", status(src, SB, "misc/z") == "", status(src, SB, "misc/z"))

    # An overwrite is a version of its own, and a delete marker follows where the rule says.
    v2 = os.urandom(5000)
    src.put_object(Bucket=SB, Key="docs/a", Body=v2)
    check("an overwrite is copied as a new version", wait_for(lambda: body(dst, DB, "docs/a") == v2, 20) and
          versions(dst, DB, "docs/a")[0] == [("docs/a", True), ("docs/a", False)], versions(dst, DB, "docs/a"))
    src.delete_object(Bucket=SB, Key="docs/a")
    check("a delete marker is copied by a rule that says so",
          wait_for(lambda: versions(dst, DB, "docs/a")[1] == [("docs/a", True)], 20), versions(dst, DB, "docs/a"))
    check("and the replica's latest is gone", body(dst, DB, "docs/a") == "NoSuchKey")
    check("every version and the marker keep the version id the source gave them",
          version_ids(dst, DB, "docs/a") == version_ids(src, SB, "docs/a") and
          len(version_ids(src, SB, "docs/a")[0]) == 2, (version_ids(src, SB, "docs/a"), version_ids(dst, DB, "docs/a")))
    src.delete_object(Bucket=SB, Key="img/x")

    # A multipart version is copied in the same parts.
    parts = [os.urandom(5 << 20), os.urandom(5 << 20), os.urandom(1 << 20)]
    up = src.create_multipart_upload(Bucket=SB, Key="docs/big", ChecksumAlgorithm="CRC32", ContentType="video/mp4",
                                     Metadata={"part": "y"})
    done = []
    for i, p in enumerate(parts, 1):
        r = src.upload_part(Bucket=SB, Key="docs/big", UploadId=up["UploadId"], PartNumber=i, Body=p,
                            ChecksumAlgorithm="CRC32")
        done.append({"PartNumber": i, "ETag": r["ETag"], "ChecksumCRC32": r["ChecksumCRC32"]})
    big = src.complete_multipart_upload(Bucket=SB, Key="docs/big", UploadId=up["UploadId"],
                                        MultipartUpload={"Parts": done})
    check("a multipart version is copied", wait_for(lambda: status(src, SB, "docs/big") == "COMPLETED", 60),
          status(src, SB, "docs/big"))
    h = call(dst.head_object, Bucket=DB, Key="docs/big", ChecksumMode="ENABLED")
    hs = call(src.head_object, Bucket=SB, Key="docs/big", ChecksumMode="ENABLED")
    check("with the same multipart ETag, parts count, composite checksum and metadata",
          isinstance(h, dict) and h["ETag"] == big["ETag"] and big["ETag"].endswith("-3\"") and
          h["ResponseMetadata"]["HTTPHeaders"].get("x-amz-mp-parts-count") == "3" and
          h.get("ChecksumCRC32") == hs.get("ChecksumCRC32") and h["ContentType"] == "video/mp4" and
          h["Metadata"] == {"part": "y"}, (h, big["ETag"], hs.get("ChecksumCRC32")))
    check("and the same bytes", hashlib.sha256(body(dst, DB, "docs/big")).hexdigest() ==
          hashlib.sha256(b"".join(parts)).hexdigest())
    check("and the same version id", version_ids(dst, DB, "docs/big") == version_ids(src, SB, "docs/big"),
          (version_ids(src, SB, "docs/big"), version_ids(dst, DB, "docs/big")))

    # An object encrypted with SSE-S3 is read in the clear and written encrypted again.
    secret = os.urandom(70000)
    src.put_object(Bucket=SB, Key="docs/enc", Body=secret, ServerSideEncryption="AES256")
    check("an SSE-S3 version is copied", wait_for(lambda: status(src, SB, "docs/enc") == "COMPLETED", 20),
          status(src, SB, "docs/enc"))
    h = call(dst.head_object, Bucket=DB, Key="docs/enc")
    check("as SSE-S3, with its bytes", isinstance(h, dict) and h.get("ServerSideEncryption") == "AES256" and
          body(dst, DB, "docs/enc") == secret, h)

    # The marker of img/x was not copied, which a later copy through the same queue shows.
    src.put_object(Bucket=SB, Key="docs/sentinel", Body=b"s")
    check("the sentinel behind it is copied",
          wait_for(lambda: status(src, SB, "docs/sentinel") == "COMPLETED", 20), status(src, SB, "docs/sentinel"))
    check("a delete marker a rule does not copy stays on the source",
          body(dst, DB, "img/x") == b"hot image" and versions(dst, DB, "img/x")[1] == [], versions(dst, DB, "img/x"))
    check("and nothing a rule does not name reached the destination",
          call(dst.head_object, Bucket=DB, Key="img/y") == "404" and call(dst.head_object, Bucket=DB, Key="misc/z")
          == "404")

    # A destination that refuses for good leaves the version FAILED.
    for b, target, dest in (("rsrc-weak", "weak", DB), ("rsrc-gone", "dst", "no-such-bucket")):
        versioned(src, b)
        src.put_bucket_replication(Bucket=b, ReplicationConfiguration=config(target, rule("all", 1, dest)))
        src.put_object(Bucket=b, Key="k", Body=b"refused")
    check("a destination whose user may not replicate leaves the version FAILED",
          wait_for(lambda: status(src, "rsrc-weak", "k") == "FAILED", 20), status(src, "rsrc-weak", "k"))
    check("and so does a destination bucket that is not there",
          wait_for(lambda: status(src, "rsrc-gone", "k") == "FAILED", 20), status(src, "rsrc-gone", "k"))

    sizes = 100 * 1024 + 9 + 5000 + 11 * (1 << 20) + 70000 + 1 + 2
    # The counters `stats` shows are a moment old, so the wait is for them to catch up; the two tag changes count.
    check("stats count what was copied, its bytes, what failed, and that nothing waits",
          wait_for(lambda: stat("rsrc", "replication_pending") == 0 and
                   stat("rsrc", "replication_completed") == 10 and stat("rsrc", "replication_bytes") == sizes and
                   stat("rsrc", "replication_failed") == 2, 10), rstats("rsrc"))

    check("a configuration is deleted", isinstance(call(src.delete_bucket_replication, Bucket="rsrc-gone"), dict) and
          call(src.get_bucket_replication, Bucket="rsrc-gone") == "ReplicationConfigurationNotFoundError")
    src.put_object(Bucket="rsrc-gone", Key="after", Body=b"x")
    check("after which a new version has no status", status(src, "rsrc-gone", "after") == "")
    check("and versioning may be suspended again",
          isinstance(call(src.put_bucket_versioning, Bucket="rsrc-gone",
                          VersioningConfiguration={"Status": "Suspended"}), dict))


# ── policy ──────────────────────────────────────────────────────────────────
def raw(port, method, path, data=b"", headers=None, key=None):
    """A request signed by `key` with botocore's signer, or unsigned, as (status, headers, body)."""
    from botocore.auth import S3SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials
    url = "http://127.0.0.1:%d%s" % (port, path)
    hdrs = dict(headers or {})
    if key:
        r = AWSRequest(method=method, url=url, data=data, headers=hdrs)
        S3SigV4Auth(Credentials(key[0], key[1]), "s3", "us-east-1").add_auth(r)
        hdrs = dict(r.headers.items())
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        c.request(method, path, body=data, headers=hdrs)
        resp = c.getresponse()
        return resp.status, dict((k.lower(), v) for k, v in resp.getheaders()), resp.read()
    finally:
        c.close()


def mode_policy(dp):
    dst = client(dp, ADMIN)
    versioned(dst, "rdst-p")
    st, _, _ = raw(dp, "PUT", "/rdst-p/plain", b"x", key=REPL)
    check("the replication user may not write an object of its own", st == 403, st)
    dst.put_object(Bucket="rdst-p", Key="seen", Body=b"y")
    st, _, _ = raw(dp, "GET", "/rdst-p/seen", key=REPL)
    check("nor read one", st == 403, st)
    st, _, _ = raw(dp, "PUT", "/rdst-p/copy", b"z", {"x-amz-replication-status": "REPLICA"}, key=REPL)
    check("but may write a replica", st == 200, st)
    check("which says REPLICA", status(dst, "rdst-p", "copy") == "REPLICA", status(dst, "rdst-p", "copy"))
    st, _, _ = raw(dp, "DELETE", "/rdst-p/copy", headers={"x-amz-replication-status": "REPLICA"}, key=REPL)
    check("and a replica's delete marker", st == 204 and versions(dst, "rdst-p", "copy")[1] == [("copy", True)], st)
    st, _, _ = raw(dp, "PUT", "/rdst-p/copy2", b"z", {"x-amz-replication-status": "REPLICA"}, key=READ)
    check("a user that may only read may not write a replica", st == 403, st)
    st, _, _ = raw(dp, "PUT", "/rdst-p/plain2", b"z", {"x-amz-replication-status": "PENDING"}, key=ADMIN)
    check("a status other than REPLICA is not taken from a client",
          st == 200 and status(dst, "rdst-p", "plain2") == "", status(dst, "rdst-p", "plain2"))
    # A replica's status is honoured only for a user let replicate, and never past a Deny of the write it stands for.
    dst.put_bucket_policy(Bucket="rdst-p", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::rdst-p/open/*"},
        {"Effect": "Deny", "Principal": "*", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::rdst-p/locked/*"}]}))
    st, _, _ = raw(dp, "PUT", "/rdst-p/locked/a", b"z", {"x-amz-replication-status": "REPLICA"}, key=ADMIN)
    check("a REPLICA status does not escape a Deny of PutObject", st == 403, st)
    st, _, _ = raw(dp, "PUT", "/rdst-p/locked/b", b"z", {"x-amz-replication-status": "REPLICA"}, key=REPL)
    check("not even for the replication user", st == 403, st)
    pinned = "f" * 32
    st, _, _ = raw(dp, "PUT", "/rdst-p/open/r", b"old", {"x-amz-replication-status": "REPLICA",
                                                        "x-socketley-replica-version-id": pinned}, key=READ)
    check("a user that may write and not replicate writes a plain object",
          st == 200 and status(dst, "rdst-p", "open/r") == "", (st, status(dst, "rdst-p", "open/r")))
    check("whose replica version id is not taken", pinned not in version_ids(dst, "rdst-p", "open/r")[0],
          version_ids(dst, "rdst-p", "open/r"))
    st, _, _ = raw(dp, "PUT", "/rdst-p/pin", b"old", {"x-amz-replication-status": "REPLICA",
                                                     "x-socketley-replica-version-id": pinned}, key=REPL)
    check("a replica dated past this clock is written", st == 200 and status(dst, "rdst-p", "pin") == "REPLICA", st)
    check("under a version id of this endpoint's", pinned not in version_ids(dst, "rdst-p", "pin")[0],
          version_ids(dst, "rdst-p", "pin"))
    dst.put_object(Bucket="rdst-p", Key="pin", Body=b"new")
    check("so a later write is still the latest", body(dst, "rdst-p", "pin") == b"new", body(dst, "rdst-p", "pin"))
    dst.delete_bucket_policy(Bucket="rdst-p")


# ── down ────────────────────────────────────────────────────────────────────
def mode_down(sp, dp):
    src = client(sp)
    dst = client(dp, ADMIN)
    r = run("stop", "rdst")
    check("the destination is stopped", r.returncode == 0, r.stdout + r.stderr)
    retries = stat("rsrc", "replication_retries")
    keys = ["docs/down%d" % i for i in range(3)]
    for k in keys:
        src.put_object(Bucket=SB, Key=k, Body=k.encode())
    check("versions written while it is down are answered and PENDING",
          all(status(src, SB, k) == "PENDING" for k in keys), [status(src, SB, k) for k in keys])
    check("and their copies are tried again", wait_for(lambda: stat("rsrc", "replication_retries") >= retries + 2, 10),
          rstats("rsrc"))
    check("and wait", stat("rsrc", "replication_pending") >= 3, rstats("rsrc"))
    r = run("start", "rdst")
    check("the destination is started again", r.returncode == 0 and wait_up(dp), r.stdout + r.stderr)
    check("and every version is copied", wait_for(lambda: all(status(src, SB, k) == "COMPLETED" for k in keys), 40),
          [status(src, SB, k) for k in keys])
    check("as it was", all(body(dst, DB, k) == k.encode() for k in keys))


# ── crash ───────────────────────────────────────────────────────────────────
class SlowProxy:
    """A TCP proxy on `port` to `to` that sends the client's bytes on at about `rate` bytes a second."""

    def __init__(self, port, to, rate):
        self.port, self.to, self.rate = port, to, rate
        self.forwarded = 0
        self.lock = threading.Lock()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(16)
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while True:
            try:
                a, _ = self.sock.accept()
            except OSError:
                return
            try:
                b = socket.create_connection(("127.0.0.1", self.to))
            except OSError:
                a.close()
                continue
            threading.Thread(target=self.pump, args=(a, b, True), daemon=True).start()
            threading.Thread(target=self.pump, args=(b, a, False), daemon=True).start()

    def pump(self, a, b, slow):
        try:
            while True:
                d = a.recv(16384)
                if not d:
                    break
                b.sendall(d)
                if slow:
                    with self.lock:
                        self.forwarded += len(d)
                    time.sleep(len(d) / self.rate)
        except OSError:
            pass
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def kill_worker(runtime, sp):
    pid = worker_pid(runtime)
    if not pid:
        return False
    os.kill(int(pid), signal.SIGKILL)

    def back():
        p = worker_pid(runtime)
        return p and p != pid and os.path.isdir("/proc/%s" % p) and wait_up(sp, 1)
    return wait_for(back, 40, 0.3)


def mode_crash(sp, dp, slow_port, data):
    src = client(sp)
    dst = client(dp, ADMIN)

    # Versions and a delete marker answered while the destination is stopped wait in the outbox, which a SIGKILL
    # does not take.
    src.put_object(Bucket=SB, Key="docs/crashm", Body=b"marked")
    wait_for(lambda: status(src, SB, "docs/crashm") == "COMPLETED", 20)
    run("stop", "rdst")
    keys = ["docs/crash%d" % i for i in range(5)]
    for k in keys:
        src.put_object(Bucket=SB, Key=k, Body=k.encode() * 100)
    src.delete_object(Bucket=SB, Key="docs/crashm")
    outbox = os.path.join(data, ".replicate", "outbox.0")
    check("answered versions wait in the outbox on disk",
          os.path.exists(outbox) and all(k.encode() in open(outbox, "rb").read() for k in keys))
    check("the worker is killed with SIGKILL and comes back", kill_worker("rsrc", sp))
    run("start", "rdst")
    wait_up(dp)
    check("every answered version is copied after the restart",
          wait_for(lambda: all(status(src, SB, k) == "COMPLETED" for k in keys), 40),
          [status(src, SB, k) for k in keys])
    check("as it was", all(body(dst, DB, k) == k.encode() * 100 for k in keys))
    check("and so is the answered delete marker, which only the outbox remembers",
          wait_for(lambda: versions(dst, DB, "docs/crashm") == ([("docs/crashm", False)], [("docs/crashm", True)]), 20),
          versions(dst, DB, "docs/crashm"))

    # A copy in the middle of its body, and a PUT in the middle of its own, when the worker is killed.
    proxy = SlowProxy(slow_port, dp, 2 << 20)
    versioned(src, "rsrc-slow")
    src.put_bucket_replication(Bucket="rsrc-slow", ReplicationConfiguration=config("slow", rule("all", 1, DB,
                                                                                              prefix="slow/")))
    huge = os.urandom(12 << 20)
    src.put_object(Bucket="rsrc-slow", Key="slow/huge", Body=huge)
    check("a slow copy is under way", wait_for(lambda: proxy.forwarded > (2 << 20), 20), proxy.forwarded)
    s = socket.create_connection(("127.0.0.1", sp))
    s.sendall(b"PUT /rsrc-slow/slow/phantom HTTP/1.1\r\nHost: x\r\nContent-Length: 4194304\r\n\r\n" + b"p" * (1 << 20))
    time.sleep(0.3)
    check("the worker is killed in the middle of both", kill_worker("rsrc", sp))
    s.close()
    check("the copy is made again whole after the restart",
          wait_for(lambda: status(src, "rsrc-slow", "slow/huge") == "COMPLETED", 90),
          (status(src, "rsrc-slow", "slow/huge"), proxy.forwarded))
    check("with the same bytes", hashlib.sha256(body(dst, DB, "slow/huge")).hexdigest() ==
          hashlib.sha256(huge).hexdigest())
    src.put_object(Bucket="rsrc-slow", Key="slow/sentinel", Body=b"s")
    check("the sentinel behind it is copied",
          wait_for(lambda: status(src, "rsrc-slow", "slow/sentinel") == "COMPLETED", 30),
          status(src, "rsrc-slow", "slow/sentinel"))
    check("a PUT never answered is on neither side",
          call(src.head_object, Bucket="rsrc-slow", Key="slow/phantom") == "404" and
          call(dst.head_object, Bucket=DB, Key="slow/phantom") == "404")
    check("and the replica has exactly the versions the source answered",
          len(versions(dst, DB, "slow/huge")[0]) == 1, versions(dst, DB, "slow/huge"))


# ── shards ──────────────────────────────────────────────────────────────────
class UnixConn(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=60)
        self.path_ = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(60)
        self.sock.connect(self.path_)


def ureq(node, method, path, data=b"", headers=None):
    c = UnixConn(node)
    try:
        c.request(method, path, body=data, headers=headers or {})
        r = c.getresponse()
        return r.status, dict((k.lower(), v) for k, v in r.getheaders()), r.read()
    finally:
        c.close()


def mode_shards(dp, nodes):
    dst = client(dp, ADMIN)
    versioned(dst, "rdst-s")
    b = "rshard-b"
    ureq(nodes[0], "PUT", "/" + b)
    ureq(nodes[1], "PUT", "/%s?versioning" % b, b'<VersioningConfiguration><Status>Enabled</Status>'
                                                b'</VersioningConfiguration>')
    doc = ("<ReplicationConfiguration><Role>%sdst</Role><Rule><ID>all</ID><Priority>1</Priority><Status>Enabled"
           "</Status><Filter><Prefix></Prefix></Filter><Destination><Bucket>arn:aws:s3:::rdst-s</Bucket></Destination>"
           "<DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication></Rule>"
           "</ReplicationConfiguration>" % ROLE).encode()
    st, _, _ = ureq(nodes[0], "PUT", "/%s?replication" % b, doc)
    check("a configuration is put through one shard", st == 200, st)
    st, _, got = ureq(nodes[1], "GET", "/%s?replication" % b)
    check("and read through the other", st == 200 and b"rdst-s" in got, got)
    n = 24
    for i in range(n):
        ureq(nodes[i % 2], "PUT", "/%s/s%02d" % (b, i), b"v" * (100 + i))
    for i in range(0, n, 6):
        ureq(nodes[(i + 1) % 2], "DELETE", "/%s/s%02d" % (b, i))

    def statuses():
        return [ureq(nodes[(i + 1) % 2], "HEAD", "/%s/s%02d?versionId=%s" % (b, i, vid(i)))[1]
                .get("x-amz-replication-status") for i in range(n)]

    vids = {}

    def vid(i):
        if i not in vids:
            st, _, x = ureq(nodes[0], "GET", "/%s?versions&prefix=s%02d" % (b, i))
            root = ET.fromstring(x)
            vids[i] = [v.findtext(NS + "VersionId") for v in root.iter(NS + "Version")][0]
        return vids[i]

    check("every version through either shard is copied",
          wait_for(lambda: all(s == "COMPLETED" for s in statuses()), 40), statuses())
    # A delete marker has no status to wait on, and is copied after the version it hides.
    check("and every delete marker through either shard",
          wait_for(lambda: all(versions(dst, "rdst-s", "s%02d" % i)[1] == [("s%02d" % i, True)]
                               for i in range(0, n, 6)), 40))
    check("and is on the destination once, as it was",
          all(body(dst, "rdst-s", "s%02d" % i) == (b"v" * (100 + i) if i % 6 else "NoSuchKey") for i in range(n)) and
          all(len(versions(dst, "rdst-s", "s%02d" % i)[0]) == 1 for i in range(n)))

    def per():
        return {k: int(s.get("replication_completed", "0")) for k, s in stats("rshard").items()}
    check("each copied by the shard that owns its key, both shards owning some",
          wait_for(lambda: sum(per().values()) == n + 4 and all(v > 0 for v in per().values()), 10), per())


# ── loop ────────────────────────────────────────────────────────────────────
def mode_loop(sp, dp):
    src = client(sp)
    dst = client(dp, ADMIN)
    versioned(src, "loop-a")
    versioned(dst, "loop-b")
    src.put_bucket_replication(Bucket="loop-a", ReplicationConfiguration=config("dst", rule("ab", 1, "loop-b")))
    dst.put_bucket_replication(Bucket="loop-b", ReplicationConfiguration=config("back", rule("ba", 1, "loop-a")))
    before = stat("rdst", "replication_completed")
    src.put_object(Bucket="loop-a", Key="k1", Body=b"from a")
    dst.put_object(Bucket="loop-b", Key="k2", Body=b"from b")
    check("a version written on either side is copied to the other",
          wait_for(lambda: status(src, "loop-a", "k1") == "COMPLETED" and status(dst, "loop-b", "k2") == "COMPLETED",
                   20), (status(src, "loop-a", "k1"), status(dst, "loop-b", "k2")))
    check("where it is a REPLICA", status(dst, "loop-b", "k1") == "REPLICA" and status(src, "loop-a", "k2") == "REPLICA")
    src.delete_object(Bucket="loop-a", Key="k1")
    dst.delete_object(Bucket="loop-b", Key="k2")
    check("a delete marker on either side crosses",
          wait_for(lambda: versions(dst, "loop-b", "k1")[1] == [("k1", True)] and
                   versions(src, "loop-a", "k2")[1] == [("k2", True)], 20))
    # A second round trip would have to queue behind these, so a sentinel through each queue settles it.
    src.put_object(Bucket="loop-a", Key="sentinel-a", Body=b"a")
    dst.put_object(Bucket="loop-b", Key="sentinel-b", Body=b"b")
    check("the sentinels through both queues are copied",
          wait_for(lambda: status(src, "loop-a", "sentinel-a") == "COMPLETED" and
                   status(dst, "loop-b", "sentinel-b") == "COMPLETED", 20))
    time.sleep(1)
    check("and nothing comes back: each key has its one version and one marker on both sides",
          all(versions(c, bk, k) == ([(k, False)], [(k, True)]) for c, bk in ((src, "loop-a"), (dst, "loop-b"))
              for k in ("k1", "k2")),
          [versions(c, bk, k) for c, bk in ((src, "loop-a"), (dst, "loop-b")) for k in ("k1", "k2")])
    check("the destination copied only what was written on it",
          stat("rdst", "replication_completed") - before == 3, rstats("rdst"))


if __name__ == "__main__":
    a = sys.argv[2:]
    if MODE == "main":
        mode_main(int(a[0]), int(a[1]))
    elif MODE == "policy":
        mode_policy(int(a[0]))
    elif MODE == "down":
        mode_down(int(a[0]), int(a[1]))
    elif MODE == "crash":
        mode_crash(int(a[0]), int(a[1]), int(a[2]), a[3])
    elif MODE == "shards":
        mode_shards(int(a[0]), a[1:])
    elif MODE == "loop":
        mode_loop(int(a[0]), int(a[1]))
    sys.exit(min(failed, 100))
