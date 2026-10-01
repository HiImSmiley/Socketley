#!/usr/bin/env python3
"""Object tagging on the storage runtime, and lifecycle rules that filter on tags.

usage: lib_storage_tagging.py MODE ARGS...

  main PORT            a runtime with credentials and a lifecycle day of a few
                       seconds: Put/Get/DeleteObjectTagging, S3's limits and
                       errors, x-amz-tagging on put, multipart and copy with both
                       directives, x-amz-tagging-count, tag changes that keep the
                       bytes, ETag and time, and lifecycle Tag / And filters
  restart PORT         after a clean stop and a start: the tags and the
                       configuration are still there
  crash PORT DATA      the worker killed with SIGKILL right after tag changes,
                       and then a start with every journal removed: the object
                       files alone bring the tags back
  shards NODE0 NODE1   an anonymous runtime of two shards, one node each: a tag
                       change through the shard that does not own the key is
                       seen by both at once, cached response headers included

Prints one PASS or FAIL line per assertion and exits with the number of failures.
"""
import hashlib
import http.client
import os
import signal
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

MODE = sys.argv[1]
AK = os.environ.get("AK", "AKIATESTACCESSKEY01")
SK = os.environ.get("SK", "test/secret+key/for.storage.sigv4")
BIN = os.environ.get("BIN", "")
RUNTIME = os.environ.get("RUNTIME", "tg")
DAY = int(os.environ.get("SOCKETLEY_STORAGE_LIFECYCLE_DAY_SECS", "2"))
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
B = "tagb"
LB = "taglc"

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, detail))


def wait_for(fn, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if fn():
            return True
        time.sleep(0.2)
    return fn()


def stats_shards():
    """`stats` as {shard: {name: value}}, one section when the runtime has one shard."""
    out = subprocess.run([BIN, "stats", RUNTIME], capture_output=True, text=True).stdout
    shards, cur = {}, 0
    for line in out.splitlines():
        if line.startswith("[shard "):
            cur = int(line[7:].rstrip("]"))
            shards[cur] = {}
        elif ":" in line:
            k, v = line.split(":", 1)
            shards.setdefault(cur, {})[k.strip()] = v.strip()
    return shards


def stat_total(name):
    return sum(int(s.get(name, "0") or 0) for s in stats_shards().values())


def xml_code(body):
    try:
        return ET.fromstring(body).findtext("Code")
    except Exception:
        return None


def tagset_of(body):
    root = ET.fromstring(body)
    return [(t.findtext(NS + "Key"), t.findtext(NS + "Value") or "") for t in root.iter(NS + "Tag")]


def tagging_doc(pairs):
    tags = "".join("<Tag><Key>%s</Key><Value>%s</Value></Tag>" % kv for kv in pairs)
    return ('<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet>%s</TagSet></Tagging>' % tags).encode()


# ── one shard over TCP, with credentials ────────────────────────────────────
def tcp_setup(port):
    global HOST, PORT
    PORT = port
    HOST = "127.0.0.1:%d" % port


def raw(method, path, query="", body=b"", extra=None):
    import lib_s3_signing as sig
    s = sig.sign(method, path, query, HOST, AK, SK, sig.sha256hex(body), extra)
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
    try:
        conn.request(method, path + ("?" + query if query else ""), body=body, headers=s.headers)
        r = conn.getresponse()
        return r.status, dict((k.lower(), v) for k, v in r.getheaders()), r.read()
    finally:
        conn.close()


def client():
    import boto3
    from botocore.config import Config
    return boto3.client("s3", endpoint_url="http://" + HOST, aws_access_key_id=AK, aws_secret_access_key=SK,
                        region_name="us-east-1",
                        config=Config(signature_version="s3v4", s3={"addressing_style": "path"},
                                      retries={"max_attempts": 1}))


def boto_code(fn):
    import botocore.exceptions
    try:
        fn()
    except botocore.exceptions.ClientError as e:
        return e.response["Error"].get("Code"), e.response["ResponseMetadata"]["HTTPStatusCode"]
    return None, 200


def tags(c, key, bucket=B):
    return [(t["Key"], t["Value"]) for t in c.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]]


def put_tags(c, key, pairs, bucket=B):
    return c.put_object_tagging(Bucket=bucket, Key=key, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in pairs]})


def tag_count(key, method="GET", bucket=B):
    st, h, _ = raw(method, "/%s/%s" % (bucket, key))
    return st, h.get("x-amz-tagging-count")


def identity(c, key, bucket=B):
    h = c.head_object(Bucket=bucket, Key=key)
    body = c.get_object(Bucket=bucket, Key=key)["Body"].read()
    return h["ETag"], h["LastModified"], hashlib.md5(body).hexdigest(), len(body)


def keys(c, bucket, prefix=""):
    out = []
    for page in c.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        out += [o["Key"] for o in page.get("Contents", [])]
    return out


def mode_main(port):
    tcp_setup(port)
    c = client()
    c.create_bucket(Bucket=B)
    c.put_object(Bucket=B, Key="a", Body=os.urandom(4096))

    # ── Put, Get and Delete ──
    check("an object without tags has an empty TagSet", tags(c, "a") == [], tags(c, "a"))
    check("and its GET carries no x-amz-tagging-count", tag_count("a") == (200, None), tag_count("a"))
    before = identity(c, "a")
    writes0, rewrites0 = stat_total("tag_writes"), stat_total("tag_rewrites")
    code = boto_code(lambda: put_tags(c, "a", [("env", "prod"), ("team", "storage")]))
    check("PutObjectTagging is 200", code == (None, 200), code)
    check("GetObjectTagging answers the set in the order it was put",
          tags(c, "a") == [("env", "prod"), ("team", "storage")], tags(c, "a"))
    check("a GET says x-amz-tagging-count: 2", tag_count("a") == (200, "2"), tag_count("a"))
    check("and so does a HEAD", tag_count("a", "HEAD") == (200, "2"), tag_count("a", "HEAD"))
    check("boto3's GetObject reads TagCount 2", c.get_object(Bucket=B, Key="a").get("TagCount") == 2)
    check("the bytes, ETag and Last-Modified are those from before the tags", identity(c, "a") == before,
          (before, identity(c, "a")))
    # `stats` is what the worker last published, so it is waited for.
    delta = lambda: (stat_total("tag_writes") - writes0, stat_total("tag_rewrites") - rewrites0)  # noqa: E731
    check("the change was written into the object's header and nothing was rewritten",
          wait_for(lambda: delta() == (1, 0), 10), delta())
    st, h, body = raw("GET", "/%s/a" % B, "tagging")
    check("the raw answer is a Tagging document in S3's namespace",
          st == 200 and body.startswith(b"<?xml") and ET.fromstring(body).tag == NS + "Tagging", (st, body))
    put_tags(c, "a", [("only", "one")])
    check("a second put replaces the whole set", tags(c, "a") == [("only", "one")], tags(c, "a"))
    check("and the count follows it", tag_count("a") == (200, "1"), tag_count("a"))
    put_tags(c, "a", [("x", "1")])
    put_tags(c, "a", [("y", "2")])
    check("changes one after another land in turn", tags(c, "a") == [("y", "2")], tags(c, "a"))
    st, _, _ = raw("DELETE", "/%s/a" % B, "tagging")
    check("DeleteObjectTagging is 204", st == 204, st)
    check("after which the set is empty", tags(c, "a") == [], tags(c, "a"))
    check("and a GET has no count", tag_count("a") == (200, None), tag_count("a"))
    check("and the object is untouched", identity(c, "a") == before, (before, identity(c, "a")))
    check("deleting tags that are not there is still 204", raw("DELETE", "/%s/a" % B, "tagging")[0] == 204)
    put_tags(c, "a", [("env", "prod")])
    code = boto_code(lambda: put_tags(c, "a", []))
    check("an empty TagSet is taken", code == (None, 200) and tags(c, "a") == [], (code, tags(c, "a")))

    # Unicode: characters are counted, not bytes.
    uk, uv = "é" * 128, "日" * 256
    code = boto_code(lambda: put_tags(c, "a", [(uk, uv), ("sp ace+-=._:/@", "")]))
    check("a 128-character key and a 256-character value in UTF-8 are taken", code == (None, 200), code)
    check("and read back as they were", tags(c, "a") == [(uk, uv), ("sp ace+-=._:/@", "")], tags(c, "a"))

    # ── limits and errors ──
    refusals = [
        ("eleven tags", [("k%d" % i, "v") for i in range(11)], "BadRequest"),
        ("a key of 129 characters", [("k" * 129, "v")], "InvalidTag"),
        ("a value of 257 characters", [("k", "v" * 257)], "InvalidTag"),
        ("two tags with one key", [("k", "1"), ("k", "2")], "InvalidTag"),
        ("an empty key", [("", "v")], "InvalidTag"),
        ("a key with a character S3 does not allow", [("a*b", "v")], "InvalidTag"),
        ("a value with a character S3 does not allow", [("k", "a#b")], "InvalidTag"),
        ("a key in the aws: namespace", [("aws:thing", "v")], "InvalidTag"),
    ]
    put_tags(c, "a", [("keep", "me")])
    for name, pairs, want in refusals:
        st, _, body = raw("PUT", "/%s/a" % B, "tagging", tagging_doc(pairs))
        check("%s is refused as %s" % (name, want), (st, xml_code(body)) == (400, want), (st, body))
    check("ten tags are taken", boto_code(lambda: put_tags(c, "a", [("k%d" % i, "v") for i in range(10)])) == (None, 200))
    put_tags(c, "a", [("keep", "me")])
    malformed = [
        ("an empty body", b""),
        ("a body that is not XML", b"tags please"),
        ("another root element", b"<Tags><TagSet></TagSet></Tags>"),
        ("a Tagging with no TagSet", b"<Tagging></Tagging>"),
        ("a Tag with no Value", b"<Tagging><TagSet><Tag><Key>k</Key></Tag></TagSet></Tagging>"),
        ("a Tag with two Keys", b"<Tagging><TagSet><Tag><Key>k</Key><Key>j</Key><Value>v</Value></Tag></TagSet></Tagging>"),
        ("an unknown element", b"<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value><Colour>red</Colour></Tag></TagSet></Tagging>"),
    ]
    for name, body in malformed:
        st, _, data = raw("PUT", "/%s/a" % B, "tagging", body)
        check("%s is MalformedXML" % name, (st, xml_code(data)) == (400, "MalformedXML"), (st, data))
    check("and no refusal changed the tags there", tags(c, "a") == [("keep", "me")], tags(c, "a"))
    for method in ("GET", "PUT", "DELETE"):
        st, _, data = raw(method, "/%s/nokey" % B, "tagging", tagging_doc([("k", "v")]) if method == "PUT" else b"")
        check("%s ?tagging of a key that does not exist is NoSuchKey" % method,
              (st, xml_code(data)) == (404, "NoSuchKey"), (st, data))
        st, _, data = raw(method, "/notagbucket/a", "tagging", tagging_doc([("k", "v")]) if method == "PUT" else b"")
        check("%s ?tagging in a bucket that does not exist is NoSuchBucket" % method,
              (st, xml_code(data)) == (404, "NoSuchBucket"), (st, data))
    bad_md5 = "1B2M2Y8AsgTpgAmY7PhCfg=="
    st, _, data = raw("PUT", "/%s/a" % B, "tagging", tagging_doc([("k", "v")]), {"Content-MD5": bad_md5})
    check("a Content-MD5 the body does not match is BadDigest", (st, xml_code(data)) == (400, "BadDigest"), (st, data))
    st, _, data = raw("POST", "/%s/a" % B, "tagging")
    check("POST ?tagging is MethodNotAllowed", (st, xml_code(data)) == (405, "MethodNotAllowed"), (st, data))
    st, _, data = raw("GET", "/" + B, "tagging")
    check("a bucket's own ?tagging is still NotImplemented", (st, xml_code(data)) == (501, "NotImplemented"), (st, data))

    # ── x-amz-tagging on PutObject ──
    c.put_object(Bucket=B, Key="p", Body=b"put", Tagging="k1=v1&k2=v%202&k3=")
    check("x-amz-tagging on a put becomes the object's tags", tags(c, "p") == [("k1", "v1"), ("k2", "v 2"), ("k3", "")], tags(c, "p"))
    check("and its GET counts three", tag_count("p") == (200, "3"), tag_count("p"))
    c.put_object(Bucket=B, Key="p", Body=b"again")
    check("a put without the header leaves the new object untagged", tags(c, "p") == [], tags(c, "p"))
    for name, header, want in [("a repeated key", "a=1&a=2", "InvalidArgument"),
                               ("eleven tags", "&".join("k%d=v" % i for i in range(11)), "BadRequest"),
                               ("a key S3 does not allow", "k%2A=v", "InvalidTag"),
                               ("a broken escape", "k=%zz", "InvalidArgument")]:
        code = boto_code(lambda: c.put_object(Bucket=B, Key="refused", Body=b"x" * 1000, Tagging=header))
        check("a put whose x-amz-tagging has %s is %s" % (name, want), code == (want, 400), code)
    check("and none of those puts stored anything", "refused" not in keys(c, B))

    # ── multipart ──
    up = c.create_multipart_upload(Bucket=B, Key="m", Tagging="mp=yes&n=2")["UploadId"]
    parts = []
    for i, body in enumerate([os.urandom(5 << 20), os.urandom(5 << 20)]):
        e = c.upload_part(Bucket=B, Key="m", UploadId=up, PartNumber=i + 1, Body=body)["ETag"]
        parts.append({"ETag": e, "PartNumber": i + 1})
    c.complete_multipart_upload(Bucket=B, Key="m", UploadId=up, MultipartUpload={"Parts": parts})
    check("x-amz-tagging on CreateMultipartUpload lands on the completed object",
          tags(c, "m") == [("mp", "yes"), ("n", "2")], tags(c, "m"))
    mbefore = identity(c, "m")
    put_tags(c, "m", [("mp", "changed")])
    check("a multipart object's tags change and its bytes, ETag and time do not",
          tags(c, "m") == [("mp", "changed")] and identity(c, "m") == mbefore, (tags(c, "m"), mbefore, identity(c, "m")))
    code = boto_code(lambda: c.create_multipart_upload(Bucket=B, Key="m2", Tagging="a=1&a=1"))
    check("CreateMultipartUpload refuses a bad x-amz-tagging", code == ("InvalidArgument", 400), code)

    # ── CopyObject ──
    c.put_object(Bucket=B, Key="src", Body=b"source", Tagging="s=1", Metadata={"m": "src"})
    c.copy_object(Bucket=B, Key="d1", CopySource={"Bucket": B, "Key": "src"})
    check("a copy takes the source's tags by default", tags(c, "d1") == [("s", "1")], tags(c, "d1"))
    c.copy_object(Bucket=B, Key="d2", CopySource={"Bucket": B, "Key": "src"}, TaggingDirective="COPY", Tagging="r=2")
    check("COPY ignores an x-amz-tagging beside it", tags(c, "d2") == [("s", "1")], tags(c, "d2"))
    c.copy_object(Bucket=B, Key="d3", CopySource={"Bucket": B, "Key": "src"}, TaggingDirective="REPLACE", Tagging="r=2&q=3")
    check("REPLACE takes the tags x-amz-tagging names", tags(c, "d3") == [("r", "2"), ("q", "3")], tags(c, "d3"))
    c.copy_object(Bucket=B, Key="d4", CopySource={"Bucket": B, "Key": "src"}, TaggingDirective="REPLACE")
    check("REPLACE without x-amz-tagging leaves the copy untagged", tags(c, "d4") == [], tags(c, "d4"))
    c.copy_object(Bucket=B, Key="d5", CopySource={"Bucket": B, "Key": "src"}, MetadataDirective="REPLACE",
                  Metadata={"m": "new"})
    check("a metadata REPLACE keeps the source's tags under the tagging COPY",
          tags(c, "d5") == [("s", "1")] and c.head_object(Bucket=B, Key="d5")["Metadata"] == {"m": "new"},
          (tags(c, "d5"), c.head_object(Bucket=B, Key="d5")["Metadata"]))
    put_tags(c, "src", [("s", "changed")])
    c.copy_object(Bucket=B, Key="d6", CopySource={"Bucket": B, "Key": "src"})
    check("a copy after a tag change takes the changed tags", tags(c, "d6") == [("s", "changed")], tags(c, "d6"))
    code = boto_code(lambda: c.copy_object(Bucket=B, Key="d7", CopySource={"Bucket": B, "Key": "src"},
                                           TaggingDirective="MERGE"))
    check("an unknown tagging directive is InvalidArgument", code == ("InvalidArgument", 400), code)
    code = boto_code(lambda: c.copy_object(Bucket=B, Key="d7", CopySource={"Bucket": B, "Key": "src"},
                                           TaggingDirective="REPLACE", Tagging="a=1&a=2"))
    check("a REPLACE with a bad x-amz-tagging is refused", code == ("InvalidArgument", 400), code)

    # ── a set too big for the header's slots writes the object again ──
    c.put_object(Bucket=B, Key="big", Body=os.urandom(3 << 20))
    bbefore = identity(c, "big")
    rewrites0 = stat_total("tag_rewrites")
    full = [("k" * 127 + str(i), "v" * 256) for i in range(10)]
    code = boto_code(lambda: put_tags(c, "big", full))
    check("ten tags of the longest key and value are taken", code == (None, 200), code)
    check("and read back", tags(c, "big") == full, len(tags(c, "big")))
    check("by writing the object again", wait_for(lambda: stat_total("tag_rewrites") - rewrites0 == 1, 10),
          stat_total("tag_rewrites") - rewrites0)
    check("whose bytes, ETag and Last-Modified are those from before", identity(c, "big") == bbefore,
          (bbefore, identity(c, "big")))

    # ── lifecycle by tag, by And and by size ──
    c.create_bucket(Bucket=LB)
    lc(c)

    # What the restart and the crash find.
    put_tags(c, "a", [("restart", "kept")])
    c.put_object(Bucket=B, Key="r", Body=b"r", Tagging="put=time")


def lc_rule(rid, filt, body="<Expiration><Days>1</Days></Expiration>"):
    return "<Rule><ID>%s</ID><Filter>%s</Filter><Status>Enabled</Status>%s</Rule>" % (rid, filt, body)


def lc_doc(*rules):
    return ('<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' + "".join(rules) +
            "</LifecycleConfiguration>").encode()


def put_lc(body, bucket=LB):
    import base64
    st, _, data = raw("PUT", "/" + bucket, "lifecycle", body,
                      {"Content-MD5": base64.b64encode(hashlib.md5(body).digest()).decode()})
    return st, xml_code(data)


def tag_xml(k, v):
    return "<Tag><Key>%s</Key><Value>%s</Value></Tag>" % (k, v)


def lc(c):
    refusals = [
        ("a Tag filter with an abort of uploads",
         lc_rule("t", tag_xml("a", "1"), "<AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload>"),
         "InvalidRequest"),
        ("an And with one tag key twice", lc_rule("t", "<And>%s%s</And>" % (tag_xml("a", "1"), tag_xml("a", "2"))), "InvalidRequest"),
        ("an And whose sizes leave nothing between them",
         lc_rule("t", "<And><ObjectSizeGreaterThan>10</ObjectSizeGreaterThan><ObjectSizeLessThan>10</ObjectSizeLessThan></And>"),
         "InvalidRequest"),
        ("a Filter with a Prefix and a Tag beside it", lc_rule("t", "<Prefix>a</Prefix>" + tag_xml("a", "1")), "MalformedXML"),
        ("a Tag with no Value", lc_rule("t", "<Tag><Key>a</Key></Tag>"), "MalformedXML"),
        ("an empty And", lc_rule("t", "<And></And>"), "MalformedXML"),
        ("an And holding an And", lc_rule("t", "<And><And><Prefix>a</Prefix></And></And>"), "MalformedXML"),
        ("an ObjectSizeLessThan of 0", lc_rule("t", "<ObjectSizeLessThan>0</ObjectSizeLessThan>"), "InvalidArgument"),
        ("a size that is not a number", lc_rule("t", "<ObjectSizeGreaterThan>big</ObjectSizeGreaterThan>"), "InvalidArgument"),
        ("a Tag key S3 does not allow", lc_rule("t", tag_xml("a*", "1")), "InvalidTag"),
    ]
    for name, rule, want in refusals:
        got = put_lc(lc_doc(rule))
        check("lifecycle: %s is refused as %s" % (name, want), got[1] == want and got[0] == 400, got)

    cfg = lc_doc(lc_rule("bytag", tag_xml("exp", "yes")),
                 lc_rule("and", "<And><Prefix>a/</Prefix>%s%s</And>" % (tag_xml("t", "1"), tag_xml("u", "2"))),
                 lc_rule("size", "<And><Prefix>s/</Prefix><ObjectSizeGreaterThan>100</ObjectSizeGreaterThan>"
                                 "<ObjectSizeLessThan>1000</ObjectSizeLessThan></And>"),
                 lc_rule("big", "<ObjectSizeGreaterThan>200000</ObjectSizeGreaterThan>"))
    check("lifecycle: a configuration of Tag, And and size filters is put", put_lc(cfg) == (200, None), put_lc(cfg))
    rules = c.get_bucket_lifecycle_configuration(Bucket=LB)["Rules"]
    got = {r["ID"]: r["Filter"] for r in rules}
    check("lifecycle: and read back filter for filter", got == {
        "bytag": {"Tag": {"Key": "exp", "Value": "yes"}},
        "and": {"And": {"Prefix": "a/", "Tags": [{"Key": "t", "Value": "1"}, {"Key": "u", "Value": "2"}]}},
        "size": {"And": {"Prefix": "s/", "ObjectSizeGreaterThan": 100, "ObjectSizeLessThan": 1000}},
        "big": {"ObjectSizeGreaterThan": 200000},
    }, got)
    code = boto_code(lambda: c.put_bucket_lifecycle_configuration(Bucket=LB, LifecycleConfiguration={"Rules": rules}))
    check("lifecycle: what boto3 read back it can put again", code == (None, 200), code)
    check("lifecycle: and it reads the same", c.get_bucket_lifecycle_configuration(Bucket=LB)["Rules"] == rules)
    # The sweep runs whenever the rules change, so nothing is put until the objects are.
    raw("DELETE", "/" + LB, "lifecycle")

    objects = {
        "x/1": (b"1", "exp=yes", True),
        "x/2": (b"2", "exp=no", False),
        "x/3": (b"3", None, False),
        "x/4": (b"4", None, True),            # tagged afterwards
        "x/5": (b"5", "exp=yes", False),      # untagged afterwards
        "a/1": (b"6", "t=1&u=2", True),
        "a/2": (b"7", "t=1", False),
        "a/3": (b"8", "t=1&u=3", False),
        "b/1": (b"9", "t=1&u=2", False),
        "s/1": (b"x" * 500, None, True),
        "s/2": (b"x" * 50, None, False),
        "s/3": (b"x" * 2000, None, False),
        "s/4": (b"x" * 100, None, False),
        "s/5": (b"x" * 1000, None, False),
        "z/big": (b"z" * 300000, None, True),
    }
    for k, (body, tagging, _) in objects.items():
        if tagging:
            c.put_object(Bucket=LB, Key=k, Body=body, Tagging=tagging)
        else:
            c.put_object(Bucket=LB, Key=k, Body=body)
    put_tags(c, "x/4", [("exp", "yes")], LB)
    c.delete_object_tagging(Bucket=LB, Key="x/5")
    check("lifecycle: the sweep's configuration is put", put_lc(cfg) == (200, None))
    gone = sorted(k for k, v in objects.items() if v[2])
    stay = sorted(k for k, v in objects.items() if not v[2])
    check("lifecycle: every object a filter matches expires",
          wait_for(lambda: not set(gone) & set(keys(c, LB)), 6 * DAY + 10), sorted(set(gone) & set(keys(c, LB))))
    time.sleep(2 * DAY + 1)
    left = keys(c, LB)
    check("lifecycle: and every object none matches is kept", sorted(set(stay) & set(left)) == stay,
          sorted(set(stay) - set(left)))
    raw("DELETE", "/" + LB, "lifecycle")
    # One for the restart to read back.
    check("lifecycle: the restart's configuration is put",
          put_lc(lc_doc(lc_rule("keep", "<And><Prefix>k/</Prefix>%s</And>" % tag_xml("keep", "1"),
                                "<Expiration><Days>4000</Days></Expiration>"))) == (200, None))


def mode_restart(port):
    tcp_setup(port)
    c = client()
    check("a tag change survives a clean stop and a start", tags(c, "a") == [("restart", "kept")], tags(c, "a"))
    check("so do tags a put set", tags(c, "r") == [("put", "time")], tags(c, "r"))
    check("so do tags that needed the object written again", len(tags(c, "big")) == 10, len(tags(c, "big")))
    check("and the GET count with them", tag_count("a") == (200, "1"), tag_count("a"))
    got = c.get_bucket_lifecycle_configuration(Bucket=LB)["Rules"]
    check("a lifecycle filter by And with a tag survives too",
          [r["Filter"] for r in got] == [{"And": {"Prefix": "k/", "Tags": [{"Key": "keep", "Value": "1"}]}}], got)


def worker_pid():
    for s in stats_shards().values():
        if s.get("pid"):
            return s["pid"]
    return None


def up(old_pid):
    def probe():
        p = worker_pid()
        try:
            return p and p != old_pid and os.path.isdir("/proc/%s" % p) and raw("GET", "/")[0] == 200
        except OSError:
            return False
    return wait_for(probe, 40)


def mode_crash(port, data):
    tcp_setup(port)
    c = client()
    for i in range(20):
        c.put_object(Bucket=B, Key="crash/%02d" % i, Body=os.urandom(2000 + i), Tagging="at=put")
    ids = {k: identity(c, k) for k in ["crash/%02d" % i for i in range(20)]}
    for i in range(20):
        put_tags(c, "crash/%02d" % i, [("at", "change"), ("i", str(i))])
    put_tags(c, "big", [("small", "again")])
    pid = worker_pid()
    os.kill(int(pid), signal.SIGKILL)
    check("the worker comes back after SIGKILL", up(pid), worker_pid())
    got = {i: tags(c, "crash/%02d" % i) for i in range(20)}
    check("every tag change answered before the kill is there after it",
          all(got[i] == [("at", "change"), ("i", str(i))] for i in range(20)), got)
    check("with the objects' bytes, ETags and times as they were",
          all(identity(c, k) == v for k, v in ids.items()))
    check("a set that replaced a rewritten header's is there too", tags(c, "big") == [("small", "again")], tags(c, "big"))

    # The object files are the truth: with every journal gone, a start finds the tags in them.
    for i in range(5):
        put_tags(c, "crash/%02d" % i, [("journal", "gone"), ("i", str(i))])
    subprocess.run([BIN, "stop", RUNTIME], capture_output=True)
    time.sleep(0.5)
    removed = 0
    for root, _, files in os.walk(data):
        for f in files:
            if f.startswith("index.") or f.startswith(".clean."):
                os.unlink(os.path.join(root, f))
                removed += 1
    check("the journals are removed while it is stopped", removed > 0, removed)
    subprocess.run([BIN, "start", RUNTIME], capture_output=True)
    check("it starts again", wait_for(lambda: raw("GET", "/")[0] == 200, 30))
    got = {i: tags(c, "crash/%02d" % i) for i in range(20)}
    check("every object's tags come back from its own file",
          all(got[i] == ([("journal", "gone"), ("i", str(i))] if i < 5 else [("at", "change"), ("i", str(i))])
              for i in range(20)), got)
    check("including the ones a put set and nothing changed", tags(c, "r") == [("put", "time")], tags(c, "r"))
    check("and the GET count with them", tag_count("crash/03") == (200, "2"), tag_count("crash/03"))


# ── two shards, one node each ───────────────────────────────────────────────
class UnixConn(http.client.HTTPConnection):
    def __init__(self, path, timeout=30):
        super().__init__("localhost", timeout=timeout)
        self.unix_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.unix_path)


def ureq(node, method, path, body=None, headers=None):
    c = UnixConn(node)
    try:
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        return r.status, dict((k.lower(), v) for k, v in r.getheaders()), r.read()
    finally:
        c.close()


def mode_shards(nodes):
    st, _, _ = ureq(nodes[0], "PUT", "/" + B)
    check("the bucket is made", st == 200, st)
    n = 16
    for i in range(n):
        st, _, _ = ureq(nodes[i % 2], "PUT", "/%s/k%02d" % (B, i), b"v" * 4096, {"x-amz-tagging": "first=1"})
        if st != 200:
            check("object %d is put" % i, False, st)
    sent0 = {k: int(s.get("shard_tags_sent", "0")) for k, s in stats_shards().items()}
    stale = []
    for i in range(n):
        path = "/%s/k%02d" % (B, i)
        # Both shards hold the object and the headers of its plain GET in memory.
        for node in nodes:
            for _ in range(2):
                ureq(node, "GET", path)
        etag = ureq(nodes[0], "HEAD", path)[1].get("etag")
        st, _, body = ureq(nodes[(i + 1) % 2], "PUT", path + "?tagging", tagging_doc([("second", str(i)), ("b", "2")]))
        if st != 200:
            stale.append((i, "put", st, body))
            continue
        for j, node in enumerate(nodes):
            st, _, body = ureq(node, "GET", path + "?tagging")
            if st != 200 or tagset_of(body) != [("second", str(i)), ("b", "2")]:
                stale.append((i, j, "tagging", st, body))
            for method in ("GET", "HEAD"):
                st, h, _ = ureq(node, method, path)
                if h.get("x-amz-tagging-count") != "2" or h.get("etag") != etag:
                    stale.append((i, j, method, st, h.get("x-amz-tagging-count"), h.get("etag"), etag))
    check("a tag change through either shard is seen by both at once, in GetObjectTagging and in a GET or HEAD",
          not stale, stale[:4])
    sent = lambda: [int(s.get("shard_tags_sent", "0")) - sent0.get(k, 0)  # noqa: E731
                    for k, s in sorted(stats_shards().items())]
    check("and both shards sent some to the owner of the key",
          wait_for(lambda: len(sent()) == 2 and all(v > 0 for v in sent()), 10), sent())
    st, _, body = ureq(nodes[0], "PUT", "/%s/missing?tagging" % B, tagging_doc([("k", "v")]))
    check("a tag change of a key that does not exist is NoSuchKey on either shard",
          (st, xml_code(body)) == (404, "NoSuchKey") and xml_code(ureq(nodes[1], "PUT", "/%s/missing?tagging" % B,
                                                                       tagging_doc([("k", "v")]))[2]) == "NoSuchKey",
          (st, body))
    st, _, _ = ureq(nodes[1], "DELETE", "/%s/k00?tagging" % B)
    check("a DeleteObjectTagging through a shard is 204", st == 204, st)
    check("and both shards have no tags for it",
          all(tagset_of(ureq(node, "GET", "/%s/k00?tagging" % B)[2]) == [] for node in nodes))
    check("nor a count", all(ureq(node, "GET", "/%s/k00" % B)[1].get("x-amz-tagging-count") is None for node in nodes))


if MODE == "main":
    mode_main(int(sys.argv[2]))
elif MODE == "restart":
    mode_restart(int(sys.argv[2]))
elif MODE == "crash":
    mode_crash(int(sys.argv[2]), sys.argv[3])
elif MODE == "shards":
    mode_shards(sys.argv[2:])
else:
    print("unknown mode " + MODE)
    sys.exit(2)
print("  Results: %d passed, %d failed" % (passed, failed))
sys.exit(failed)
