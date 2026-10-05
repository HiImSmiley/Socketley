#!/usr/bin/env python3
"""Bucket lifecycle on the storage runtime: the configuration and its sweep.

usage: lib_storage_bucket_lifecycle.py MODE ARGS...

  main PORT            a runtime with credentials and a lifecycle day of a few
                       seconds: put/get/delete of the configuration through
                       boto3 and raw, every refusal, and expiry by prefix, by
                       date, of disabled rules and of incomplete uploads
  restart PORT         after a stop and a start: the configuration is still
                       there and the sweep still runs
  shards NODE0 NODE1   an anonymous runtime of two shards, one node each: a
                       configuration put through one shard is every shard's,
                       and each expires the keys it owns
  shards_restart NODE0 NODE1
                       after a stop and a start, both shards still have it

Prints one PASS or FAIL line per assertion and exits with the number of failures.
"""
import base64
import hashlib
import http.client
import os
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
RUNTIME = os.environ.get("RUNTIME", "lc")
DAY = int(os.environ.get("SOCKETLEY_STORAGE_LIFECYCLE_DAY_SECS", "2"))
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
B = "lcb"

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
    return sum(int(s.get(name, "0")) for s in stats_shards().values())


def xml_code(body):
    try:
        return ET.fromstring(body).findtext("Code")
    except Exception:
        return None


def rules_of(body):
    """The rules of a GetBucketLifecycleConfiguration answer, as dicts of what this runtime keeps."""
    out = []
    for r in ET.fromstring(body).findall(NS + "Rule"):
        f = r.find(NS + "Filter")
        out.append({
            "id": r.findtext(NS + "ID"),
            "status": r.findtext(NS + "Status"),
            "prefix": r.findtext(NS + "Prefix"),
            "filter": None if f is None else (f.findtext(NS + "Prefix") or ""),
            "days": r.findtext(NS + "Expiration/" + NS + "Days"),
            "date": r.findtext(NS + "Expiration/" + NS + "Date"),
            "abort": r.findtext(NS + "AbortIncompleteMultipartUpload/" + NS + "DaysAfterInitiation"),
        })
    return out


def doc(*rules):
    return ('<?xml version="1.0" encoding="UTF-8"?>\n<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            + "".join(rules) + "</LifecycleConfiguration>").encode()


def rule(body, rid=None, status="Enabled", prefix=None, legacy=False):
    head = "" if rid is None else "<ID>%s</ID>" % rid
    if legacy:
        head += "<Prefix>%s</Prefix>" % (prefix or "")
    elif prefix is None:
        head += "<Filter></Filter>"
    else:
        head += "<Filter><Prefix>%s</Prefix></Filter>" % prefix
    return "<Rule>%s<Status>%s</Status>%s</Rule>" % (head, status, body)


def days(n):
    return "<Expiration><Days>%s</Days></Expiration>" % n


def abort(n):
    return "<AbortIncompleteMultipartUpload><DaysAfterInitiation>%s</DaysAfterInitiation></AbortIncompleteMultipartUpload>" % n


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
        return r.status, r.read()
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


def put_lc(body, extra=None):
    st, data = raw("PUT", "/" + B, "lifecycle", body, dict({"Content-MD5": base64.b64encode(hashlib.md5(body).digest()).decode()}, **(extra or {})))
    return st, xml_code(data)


def get_lc(bucket=B):
    return raw("GET", "/" + bucket, "lifecycle")


def keys(c, prefix=""):
    out = []
    for page in c.get_paginator("list_objects_v2").paginate(Bucket=B, Prefix=prefix):
        out += [o["Key"] for o in page.get("Contents", [])]
    return out


def mode_main(port):
    tcp_setup(port)
    c = client()
    c.create_bucket(Bucket=B)

    # ── the configuration ──
    st, data = get_lc()
    check("a bucket without a configuration is NoSuchLifecycleConfiguration 404",
          st == 404 and xml_code(data) == "NoSuchLifecycleConfiguration", (st, data))
    check("and the error names the bucket", ET.fromstring(data).findtext("BucketName") == B, data)
    check("GET on a bucket that does not exist is NoSuchBucket", xml_code(get_lc("nolcbucket")[1]) == "NoSuchBucket")

    good = doc(rule(days(30), "logs", prefix="logs/") + rule(abort(7), "mpu", prefix="tmp/"))
    check("a configuration is put", put_lc(good) == (200, None))
    st, data = get_lc()
    got = rules_of(data) if st == 200 else []
    check("and read back rule for rule",
          got == [{"id": "logs", "status": "Enabled", "prefix": None, "filter": "logs/", "days": "30", "date": None, "abort": None},
                  {"id": "mpu", "status": "Enabled", "prefix": None, "filter": "tmp/", "days": None, "date": None, "abort": "7"}],
          got)

    refusals = [
        ("an empty body", b"", "MalformedXML"),
        ("a body that is not XML", b"lifecycle please", "MalformedXML"),
        ("another root element", b"<Delete><Object><Key>a</Key></Object></Delete>", "MalformedXML"),
        ("a configuration with no rule", doc(), "MalformedXML"),
        ("an unknown element in a rule", doc(rule(days(1) + "<Colour>red</Colour>", "u")), "MalformedXML"),
        ("a rule with no Status", doc("<Rule><ID>s</ID><Filter></Filter>" + days(1) + "</Rule>"), "MalformedXML"),
        ("a Status that is neither Enabled nor Disabled", doc(rule(days(1), "s", status="enabled")), "MalformedXML"),
        ("a rule with both a Filter and its own Prefix",
         doc("<Rule><ID>p</ID><Prefix>a</Prefix><Filter></Filter><Status>Enabled</Status>" + days(1) + "</Rule>"), "MalformedXML"),
        ("a rule with neither a Filter nor a Prefix", doc("<Rule><ID>p</ID><Status>Enabled</Status>" + days(1) + "</Rule>"), "MalformedXML"),
        ("an Expiration with Days and a Date",
         doc(rule("<Expiration><Days>1</Days><Date>2030-01-01T00:00:00Z</Date></Expiration>", "dd")), "MalformedXML"),
        ("an empty Expiration", doc(rule("<Expiration></Expiration>", "e")), "MalformedXML"),
        ("Days of zero", doc(rule(days(0), "z")), "InvalidArgument"),
        ("negative Days", doc(rule(days(-3), "n")), "InvalidArgument"),
        ("Days that are not a number", doc(rule(days("ten"), "t")), "InvalidArgument"),
        ("a Date that is not midnight", doc(rule("<Expiration><Date>2030-01-01T10:00:00Z</Date></Expiration>", "m")), "InvalidArgument"),
        ("a Date that is not a date", doc(rule("<Expiration><Date>soon</Date></Expiration>", "m")), "InvalidArgument"),
        ("DaysAfterInitiation of zero", doc(rule(abort(0), "a")), "InvalidArgument"),
        ("two rules with one ID", doc(rule(days(1), "same", prefix="a/") + rule(days(2), "same", prefix="b/")), "InvalidArgument"),
        ("an ID longer than 255", doc(rule(days(1), "x" * 256)), "InvalidArgument"),
        ("a rule with no action", doc(rule("", "noop")), "InvalidRequest"),
        ("a filter by tag beside an abort of uploads", doc("<Rule><ID>t</ID><Filter><Tag><Key>k</Key><Value>v</Value></Tag></Filter><Status>Enabled</Status>" + abort(1) + "</Rule>"), "InvalidRequest"),
        ("a filter by And with one tag key twice", doc("<Rule><ID>t</ID><Filter><And><Prefix>a</Prefix><Tag><Key>k</Key><Value>1</Value></Tag><Tag><Key>k</Key><Value>2</Value></Tag></And></Filter><Status>Enabled</Status>" + days(1) + "</Rule>"), "InvalidRequest"),
        ("a filter by size beside an abort of uploads", doc("<Rule><ID>t</ID><Filter><ObjectSizeGreaterThan>5</ObjectSizeGreaterThan></Filter><Status>Enabled</Status>" + abort(1) + "</Rule>"), "InvalidRequest"),
        ("a transition to a class that is no tier of --tiers", doc(rule("<Transition><Days>1</Days><StorageClass>GLACIER</StorageClass></Transition>", "tr")), "InvalidStorageClass"),
        ("two transitions in one rule", doc(rule("<Transition><Days>1</Days><StorageClass>A</StorageClass></Transition><Transition><Days>2</Days><StorageClass>B</StorageClass></Transition>", "t2")), "NotImplemented"),
        ("a noncurrent version expiration that keeps newer versions", doc(rule("<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays><NewerNoncurrentVersions>2</NewerNoncurrentVersions></NoncurrentVersionExpiration>", "nv")), "NotImplemented"),
        ("NoncurrentDays of zero", doc(rule("<NoncurrentVersionExpiration><NoncurrentDays>0</NoncurrentDays></NoncurrentVersionExpiration>", "nz")), "InvalidArgument"),
        ("1001 rules", doc(*[rule(days(1), "r%d" % i, prefix="p%d/" % i) for i in range(1001)]), "InvalidArgument"),
    ]
    for name, body, want in refusals:
        st, code = put_lc(body)
        check("%s is refused as %s" % (name, want), code == want and st in (400, 501), (st, code))
    check("and none of them replaced the configuration that was there", rules_of(get_lc()[1]) == got, rules_of(get_lc()[1]))

    bad_md5 = base64.b64encode(hashlib.md5(b"other").digest()).decode()
    st, data = raw("PUT", "/" + B, "lifecycle", good, {"Content-MD5": bad_md5})
    check("a Content-MD5 the body does not match is BadDigest", (st, xml_code(data)) == (400, "BadDigest"), (st, data))
    st, data = raw("PUT", "/nolcbucket", "lifecycle", good)
    check("a configuration for a bucket that does not exist is NoSuchBucket", (st, xml_code(data)) == (404, "NoSuchBucket"), (st, data))
    c.put_object(Bucket=B, Key="plain", Body=b"x")
    st, data = raw("GET", "/%s/plain" % B, "lifecycle")
    check("?lifecycle on an object is NotImplemented", (st, xml_code(data)) == (501, "NotImplemented"), (st, data))
    c.delete_object(Bucket=B, Key="plain")

    thousand = doc(*[rule(days(1000 + i), "r%d" % i, prefix="p%d/" % i) for i in range(1000)])
    check("1000 rules are taken", put_lc(thousand) == (200, None))
    check("and read back as 1000", len(rules_of(get_lc()[1])) == 1000)

    no_id = doc(rule(days(9), prefix="n/"))
    put_lc(no_id)
    rid = rules_of(get_lc()[1])[0]["id"]
    check("a rule without an ID is given one", bool(rid) and len(rid) <= 255, rid)

    legacy = doc(rule(days(9), "old", prefix="old/", legacy=True))
    put_lc(legacy)
    check("a rule's own Prefix is written back as it came",
          [(r["prefix"], r["filter"]) for r in rules_of(get_lc()[1])] == [("old/", None)], rules_of(get_lc()[1]))

    # boto3, which is what people run.
    rules = [{"ID": "b1", "Filter": {"Prefix": "b/"}, "Status": "Enabled", "Expiration": {"Days": 3},
              "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 2}},
             {"ID": "b2", "Filter": {}, "Status": "Disabled", "Expiration": {"Date": "2031-02-03T00:00:00Z"}}]
    code = boto_code(lambda: c.put_bucket_lifecycle_configuration(Bucket=B, LifecycleConfiguration={"Rules": rules}))
    check("boto3 puts a configuration", code == (None, 200), code)
    got_b = c.get_bucket_lifecycle_configuration(Bucket=B)["Rules"]
    check("and reads it back",
          [(r["ID"], r["Status"], r.get("Filter"), r.get("Expiration", {}).get("Days"),
            str(r.get("Expiration", {}).get("Date", ""))[:10],
            r.get("AbortIncompleteMultipartUpload", {}).get("DaysAfterInitiation")) for r in got_b]
          == [("b1", "Enabled", {"Prefix": "b/"}, 3, "", 2), ("b2", "Disabled", {}, None, "2031-02-03", None)], got_b)
    code = boto_code(lambda: c.delete_bucket_lifecycle(Bucket=B))
    check("boto3 deletes it", code == (None, 200), code)
    check("after which it is NoSuchLifecycleConfiguration",
          boto_code(lambda: c.get_bucket_lifecycle_configuration(Bucket=B)) == ("NoSuchLifecycleConfiguration", 404))
    st, _ = raw("DELETE", "/" + B, "lifecycle")
    check("deleting it again is still 204", st == 204, st)
    check("and the bucket itself was not deleted by either", boto_code(lambda: c.head_bucket(Bucket=B)) == (None, 200))

    # ── the sweep ──
    names = {"logs": ["logs/a", "logs/b", "logs/deep/c"], "keep": ["keep/a", "keep/logs/b", "log"],
             "off": ["off/a", "off/b"], "dated": ["dated/a"], "future": ["future/a"], "legacy": ["legacy/a"]}
    put_at = {}
    for ks in names.values():
        for k in ks:
            c.put_object(Bucket=B, Key=k, Body=k.encode())
            put_at[k] = time.time()
    m1 = c.create_multipart_upload(Bucket=B, Key="mpu/a")["UploadId"]
    c.upload_part(Bucket=B, Key="mpu/a", UploadId=m1, PartNumber=1, Body=b"p" * 1000)
    m2 = c.create_multipart_upload(Bucket=B, Key="other/a")["UploadId"]
    before = stat_total("lifecycle_expired"), stat_total("lifecycle_aborted")
    sweep = doc(rule(days(1), "logs", prefix="logs/"),
                rule(days(1), "off", status="Disabled", prefix="off/"),
                rule("<Expiration><Date>2020-01-01T00:00:00Z</Date></Expiration>", "dated", prefix="dated/"),
                rule("<Expiration><Date>2999-01-01T00:00:00.000Z</Date></Expiration>", "future", prefix="future/"),
                rule(days(1), "legacy", prefix="legacy/", legacy=True),
                rule(abort(1), "mpu", prefix="mpu/"))
    t_cfg = time.time()
    check("the sweep's configuration is put", put_lc(sweep) == (200, None))
    gone = names["logs"] + names["dated"] + names["legacy"]
    gone_at = {}
    end = time.time() + 6 * DAY + 10
    while time.time() < end and len(gone_at) < len(gone):
        present = set(keys(c))
        for k in gone:
            if k not in present and k not in gone_at:
                gone_at[k] = time.time()
        time.sleep(0.1)
    check("objects under an expiring prefix are deleted within a few lifecycle days", len(gone_at) == len(gone), keys(c))
    early = [(k, round(gone_at[k] - put_at[k], 2)) for k in names["logs"] + names["legacy"]
             if k in gone_at and gone_at[k] - put_at[k] < DAY - 0.3]
    check("and none of those with Days goes before a day after its mtime", not early, early)
    soon = gone_at.get("dated/a", 1e18) - t_cfg
    check("one under a date already past goes at the first pass", soon <= 3.0, soon)
    open_ups = lambda: [(u["Key"], u["UploadId"]) for u in c.list_multipart_uploads(Bucket=B).get("Uploads", [])]  # noqa: E731
    check("an incomplete upload under the abort rule's prefix is aborted",
          wait_for(lambda: ("mpu/a", m1) not in open_ups(), 6 * DAY + 10), open_ups())
    time.sleep(2 * DAY + 2)
    left = keys(c)
    check("objects outside every prefix are kept", all(k in left for k in names["keep"]), left)
    check("objects under a disabled rule are kept", all(k in left for k in names["off"]), left)
    check("an object under a date still to come is kept", "future/a" in left, left)
    check("an upload outside the abort rule's prefix is kept", ("other/a", m2) in open_ups(), open_ups())
    after = stat_total("lifecycle_expired"), stat_total("lifecycle_aborted")
    check("stats counts the objects expired", after[0] - before[0] == len(gone), (before, after))
    check("and the uploads aborted", after[1] - before[1] == 1, (before, after))
    check("a GET of an expired object is NoSuchKey", boto_code(lambda: c.get_object(Bucket=B, Key="logs/a")) == ("NoSuchKey", 404))

    # One put now under the expiring prefix is there until its own day is over.
    c.put_object(Bucket=B, Key="logs/fresh", Body=b"f")
    check("a new object under an expiring prefix is there at first", "logs/fresh" in keys(c))
    check("and goes after its day", wait_for(lambda: "logs/fresh" not in keys(c), 6 * DAY + 10), keys(c))

    # The configuration removed stops the sweep.
    raw("DELETE", "/" + B, "lifecycle")
    c.put_object(Bucket=B, Key="logs/after-delete", Body=b"d")
    time.sleep(3 * DAY + 2)
    check("with the configuration deleted nothing more expires", "logs/after-delete" in keys(c), keys(c))

    # What the restart half finds.
    check("the restart half's configuration is put", put_lc(doc(rule(days(1), "r", prefix="restart/"), rule(days(5000), "long", prefix="long/"))) == (200, None))


def mode_restart(port):
    tcp_setup(port)
    c = client()
    got = rules_of(get_lc()[1])
    check("the configuration survives a stop and a start",
          [(r["id"], r["filter"], r["days"]) for r in got] == [("r", "restart/", "1"), ("long", "long/", "5000")], got)
    c.put_object(Bucket=B, Key="restart/a", Body=b"r")
    c.put_object(Bucket=B, Key="long/a", Body=b"l")
    check("and the sweep runs after it", wait_for(lambda: "restart/a" not in keys(c), 6 * DAY + 10), keys(c))
    check("by the rules it held", "long/a" in keys(c), keys(c))


# ── two shards, one node each ───────────────────────────────────────────────
class UnixConn(http.client.HTTPConnection):
    def __init__(self, path, timeout=30):
        super().__init__("localhost", timeout=timeout)
        self.unix_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.unix_path)


def ureq(node, method, path, body=None):
    c = UnixConn(node)
    try:
        c.request(method, path, body=body)
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def ukeys(node, prefix):
    st, body = ureq(node, "GET", "/%s?list-type=2&prefix=%s" % (B, prefix))
    return [k.text for k in ET.fromstring(body).iter(NS + "Key")] if st == 200 else None


def mode_shards(nodes):
    st, _ = ureq(nodes[0], "PUT", "/" + B)
    check("the bucket is made", st == 200, st)
    for i, node in enumerate(nodes):
        st, data = ureq(node, "GET", "/%s?lifecycle" % B)
        check("shard %d has no configuration at first" % i, (st, xml_code(data)) == (404, "NoSuchLifecycleConfiguration"), (st, data))
    cfg = doc(rule(days(1), "x", prefix="x/"), rule(abort(1), "u", prefix="x/"))
    st, data = ureq(nodes[1], "PUT", "/%s?lifecycle" % B, cfg)
    check("a configuration is put through shard 1, which is not the shard that writes it", st == 200, (st, data))
    want = None
    for i, node in enumerate(nodes):
        st, data = ureq(node, "GET", "/%s?lifecycle" % B)
        if want is None:
            want = data
        check("shard %d answers with it" % i, st == 200 and rules_of(data) and data == want, (st, data))
    check("the file shard 0 wrote is the one configuration", os.path.exists(os.path.join(os.environ["LC_DATA"], B, "lifecycle")))

    n = 24
    for i in range(n):
        st, _ = ureq(nodes[i % 2], "PUT", "/%s/x/%02d" % (B, i), b"v%d" % i)
        if st != 200:
            check("object %d is put" % i, False, st)
    for i in range(4):
        ureq(nodes[i % 2], "PUT", "/%s/y/%02d" % (B, i), b"y")
    check("every object expires, on whichever shard owns it",
          wait_for(lambda: ukeys(nodes[0], "x/") == [], 6 * DAY + 10), ukeys(nodes[0], "x/"))
    check("and the ones outside the prefix stay", len(ukeys(nodes[1], "y/") or []) == 4, ukeys(nodes[1], "y/"))
    per = {}
    for _ in range(20):
        s = stats_shards()
        per = {k: int(v.get("lifecycle_expired", "0")) for k, v in s.items()}
        if sum(per.values()) == n:
            break
        time.sleep(0.5)
    check("each shard expired only its own keys, %d in all" % n, sum(per.values()) == n and len(per) == 2, per)
    check("and both shards had some", all(v > 0 for v in per.values()), per)

    st, _ = ureq(nodes[0], "DELETE", "/%s?lifecycle" % B)
    check("deleting it through shard 0 is 204", st == 204, st)
    for i, node in enumerate(nodes):
        st, data = ureq(node, "GET", "/%s?lifecycle" % B)
        check("and shard %d no longer has it" % i, (st, xml_code(data)) == (404, "NoSuchLifecycleConfiguration"), (st, data))
    st, data = ureq(nodes[0], "PUT", "/%s?lifecycle" % B, doc(rule(days(4000), "keep", prefix="k/")))
    check("one more is put through shard 0 for the restart", st == 200, (st, data))


def mode_shards_restart(nodes):
    for i, node in enumerate(nodes):
        st, data = ureq(node, "GET", "/%s?lifecycle" % B)
        got = rules_of(data) if st == 200 else data
        check("shard %d has the configuration after a stop and a start" % i,
              st == 200 and [(r["id"], r["filter"], r["days"]) for r in got] == [("keep", "k/", "4000")], (st, got))


if MODE == "main":
    mode_main(int(sys.argv[2]))
elif MODE == "restart":
    mode_restart(int(sys.argv[2]))
elif MODE == "shards":
    mode_shards(sys.argv[2:])
elif MODE == "shards_restart":
    mode_shards_restart(sys.argv[2:])
else:
    print("unknown mode " + MODE)
    sys.exit(2)
print("  Results: %d passed, %d failed" % (passed, failed))
sys.exit(failed)
