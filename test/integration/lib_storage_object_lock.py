#!/usr/bin/env python3
"""S3 Object Lock on the storage runtime.

usage: lib_storage_object_lock.py MODE ARGS...

  main PORT DATA       a runtime with two keys over TCP: the bucket configuration, both retention modes, the bypass
                       with and without s3:BypassGovernanceRetention, legal hold, lengthening against shortening,
                       multipart and copy, DeleteObjects, the lifecycle, DeleteBucket and boto3
  recovery PORT DATA   versions whose lock is in their header, in a slot and in a header written again, after a clean
                       restart, after a SIGKILL, and after a SIGKILL with every journal removed
  shards NODE0 NODE1   two shards, one unix node each, anonymous: every lock operation through the shard that owns the
                       key and the one that does not, and the configuration through both

Prints one PASS or FAIL line per assertion and exits with the number of failures.
"""
import base64
import datetime
import hashlib
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib_s3_signing as sig  # noqa: E402

MODE = sys.argv[1]
BIN = os.environ.get("BIN", "")
RUNTIME = os.environ.get("RUNTIME", "olk")
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
AK1 = os.environ.get("AK1", "AKIALOCKKEYONE000001")
SK1 = os.environ.get("SK1", "lock/one/secret")
AK2 = os.environ.get("AK2", "AKIALOCKKEYTWO000002")
SK2 = os.environ.get("SK2", "lock/two/secret")
K1 = (AK1, SK1)
K2 = (AK2, SK2)
DAY = 86400
# Metadata and tags that fill a header's first 4 KiB, so it has no room for a slot.
FAT = {"x-amz-meta-big": "m" * 1900,
       "x-amz-tagging": "&".join("%s=%s" % (chr(97 + i) * 100, "v" * 200) for i in range(6))}

passed = failed = 0
TARGET = None
KEY = K1


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
        v = fn()
        if v:
            return v
        time.sleep(0.2)
    return fn()


class UnixConn(http.client.HTTPConnection):
    def __init__(self, path, timeout=60):
        super().__init__("localhost", timeout=timeout)
        self.unix_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.unix_path)


class Resp:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    def code(self):
        try:
            return ET.fromstring(self.body).findtext("Code") or ""
        except ET.ParseError:
            return ""

    def text(self, name):
        try:
            return ET.fromstring(self.body).findtext(".//" + NS + name)
        except ET.ParseError:
            return None

    def __repr__(self):
        return "%d %s %s" % (self.status, self.code() or "", self.body[:300])


def req(method, path, query="", body=b"", headers=None, cred="default", target=None, payload=None):
    """One request, signed with `cred` unless it is None, to a port or a unix socket; `payload` is the hash it signs,
    the body's SHA-256 unless it is given (UNSIGNED-PAYLOAD for one that says nothing of its body)."""
    target = target or TARGET
    key = KEY if cred == "default" else cred
    if isinstance(body, str):
        body = body.encode()
    if isinstance(target, str):
        c, host = UnixConn(target), "localhost"
    else:
        c, host = http.client.HTTPConnection("127.0.0.1", target, timeout=60), "127.0.0.1:%d" % target
    hdrs = dict(headers or {})
    if key is not None:
        hdrs = dict(sig.sign(method, path, query, host, key[0], key[1], payload or sig.sha256hex(body),
                             extra_headers=hdrs).headers)
    hdrs["Host"] = host
    try:
        c.request(method, path + ("?" + query if query else ""), body=body if body or method in ("PUT", "POST") else None,
                  headers=hdrs)
        r = c.getresponse()
        return Resp(r.status, {k.lower(): v for k, v in r.getheaders()}, r.read())
    finally:
        c.close()


def md5h(body):
    return {"Content-MD5": base64.b64encode(hashlib.md5(body).digest()).decode()}


def iso(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def ms_of(s):
    return int(datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=datetime.timezone.utc)
               .timestamp() * 1000 + 0.5)


def create(bucket, lock=False, **kw):
    return req("PUT", "/" + bucket, headers={"x-amz-bucket-object-lock-enabled": "true"} if lock else None, **kw)


def lock_doc(mode=None, days=None, years=None, enabled="Enabled"):
    rule = ""
    if mode is not None:
        rule = "<Rule><DefaultRetention><Mode>%s</Mode>%s%s</DefaultRetention></Rule>" % (
            mode, "<Days>%s</Days>" % days if days is not None else "",
            "<Years>%s</Years>" % years if years is not None else "")
    return ('<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            "<ObjectLockEnabled>%s</ObjectLockEnabled>%s</ObjectLockConfiguration>" % (enabled, rule)).encode()


def put_lock_config(bucket, doc, integrity="md5", **kw):
    h = md5h(doc) if integrity == "md5" else {}
    if integrity is None:
        kw.setdefault("payload", "UNSIGNED-PAYLOAD")
    if integrity == "crc32":
        h = {"x-amz-checksum-crc32": sig.crc32_b64(doc)}
    return req("PUT", "/" + bucket, "object-lock", doc, h, **kw)


def get_lock_config(bucket, **kw):
    return req("GET", "/" + bucket, "object-lock", **kw)


def set_versioning(bucket, status, **kw):
    doc = ('<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
           "<Status>%s</Status></VersioningConfiguration>" % status).encode()
    return req("PUT", "/" + bucket, "versioning", doc, **kw)


def get_versioning(bucket, **kw):
    return req("GET", "/" + bucket, "versioning", **kw).text("Status")


def put(bucket, key, body=b"x", mode=None, until=None, hold=None, extra=None, integrity=True, **kw):
    h = dict(extra or {})
    if mode is not None:
        h["x-amz-object-lock-mode"] = mode
    if until is not None:
        h["x-amz-object-lock-retain-until-date"] = until if isinstance(until, str) else iso(until)
    if hold is not None:
        h["x-amz-object-lock-legal-hold"] = hold
    if integrity:
        h.update(md5h(body))
    elif integrity is False:
        kw.setdefault("payload", "UNSIGNED-PAYLOAD")
    return req("PUT", "/%s/%s" % (bucket, key), "", body, h, **kw)


def vq(vid):
    return "versionId=" + vid if vid else ""


def retention_doc(mode=None, until=None):
    inner = ""
    if mode is not None:
        inner = "<Mode>%s</Mode><RetainUntilDate>%s</RetainUntilDate>" % (
            mode, until if isinstance(until, str) else iso(until))
    return ('<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/">%s</Retention>' % inner).encode()


def put_retention(bucket, key, mode=None, until=None, vid=None, bypass=False, integrity=True, **kw):
    doc = retention_doc(mode, until)
    h = md5h(doc) if integrity else {}
    if not integrity:
        kw.setdefault("payload", "UNSIGNED-PAYLOAD")
    if bypass:
        h["x-amz-bypass-governance-retention"] = "true"
    return req("PUT", "/%s/%s" % (bucket, key), "retention" + ("&" + vq(vid) if vid else ""), doc, h, **kw)


def get_retention(bucket, key, vid=None, **kw):
    r = req("GET", "/%s/%s" % (bucket, key), "retention" + ("&" + vq(vid) if vid else ""), **kw)
    if r.status != 200:
        return r.status, r.code()
    return r.text("Mode"), ms_of(r.text("RetainUntilDate"))


def put_hold(bucket, key, status, vid=None, **kw):
    doc = ('<LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>%s</Status></LegalHold>' %
           status).encode()
    return req("PUT", "/%s/%s" % (bucket, key), "legal-hold" + ("&" + vq(vid) if vid else ""), doc, md5h(doc), **kw)


def get_hold(bucket, key, vid=None, **kw):
    r = req("GET", "/%s/%s" % (bucket, key), "legal-hold" + ("&" + vq(vid) if vid else ""), **kw)
    return r.text("Status") if r.status == 200 else (r.status, r.code())


def delete(bucket, key, vid=None, bypass=False, **kw):
    h = {"x-amz-bypass-governance-retention": "true"} if bypass else None
    return req("DELETE", "/%s/%s" % (bucket, key), vq(vid), headers=h, **kw)


def head(bucket, key, vid=None, **kw):
    r = req("HEAD", "/%s/%s" % (bucket, key), vq(vid), **kw)
    return r.status, r.headers


def lock_headers(bucket, key, vid=None, **kw):
    st, h = head(bucket, key, vid, **kw)
    until = h.get("x-amz-object-lock-retain-until-date")
    return (st, h.get("x-amz-object-lock-mode"), ms_of(until) if until else None, h.get("x-amz-object-lock-legal-hold"))


def exists(bucket, key, vid):
    return req("GET", "/%s/%s" % (bucket, key), vq(vid)).status == 200


def denied(r):
    return r.status == 403 and r.code() == "AccessDenied"


# ─── main ───────────────────────────────────────────────────────────────────

def config():
    r = create("lkb", lock=True)
    check("CreateBucket with x-amz-bucket-object-lock-enabled: true", r.status == 200, r)
    check("it turns versioning on", get_versioning("lkb") == "Enabled", get_versioning("lkb"))
    r = get_lock_config("lkb")
    check("GetObjectLockConfiguration of it is Enabled with no rule",
          r.status == 200 and r.text("ObjectLockEnabled") == "Enabled" and r.text("Rule") is None, r)
    r = set_versioning("lkb", "Suspended")
    check("versioning of a locked bucket cannot be suspended", (r.status, r.code()) == (409, "InvalidBucketState"), r)
    check("and stays Enabled", get_versioning("lkb") == "Enabled")

    create("plain")
    r = get_lock_config("plain")
    check("GetObjectLockConfiguration of a bucket without it is ObjectLockConfigurationNotFoundError",
          (r.status, r.code()) == (404, "ObjectLockConfigurationNotFoundError"), r)
    r = put_lock_config("plain", lock_doc("GOVERNANCE", days=1))
    check("PutObjectLockConfiguration of an unversioned bucket is InvalidBucketState",
          (r.status, r.code()) == (409, "InvalidBucketState"), r)
    set_versioning("plain", "Suspended")
    r = put_lock_config("plain", lock_doc("GOVERNANCE", days=1))
    check("and of a suspended one", (r.status, r.code()) == (409, "InvalidBucketState"), r)
    set_versioning("plain", "Enabled")
    r = put_lock_config("plain", lock_doc("GOVERNANCE", days=1))
    check("an existing bucket with versioning Enabled takes object lock", r.status == 200, r)
    r = get_lock_config("plain")
    check("and reads it back", r.status == 200 and r.text("Mode") == "GOVERNANCE" and r.text("Days") == "1", r)
    r = set_versioning("plain", "Suspended")
    check("after which its versioning cannot be suspended either", r.status == 409, r)

    doc = lock_doc("COMPLIANCE", years=1)
    r = put_lock_config("lkb", doc, integrity=None)
    check("PutObjectLockConfiguration with neither Content-MD5 nor a checksum is InvalidRequest",
          (r.status, r.code()) == (400, "InvalidRequest"), r)
    r = req("PUT", "/lkb", "object-lock", doc, {"Content-MD5": base64.b64encode(hashlib.md5(b"other").digest()).decode()})
    check("a Content-MD5 the body does not match is BadDigest", (r.status, r.code()) == (400, "BadDigest"), r)
    r = req("PUT", "/lkb", "object-lock", doc, {"x-amz-checksum-crc32": sig.crc32_b64(b"other")})
    check("an x-amz-checksum-crc32 it does not match is BadDigest", (r.status, r.code()) == (400, "BadDigest"), r)
    r = put_lock_config("lkb", doc, integrity="crc32")
    check("an x-amz-checksum-crc32 alone is taken", r.status == 200, r)
    r = get_lock_config("lkb")
    check("COMPLIANCE for one year reads back", (r.text("Mode"), r.text("Years"), r.text("Days")) ==
          ("COMPLIANCE", "1", None), r)
    for name, d, code in (("Days and Years", lock_doc("GOVERNANCE", 1, 1), "MalformedXML"),
                          ("Days 0", lock_doc("GOVERNANCE", 0), "InvalidRetentionPeriod"),
                          ("Years -1", lock_doc("GOVERNANCE", years=-1), "InvalidRetentionPeriod"),
                          ("Days past 100 years", lock_doc("GOVERNANCE", 36501), "InvalidRetentionPeriod"),
                          ("a mode in lowercase", lock_doc("governance", 1), "MalformedXML"),
                          ("no period", lock_doc("GOVERNANCE"), "MalformedXML"),
                          ("ObjectLockEnabled Disabled", lock_doc("GOVERNANCE", 1, enabled="Disabled"), "MalformedXML")):
        r = put_lock_config("lkb", d)
        check("PutObjectLockConfiguration refuses %s as %s" % (name, code), (r.status, r.code()) == (400, code), r)
    r = put_lock_config("lkb", lock_doc())
    check("a configuration with no rule drops the default and keeps the lock", r.status == 200 and
          get_lock_config("lkb").text("Rule") is None and get_versioning("lkb") == "Enabled", r)

    # A bucket without object lock takes none of it.
    create("plainer")
    put("plainer", "k", b"k")
    for name, r in (("PutObjectRetention", put_retention("plainer", "k", "GOVERNANCE", time.time() + DAY)),
                    ("GetObjectRetention", req("GET", "/plainer/k", "retention")),
                    ("PutObjectLegalHold", put_hold("plainer", "k", "ON")),
                    ("GetObjectLegalHold", req("GET", "/plainer/k", "legal-hold")),
                    ("PutObject with a retention", put("plainer", "k2", mode="GOVERNANCE", until=time.time() + DAY))):
        check("%s on a bucket without object lock is InvalidRequest" % name,
              (r.status, r.code()) == (400, "InvalidRequest"), r)


def modes():
    now = time.time()
    r = put("lkb", "c", b"compliance", mode="COMPLIANCE", until=now + DAY)
    c1 = r.headers.get("x-amz-version-id")
    check("PutObject with a COMPLIANCE retention", r.status == 200 and c1, r)
    st, mode, until, hold = lock_headers("lkb", "c")
    check("HEAD names its mode and retain-until date, and no legal hold",
          (st, mode, hold) == (200, "COMPLIANCE", None) and abs(until - (now + DAY) * 1000) < 1000, (st, mode, until))
    got = get_retention("lkb", "c")
    check("GetObjectRetention reads it", got[0] == "COMPLIANCE" and got[1] == until, got)
    # A date with an offset from UTC, as clients in another zone write it (minio-go among them), is that instant.
    r = put("lkb", "z", b"zoned")
    zone = datetime.timezone(datetime.timedelta(hours=2))
    local = datetime.datetime.fromtimestamp(int(now) + DAY, zone).strftime("%Y-%m-%dT%H:%M:%S.123456789+02:00")
    r = put_retention("lkb", "z", "GOVERNANCE", local)
    got = get_retention("lkb", "z")
    check("a RetainUntilDate with an offset from UTC is taken as that instant",
          r.status == 200 and got == ("GOVERNANCE", (int(now) + DAY) * 1000 + 123), (r, got))
    r = delete("lkb", "c", c1)
    check("DELETE of the version is AccessDenied", denied(r), r)
    r = delete("lkb", "c", c1, bypass=True)
    check("and the bypass does not lift COMPLIANCE", denied(r), r)
    r = delete("lkb", "c")
    check("DELETE without a version puts a delete marker in front of it",
          r.status == 204 and r.headers.get("x-amz-delete-marker") == "true", r)
    check("and the version stays", exists("lkb", "c", c1))

    r = put_retention("lkb", "c", "COMPLIANCE", until / 1000 - 3600, vid=c1)
    check("COMPLIANCE cannot be shortened", denied(r), r)
    r = put_retention("lkb", "c", "GOVERNANCE", until / 1000, vid=c1, bypass=True)
    check("nor turned into GOVERNANCE, bypass or not", denied(r), r)
    r = put_retention("lkb", "c", vid=c1, bypass=True)
    check("nor removed", denied(r), r)
    r = put_retention("lkb", "c", "COMPLIANCE", until / 1000 + DAY, vid=c1)
    check("and can be lengthened", r.status == 200, r)
    got = get_retention("lkb", "c", c1)
    check("which reads back", got == ("COMPLIANCE", until + DAY * 1000), (got, until))
    r = put_retention("lkb", "c", "COMPLIANCE", until / 1000 + DAY, vid=c1)
    check("and set again to the same date", r.status == 200, r)

    r = put("lkb", "g", b"governance", mode="GOVERNANCE", until=now + DAY)
    g1 = r.headers.get("x-amz-version-id")
    check("PutObject with a GOVERNANCE retention", r.status == 200, r)
    check("DELETE of a GOVERNANCE version without the bypass is AccessDenied", denied(delete("lkb", "g", g1)))
    r = put_retention("lkb", "g", "GOVERNANCE", now + 3600)
    check("GOVERNANCE is not shortened without the bypass", denied(r), r)
    r = put_retention("lkb", "g", "COMPLIANCE", now + DAY)
    check("nor made COMPLIANCE without it", denied(r), r)
    r = put_retention("lkb", "g", "GOVERNANCE", now + 2 * DAY)
    check("and is lengthened without it", r.status == 200 and get_retention("lkb", "g")[1] == int((now + 2 * DAY)) * 1000,
          (r, get_retention("lkb", "g")))
    r = put_retention("lkb", "g", "GOVERNANCE", now + 3600, bypass=True)
    check("the bypass shortens it", r.status == 200 and get_retention("lkb", "g")[1] == int(now + 3600) * 1000, r)
    r = put_retention("lkb", "g", bypass=True)
    check("and removes it", r.status == 200, r)
    got = get_retention("lkb", "g")
    check("after which GetObjectRetention is NoSuchObjectLockConfiguration",
          got == (404, "NoSuchObjectLockConfiguration"), got)
    st, mode, until2, _ = lock_headers("lkb", "g")
    check("and HEAD names none", (st, mode, until2) == (200, None, None), (st, mode))
    put_retention("lkb", "g", "GOVERNANCE", now + DAY)
    r = delete("lkb", "g", g1, bypass=True)
    check("DELETE with the bypass removes a GOVERNANCE version", r.status == 204, r)
    check("which is gone", req("GET", "/lkb/g", vq(g1)).code() == "NoSuchVersion")

    for name, kw, code in (("a date in the past", {"mode": "GOVERNANCE", "until": now - 60}, "InvalidArgument"),
                           ("a mode without a date", {"mode": "GOVERNANCE"}, "InvalidArgument"),
                           ("a date without a mode", {"until": now + DAY}, "InvalidArgument"),
                           ("an unknown mode", {"mode": "governance", "until": now + DAY}, "InvalidArgument"),
                           ("a date that is no date", {"mode": "GOVERNANCE", "until": "tomorrow"}, "InvalidArgument"),
                           ("a legal hold of maybe", {"hold": "MAYBE"}, "InvalidArgument")):
        r = put("lkb", "bad", **kw)
        check("PutObject refuses %s as %s" % (name, code), (r.status, r.code()) == (400, code), r)
    r = put("lkb", "bad", mode="GOVERNANCE", until=now + DAY, integrity=False)
    check("PutObject with a lock and neither Content-MD5 nor a checksum is InvalidRequest",
          (r.status, r.code()) == (400, "InvalidRequest"), r)
    r = put("lkb", "crc", b"crc", mode="GOVERNANCE", until=now + DAY, integrity=False,
            extra={"x-amz-checksum-crc32": sig.crc32_b64(b"crc")})
    check("an x-amz-checksum-crc32 is enough", r.status == 200, r)
    r = put("lkb", "sha", b"sha", mode="GOVERNANCE", until=now + DAY, integrity=None)
    check("and so is a signed SHA-256 of the body, all an older SDK sends", r.status == 200, r)
    check("nothing was stored by the refused writes", req("HEAD", "/lkb/bad").status == 404)
    r = put_retention("lkb", "crc", "GOVERNANCE", now - 60)
    check("PutObjectRetention of a date in the past is InvalidArgument", (r.status, r.code()) == (400, "InvalidArgument"), r)
    for name, doc in (("a lowercase mode", retention_doc("governance", now + DAY)),
                      ("a mode alone", b"<Retention><Mode>GOVERNANCE</Mode></Retention>"),
                      ("a date that is no date", retention_doc("GOVERNANCE", "soon"))):
        r = req("PUT", "/lkb/crc", "retention", doc, md5h(doc))
        check("PutObjectRetention refuses %s as MalformedXML" % name, (r.status, r.code()) == (400, "MalformedXML"), r)
    r = put_retention("lkb", "crc", "GOVERNANCE", now + 2 * DAY, integrity=False)
    check("PutObjectRetention with neither Content-MD5 nor a checksum is InvalidRequest",
          (r.status, r.code()) == (400, "InvalidRequest"), r)
    r = put_retention("lkb", "nokey", "GOVERNANCE", now + DAY)
    check("PutObjectRetention of a key that is not there is NoSuchKey", (r.status, r.code()) == (404, "NoSuchKey"), r)

    # The server's clock decides: a retention that has run out holds nothing.
    end = int(time.time()) + 4
    r = put("lkb", "short", b"s", mode="COMPLIANCE", until=end)
    s1 = r.headers.get("x-amz-version-id")
    check("a COMPLIANCE retention of a few seconds holds while it runs", denied(delete("lkb", "short", s1)))
    time.sleep(max(0.0, end - time.time()) + 0.5)
    r = delete("lkb", "short", s1)
    check("and nothing once it has passed", r.status == 204, r)


def bypass_permission():
    now = time.time()
    create("pol", lock=True)
    v = put("pol", "k", b"k", mode="GOVERNANCE", until=now + DAY).headers.get("x-amz-version-id")
    w = put("pol", "w", b"w", mode="GOVERNANCE", until=now + DAY).headers.get("x-amz-version-id")
    deny = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Deny", "Principal": {"AWS": "arn:aws:iam::123456789012:user/" + AK2},
         "Action": ["s3:BypassGovernanceRetention", "s3:PutObjectLegalHold"], "Resource": "arn:aws:s3:::pol/*"}]}).encode()
    r = req("PUT", "/pol", "policy", deny, md5h(deny))
    check("a policy that denies one key s3:BypassGovernanceRetention is taken", r.status == 204, r)
    r = delete("pol", "k", v, bypass=True, cred=K2)
    check("that key's bypass is refused", denied(r), r)
    r = put_retention("pol", "k", "GOVERNANCE", now + 60, bypass=True, cred=K2)
    check("and so is its shortening", denied(r), r)
    r = put_hold("pol", "k", "ON", cred=K2)
    check("and its PutObjectLegalHold", denied(r), r)
    r = put("pol", "h", b"h", hold="ON", cred=K2)
    check("and a PutObject of it that asks for a legal hold", denied(r), r)
    check("the version is still there", exists("pol", "k", v))
    r = delete("pol", "w", w, bypass=True, cred=K1)
    check("the other key's bypass removes a version", r.status == 204, r)
    r = delete("pol", "k", v, bypass=True, cred=K1)
    check("including the one the first could not", r.status == 204, r)
    allow = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": ["s3:DeleteObjectVersion", "s3:DeleteObject"],
         "Resource": "arn:aws:s3:::pol/*"}]}).encode()
    req("PUT", "/pol", "policy", allow, md5h(allow))
    a = put("pol", "anon", b"a", mode="GOVERNANCE", until=now + DAY).headers.get("x-amz-version-id")
    r = delete("pol", "anon", a, bypass=True, cred=None)
    check("an anonymous caller a policy lets delete versions has no bypass without an Allow of it", denied(r), r)
    allow = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*",
         "Action": ["s3:DeleteObjectVersion", "s3:BypassGovernanceRetention"], "Resource": "arn:aws:s3:::pol/*"}]}).encode()
    req("PUT", "/pol", "policy", allow, md5h(allow))
    r = delete("pol", "anon", a, bypass=True, cred=None)
    check("and has it with one", r.status == 204, r)
    req("DELETE", "/pol", "policy")


def legal_hold():
    v = put("lkb", "h", b"held").headers.get("x-amz-version-id")
    got = get_hold("lkb", "h")
    check("GetObjectLegalHold of a version never held is NoSuchObjectLockConfiguration",
          got == (404, "NoSuchObjectLockConfiguration"), got)
    r = put_hold("lkb", "h", "ON")
    check("PutObjectLegalHold ON", r.status == 200, r)
    check("GetObjectLegalHold reads ON", get_hold("lkb", "h") == "ON")
    check("HEAD names it", lock_headers("lkb", "h")[3] == "ON")
    check("DELETE of the version is AccessDenied", denied(delete("lkb", "h", v)))
    check("and the bypass does not lift a legal hold", denied(delete("lkb", "h", v, bypass=True)))
    doc = b'<LegalHold><Status>abc</Status></LegalHold>'
    r = req("PUT", "/lkb/h", "legal-hold", doc, md5h(doc))
    check("a Status other than ON or OFF is MalformedXML", (r.status, r.code()) == (400, "MalformedXML"), r)
    r = req("PUT", "/lkb/h", "legal-hold", b"<LegalHold><Status>OFF</Status></LegalHold>", payload="UNSIGNED-PAYLOAD")
    check("PutObjectLegalHold with neither Content-MD5 nor a checksum is InvalidRequest",
          (r.status, r.code()) == (400, "InvalidRequest"), r)
    r = put_hold("lkb", "h", "OFF", vid=v)
    check("PutObjectLegalHold OFF by version id", r.status == 200 and get_hold("lkb", "h", v) == "OFF", r)
    r = delete("lkb", "h", v)
    check("after which the version is removed", r.status == 204, r)

    now = time.time()
    r = put("lkb", "hr", b"both", mode="GOVERNANCE", until=now + DAY, hold="ON")
    hv = r.headers.get("x-amz-version-id")
    check("PutObject with a retention and a legal hold", r.status == 200 and lock_headers("lkb", "hr")[1:2] ==
          ("GOVERNANCE",) and get_hold("lkb", "hr") == "ON", lock_headers("lkb", "hr"))
    check("the bypass lifts the retention and not the hold", denied(delete("lkb", "hr", hv, bypass=True)))
    put_hold("lkb", "hr", "OFF")
    check("and once the hold is off it removes the version", delete("lkb", "hr", hv, bypass=True).status == 204)

    # Tags and a lock share the header's slots, and a change of one keeps the other.
    v = put("lkb", "t", b"tagged", mode="GOVERNANCE", until=now + DAY).headers.get("x-amz-version-id")
    tags = b"<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value></Tag></TagSet></Tagging>"
    r = req("PUT", "/lkb/t", "tagging", tags)
    check("a version under retention takes tags", r.status == 200, r)
    put_hold("lkb", "t", "ON")
    r = req("GET", "/lkb/t", "tagging")
    check("a legal hold set after them keeps them", r.status == 200 and b"<Key>a</Key>" in r.body, r)
    check("and the tags kept the retention", get_retention("lkb", "t")[0] == "GOVERNANCE")
    req("DELETE", "/lkb/t", "tagging")
    check("removing the tags keeps the hold and the retention", get_hold("lkb", "t") == "ON" and
          get_retention("lkb", "t")[0] == "GOVERNANCE")
    put_hold("lkb", "t", "OFF")
    delete("lkb", "t", v, bypass=True)

    # A header with no room for a slot is written again with the lock in it, its bytes and ETag kept.
    r = put("lkb", "fat", b"fat body", extra=FAT)
    fv, etag = r.headers.get("x-amz-version-id"), r.headers.get("etag")
    r = put_retention("lkb", "fat", "GOVERNANCE", now + DAY)
    st, h = head("lkb", "fat")
    check("a retention on a version whose header is full is kept by writing it again",
          r.status == 200 and h.get("x-amz-object-lock-mode") == "GOVERNANCE" and h.get("etag") == etag and
          req("GET", "/lkb/fat").body == b"fat body", (r, h))
    check("and holds", denied(delete("lkb", "fat", fv)))


def default_retention():
    create("dflt", lock=True)
    r = put_lock_config("dflt", lock_doc("GOVERNANCE", days=1))
    check("a default retention of one day", r.status == 200, r)
    before = time.time()
    r = put("dflt", "d", b"d", integrity=False)
    check("a PutObject that asks for no lock is taken without a Content-MD5", r.status == 200, r)
    st, mode, until, _ = lock_headers("dflt", "d")
    check("and is given the default from the moment it was written",
          mode == "GOVERNANCE" and before * 1000 + DAY * 1000 - 2000 <= until <= time.time() * 1000 + DAY * 1000 + 2000,
          (mode, until, before))
    r = put("dflt", "e", b"e", mode="COMPLIANCE", until=time.time() + 600)
    check("explicit headers win over the default", lock_headers("dflt", "e")[1] == "COMPLIANCE", r)
    r = put("dflt", "nolock", b"n", hold="ON")
    check("a legal hold alone still takes the default retention",
          lock_headers("dflt", "nolock")[1] == "GOVERNANCE" and get_hold("dflt", "nolock") == "ON")
    put_lock_config("dflt", lock_doc("COMPLIANCE", years=2))
    put("dflt", "y", b"y")
    _, mode, until, _ = lock_headers("dflt", "y")
    want = datetime.datetime.now(datetime.timezone.utc)
    want = want.replace(year=want.year + 2) if not (want.month == 2 and want.day == 29) else \
        want.replace(year=want.year + 2, day=28)
    check("Years are counted on the calendar", mode == "COMPLIANCE" and abs(until - want.timestamp() * 1000) < 5000,
          (mode, until, want))


def multipart_and_copy():
    now = time.time()
    until = int(now + DAY)
    r = req("POST", "/lkb/mp", "uploads", headers={"x-amz-object-lock-mode": "COMPLIANCE",
                                                  "x-amz-object-lock-retain-until-date": iso(until),
                                                  "x-amz-object-lock-legal-hold": "ON"})
    uid = r.text("UploadId")
    check("CreateMultipartUpload with a retention and a legal hold", r.status == 200 and uid, r)
    part = b"p" * 1024
    r = req("PUT", "/lkb/mp", "partNumber=1&uploadId=" + uid, part)
    etag = r.headers.get("etag")
    doc = ("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>"
           % etag).encode()
    r = req("POST", "/lkb/mp", "uploadId=" + uid, doc)
    mv = r.headers.get("x-amz-version-id")
    check("its completion", r.status == 200 and mv, r)
    st, mode, u, hold = lock_headers("lkb", "mp")
    check("the object it made has both", (mode, u, hold) == ("COMPLIANCE", until * 1000, "ON"), (mode, u, hold))
    check("and its version cannot be removed", denied(delete("lkb", "mp", mv, bypass=True)))
    r = req("POST", "/plainer/mp", "uploads", headers={"x-amz-object-lock-legal-hold": "ON"})
    check("CreateMultipartUpload with a lock into a bucket without one is InvalidRequest",
          (r.status, r.code()) == (400, "InvalidRequest"), r)

    # A copy is a new version whose lock is its own.
    r = req("PUT", "/lkb/cp", headers={"x-amz-copy-source": "/lkb/mp"})
    cv = r.headers.get("x-amz-version-id")
    st, mode, u, hold = lock_headers("lkb", "cp")
    check("a copy of a locked object without lock headers carries none of its source's lock",
          r.status == 200 and (mode, hold) == (None, None), (r, mode, hold))
    check("so it can be removed", delete("lkb", "cp", cv).status == 204)
    r = req("PUT", "/lkb/cp2", headers={"x-amz-copy-source": "/lkb/mp", "x-amz-object-lock-mode": "GOVERNANCE",
                                       "x-amz-object-lock-retain-until-date": iso(now + 600)})
    c2 = r.headers.get("x-amz-version-id")
    check("a copy that asks for a retention has it", r.status == 200 and lock_headers("lkb", "cp2")[1] == "GOVERNANCE", r)
    check("and is held by it", denied(delete("lkb", "cp2", c2)))
    delete("lkb", "cp2", c2, bypass=True)
    r = req("PUT", "/plainer/fromlock", headers={"x-amz-copy-source": "/lkb/mp", "x-amz-metadata-directive": "REPLACE"})
    check("a copy into an unlocked bucket carries no lock",
          r.status == 200 and lock_headers("plainer", "fromlock")[1:] == (None, None, None),
          (r, lock_headers("plainer", "fromlock")))
    check("and can be removed", req("DELETE", "/plainer/fromlock").status == 204)
    r = req("PUT", "/plainer/fromlock2", headers={"x-amz-copy-source": "/lkb/mp",
                                                "x-amz-object-lock-legal-hold": "ON"})
    check("and a copy that asks it for a lock it has not got is InvalidRequest",
          (r.status, r.code()) == (400, "InvalidRequest"), r)


def delete_objects():
    now = time.time()
    a = put("lkb", "da", b"a", mode="GOVERNANCE", until=now + DAY).headers.get("x-amz-version-id")
    b = put("lkb", "db", b"b").headers.get("x-amz-version-id")
    doc = ("<Delete><Object><Key>da</Key><VersionId>%s</VersionId></Object>"
           "<Object><Key>db</Key><VersionId>%s</VersionId></Object></Delete>" % (a, b)).encode()
    r = req("POST", "/lkb", "delete", doc, md5h(doc))
    root = ET.fromstring(r.body)
    errs = [(e.findtext(NS + "Key"), e.findtext(NS + "Code"), e.findtext(NS + "VersionId")) for e in root.findall(NS + "Error")]
    dels = [(d.findtext(NS + "Key"), d.findtext(NS + "VersionId")) for d in root.findall(NS + "Deleted")]
    check("DeleteObjects answers the locked version AccessDenied and removes the other",
          errs == [("da", "AccessDenied", a)] and dels == [("db", b)], (errs, dels))
    doc = ("<Delete><Object><Key>da</Key><VersionId>%s</VersionId></Object></Delete>" % a).encode()
    r = req("POST", "/lkb", "delete", doc, dict(md5h(doc), **{"x-amz-bypass-governance-retention": "true"}))
    dels = [(d.findtext(NS + "Key"), d.findtext(NS + "VersionId")) for d in ET.fromstring(r.body).findall(NS + "Deleted")]
    check("and with the bypass removes it too", dels == [("da", a)], r)


def lifecycle():
    now = time.time()
    create("lcb", lock=True)
    locked1 = put("lcb", "a/locked", b"l1", mode="GOVERNANCE", until=now + DAY).headers.get("x-amz-version-id")
    put("lcb", "a/locked", b"l2")
    free1 = put("lcb", "a/free", b"f1").headers.get("x-amz-version-id")
    put("lcb", "a/free", b"f2")
    held = put("lcb", "a/held", b"h1", hold="ON").headers.get("x-amz-version-id")
    put("lcb", "a/held", b"h2")
    rules = ("<LifecycleConfiguration><Rule><ID>nc</ID><Filter><Prefix>a/</Prefix></Filter><Status>Enabled</Status>"
             "<Expiration><Days>1</Days></Expiration>"
             "<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule>"
             "</LifecycleConfiguration>").encode()
    r = req("PUT", "/lcb", "lifecycle", rules, md5h(rules))
    check("a lifecycle that expires current and noncurrent versions after a day", r.status == 200, r)
    gone = wait_for(lambda: not exists("lcb", "a/free", free1), 40)
    check("an unlocked noncurrent version is expired", gone)
    # Several more lifecycle days, so a locked version that was going to go would have.
    time.sleep(6)
    check("a version under retention is not", exists("lcb", "a/locked", locked1))
    check("nor one under a legal hold", exists("lcb", "a/held", held))
    r = req("GET", "/lcb/a/locked")
    check("the current version's expiry puts a delete marker in front, as it may",
          r.status == 404 and r.headers.get("x-amz-delete-marker") == "true", r)
    req("DELETE", "/lcb", "lifecycle")

    r = req("DELETE", "/lcb")
    check("DeleteBucket refuses a bucket holding locked versions", (r.status, r.code()) == (409, "BucketNotEmpty"), r)


def boto3_half(port):
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        print("  SKIP: boto3 is not installed")
        return
    s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % port, aws_access_key_id=AK1,
                      aws_secret_access_key=SK1, region_name="us-east-1",
                      config=Config(signature_version="s3v4", s3={"addressing_style": "path"},
                                    retries={"max_attempts": 1}))
    from botocore.exceptions import ClientError
    s3.create_bucket(Bucket="btb", ObjectLockEnabledForBucket=True)
    conf = {"ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 1}}}
    s3.put_object_lock_configuration(Bucket="btb", ObjectLockConfiguration=conf)
    check("boto3 reads back the configuration it put",
          s3.get_object_lock_configuration(Bucket="btb")["ObjectLockConfiguration"] == conf)
    until = datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc)
    body = b"boto"
    try:
        v = s3.put_object(Bucket="btb", Key="k", Body=body, ObjectLockMode="COMPLIANCE", ObjectLockRetainUntilDate=until,
                          ObjectLockLegalHoldStatus="ON",
                          ContentMD5=base64.b64encode(hashlib.md5(body).digest()).decode())["VersionId"]
    except ClientError as e:
        check("boto3 put_object with a lock", False, e)
        return
    h = s3.head_object(Bucket="btb", Key="k")
    check("boto3 head_object names the lock", (h.get("ObjectLockMode"), h.get("ObjectLockRetainUntilDate"),
                                                h.get("ObjectLockLegalHoldStatus")) == ("COMPLIANCE", until, "ON"), h)
    check("boto3 get_object_retention",
          s3.get_object_retention(Bucket="btb", Key="k")["Retention"] == {"Mode": "COMPLIANCE", "RetainUntilDate": until})
    check("boto3 get_object_legal_hold", s3.get_object_legal_hold(Bucket="btb", Key="k")["LegalHold"] == {"Status": "ON"})
    try:
        s3.delete_object(Bucket="btb", Key="k", VersionId=v, BypassGovernanceRetention=True)
        check("boto3 delete_object of a COMPLIANCE version is refused", False)
    except ClientError as e:
        check("boto3 delete_object of a COMPLIANCE version is refused", e.response["Error"]["Code"] == "AccessDenied", e)
    v2 = s3.put_object(Bucket="btb", Key="g", Body=b"g", ContentMD5=base64.b64encode(hashlib.md5(b"g").digest()).decode())
    s3.put_object_retention(Bucket="btb", Key="g", Retention={"Mode": "GOVERNANCE",
                                                            "RetainUntilDate": datetime.datetime(2098, 1, 1,
                                                                                                 tzinfo=datetime.timezone.utc)},
                            BypassGovernanceRetention=True)
    s3.put_object_legal_hold(Bucket="btb", Key="g", LegalHold={"Status": "OFF"})
    r = s3.delete_object(Bucket="btb", Key="g", VersionId=v2["VersionId"], BypassGovernanceRetention=True)
    check("boto3 delete_object with BypassGovernanceRetention", r["ResponseMetadata"]["HTTPStatusCode"] == 204, r)


def mode_main(port, data):
    global TARGET
    TARGET = port
    config()
    modes()
    bypass_permission()
    legal_hold()
    default_retention()
    multipart_and_copy()
    delete_objects()
    lifecycle()
    boto3_half(port)


# ─── recovery ───────────────────────────────────────────────────────────────

def stats():
    out = subprocess.run([BIN, "stats", RUNTIME], capture_output=True, text=True).stdout
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d


def probe():
    try:
        return req("GET", "/").status == 200
    except OSError:
        return False


def remove_journals(data):
    removed = 0
    for root, _, files in os.walk(data):
        for f in files:
            if f.startswith("index.") or f.startswith(".clean."):
                os.unlink(os.path.join(root, f))
                removed += 1
    return removed


def lock_state(cases):
    """What each case's version says of its lock, and whether a DELETE of it is refused."""
    out = {}
    for name, (key, vid) in cases.items():
        out[name] = (get_retention("rkb", key, vid), get_hold("rkb", key, vid), denied(delete("rkb", key, vid)))
    return out


def kill_and_wait(port):
    pid = stats().get("pid")
    os.kill(int(pid), signal.SIGKILL)
    return wait_for(lambda: (lambda p: p if p and p != pid and probe() else None)(stats().get("pid")), 40)


def mode_recovery(port, data):
    global TARGET
    TARGET = port
    now = time.time()
    create("rkb", lock=True)
    cases = {}
    cases["in the header"] = ("h", put("rkb", "h", b"h", mode="COMPLIANCE", until=now + DAY).headers["x-amz-version-id"])
    v = put("rkb", "s", b"s").headers["x-amz-version-id"]
    put_retention("rkb", "s", "GOVERNANCE", now + DAY)
    put_hold("rkb", "s", "ON")
    cases["in a slot"] = ("s", v)
    v = put("rkb", "shb", b"shb", mode="GOVERNANCE", until=now + DAY).headers["x-amz-version-id"]
    put_retention("rkb", "shb", "GOVERNANCE", now + 3 * DAY)
    cases["in the header and then a slot"] = ("shb", v)
    v = put("rkb", "f", b"fat", extra=FAT).headers["x-amz-version-id"]
    put_retention("rkb", "f", "COMPLIANCE", now + DAY)
    cases["in a header written again"] = ("f", v)
    v = put("rkb", "n", b"n1", hold="ON").headers["x-amz-version-id"]
    put("rkb", "n", b"n2")
    put_retention("rkb", "n", "COMPLIANCE", now + DAY, vid=v)
    cases["of a noncurrent version"] = ("n", v)
    v = put("rkb", "off", b"o", mode="GOVERNANCE", until=now + DAY).headers["x-amz-version-id"]
    put_hold("rkb", "off", "ON")
    put_hold("rkb", "off", "OFF")
    cases["a hold set and taken off"] = ("off", v)

    before = lock_state(cases)
    check("before any restart every case is as it was set",
          all(s[2] for s in before.values()) and before["a hold set and taken off"][1] == "OFF" and
          before["in a slot"][1] == "ON" and before["in a header written again"][0][0] == "COMPLIANCE", before)

    subprocess.run([BIN, "stop", RUNTIME], capture_output=True)
    time.sleep(0.5)
    subprocess.run([BIN, "start", RUNTIME], capture_output=True)
    check("it starts again", wait_for(probe, 30))
    after = lock_state(cases)
    check("after a clean restart every lock reads and holds as before", after == before, (before, after))
    r = set_versioning("rkb", "Suspended")
    check("and the bucket's lock is still its own", r.status == 409 and get_lock_config("rkb").status == 200, r)

    # A change answered and then a crash: the answer was given after the header was synced.
    v = put("rkb", "k9", b"k9").headers["x-amz-version-id"]
    put_retention("rkb", "k9", "COMPLIANCE", now + DAY)
    put_hold("rkb", "k9", "ON")
    cases["changed just before a SIGKILL"] = ("k9", v)
    before = lock_state(cases)
    check("a SIGKILL is restarted", kill_and_wait(port))
    after = lock_state(cases)
    check("after a SIGKILL every lock reads and holds as before", after == before, (before, after))

    removed = remove_journals(data)
    check("a SIGKILL with %d journal files removed is restarted" % removed, removed > 0 and kill_and_wait(port))
    after = lock_state(cases)
    check("and every lock comes back from the files alone", after == before, (before, after))
    r = delete("rkb", "h")
    check("a delete marker can still be put in front of a locked version", r.status == 204, r)
    r = req("DELETE", "/rkb")
    check("and the bucket cannot be deleted", r.status == 409, r)


# ─── shards ─────────────────────────────────────────────────────────────────

def mode_shards(n0, n1):
    global TARGET, KEY
    KEY = None
    TARGET = n0
    nodes = (n0, n1)
    now = time.time()
    r = create("shb", lock=True)
    check("CreateBucket with object lock through shard 0", r.status == 200, r)
    for i, n in enumerate(nodes):
        r = get_lock_config("shb", target=n)
        check("shard %d reads the configuration" % i, r.status == 200 and r.text("ObjectLockEnabled") == "Enabled", r)
        check("shard %d says versioning is Enabled" % i, get_versioning("shb", target=n) == "Enabled")
    r = set_versioning("shb", "Suspended", target=n1)
    check("suspending through shard 1 is refused by shard 0", (r.status, r.code()) == (409, "InvalidBucketState"), r)
    r = put_lock_config("shb", lock_doc("GOVERNANCE", days=1), target=n1)
    check("a default retention set through shard 1", r.status == 200, r)
    check("is read through shard 0", get_lock_config("shb", target=n0).text("Days") == "1")

    # Enough keys that each node is the owner of some and not of others.
    keys = ["k%d" % i for i in range(12)]
    vids = {}
    for i, k in enumerate(keys):
        r = put("shb", k, k.encode(), target=nodes[i % 2])
        vids[k] = r.headers.get("x-amz-version-id")
    got = [lock_headers("shb", k, target=n)[1] for k in keys for n in nodes]
    check("the default reaches every key through either shard", got == ["GOVERNANCE"] * len(got), got)
    for k in keys:
        for n in nodes:
            r = delete("shb", k, vids[k], target=n)
            if not denied(r):
                check("a version of %s is refused through every shard" % k, False, r)
                break
        else:
            continue
        break
    else:
        check("every version is refused through both shards, whichever owns it", True)

    bad_steps = []
    for i, k in enumerate(keys):
        a, b = nodes[i % 2], nodes[(i + 1) % 2]
        steps = (("hold", lambda: put_hold("shb", k, "ON", target=a)),
                 ("hold read", lambda: (get_hold("shb", k, target=b), lock_headers("shb", k, target=b))),
                 ("retention", lambda: put_retention("shb", k, "COMPLIANCE", now + 2 * DAY, bypass=True, target=b)),
                 ("retention read", lambda: get_retention("shb", k, target=a)),
                 ("refused", lambda: delete("shb", k, vids[k], bypass=True, target=a)))
        want = (lambda r: r.status == 200, lambda g: g[0] == "ON" and g[1][3] == "ON", lambda r: r.status == 200,
                lambda g: g[0] == "COMPLIANCE", denied)
        for (n, f), w in zip(steps, want):
            got = f()
            if not w(got):
                bad_steps.append((k, n, got))
    check("a hold and a retention set through one shard are read and enforced through the other", not bad_steps,
          bad_steps[:4])

    ok = True
    for i, k in enumerate(keys[:6]):
        a, b = nodes[i % 2], nodes[(i + 1) % 2]
        v = put("shb", "g" + k, b"g", mode="GOVERNANCE", until=now + DAY, target=a).headers.get("x-amz-version-id")
        ok = ok and denied(delete("shb", "g" + k, v, target=b))
        ok = ok and denied(put_retention("shb", "g" + k, "GOVERNANCE", now + 60, target=b))
        ok = ok and put_retention("shb", "g" + k, "GOVERNANCE", now + 60, bypass=True, target=b).status == 200
        ok = ok and delete("shb", "g" + k, v, bypass=True, target=b).status == 204
    check("the bypass crosses to the owner and lifts GOVERNANCE there, and only with the header", ok)


if MODE == "main":
    mode_main(int(sys.argv[2]), sys.argv[3])
elif MODE == "recovery":
    mode_recovery(int(sys.argv[2]), sys.argv[3])
elif MODE == "shards":
    mode_shards(sys.argv[2], sys.argv[3])
else:
    print("unknown mode " + MODE)
    sys.exit(2)
print("Results: %d passed, %d failed" % (passed, failed))
sys.exit(min(failed, 100))
