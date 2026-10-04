#!/usr/bin/env python3
"""A storage runtime's bucket policies: the configuration and how every request is judged by it.

usage: lib_storage_policy.py MODE ARGS...

  config  PORT               Put/Get/DeleteBucketPolicy and GetBucketPolicyStatus through
                             boto3 and by hand, every MalformedPolicy, public read on a
                             prefix for anonymous GET and HEAD and nothing else, presigned
                             URLs beside it; leaves bucket "pub" with PUBLIC for the restart
  deny    PORT               a Deny for one signed key and not the other, by bare key, by
                             user ARN and for the account, DeleteObjects, the source of a
                             copy, and the policy operations no policy can refuse
  sourceip PORT              aws:SourceIp IpAddress and NotIpAddress, 127.0.0.1 inside and
                             outside the range
  hook    PORT               the order: authentication, the policy, then on_request
  secure  PLAIN TLS CAFILE   aws:SecureTransport on a cleartext and a TLS listener
  anon    NODE               a Deny on a runtime with --anonymous
  shards  NODE0 NODE1        set through one shard and judged the same by both
  missing PORT               a key that is not there is 403 to whoever may read and not list
  brokenprep PORT            bucket "brk" with a policy, before its file is replaced by one that does not compile
  broken  PORT               that bucket refuses everything but the policy operations by its keys
  brokenfix PORT             and is opened again by a policy put in its place
  propagation NODE0 NODE1 FAULTDIR DATADIR
                             a change shard 1 cannot be told of fails and changes nothing, and
                             one it is not told the outcome of is never served old there
  persist TARGET...          PUBLIC is on "pub" through every target and is obeyed

A TARGET is a port or a unix socket path.  The keys are AK1/SK1 and AK2/SK2 in the
environment.  Every mode prints one PASS or FAIL line per assertion and exits with
the number of failures.
"""
import base64
import hashlib
import http.client
import json
import os
import socket
import ssl
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib_s3_signing as sig  # noqa: E402

AK1 = os.environ.get("AK1", "AKIAPOLICYKEYONE0001")
SK1 = os.environ.get("SK1", "policy/one/secret")
AK2 = os.environ.get("AK2", "AKIAPOLICYKEYTWO0002")
SK2 = os.environ.get("SK2", "policy/two/secret")

PUBLIC = json.dumps({
    "Version": "2012-10-17",
    "Id": "public-read",
    "Statement": [
        {"Sid": "PublicRead", "Effect": "Allow", "Principal": "*",
         "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::pub/public/*"},
    ],
}, indent=2)

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, detail))


def finish():
    print("Results: %d passed, %d failed" % (passed, failed))
    sys.exit(min(failed, 100))


class UnixConn(http.client.HTTPConnection):
    def __init__(self, path, timeout=30):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


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

    def message(self):
        try:
            return ET.fromstring(self.body).findtext("Message") or ""
        except ET.ParseError:
            return ""

    def __repr__(self):
        return "%d %s" % (self.status, self.body[:300])


# A target is a port, a unix socket path, or ("tls", port, cafile).
def connect(target):
    if isinstance(target, tuple):
        ctx = ssl.create_default_context(cafile=target[2])
        return http.client.HTTPSConnection("localhost", target[1], context=ctx, timeout=30), "localhost:%d" % target[1]
    if str(target).isdigit():
        return http.client.HTTPConnection("127.0.0.1", int(target), timeout=30), "127.0.0.1:%d" % int(target)
    return UnixConn(target), "localhost"


def req(target, method, path, query="", body=b"", key=None, headers=None):
    """One request, signed with `key` (an (access, secret) pair) or anonymous when it is None."""
    if isinstance(body, str):
        body = body.encode()
    c, host = connect(target)
    hdrs = dict(headers or {})
    if key is not None:
        signed = sig.sign(method, path, query, host, key[0], key[1], sig.sha256hex(body), extra_headers=hdrs)
        hdrs = dict(signed.headers)
    hdrs["Host"] = host
    try:
        c.request(method, path + ("?" + query if query else ""), body=body if body or method in ("PUT", "POST") else None,
                  headers=hdrs)
        r = c.getresponse()
        data = r.read()
        return Resp(r.status, {k.lower(): v for k, v in r.getheaders()}, data)
    finally:
        c.close()


K1 = (AK1, SK1)
K2 = (AK2, SK2)


def put_policy(target, bucket, doc, key=K1, md5=True):
    body = doc.encode() if isinstance(doc, str) else doc
    h = {}
    if md5:
        h["Content-MD5"] = base64.b64encode(hashlib.md5(body).digest()).decode()
    return req(target, "PUT", "/" + bucket, "policy", body, key, h)


def get_policy(target, bucket, key=K1):
    return req(target, "GET", "/" + bucket, "policy", key=key)


def delete_policy(target, bucket, key=K1):
    return req(target, "DELETE", "/" + bucket, "policy", key=key)


def policy(*statements, version="2012-10-17"):
    return json.dumps({"Version": version, "Statement": list(statements)})


def stmt(effect, principal, action, resource, condition=None, sid=None):
    s = {"Effect": effect, "Principal": principal, "Action": action, "Resource": resource}
    if condition is not None:
        s["Condition"] = condition
    if sid is not None:
        s["Sid"] = sid
    return s


def put_object(target, bucket, k, data, key=K1):
    return req(target, "PUT", "/%s/%s" % (bucket, k), "", data, key)


def boto(port, key=K1):
    import boto3
    from botocore.config import Config
    return boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % port, aws_access_key_id=key[0],
                        aws_secret_access_key=key[1], region_name="us-east-1",
                        config=Config(signature_version="s3v4", s3={"addressing_style": "path"},
                                      retries={"max_attempts": 1}))


def malformed(target, bucket, name, doc, want_message=None):
    r = put_policy(target, bucket, doc)
    ok = r.status == 400 and r.code() == "MalformedPolicy"
    if want_message is not None:
        ok = ok and want_message in r.message()
    check("MalformedPolicy: " + name, ok, repr(r))


# ─── config ─────────────────────────────────────────────────────────────────

def mode_config(port):
    T = port
    check("the bucket is made", req(T, "PUT", "/pub", key=K1).status == 200)
    for k, v in (("public/a", b"public bytes"), ("private/b", b"private bytes"), ("v1/x", b"v1"),
                 ("v10/x", b"v10")):
        check("object %s is put" % k, put_object(T, "pub", k, v).status == 200)

    r = get_policy(T, "pub")
    check("GetBucketPolicy with none is 404 NoSuchBucketPolicy",
          r.status == 404 and r.code() == "NoSuchBucketPolicy" and b"<BucketName>pub</BucketName>" in r.body, repr(r))
    r = req(T, "GET", "/pub", "policyStatus", key=K1)
    check("GetBucketPolicyStatus with none is 404 NoSuchBucketPolicy", r.status == 404 and r.code() == "NoSuchBucketPolicy", repr(r))
    r = delete_policy(T, "pub")
    check("DeleteBucketPolicy with none is 204", r.status == 204, repr(r))
    r = get_policy(T, "nosuchbucket")
    check("GetBucketPolicy on a bucket that is not there is NoSuchBucket", r.status == 404 and r.code() == "NoSuchBucket", repr(r))
    r = put_policy(T, "nosuchbucket", PUBLIC.replace("pub/", "nosuchbucket/"))
    check("PutBucketPolicy on a bucket that is not there is NoSuchBucket", r.status == 404 and r.code() == "NoSuchBucket", repr(r))
    r = req(T, "GET", "/pub/public/a", "policy", key=K1)
    check("?policy on an object is NotImplemented, never a GetObject", r.status == 501, repr(r))

    # Before any policy, an anonymous request is refused exactly as it was.
    r = req(T, "GET", "/pub/public/a")
    check("without a policy an anonymous GET is 403 AccessDenied", r.status == 403 and r.code() == "AccessDenied", repr(r))

    good = PUBLIC
    bad = [
        ("not JSON", "this is not json", "valid JSON"),
        ("a list, not an object", "[]", "valid JSON"),
        ("trailing bytes", good + "x", None),
        ("a duplicated field", '{"Version":"2012-10-17","Version":"2012-10-17","Statement":%s}'
         % json.dumps(json.loads(good)["Statement"]), None),
        ("no statements", '{"Version":"2012-10-17","Statement":[]}', None),
        ("no Statement", '{"Version":"2012-10-17"}', "Statement"),
        ("an unknown Version", policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::pub/*"), version="2020-01-01"), "Version"),
        ("an unknown top-level field", json.dumps({"Version": "2012-10-17", "Foo": 1, "Statement": json.loads(good)["Statement"]}), "Foo"),
        ("no Principal", json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::pub/*"}]}), "Principal"),
        ("no Resource", json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}), "Resource"),
        ("Effect in lowercase", policy(stmt("allow", "*", "s3:GetObject", "arn:aws:s3:::pub/*")), "Effect"),
        ("NotAction", json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "NotAction": "s3:PutObject", "Resource": "arn:aws:s3:::pub/*"}]}), "NotAction"),
        ("NotPrincipal", json.dumps({"Statement": [{"Effect": "Deny", "NotPrincipal": {"AWS": AK1}, "Action": "s3:*", "Resource": "arn:aws:s3:::pub/*"}]}), "NotPrincipal"),
        ("an action S3 does not have", policy(stmt("Allow", "*", "s3:FlyToTheMoon", "arn:aws:s3:::pub/*")), "invalid action"),
        ("an action of another service", policy(stmt("Allow", "*", "ec2:RunInstances", "arn:aws:s3:::pub/*")), "invalid action"),
        ("a resource in another bucket", policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::other/*")), "invalid resource"),
        ("a resource that is not an S3 ARN", policy(stmt("Allow", "*", "s3:GetObject", "pub/*")), "invalid resource"),
        ("a policy variable", policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::pub/${aws:username}/*")), "variables"),
        ("an object action on the bucket alone", policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::pub")), "does not apply"),
        ("a bucket action on objects alone", policy(stmt("Allow", "*", "s3:ListBucket", "arn:aws:s3:::pub/*")), "does not apply"),
        ("a condition operator not supported", policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::pub/*",
                                                           {"BinaryEquals": {"aws:Referer": "eA=="}})), "BinaryEquals"),
        ("a condition key not supported", policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::pub/*",
                                                      {"StringEquals": {"aws:SourceVpc": "vpc-1"}})), "aws:SourceVpc"),
        ("a tag of the object as it is, which is not read before the judgement",
         policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::pub/*",
                     {"StringEquals": {"s3:ExistingObjectTag/team": "a"}})), "ExistingObjectTag"),
        ("a number that is none", policy(stmt("Allow", "*", "s3:ListBucket", "arn:aws:s3:::pub",
                                              {"NumericLessThan": {"s3:max-keys": "ten"}})), "number"),
        ("a date that is none", policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::pub/*",
                                            {"DateLessThan": {"aws:CurrentTime": "soon"}})), "date"),
        ("IpAddress on another key", policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::pub/*",
                                                 {"IpAddress": {"aws:Referer": "127.0.0.1/32"}})), "aws:Referer"),
        ("an address that is not one", policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::pub/*",
                                                    {"IpAddress": {"aws:SourceIp": "300.0.0.0/8"}})), "300.0.0.0/8"),
        ("a prefix length too long", policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::pub/*",
                                                 {"IpAddress": {"aws:SourceIp": "10.0.0.0/33"}})), None),
        ("SecureTransport neither true nor false", policy(stmt("Deny", "*", "s3:*", "arn:aws:s3:::pub/*",
                                                              {"Bool": {"aws:SecureTransport": "maybe"}})), "maybe"),
        ("a service principal that is no host name", policy(stmt("Allow", {"Service": "*"}, "s3:GetObject", "arn:aws:s3:::pub/*")), "principal"),
        ("a federated principal", policy(stmt("Allow", {"Federated": "cognito-identity.amazonaws.com"}, "s3:GetObject", "arn:aws:s3:::pub/*")), "Federated"),
        ("a role principal", policy(stmt("Allow", {"AWS": "arn:aws:iam::123456789012:role/x"}, "s3:GetObject", "arn:aws:s3:::pub/*")), "principal"),
        ("a principal string that is not *", policy(stmt("Allow", AK1, "s3:GetObject", "arn:aws:s3:::pub/*")), "principal"),
        ("an empty action list", policy(stmt("Allow", "*", [], "arn:aws:s3:::pub/*")), "Action"),
        ("two statements with one Sid", policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::pub/*", sid="same"),
                                              stmt("Deny", "*", "s3:PutObject", "arn:aws:s3:::pub/*", sid="same")), "unique"),
        ("a document over 20 KiB", json.dumps({"Version": "2012-10-17", "Id": "x" * 20500,
                                               "Statement": json.loads(good)["Statement"]}), "maximum"),
    ]
    for name, doc, msg in bad:
        malformed(T, "pub", name, doc, msg)
    check("no refused document was kept", get_policy(T, "pub").status == 404)
    # Conditions on the keys a request carries, each operator family once.
    put_object(T, "pub", "cond/x", b"conditioned")
    def anon(path, query="", headers=None, method="GET", body=b""):
        return req(T, method, path, query, body, None, headers)
    r = put_policy(T, "pub", policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::pub/cond/*",
                                         {"StringLike": {"aws:Referer": "http://www.example.com/*"}})))
    check("StringLike on aws:Referer is taken", r.status == 204, repr(r))
    check("and lets in a request from a page it names", anon("/pub/cond/x", headers={"Referer": "http://www.example.com/a"}).status == 200)
    check("not one from another", anon("/pub/cond/x", headers={"Referer": "http://evil.example/"}).status == 403)
    check("nor one that names no page", anon("/pub/cond/x").status == 403)
    put_policy(T, "pub", policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::pub/cond/*",
                                     {"StringLikeIfExists": {"aws:Referer": "http://www.example.com/*"}})))
    check("StringLikeIfExists lets in one that names no page", anon("/pub/cond/x").status == 200)
    check("and still not one from another", anon("/pub/cond/x", headers={"Referer": "http://evil.example/"}).status == 403)
    put_policy(T, "pub", policy(stmt("Allow", "*", "s3:ListBucket", "arn:aws:s3:::pub",
                                     {"StringEquals": {"s3:prefix": "cond/"}, "NumericLessThanEquals": {"s3:max-keys": "10"}})))
    check("s3:prefix and s3:max-keys let in the listing they name",
          anon("/pub", "list-type=2&prefix=cond/&max-keys=5").status == 200)
    check("not one of another prefix", anon("/pub", "list-type=2&prefix=public/&max-keys=5").status == 403)
    check("nor one of more keys", anon("/pub", "list-type=2&prefix=cond/&max-keys=50").status == 403)
    check("nor one that names no max-keys, the operator not being negated",
          anon("/pub", "list-type=2&prefix=cond/").status == 403)
    put_policy(T, "pub", policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::pub/cond/*",
                                     {"DateGreaterThan": {"aws:CurrentTime": "2020-01-01T00:00:00Z"}}),
                                stmt("Deny", "*", "s3:GetObject", "arn:aws:s3:::pub/cond/*",
                                     {"StringNotEquals": {"aws:UserAgent": "good-agent"}})))
    check("DateGreaterThan on aws:CurrentTime with a StringNotEquals Deny lets in the agent it names",
          anon("/pub/cond/x", headers={"User-Agent": "good-agent"}).status == 200)
    check("and denies any other, signed or not", anon("/pub/cond/x", headers={"User-Agent": "curl"}).status == 403
          and req(T, "GET", "/pub/cond/x", key=K1, headers={"User-Agent": "curl"}).status == 403)
    put_policy(T, "pub", policy(stmt("Allow", "*", "s3:PutObject", "arn:aws:s3:::pub/cond/*",
                                     {"ForAnyValue:StringEquals": {"s3:RequestObjectTagKeys": ["project"]},
                                      "StringEquals": {"s3:RequestObjectTag/project": "alpha"}})))
    check("a tag the request sets lets in a put it names",
          anon("/pub/cond/t", method="PUT", body=b"t", headers={"x-amz-tagging": "project=alpha"}).status == 200)
    check("not one with another value", anon("/pub/cond/t2", method="PUT", body=b"t",
                                               headers={"x-amz-tagging": "project=beta"}).status == 403)
    check("nor one with no tags", anon("/pub/cond/t3", method="PUT", body=b"t").status == 403)
    delete_policy(T, "pub")

    # A bucket named by a pattern that covers it: arn:aws:s3:::* is the bucket and, IAM's * spanning a slash, its objects.
    r = put_policy(T, "pub", policy(stmt("Allow", "*", ["s3:GetObject", "s3:ListBucket"], "arn:aws:s3:::*")))
    check("arn:aws:s3:::* is taken", r.status == 204, repr(r))
    check("and covers the bucket's listing", anon("/pub", "list-type=2&prefix=cond/").status == 200)
    check("and its objects", anon("/pub/cond/x").status == 200)
    r = put_policy(T, "pub", policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::p*/cond/*")))
    check("a bucket pattern with a key pattern is taken", r.status == 204, repr(r))
    check("and covers the keys it names", anon("/pub/cond/x").status == 200 and anon("/pub/public/a").status == 403)
    malformed(T, "pub", "a bucket pattern that does not cover this bucket",
              policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::other*/*")), "does not cover")
    delete_policy(T, "pub")

    # A statement for a service alone is taken, and lets in no request, whatever its conditions.
    r = put_policy(T, "pub", policy(stmt("Allow", {"Service": "logging.s3.amazonaws.com"}, "s3:GetObject", "arn:aws:s3:::pub/*",
                                         {"ArnLike": {"aws:SourceArn": "arn:aws:s3:::src"}})))
    check("a statement naming a service alone is taken, conditions unchecked", r.status == 204, repr(r))
    r = req(T, "GET", "/pub/public/a")
    check("and lets no anonymous request in", r.status == 403 and r.code() == "AccessDenied", repr(r))
    delete_policy(T, "pub")
    r = put_policy(T, "pub", good.replace("public", "publik"), md5=False, key=K1)
    r2 = req(T, "PUT", "/pub", "policy", good.encode(), K1,
             {"Content-MD5": base64.b64encode(hashlib.md5(b"other").digest()).decode()})
    check("a Content-MD5 the body does not match is BadDigest", r2.status == 400 and r2.code() == "BadDigest", repr(r2))
    check("a policy is taken without Content-MD5", r.status == 204, repr(r))

    # Accepted forms beside the ones above: one statement as an object, the older Version, a wildcard action.
    for name, doc in (
        ("Statement as a single object", json.dumps({"Version": "2008-10-17", "Statement":
                                                     stmt("Allow", {"AWS": "*"}, "s3:Get*", "arn:aws:s3:::pub/public/*")})),
        ("no Version, Action *, a root principal", json.dumps({"Statement": [stmt("Deny", {"AWS": ["arn:aws:iam::123456789012:root"]},
                                                                                "*", ["arn:aws:s3:::pub", "arn:aws:s3:::pub/zz*"])]})),
        ("an action named for S3 that this runtime does not implement", policy(stmt("Allow", "*", ["s3:GetObject", "s3:GetObjectVersion"],
                                                                                   "arn:aws:s3:::pub/public/*"))),
        ("a JSON boolean for SecureTransport and IPv6 ranges", policy(stmt("Deny", "*", "s3:*", "arn:aws:s3:::pub/zz/*",
                                                                          {"Bool": {"aws:SecureTransport": False},
                                                                           "NotIpAddress": {"aws:SourceIp": ["::1/128", "10.0.0.0/8"]}}))),
    ):
        r = put_policy(T, "pub", doc)
        check("accepted: " + name, r.status == 204, repr(r))

    # A refused document leaves the one that was there.
    check("the public-read policy is set", put_policy(T, "pub", PUBLIC).status == 204)
    malformed(T, "pub", "after a good one", "{")
    r = get_policy(T, "pub")
    check("GetBucketPolicy answers the document as it was given, after a refusal",
          r.status == 200 and r.body.decode() == PUBLIC and r.headers.get("content-type") == "application/json", repr(r))
    r = req(T, "GET", "/pub", "policyStatus", key=K1)
    check("GetBucketPolicyStatus says it is public",
          r.status == 200 and b"<IsPublic>true</IsPublic>" in r.body and b"<PolicyStatus" in r.body, repr(r))

    # What it lets an anonymous request do, and what it does not.
    r = req(T, "GET", "/pub/public/a")
    check("an anonymous GET under the public prefix is served", r.status == 200 and r.body == b"public bytes", repr(r))
    r = req(T, "HEAD", "/pub/public/a")
    check("an anonymous HEAD under the public prefix is served",
          r.status == 200 and r.headers.get("content-length") == str(len(b"public bytes")), repr(r))
    r = req(T, "GET", "/pub/public/a", headers={"Range": "bytes=0-5"})
    check("an anonymous ranged GET is served", r.status == 206 and r.body == b"public", repr(r))
    r = req(T, "GET", "/pub/public/missing")
    check("an anonymous GET of a public key that is not there is AccessDenied, since it may not list",
          r.status == 403 and r.code() == "AccessDenied", repr(r))
    r = req(T, "GET", "/pub/private/b")
    check("an anonymous GET outside the prefix is AccessDenied", r.status == 403 and r.code() == "AccessDenied", repr(r))
    r = req(T, "HEAD", "/pub/private/b")
    check("an anonymous HEAD outside the prefix is 403", r.status == 403, repr(r))
    r = req(T, "PUT", "/pub/public/new", body=b"anonymous upload")
    check("an anonymous PUT under the public prefix is AccessDenied", r.status == 403 and r.code() == "AccessDenied", repr(r))
    r = req(T, "GET", "/pub/public/new", key=K1)
    check("and stored nothing", r.status == 404, repr(r))
    r = req(T, "DELETE", "/pub/public/a")
    check("an anonymous DELETE under the public prefix is AccessDenied", r.status == 403, repr(r))
    check("and removed nothing", req(T, "GET", "/pub/public/a").status == 200)
    r = req(T, "GET", "/pub", "list-type=2")
    check("an anonymous listing is AccessDenied", r.status == 403 and r.code() == "AccessDenied", repr(r))
    r = req(T, "GET", "/")
    check("an anonymous ListBuckets is AccessDenied", r.status == 403, repr(r))
    r = req(T, "GET", "/pub", "policy")
    check("an anonymous GetBucketPolicy is AccessDenied", r.status == 403, repr(r))
    r = req(T, "GET", "/pub/public/a", "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=nobody")
    check("a broken presigned URL under the public prefix is still refused, never read as anonymous",
          r.status in (400, 403) and r.code() != "", repr(r))
    r = req(T, "GET", "/pub/public/a", headers={"Authorization": "AWS4-HMAC-SHA256 Credential=%s/x, Signature=00" % AK1})
    check("a bad signature under the public prefix is refused, never read as anonymous", r.status in (400, 403), repr(r))

    # The ? wildcard: one character.
    put_policy(T, "pub", policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::pub/v?/*")))
    check("? matches one character", req(T, "GET", "/pub/v1/x").status == 200)
    check("and not two", req(T, "GET", "/pub/v10/x").status == 403)

    # A policy that grants everything still grants nobody the policy itself.
    check("a policy of s3:* for everyone is taken",
          put_policy(T, "pub", policy(stmt("Allow", "*", "s3:*", ["arn:aws:s3:::pub", "arn:aws:s3:::pub/*"]))).status == 204)
    r = req(T, "GET", "/pub", "list-type=2")
    check("under it an anonymous listing is served", r.status == 200 and b"<Key>public/a</Key>" in r.body, repr(r))
    r = req(T, "PUT", "/pub/anon/up", body=b"anonymous upload")
    check("and an anonymous PUT", r.status == 200, repr(r))
    check("which stored the body", req(T, "GET", "/pub/anon/up", key=K1).body == b"anonymous upload")
    check("and an anonymous DELETE", req(T, "DELETE", "/pub/anon/up").status == 204)
    r = delete_policy(T, "pub", key=None)
    check("but an anonymous DeleteBucketPolicy is AccessDenied", r.status == 403 and r.code() == "AccessDenied", repr(r))
    r = put_policy(T, "pub", PUBLIC, key=None)
    check("and an anonymous PutBucketPolicy", r.status == 403, repr(r))
    r = req(T, "GET", "/pub", "policyStatus")
    check("and an anonymous GetBucketPolicyStatus", r.status == 403, repr(r))

    # Through boto3, the client people run.
    try:
        c = boto(T)
        c.put_bucket_policy(Bucket="pub", Policy=PUBLIC)
        check("boto3 put_bucket_policy", True)
        got = c.get_bucket_policy(Bucket="pub")["Policy"]
        check("boto3 get_bucket_policy returns the document", got == PUBLIC, got[:200])
        st = c.get_bucket_policy_status(Bucket="pub")["PolicyStatus"]
        check("boto3 get_bucket_policy_status reads IsPublic", st.get("IsPublic") is True, st)
        c.delete_bucket_policy(Bucket="pub")
        check("boto3 delete_bucket_policy", get_policy(T, "pub").status == 404)
        check("an anonymous GET is refused once the policy is gone", req(T, "GET", "/pub/public/a").status == 403)
        c.put_bucket_policy(Bucket="pub", Policy=policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::pub/public/*",
                                                             {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}})))
        st = c.get_bucket_policy_status(Bucket="pub")["PolicyStatus"]
        check("a policy that lets everyone in only from a range is not public", st.get("IsPublic") is False, st)
        c.put_bucket_policy(Bucket="pub", Policy=PUBLIC)

        # A presigned URL is a signed request, and the policy does not get in its way.
        import requests
        url = c.generate_presigned_url("get_object", Params={"Bucket": "pub", "Key": "private/b"}, ExpiresIn=300)
        r = requests.get(url)
        check("a presigned GET outside the public prefix is served", r.status_code == 200 and r.content == b"private bytes", r.status_code)
        url = c.generate_presigned_url("put_object", Params={"Bucket": "pub", "Key": "private/pre"}, ExpiresIn=300)
        r = requests.put(url, data=b"presigned")
        check("a presigned PUT is served", r.status_code == 200, (r.status_code, r.text[:200]))
        u = c.generate_presigned_url("get_object", Params={"Bucket": "pub", "Key": "public/a"}, ExpiresIn=300)
        cut = u.index("X-Amz-Signature=") + len("X-Amz-Signature=")
        r = requests.get(u[:cut] + ("0" if u[cut] != "0" else "1") + u[cut + 1:])
        check("a presigned URL with a broken signature is refused even under the public prefix", r.status_code == 403,
              r.status_code)
        keys = [o["Key"] for o in c.list_objects_v2(Bucket="pub").get("Contents", [])]
        check("a signed listing is served as before", "private/b" in keys and "private/pre" in keys, keys)
    except ImportError:
        print("  SKIP: boto3 is not installed")
    check("PUBLIC is left on the bucket", put_policy(T, "pub", PUBLIC).status == 204)


# ─── deny ───────────────────────────────────────────────────────────────────

def mode_deny(port):
    T = port
    check("the bucket is made", req(T, "PUT", "/dny", key=K1).status == 200)
    for k in ("open/a", "secret/a", "keep/a", "keep/b", "src/a", "other/a"):
        put_object(T, "dny", k, ("body of " + k).encode())
    doc = policy(
        stmt("Deny", {"AWS": "arn:aws:iam::123456789012:user/" + AK2}, ["s3:PutObject", "s3:DeleteObject"],
             "arn:aws:s3:::dny/*", sid="two-writes-nothing"),
        stmt("Deny", {"AWS": AK2}, "s3:GetObject", "arn:aws:s3:::dny/secret/*", sid="two-reads-no-secrets"),
        stmt("Deny", {"AWS": "arn:aws:iam::123456789012:root"}, "s3:DeleteObject", "arn:aws:s3:::dny/keep/*", sid="keep"),
        stmt("Allow", "*", "s3:GetObject", ["arn:aws:s3:::dny/open/*", "arn:aws:s3:::dny/src/*"], sid="open"),
        stmt("Allow", "*", "s3:PutObject", "arn:aws:s3:::dny/drop/*", sid="drop"),
    )
    r = put_policy(T, "dny", doc)
    check("a policy with denials is taken", r.status == 204, repr(r))
    r = req(T, "GET", "/dny", "policyStatus", key=K1)
    check("it is public, since anyone may read open/", b"<IsPublic>true</IsPublic>" in r.body, repr(r))

    r = put_object(T, "dny", "other/new", b"x", key=K2)
    check("a PUT by the key a user ARN denies is AccessDenied", r.status == 403 and r.code() == "AccessDenied", repr(r))
    check("and stored nothing", req(T, "GET", "/dny/other/new", key=K1).status == 404)
    check("the other key may PUT", put_object(T, "dny", "other/new", b"x", key=K1).status == 200)
    r = req(T, "DELETE", "/dny/other/a", key=K2)
    check("a DELETE by the denied key is AccessDenied", r.status == 403, repr(r))
    check("and removed nothing", req(T, "GET", "/dny/other/a", key=K1).status == 200)
    r = req(T, "GET", "/dny/secret/a", key=K2)
    check("a GET a bare-key Deny covers is AccessDenied", r.status == 403 and r.code() == "AccessDenied", repr(r))
    r = req(T, "GET", "/dny/other/a", key=K2)
    check("a GET by that key outside it is served", r.status == 200 and r.body == b"body of other/a", repr(r))
    check("the other key reads the secret", req(T, "GET", "/dny/secret/a", key=K1).status == 200)
    r = req(T, "GET", "/dny", "list-type=2", key=K2)
    check("a listing by the denied key, which no statement denies, is served", r.status == 200, repr(r))

    for kk, name in ((K1, "one"), (K2, "two")):
        r = req(T, "DELETE", "/dny/keep/a", key=kk)
        check("a DELETE the account-root Deny covers is refused for key %s" % name, r.status == 403, repr(r))
    check("and keep/a is still there", req(T, "GET", "/dny/keep/a", key=K1).status == 200)
    check("the account-root Deny does not touch an anonymous GET it does not name",
          req(T, "GET", "/dny/open/a").status == 200)

    # DeleteObjects names its keys in the body, so any Deny over a key of the bucket refuses it.
    body = b"<Delete><Object><Key>other/a</Key></Object></Delete>"
    md5h = {"Content-MD5": base64.b64encode(hashlib.md5(body).digest()).decode()}
    r = req(T, "POST", "/dny", "delete", body, K2, md5h)
    check("DeleteObjects by the denied key is AccessDenied", r.status == 403 and r.code() == "AccessDenied", repr(r))
    r = req(T, "POST", "/dny", "delete", body, K1, md5h)
    check("DeleteObjects by the other key is refused too, since keep/* is denied to every key and the body may name it",
          r.status == 403, repr(r))
    r = req(T, "POST", "/dny", "delete", body, None, md5h)
    check("an anonymous DeleteObjects, which no statement allows over every key, is refused", r.status == 403, repr(r))

    # A copy reads its source, and the source has to be readable too.
    r = req(T, "PUT", "/dny/drop/x", headers={"x-amz-copy-source": "/dny/src/a"})
    check("an anonymous copy from a readable source into a writable prefix is served", r.status == 200, repr(r))
    check("and copied the bytes", req(T, "GET", "/dny/drop/x", key=K1).body == b"body of src/a")
    r = req(T, "PUT", "/dny/drop/y", headers={"x-amz-copy-source": "/dny/other/a"})
    check("an anonymous copy from a source it may not read is AccessDenied", r.status == 403, repr(r))
    check("and copied nothing", req(T, "GET", "/dny/drop/y", key=K1).status == 404)
    r = req(T, "PUT", "/dny/drop/z", key=K2, headers={"x-amz-copy-source": "/dny/secret/a"})
    check("a signed copy whose source a Deny covers is AccessDenied", r.status == 403, repr(r))
    r = req(T, "PUT", "/dny/drop/w", headers={"x-amz-copy-source": "/dny/src/a"}, key=K1)
    check("a signed copy is served as before", r.status == 200, repr(r))

    # Presigned URLs carry the same key, and the same denials.
    try:
        import requests
        u2 = boto(T, K2).generate_presigned_url("get_object", Params={"Bucket": "dny", "Key": "secret/a"}, ExpiresIn=300)
        u1 = boto(T, K1).generate_presigned_url("get_object", Params={"Bucket": "dny", "Key": "secret/a"}, ExpiresIn=300)
        check("a presigned GET by the denied key is refused", requests.get(u2).status_code == 403)
        check("a presigned GET by the other key is served", requests.get(u1).status_code == 200)
    except ImportError:
        print("  SKIP: boto3 is not installed")

    # A Deny over everything still leaves the policy itself in reach.
    lock = policy(stmt("Deny", "*", "s3:*", ["arn:aws:s3:::dny", "arn:aws:s3:::dny/*"]))
    check("a policy that denies everything to everyone is taken", put_policy(T, "dny", lock).status == 204)
    check("under it a signed GET is refused", req(T, "GET", "/dny/open/a", key=K1).status == 403)
    check("and a signed listing", req(T, "GET", "/dny", "list-type=2", key=K1).status == 403)
    check("and a signed HeadBucket", req(T, "HEAD", "/dny", key=K1).status == 403)
    r = req(T, "GET", "/dny", "policyStatus", key=K2)
    check("but GetBucketPolicyStatus is not, and the policy is not public", r.status == 200 and b"false" in r.body, repr(r))
    check("nor GetBucketPolicy", get_policy(T, "dny", key=K2).body.decode() == lock)
    check("nor DeleteBucketPolicy", delete_policy(T, "dny", key=K2).status == 204)
    check("and with it gone a signed GET is served again", req(T, "GET", "/dny/open/a", key=K1).status == 200)
    check("and an anonymous one refused again", req(T, "GET", "/dny/open/a").status == 403)


# ─── sourceip ───────────────────────────────────────────────────────────────

def mode_sourceip(port):
    T = port
    check("the bucket is made", req(T, "PUT", "/ips", key=K1).status == 200)
    put_object(T, "ips", "public/a", b"ip bytes")

    def allow_from(ranges):
        return policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::ips/public/*", {"IpAddress": {"aws:SourceIp": ranges}}))

    put_policy(T, "ips", allow_from("127.0.0.0/8"))
    check("an anonymous GET from inside the allowed range is served", req(T, "GET", "/ips/public/a").status == 200)
    put_policy(T, "ips", allow_from("127.0.0.1"))
    check("a bare address is a /32", req(T, "GET", "/ips/public/a").status == 200)
    put_policy(T, "ips", allow_from("::ffff:127.0.0.1/128"))
    check("an IPv4 address written as IPv6 is the IPv4 address", req(T, "GET", "/ips/public/a").status == 200)
    put_policy(T, "ips", allow_from(["10.0.0.0/8", "192.168.0.0/16", "::1/128"]))
    r = req(T, "GET", "/ips/public/a")
    check("an anonymous GET from outside every allowed range is AccessDenied", r.status == 403 and r.code() == "AccessDenied", repr(r))
    put_policy(T, "ips", allow_from("127.0.0.2/31"))
    check("a range that ends one address short of the client is outside", req(T, "GET", "/ips/public/a").status == 403)
    put_policy(T, "ips", allow_from("127.0.0.0/31"))
    check("and one whose last bit holds it is inside", req(T, "GET", "/ips/public/a").status == 200)

    def deny_unless(ranges):
        return policy(stmt("Deny", "*", "s3:*", ["arn:aws:s3:::ips", "arn:aws:s3:::ips/*"],
                           {"NotIpAddress": {"aws:SourceIp": ranges}}))

    put_policy(T, "ips", deny_unless("10.0.0.0/8"))
    r = req(T, "GET", "/ips/public/a", key=K1)
    check("a signed GET from outside a NotIpAddress Deny's range is AccessDenied", r.status == 403 and r.code() == "AccessDenied", repr(r))
    check("and a signed PUT", put_object(T, "ips", "public/b", b"x").status == 403)
    put_policy(T, "ips", deny_unless(["10.0.0.0/8", "127.0.0.1/32"]))
    check("a signed GET from inside it is served", req(T, "GET", "/ips/public/a", key=K1).status == 200)
    check("and a signed PUT", put_object(T, "ips", "public/b", b"x").status == 200)
    check("and an anonymous GET, which no statement allows, is refused as before", req(T, "GET", "/ips/public/a").status == 403)
    check("the policy is removed", delete_policy(T, "ips").status == 204)


# ─── hook ───────────────────────────────────────────────────────────────────

def mode_hook(port):
    T = port
    check("the bucket is made", req(T, "PUT", "/hook", key=K1).status == 200)
    for k in ("public/a", "hooked/a", "hooked/deny-a"):
        put_object(T, "hook", k, b"hook bytes")
    doc = policy(stmt("Allow", "*", "s3:GetObject", ["arn:aws:s3:::hook/public/*", "arn:aws:s3:::hook/hooked/*"]),
                 stmt("Deny", "*", "s3:GetObject", "arn:aws:s3:::hook/hooked/deny-*"))
    check("the policy is taken", put_policy(T, "hook", doc).status == 204)
    r = req(T, "GET", "/hook/public/a")
    check("a request the policy lets in and the hook lets through is served", r.status == 200, repr(r))
    r = req(T, "GET", "/hook/hooked/a")
    check("a request the policy lets in is still the hook's to refuse",
          r.status == 403 and r.message() == "hook says no", repr(r))
    r = req(T, "GET", "/hook/hooked/deny-a")
    check("a request the policy refuses never reaches the hook",
          r.status == 403 and r.code() == "AccessDenied" and r.message() == "Access Denied", repr(r))
    r = req(T, "GET", "/hook/hooked/a", key=K1)
    check("the hook refuses a signed request too", r.status == 403 and r.message() == "hook says no", repr(r))
    check("the policy is removed", delete_policy(T, "hook").status == 204)


# ─── secure ─────────────────────────────────────────────────────────────────

def mode_secure(plain, tls_port, cafile):
    TLS = ("tls", int(tls_port), cafile)
    doc = policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::sec/public/*", {"Bool": {"aws:SecureTransport": "true"}}),
                 stmt("Deny", "*", "s3:GetObject", "arn:aws:s3:::sec/private/*", {"Bool": {"aws:SecureTransport": "false"}}))
    for T, name in ((plain, "cleartext"), (TLS, "TLS")):
        check("the bucket is made over " + name, req(T, "PUT", "/sec", key=K1).status == 200)
        put_object(T, "sec", "public/a", b"sec bytes")
        put_object(T, "sec", "private/a", b"sec private")
        check("the policy is taken over " + name, put_policy(T, "sec", doc).status == 204)
    r = req(plain, "GET", "/sec/public/a")
    check("an anonymous GET that must be over TLS is refused in cleartext", r.status == 403, repr(r))
    r = req(TLS, "GET", "/sec/public/a")
    check("and served over TLS", r.status == 200 and r.body == b"sec bytes", repr(r))
    r = req(plain, "GET", "/sec/private/a", key=K1)
    check("a signed GET denied in cleartext is AccessDenied", r.status == 403 and r.code() == "AccessDenied", repr(r))
    r = req(TLS, "GET", "/sec/private/a", key=K1)
    check("and served over TLS", r.status == 200 and r.body == b"sec private", repr(r))


# ─── anon ───────────────────────────────────────────────────────────────────

def mode_anon(node):
    T = node
    check("the bucket is made", req(T, "PUT", "/anon").status == 200)
    check("an object is put", put_object(T, "anon", "ro/a", b"anon bytes", key=None).status == 200)
    doc = policy(stmt("Deny", "*", ["s3:PutObject", "s3:DeleteObject"], "arn:aws:s3:::anon/ro/*"))
    r = put_policy(T, "anon", doc, key=None)
    check("on a runtime with --anonymous an anonymous request may set the policy", r.status == 204, repr(r))
    r = put_object(T, "anon", "ro/b", b"x", key=None)
    check("a Deny refuses an anonymous PUT the runtime would otherwise take", r.status == 403 and r.code() == "AccessDenied", repr(r))
    check("and an anonymous DELETE", req(T, "DELETE", "/anon/ro/a").status == 403)
    check("an anonymous GET it does not deny is served", req(T, "GET", "/anon/ro/a").body == b"anon bytes")
    check("and a PUT elsewhere", put_object(T, "anon", "rw/a", b"x", key=None).status == 200)
    check("the policy is removed", delete_policy(T, "anon", key=None).status == 204)
    check("and the PUT is taken again", put_object(T, "anon", "ro/b", b"x", key=None).status == 200)


# ─── shards ─────────────────────────────────────────────────────────────────

def mode_shards(n0, n1):
    nodes = (n0, n1)
    check("the bucket is made", req(n0, "PUT", "/pub", key=K1).status == 200)
    keys = ["public/k%02d" % i for i in range(16)] + ["private/k%02d" % i for i in range(16)]
    for i, k in enumerate(keys):
        put_object(nodes[i % 2], "pub", k, k.encode())
    r = put_policy(n1, "pub", PUBLIC)
    check("the policy is set through shard 1", r.status == 204, repr(r))
    for i, n in enumerate(nodes):
        check("shard %d has it" % i, get_policy(n, "pub").body.decode() == PUBLIC)
        pub = [req(n, "GET", "/pub/" + k).status for k in keys if k.startswith("public/")]
        prv = [req(n, "GET", "/pub/" + k).status for k in keys if k.startswith("private/")]
        check("shard %d serves every public key, whichever shard owns it, anonymously" % i, pub == [200] * 16, pub)
        check("shard %d refuses every private key" % i, prv == [403] * 16, prv)
    check("the policy is removed through shard 0", delete_policy(n0, "pub").status == 204)
    for i, n in enumerate(nodes):
        check("shard %d no longer has it" % i, get_policy(n, "pub").status == 404)
        check("shard %d refuses a public key again" % i, req(n, "GET", "/pub/public/k00").status == 403)
    check("the policy is set again through shard 0 for the restart", put_policy(n0, "pub", PUBLIC).status == 204)


# ─── missing ────────────────────────────────────────────────────────────────

def mode_missing(port):
    T = port
    check("the bucket is made", req(T, "PUT", "/mis", key=K1).status == 200)
    check("an object is put", put_object(T, "mis", "pub/here", b"here").status == 200)
    read_only = policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::mis/pub/*"))
    check("a policy that lets everyone read and not list is taken", put_policy(T, "mis", read_only).status == 204)
    r = req(T, "GET", "/mis/pub/here")
    check("an anonymous GET of a key that is there is served", r.status == 200 and r.body == b"here", repr(r))
    r = req(T, "GET", "/mis/pub/gone")
    check("an anonymous GET of a key that is not there is 403 AccessDenied without s3:ListBucket",
          r.status == 403 and r.code() == "AccessDenied", repr(r))
    r = req(T, "HEAD", "/mis/pub/gone")
    check("and an anonymous HEAD is 403", r.status == 403, repr(r))
    r = req(T, "GET", "/mis/pub/gone", "tagging")
    check("and its tags are not there either, as AccessDenied", r.status == 403, repr(r))
    r = req(T, "GET", "/mis/pub/gone", key=K1)
    check("a signed GET of it is still 404 NoSuchKey", r.status == 404 and r.code() == "NoSuchKey", repr(r))

    listable = policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::mis/pub/*"),
                      stmt("Allow", "*", "s3:ListBucket", "arn:aws:s3:::mis"))
    check("a policy that lets everyone read and list is taken", put_policy(T, "mis", listable).status == 204)
    r = req(T, "GET", "/mis/pub/gone")
    check("with s3:ListBucket an anonymous GET of a key that is not there is 404 NoSuchKey",
          r.status == 404 and r.code() == "NoSuchKey", repr(r))
    r = req(T, "HEAD", "/mis/pub/gone")
    check("and an anonymous HEAD is 404", r.status == 404, repr(r))

    cond = policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::mis/pub/*"),
                  stmt("Allow", "*", "s3:ListBucket", "arn:aws:s3:::mis", {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}))
    check("a policy that lets everyone list only from elsewhere is taken", put_policy(T, "mis", cond).status == 204)
    r = req(T, "GET", "/mis/pub/gone")
    check("s3:ListBucket that does not apply to the requester is not s3:ListBucket", r.status == 403, repr(r))

    no_list = policy(stmt("Deny", {"AWS": AK2}, "s3:ListBucket", "arn:aws:s3:::mis"))
    check("a policy that denies one key the listing is taken", put_policy(T, "mis", no_list).status == 204)
    r = req(T, "GET", "/mis/pub/gone", key=K2)
    check("that key is told 403 for a key that is not there", r.status == 403 and r.code() == "AccessDenied", repr(r))
    r = req(T, "GET", "/mis/pub/here", key=K2)
    check("and is served one that is", r.status == 200, repr(r))
    r = req(T, "GET", "/mis/pub/gone", key=K1)
    check("the other key is told 404", r.status == 404 and r.code() == "NoSuchKey", repr(r))
    check("the policy is removed", delete_policy(T, "mis").status == 204)


# ─── broken ─────────────────────────────────────────────────────────────────

BROKEN = json.dumps({"Statement": [{"Effect": "Deny", "NotPrincipal": {"AWS": AK2}, "Action": "s3:*",
                                    "Resource": "arn:aws:s3:::brk/*"}]})


def mode_brokenprep(port):
    T = port
    check("the bucket is made", req(T, "PUT", "/brk", key=K1).status == 200)
    check("an object is put", put_object(T, "brk", "public/a", b"brk bytes").status == 200)
    doc = policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::brk/public/*"),
                 stmt("Deny", {"AWS": AK2}, "s3:GetObject", "arn:aws:s3:::brk/*"))
    check("a policy is taken", put_policy(T, "brk", doc).status == 204)
    check("which lets everyone read", req(T, "GET", "/brk/public/a").status == 200)
    check("and denies the second key", req(T, "GET", "/brk/public/a", key=K2).status == 403)


def mode_broken(port):
    T = port
    r = req(T, "GET", "/brk/public/a", key=K1)
    check("a stored policy that does not compile refuses a signed GET",
          r.status == 403 and r.code() == "AccessDenied" and "cannot be applied" in r.message(), repr(r))
    r = req(T, "GET", "/brk/public/a")
    check("and an anonymous one", r.status == 403 and r.code() == "AccessDenied", repr(r))
    r = put_object(T, "brk", "public/b", b"x")
    check("and a signed PUT", r.status == 403, repr(r))
    r = req(T, "GET", "/brk", "list-type=2", key=K1)
    check("and a signed listing", r.status == 403, repr(r))
    r = req(T, "GET", "/brk", "cors", key=K1)
    check("and the bucket's other configuration", r.status == 403, repr(r))
    r = get_policy(T, "brk")
    check("GetBucketPolicy by a key answers the stored document so it can be fixed",
          r.status == 200 and r.body.decode() == BROKEN, repr(r))
    r = req(T, "GET", "/brk", "policyStatus", key=K1)
    check("GetBucketPolicyStatus by a key says it is not public", r.status == 200 and b"<IsPublic>false</IsPublic>" in r.body,
          repr(r))
    r = req(T, "GET", "/pub", "policyStatus", key=K1)
    check("another bucket's policy is unaffected", r.status == 200, repr(r))
    r = delete_policy(T, "brk", key=None)
    check("an anonymous DeleteBucketPolicy is still refused", r.status == 403, repr(r))
    check("DeleteBucketPolicy by a key is taken", delete_policy(T, "brk").status == 204)
    r = req(T, "GET", "/brk/public/a", key=K1)
    check("and the bucket serves again", r.status == 200 and r.body == b"brk bytes", repr(r))


def mode_brokenfix(port):
    T = port
    r = req(T, "GET", "/brk/public/a", key=K1)
    check("after another start the bucket refuses again", r.status == 403, repr(r))
    good = policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::brk/public/*"))
    check("PutBucketPolicy by a key replaces it", put_policy(T, "brk", good).status == 204)
    r = req(T, "GET", "/brk/public/a")
    check("and the replacement is obeyed", r.status == 200 and r.body == b"brk bytes", repr(r))
    check("by signed requests too", req(T, "GET", "/brk/public/a", key=K1).status == 200)


# ─── propagation ────────────────────────────────────────────────────────────

def touch(path):
    open(path, "w").close()


def mode_propagation(n0, n1, faults, data):
    nodes = (n0, n1)
    narrow = policy(stmt("Allow", "*", "s3:GetObject", "arn:aws:s3:::pub/public/k0*"))
    deny_all = policy(stmt("Deny", "*", "s3:GetObject", "arn:aws:s3:::pub/*"))

    def on_disk(name):
        try:
            with open(os.path.join(data, "pub", name)) as f:
                return f.read()
        except FileNotFoundError:
            return None

    check("PUBLIC is on the bucket", put_policy(n0, "pub", PUBLIC).status == 204)

    # Shard 1 is alive and never hears that a change may happen.
    touch(os.path.join(faults, "1.prepare"))
    r = put_policy(n0, "pub", deny_all)
    check("a policy shard 1 cannot be told of is refused 503 through shard 0",
          r.status == 503 and r.code() == "ServiceUnavailable", repr(r))
    r = put_policy(n1, "pub", deny_all)
    check("and through shard 1", r.status == 503 and r.code() == "ServiceUnavailable", repr(r))
    r = delete_policy(n1, "pub")
    check("and so is its removal", r.status == 503, repr(r))
    os.unlink(os.path.join(faults, "1.prepare"))
    check("nothing changed on disk", on_disk("policy") == PUBLIC and on_disk("policy.new") is None,
          (on_disk("policy"), on_disk("policy.new")))
    for i, n in enumerate(nodes):
        check("shard %d still has the policy that was there" % i, get_policy(n, "pub").body.decode() == PUBLIC)
        r = req(n, "GET", "/pub/public/k15")
        check("shard %d still obeys it" % i, r.status == 200, repr(r))

    # Shard 1 promised to wait and never hears how the change ended.
    touch(os.path.join(faults, "1.commit"))
    r = put_policy(n0, "pub", narrow)
    check("a policy shard 1 is not told the outcome of is taken", r.status == 204, repr(r))
    r = req(n1, "GET", "/pub/public/k15")
    check("and shard 1 does not go on with the old one", r.status == 403 and r.code() == "AccessDenied", repr(r))
    r = req(n1, "GET", "/pub/public/k01")
    check("it obeys the new one", r.status == 200, repr(r))
    check("and answers it", get_policy(n1, "pub").body.decode() == narrow)
    r = delete_policy(n0, "pub")
    check("a removal shard 1 is not told the outcome of is taken", r.status == 204, repr(r))
    r = get_policy(n1, "pub")
    check("and shard 1 has no policy either", r.status == 404 and r.code() == "NoSuchBucketPolicy", repr(r))
    check("and refuses what it no longer allows", req(n1, "GET", "/pub/public/k01").status == 403)
    os.unlink(os.path.join(faults, "1.commit"))

    check("PUBLIC is put back for the restart", put_policy(n0, "pub", PUBLIC).status == 204)
    for i, n in enumerate(nodes):
        r = req(n, "GET", "/pub/public/k15")
        check("shard %d serves under PUBLIC again" % i, r.status == 200, repr(r))


# ─── persist ────────────────────────────────────────────────────────────────

def mode_persist(targets):
    for t in targets:
        r = get_policy(t, "pub")
        check("%s has the policy as it was given" % t, r.status == 200 and r.body.decode() == PUBLIC, repr(r))
        r = req(t, "GET", "/pub/public/a" if str(t).isdigit() else "/pub/public/k01")
        check("%s serves an anonymous GET under the prefix" % t, r.status == 200, repr(r))
        r = req(t, "GET", "/pub/private/b" if str(t).isdigit() else "/pub/private/k01")
        check("%s refuses one outside it" % t, r.status == 403, repr(r))


def main():
    mode = sys.argv[1]
    a = sys.argv[2:]
    if mode == "config":
        mode_config(int(a[0]))
    elif mode == "deny":
        mode_deny(int(a[0]))
    elif mode == "sourceip":
        mode_sourceip(int(a[0]))
    elif mode == "hook":
        mode_hook(int(a[0]))
    elif mode == "secure":
        mode_secure(int(a[0]), a[1], a[2])
    elif mode == "anon":
        mode_anon(a[0])
    elif mode == "shards":
        mode_shards(a[0], a[1])
    elif mode == "missing":
        mode_missing(int(a[0]))
    elif mode == "brokenprep":
        mode_brokenprep(int(a[0]))
    elif mode == "broken":
        mode_broken(int(a[0]))
    elif mode == "brokenfix":
        mode_brokenfix(int(a[0]))
    elif mode == "propagation":
        mode_propagation(a[0], a[1], a[2], a[3])
    elif mode == "persist":
        mode_persist([int(x) if x.isdigit() else x for x in a])
    else:
        print("unknown mode " + mode)
        sys.exit(1)
    finish()


if __name__ == "__main__":
    main()
