#!/usr/bin/env python3
"""A storage runtime's bucket CORS: the configuration and what a browser hears.

usage: lib_storage_cors.py MODE ARGS...

  basic   NODE               PutBucketCors / GetBucketCors / DeleteBucketCors,
                             the refusals, the preflight and the headers of
                             actual requests and of errors; leaves bucket "web"
                             with CONFIG for the restart check
  persist NODE...            "web" has CONFIG through every node, and its
                             preflight and actual GET are answered from it
  shards  NODE0 NODE1        set and removed through one shard, the same on both
  signed  PORT AK SK         boto3 sets and reads it on a runtime that wants
                             signatures, and a preflight needs none

Every mode prints one PASS or FAIL line per assertion and exits with the
number of failures.
"""
import base64
import hashlib
import http.client
import socket
import sys
import xml.etree.ElementTree as ET

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
APP = "https://app.example.com"

CONFIG = """<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <CORSRule>
    <ID>uploads</ID>
    <AllowedOrigin>https://app.example.com</AllowedOrigin>
    <AllowedMethod>PUT</AllowedMethod>
    <AllowedMethod>GET</AllowedMethod>
    <AllowedHeader>content-type</AllowedHeader>
    <AllowedHeader>x-amz-*</AllowedHeader>
    <ExposeHeader>ETag</ExposeHeader>
    <ExposeHeader>x-amz-request-id</ExposeHeader>
    <MaxAgeSeconds>600</MaxAgeSeconds>
  </CORSRule>
  <CORSRule>
    <AllowedOrigin>http://*.example.org</AllowedOrigin>
    <AllowedMethod>GET</AllowedMethod>
  </CORSRule>
  <CORSRule>
    <AllowedOrigin>*</AllowedOrigin>
    <AllowedMethod>HEAD</AllowedMethod>
  </CORSRule>
</CORSConfiguration>"""

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


def req(node, method, path, body=None, headers=None):
    c = UnixConn(node) if not str(node).isdigit() else http.client.HTTPConnection("127.0.0.1", int(node), timeout=30)
    try:
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data
    finally:
        c.close()


def code_of(body):
    try:
        return ET.fromstring(body).findtext("Code") or ""
    except ET.ParseError:
        return ""


def rules_of(body):
    root = ET.fromstring(body)
    out = []
    for r in root.findall(NS + "CORSRule"):
        out.append({
            "id": r.findtext(NS + "ID"),
            "origins": [e.text for e in r.findall(NS + "AllowedOrigin")],
            "methods": [e.text for e in r.findall(NS + "AllowedMethod")],
            "headers": [e.text for e in r.findall(NS + "AllowedHeader")],
            "expose": [e.text for e in r.findall(NS + "ExposeHeader")],
            "age": r.findtext(NS + "MaxAgeSeconds"),
        })
    return out


def preflight(node, path, origin=APP, method="PUT", headers=None):
    h = {}
    if origin is not None:
        h["Origin"] = origin
    if method is not None:
        h["Access-Control-Request-Method"] = method
    if headers is not None:
        h["Access-Control-Request-Headers"] = headers
    return req(node, "OPTIONS", path, headers=h)


def put_cors(node, bucket, xml, md5=True):
    body = xml.encode()
    h = {"Content-Type": "application/xml"}
    if md5:
        h["Content-MD5"] = base64.b64encode(hashlib.md5(body).digest()).decode()
    return req(node, "PUT", "/%s?cors" % bucket, body, h)


def config_is_ours(rules):
    return (len(rules) == 3 and rules[0]["id"] == "uploads" and rules[0]["origins"] == [APP]
            and rules[0]["methods"] == ["PUT", "GET"] and rules[0]["headers"] == ["content-type", "x-amz-*"]
            and rules[0]["expose"] == ["ETag", "x-amz-request-id"] and rules[0]["age"] == "600"
            and rules[1]["origins"] == ["http://*.example.org"] and rules[1]["id"] is None
            and rules[1]["age"] is None and rules[2]["origins"] == ["*"] and rules[2]["methods"] == ["HEAD"])


def has_ours(node, bucket="web"):
    s, _, b = req(node, "GET", "/%s?cors" % bucket)
    return s == 200 and config_is_ours(rules_of(b)), "%d %s" % (s, b[:300])


# ── basic ───────────────────────────────────────────────────────────────────
def basic(node):
    req(node, "PUT", "/web")
    req(node, "PUT", "/plain")

    s, _, b = req(node, "GET", "/web?cors")
    check("GetBucketCors on a bucket without rules is 404 NoSuchCORSConfiguration",
          s == 404 and code_of(b) == "NoSuchCORSConfiguration" and b"<BucketName>web</BucketName>" in b, "%d %s" % (s, b))
    s, _, b = req(node, "GET", "/nobucket?cors")
    check("and on a bucket that is not there NoSuchBucket", s == 404 and code_of(b) == "NoSuchBucket", "%d %s" % (s, b))
    s, h, b = preflight(node, "/web/obj")
    check("a preflight to a bucket without rules is 403 AccessForbidden, CORS not enabled",
          s == 403 and code_of(b) == "AccessForbidden" and b"CORS is not enabled for this bucket" in b
          and "access-control-allow-origin" not in h, "%d %s %s" % (s, h, b))

    s, _, b = put_cors(node, "web", CONFIG.replace("600", "601"), md5=False)
    check("PutBucketCors without Content-MD5 is taken", s == 200, "%d %s" % (s, b))
    s, _, b = req(node, "PUT", "/web?cors", CONFIG.encode(),
                  {"Content-MD5": base64.b64encode(hashlib.md5(b"other").digest()).decode()})
    check("a Content-MD5 that is not the body's is BadDigest", s == 400 and code_of(b) == "BadDigest", "%d %s" % (s, b))
    s, _, b = put_cors(node, "web", CONFIG)
    check("PutBucketCors with Content-MD5 is 200", s == 200, "%d %s" % (s, b))
    ok, why = has_ours(node)
    check("GetBucketCors gives back every rule, element for element", ok, why)
    s, h, b = req(node, "GET", "/web?cors")
    check("as application/xml in the S3 namespace",
          h.get("content-type") == "application/xml" and b'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"' in b, str(h))
    s, _, b = put_cors(node, "nobucket", CONFIG)
    check("PutBucketCors on a bucket that is not there is NoSuchBucket", s == 404 and code_of(b) == "NoSuchBucket", "%d %s" % (s, b))

    rule = "<CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule>"
    malformed = {
        "a body that is not XML": "this is not xml",
        "an empty body": "",
        "a configuration without rules": "<CORSConfiguration></CORSConfiguration>",
        "a rule without AllowedMethod": "<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>",
        "a rule without AllowedOrigin": "<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>",
        "an element S3 does not know": "<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><Bogus>1</Bogus></CORSRule></CORSConfiguration>",
        "a MaxAgeSeconds that is not a number": "<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><MaxAgeSeconds>ten</MaxAgeSeconds></CORSRule></CORSConfiguration>",
        "a root that is not CORSConfiguration": "<Delete>" + rule + "</Delete>",
        "an element left open": "<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</CORSRule></CORSConfiguration>",
        "text after the root": "<CORSConfiguration>" + rule + "</CORSConfiguration>trailing",
        "a header value that would split a line": "<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><ExposeHeader>a&#13;&#10;Set-Cookie: x</ExposeHeader></CORSRule></CORSConfiguration>",
    }
    for name, x in malformed.items():
        s, _, b = put_cors(node, "web", x)
        check(name + " is MalformedXML", s == 400 and code_of(b) == "MalformedXML", "%d %s" % (s, b))
    invalid = {
        "a method S3 does not allow": "<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>PATCH</AllowedMethod></CORSRule></CORSConfiguration>",
        "an origin with two wildcards": "<CORSConfiguration><CORSRule><AllowedOrigin>http://*.*.example.com</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>",
        "a header with two wildcards": "<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><AllowedHeader>x-*-*</AllowedHeader></CORSRule></CORSConfiguration>",
        "101 rules": "<CORSConfiguration>" + rule * 101 + "</CORSConfiguration>",
    }
    for name, x in invalid.items():
        s, _, b = put_cors(node, "web", x)
        check(name + " is InvalidRequest", s == 400 and code_of(b) == "InvalidRequest", "%d %s" % (s, b))
    ok, why = has_ours(node)
    check("and none of the refusals changed the rules", ok, why)

    s, _, b = put_cors(node, "plain", '<?xml version="1.0" encoding="UTF-8"?>\n<!-- a comment -->'
                       "<CORSConfiguration>" + rule * 100 + "</CORSConfiguration>")
    s2, _, b2 = req(node, "GET", "/plain?cors")
    check("100 rules, after a declaration and a comment, are taken", s == 200 and s2 == 200 and len(rules_of(b2)) == 100,
          "%d %s / %d" % (s, b, s2))
    s, _, _ = req(node, "DELETE", "/plain?cors")
    check("DeleteBucketCors is 204", s == 204, str(s))
    s, _, b = req(node, "GET", "/plain?cors")
    check("and the rules are gone", s == 404 and code_of(b) == "NoSuchCORSConfiguration", "%d %s" % (s, b))
    s, _, _ = req(node, "DELETE", "/plain?cors")
    check("DeleteBucketCors of no rules is 204 as well", s == 204, str(s))
    ok, why = has_ours(node)
    check("and another bucket's rules are untouched", ok, why)
    s, _, b = req(node, "PUT", "/web/obj?cors", b"<x/>")
    check("?cors on an object is NotImplemented", s == 501 and code_of(b) == "NotImplemented", "%d %s" % (s, b))
    s, _, b = req(node, "POST", "/web?cors")
    check("POST ?cors is MethodNotAllowed", s == 405, "%d %s" % (s, b))

    # ── preflight ───────────────────────────────────────────────────────────
    s, h, b = preflight(node, "/web/obj", APP, "PUT", "Content-Type, X-Amz-Date")
    check("a preflight a rule allows is 200 with no body", s == 200 and b == b"", "%d %s" % (s, b))
    check("Access-Control-Allow-Origin is the origin", h.get("access-control-allow-origin") == APP, str(h))
    check("Access-Control-Allow-Methods are the rule's", h.get("access-control-allow-methods") == "PUT, GET", str(h))
    check("Access-Control-Allow-Headers are the ones asked for", h.get("access-control-allow-headers") == "content-type, x-amz-date", str(h))
    check("Access-Control-Max-Age is the rule's", h.get("access-control-max-age") == "600", str(h))
    check("Access-Control-Expose-Headers are the rule's", h.get("access-control-expose-headers") == "ETag, x-amz-request-id", str(h))
    check("credentials are allowed to a named origin", h.get("access-control-allow-credentials") == "true", str(h))
    check("Vary names Origin", "Origin" in h.get("vary", ""), str(h))
    s, h, _ = preflight(node, "/web", APP, "GET")
    check("a preflight for the bucket itself is answered the same way",
          s == 200 and h.get("access-control-allow-origin") == APP and "access-control-allow-headers" not in h, "%d %s" % (s, h))
    s, h, _ = preflight(node, "/web/obj", "http://cdn.example.org", "GET")
    check("a wildcard origin matches a subdomain",
          s == 200 and h.get("access-control-allow-origin") == "http://cdn.example.org" and "access-control-max-age" not in h,
          "%d %s" % (s, h))
    s, h, b = preflight(node, "/web/obj", "http://example.org", "GET")
    check("and not the bare domain", s == 403 and code_of(b) == "AccessForbidden" and b"not allowed" in b, "%d %s" % (s, b))
    s, h, _ = preflight(node, "/web/obj", "https://anyone.test", "HEAD")
    check("an origin allowed by * is answered * without credentials",
          s == 200 and h.get("access-control-allow-origin") == "*" and "access-control-allow-credentials" not in h,
          "%d %s" % (s, h))
    s, h, b = preflight(node, "/web/obj", "https://anyone.test", "GET")
    check("a method no rule allows that origin is 403", s == 403 and code_of(b) == "AccessForbidden"
          and "access-control-allow-origin" not in h, "%d %s" % (s, b))
    s, _, b = preflight(node, "/web/obj", APP, "PUT", "content-type, x-custom")
    check("a request header no rule allows is 403", s == 403 and code_of(b) == "AccessForbidden", "%d %s" % (s, b))
    s, _, b = preflight(node, "/web/obj", APP, "DELETE")
    check("a method the origin's rule does not list is 403", s == 403, "%d %s" % (s, b))
    s, _, b = preflight(node, "/web/obj", APP.upper(), "PUT")
    check("an origin is matched as written", s == 403, "%d %s" % (s, b))
    s, _, b = preflight(node, "/web/obj", None, "PUT")
    check("a preflight without Origin is 400", s == 400 and b"Origin request header needed" in b, "%d %s" % (s, b))
    s, _, b = preflight(node, "/web/obj", APP, None)
    check("a preflight without Access-Control-Request-Method is 400", s == 400 and code_of(b) == "BadRequest", "%d %s" % (s, b))
    s, _, b = preflight(node, "/web/obj", APP, "PATCH")
    check("one asking for a method S3 does not have is 400", s == 400 and b"PATCH" in b, "%d %s" % (s, b))
    s, _, b = preflight(node, "/nobucket/obj", APP, "PUT")
    check("one to a bucket that is not there is NoSuchBucket", s == 404 and code_of(b) == "NoSuchBucket", "%d %s" % (s, b))
    s, h, _ = preflight(node, "/plain/obj", APP, "PUT")
    check("a bucket whose rules were removed is not enabled", s == 403 and "access-control-allow-origin" not in h, str(s))

    # ── actual requests ─────────────────────────────────────────────────────
    s, h, _ = req(node, "PUT", "/web/obj", b"hello", {"Origin": APP, "Content-Type": "text/plain"})
    check("a PUT from an allowed origin carries the rule",
          s == 200 and h.get("access-control-allow-origin") == APP and h.get("access-control-expose-headers") == "ETag, x-amz-request-id"
          and h.get("access-control-allow-credentials") == "true" and "Origin" in h.get("vary", ""), "%d %s" % (s, h))
    for i in range(3):
        s, h, b = req(node, "GET", "/web/obj", headers={"Origin": APP})
        check("GET %d from an allowed origin carries it" % i,
              s == 200 and b == b"hello" and h.get("access-control-allow-origin") == APP, "%d %s" % (s, h))
        s, h, b = req(node, "GET", "/web/obj")
        check("GET %d without Origin carries none" % i, s == 200 and b == b"hello"
              and not any(k.startswith("access-control-") for k in h) and "vary" not in h, str(h))
    s, h, _ = req(node, "GET", "/web/obj", headers={"Origin": "https://anyone.test"})
    check("a GET from an origin only allowed HEAD carries none", s == 200 and "access-control-allow-origin" not in h, str(h))
    s, h, _ = req(node, "HEAD", "/web/obj", headers={"Origin": "https://anyone.test"})
    check("and its HEAD carries *", s == 200 and h.get("access-control-allow-origin") == "*", str(h))
    s, h, b = req(node, "GET", "/web/missing", headers={"Origin": APP})
    check("a NoSuchKey to an allowed origin carries the rule, so the page can read the error",
          s == 404 and code_of(b) == "NoSuchKey" and h.get("access-control-allow-origin") == APP, "%d %s" % (s, h))
    s, h, b = req(node, "GET", "/web/obj", headers={"Origin": APP, "Range": "bytes=10-20"})
    check("so does an InvalidRange", s == 416 and h.get("access-control-allow-origin") == APP, "%d %s" % (s, h))
    s, h, _ = req(node, "DELETE", "/web/obj", headers={"Origin": APP})
    check("a DELETE the rule does not list carries none", s == 204 and "access-control-allow-origin" not in h, str(h))
    req(node, "PUT", "/plain/obj", b"x")
    s, h, _ = req(node, "GET", "/plain/obj", headers={"Origin": APP})
    check("a GET from a bucket without rules carries none", s == 200 and "access-control-allow-origin" not in h, str(h))
    req(node, "DELETE", "/plain/obj")

    # ── a bucket dropped and made again has no rules ────────────────────────
    req(node, "PUT", "/again")
    put_cors(node, "again", CONFIG)
    s1, _, _ = req(node, "DELETE", "/again")
    s2, _, _ = req(node, "PUT", "/again")
    s, _, b = req(node, "GET", "/again?cors")
    check("a bucket dropped with rules and made again has none",
          s1 == 204 and s2 == 200 and s == 404 and code_of(b) == "NoSuchCORSConfiguration", "%d %d %d %s" % (s1, s2, s, b))
    req(node, "PUT", "/web/obj", b"hello")


# ── after a restart ─────────────────────────────────────────────────────────
def persist(nodes):
    for i, node in enumerate(nodes):
        ok, why = has_ours(node)
        check("node %d has the rules after the restart" % i, ok, why)
        s, h, _ = preflight(node, "/web/obj", APP, "PUT", "content-type")
        check("node %d answers a preflight from them" % i, s == 200 and h.get("access-control-allow-origin") == APP, "%d %s" % (s, h))
        s, h, _ = req(node, "GET", "/web/obj", headers={"Origin": APP})
        check("node %d's GET carries them" % i, s == 200 and h.get("access-control-allow-origin") == APP, "%d %s" % (s, h))
        s, h, _ = preflight(node, "/plain/obj", APP, "PUT")
        check("node %d still has no rules for the bucket whose rules were removed" % i, s == 403, str(s))


# ── two shards ──────────────────────────────────────────────────────────────
def shards(n0, n1):
    nodes = [n0, n1]
    s, _, _ = req(n1, "PUT", "/web")
    check("a bucket is made through shard 1", s == 200, str(s))
    req(n1, "PUT", "/plain")
    req(n0, "PUT", "/web/obj", b"hello")
    s, _, b = put_cors(n1, "web", CONFIG)
    check("rules are set through shard 1, which is not the shard that writes them", s == 200, "%d %s" % (s, b))
    for i, node in enumerate(nodes):
        ok, why = has_ours(node)
        check("shard %d has them as soon as the put is answered" % i, ok, why)
        s, h, _ = preflight(node, "/web/obj", APP, "PUT")
        check("shard %d answers a preflight from them" % i, s == 200 and h.get("access-control-allow-origin") == APP, "%d %s" % (s, h))
        s, h, _ = req(node, "GET", "/web/obj", headers={"Origin": APP})
        check("shard %d's GET carries them" % i, s == 200 and h.get("access-control-allow-origin") == APP, "%d %s" % (s, h))
    s, _, _ = req(n1, "DELETE", "/web?cors")
    check("they are removed through shard 1", s == 204, str(s))
    for i, node in enumerate(nodes):
        s, _, b = req(node, "GET", "/web?cors")
        check("shard %d has none" % i, s == 404 and code_of(b) == "NoSuchCORSConfiguration", "%d %s" % (s, b))
        s, h, _ = req(node, "GET", "/web/obj", headers={"Origin": APP})
        check("shard %d's GET carries none" % i, s == 200 and "access-control-allow-origin" not in h, str(h))
    s, _, _ = put_cors(n0, "web", CONFIG.replace("<MaxAgeSeconds>600", "<MaxAgeSeconds>5"))
    s1, _, _ = put_cors(n1, "web", CONFIG)
    check("set again through shard 0 and then shard 1", s == 200 and s1 == 200, "%d %d" % (s, s1))
    for i, node in enumerate(nodes):
        ok, why = has_ours(node)
        check("shard %d has the later of the two" % i, ok, why)
    s, _, b = put_cors(n1, "nobucket", CONFIG)
    check("a bucket no shard has is NoSuchBucket through shard 1", s == 404 and code_of(b) == "NoSuchBucket", "%d %s" % (s, b))
    s, _, b = put_cors(n1, "web", "<CORSConfiguration/>")
    check("a malformed document is refused through shard 1 without crossing", s == 400 and code_of(b) == "MalformedXML", "%d %s" % (s, b))


# ── signed requests ─────────────────────────────────────────────────────────
def signed(port, ak, sk):
    try:
        import boto3
        from botocore.config import Config
        from botocore.exceptions import ClientError
    except ImportError:
        print("  SKIP: boto3 is not installed")
        return
    url = "http://127.0.0.1:%s" % port
    s3 = boto3.client("s3", endpoint_url=url, aws_access_key_id=ak, aws_secret_access_key=sk,
                      region_name="us-east-1",
                      config=Config(signature_version="s3v4", s3={"addressing_style": "path"},
                                    retries={"max_attempts": 1}))
    s3.create_bucket(Bucket="site")
    s3.put_object(Bucket="site", Key="page.txt", Body=b"page")
    try:
        s3.get_bucket_cors(Bucket="site")
        check("boto3 hears NoSuchCORSConfiguration before any rules", False, "no error")
    except ClientError as e:
        check("boto3 hears NoSuchCORSConfiguration before any rules",
              e.response["Error"]["Code"] == "NoSuchCORSConfiguration", str(e.response["Error"]))
    rules = {"CORSRules": [
        {"ID": "browser", "AllowedOrigins": [APP], "AllowedMethods": ["GET", "PUT"],
         "AllowedHeaders": ["*"], "ExposeHeaders": ["ETag"], "MaxAgeSeconds": 300},
    ]}
    try:
        s3.put_bucket_cors(Bucket="site", CORSConfiguration=rules)
        got = s3.get_bucket_cors(Bucket="site")["CORSRules"]
        check("boto3's put_bucket_cors and get_bucket_cors round-trip", got == rules["CORSRules"], str(got))
    except ClientError as e:
        check("boto3's put_bucket_cors and get_bucket_cors round-trip", False, str(e.response["Error"]))

    s, h, _ = preflight(port, "/site/page.txt", APP, "PUT", "authorization, x-amz-date, x-amz-content-sha256")
    check("an unsigned preflight to a runtime that wants signatures is 200",
          s == 200 and h.get("access-control-allow-origin") == APP
          and h.get("access-control-allow-headers") == "authorization, x-amz-date, x-amz-content-sha256", "%d %s" % (s, h))
    s, h, b = req(port, "GET", "/site/page.txt", headers={"Origin": APP})
    check("an unsigned GET is AccessDenied and still carries the rule",
          s == 403 and code_of(b) == "AccessDenied" and h.get("access-control-allow-origin") == APP, "%d %s" % (s, h))
    url_put = s3.generate_presigned_url("put_object", Params={"Bucket": "site", "Key": "up.txt"}, ExpiresIn=300)
    path = url_put[len(url):]
    s, h, _ = req(port, "PUT", path, b"from the browser", {"Origin": APP})
    check("a presigned PUT from the page's origin is stored and carries the rule",
          s == 200 and h.get("access-control-allow-origin") == APP and h.get("access-control-expose-headers") == "ETag", "%d %s" % (s, h))
    got = s3.get_object(Bucket="site", Key="up.txt")["Body"].read()
    check("and what it stored is the body", got == b"from the browser", repr(got))
    s3.delete_bucket_cors(Bucket="site")
    try:
        s3.get_bucket_cors(Bucket="site")
        check("boto3's delete_bucket_cors removes them", False, "no error")
    except ClientError as e:
        check("boto3's delete_bucket_cors removes them", e.response["Error"]["Code"] == "NoSuchCORSConfiguration",
              str(e.response["Error"]))


def main():
    mode, args = sys.argv[1], sys.argv[2:]
    if mode == "basic":
        basic(args[0])
    elif mode == "persist":
        persist(args)
    elif mode == "shards":
        shards(args[0], args[1])
    elif mode == "signed":
        signed(args[0], args[1], args[2])
    else:
        print("unknown mode " + mode)
        sys.exit(100)
    finish()


if __name__ == "__main__":
    main()
