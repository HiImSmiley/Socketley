#!/usr/bin/env python3
"""Virtual-hosted-style addressing on a storage runtime given --domain localhost,s3.vh.test.

usage: lib_storage_vhost.py MODE PORT ACCESS SECRET

  boto3   every operation through boto3 with addressing_style "virtual" and again "path", each
          request's URL checked to be the style asked for, and what one style wrote read by the other
  raw     requests signed here with a Host of our choosing: the domain itself, an address, an unknown
          name, upper case, a trailing dot, a second domain, and a signature over the wrong path
  after   what boto3 left is still served in both styles, after a restart

`<bucket>.localhost` resolves to the loopback on Linux, which is what lets a client reach it unaided.
Prints one PASS or FAIL line per assertion and exits with the number of failures (at most 100).
"""
import http.client
import os
import re
import sys
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib_s3_signing as sig  # noqa: E402

MODE = sys.argv[1]
PORT = int(sys.argv[2])
ACCESS = sys.argv[3]
SECRET = sys.argv[4]
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, str(detail)[:400]))


def finish():
    print("Results: %d passed, %d failed" % (passed, failed))
    sys.exit(min(failed, 100))


def raw(method, host, path, query="", body=b"", headers=None, signed=True, sign_path=None):
    """(status, headers, body) of one request to the runtime with Host `host`, signed over `sign_path` or the path."""
    hdrs = dict(headers or {})
    if signed:
        s = sig.sign(method, sign_path or path, query, host, ACCESS, SECRET, sig.sha256hex(body), extra_headers=hdrs)
        hdrs = dict(s.headers)
    hdrs["Host"] = host
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    try:
        c.request(method, path + ("?" + query if query else ""), body=body if body or method in ("PUT", "POST") else None,
                  headers=hdrs)
        r = c.getresponse()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
    finally:
        c.close()


def code_of_body(data):
    try:
        return ET.fromstring(data).findtext("Code") or ""
    except ET.ParseError:
        return ""


def fetch(url, method="GET", body=None, headers=None):
    """(status, body) of a plain request to `url`, as a browser or curl would send it."""
    rq = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(rq, timeout=30) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


# ─── boto3 in both styles ───────────────────────────────────────────────────

def boto3_mode():
    try:
        import boto3
        from botocore.config import Config
        from botocore.exceptions import ClientError
    except ImportError:
        print("  SKIP: boto3 is not installed")
        finish()

    sent = []

    def client(style, sigv=None):
        cfg = Config(s3={"addressing_style": style}, retries={"max_attempts": 1}, signature_version=sigv)
        c = boto3.client("s3", endpoint_url="http://localhost:%d" % PORT, region_name="us-east-1",
                         aws_access_key_id=ACCESS, aws_secret_access_key=SECRET, config=cfg)
        c.meta.events.register("before-send.s3", lambda request, **kw: sent.append(request.url))
        return c

    def code_of(fn):
        try:
            fn()
        except ClientError as e:
            return e.response["Error"].get("Code")
        return None

    vh, ps = client("virtual"), client("path")
    vb, pb = "vh-bucket", "vh-pathbucket"
    vhost_url = re.compile(r"^http://%s\.localhost:%d/" % (re.escape(vb), PORT))

    print("=== boto3, addressing_style virtual ===")
    sent.clear()
    vh.create_bucket(Bucket=vb)
    check("CreateBucket is sent to <bucket>.localhost", sent and vhost_url.match(sent[-1]), sent)
    vh.put_object(Bucket=vb, Key="dir/a b+c.txt", Body=b"virtual one")
    check("PutObject is sent with the key as the whole path", sent[-1].startswith("http://%s.localhost:%d/dir/a%%20b%%2Bc.txt"
                                                                                  % (vb, PORT)), sent[-1])
    got = vh.get_object(Bucket=vb, Key="dir/a b+c.txt")["Body"].read()
    check("GetObject reads it back", got == b"virtual one", got)
    check("and path style reads the same object", ps.get_object(Bucket=vb, Key="dir/a b+c.txt")["Body"].read() == b"virtual one")
    check("HeadObject answers its length", vh.head_object(Bucket=vb, Key="dir/a b+c.txt")["ContentLength"] == 11)
    vh.head_bucket(Bucket=vb)
    check("HeadBucket is sent to the bucket's host", vhost_url.match(sent[-1]), sent[-1])
    for i in range(3):
        vh.put_object(Bucket=vb, Key="dir/sub/k%d" % i, Body=b"x" * i)
    lst = vh.list_objects_v2(Bucket=vb, Prefix="dir/", Delimiter="/")
    check("ListObjectsV2 with a delimiter lists the bucket the host names",
          [o["Key"] for o in lst.get("Contents", [])] == ["dir/a b+c.txt"] and
          [p["Prefix"] for p in lst.get("CommonPrefixes", [])] == ["dir/sub/"] and lst.get("Name") == vb, lst)
    check("and was sent to the bucket's host with no bucket in the path", re.match(r"^http://%s\.localhost:%d/\?" % (vb, PORT), sent[-1]),
          sent[-1])
    names = [b["Name"] for b in vh.list_buckets()["Buckets"]]
    check("ListBuckets goes to the domain itself and lists every bucket", vb in names and sent[-1] == "http://localhost:%d/" % PORT,
          (names, sent[-1]))
    check("GetBucketLocation answers", "LocationConstraint" in vh.get_bucket_location(Bucket=vb))

    ps.create_bucket(Bucket=pb)
    ps.put_object(Bucket=pb, Key="src", Body=b"copied across")
    vh.copy_object(Bucket=vb, Key="copy", CopySource={"Bucket": pb, "Key": "src"})
    check("CopyObject from another bucket, x-amz-copy-source still /bucket/key",
          vh.get_object(Bucket=vb, Key="copy")["Body"].read() == b"copied across")
    vh.copy_object(Bucket=vb, Key="copy2", CopySource={"Bucket": vb, "Key": "dir/a b+c.txt"})
    check("and within the bucket", vh.get_object(Bucket=vb, Key="copy2")["Body"].read() == b"virtual one")

    part = os.urandom(5 << 20)
    up = vh.create_multipart_upload(Bucket=vb, Key="big file")
    e1 = vh.upload_part(Bucket=vb, Key="big file", UploadId=up["UploadId"], PartNumber=1, Body=part)["ETag"]
    e2 = vh.upload_part_copy(Bucket=vb, Key="big file", UploadId=up["UploadId"], PartNumber=2,
                             CopySource={"Bucket": pb, "Key": "src"})["CopyPartResult"]["ETag"]
    parts = vh.list_parts(Bucket=vb, Key="big file", UploadId=up["UploadId"])
    check("ListParts lists both parts", [p["PartNumber"] for p in parts.get("Parts", [])] == [1, 2] and parts.get("Bucket") == vb,
          parts.get("Parts"))
    ups = vh.list_multipart_uploads(Bucket=vb)
    check("ListMultipartUploads names the upload", [u["Key"] for u in ups.get("Uploads", [])] == ["big file"], ups.get("Uploads"))
    done = vh.complete_multipart_upload(Bucket=vb, Key="big file", UploadId=up["UploadId"],
                                        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": e1}, {"PartNumber": 2, "ETag": e2}]})
    check("CompleteMultipartUpload's Location is the object's virtual-hosted URL",
          done.get("Location") == "http://%s.localhost:%d/big%%20file" % (vb, PORT) and done.get("Bucket") == vb and
          done.get("Key") == "big file", done.get("Location"))
    check("and the object is both parts", vh.get_object(Bucket=vb, Key="big file")["Body"].read() == part + b"copied across")
    up = vh.create_multipart_upload(Bucket=vb, Key="dropped")
    vh.abort_multipart_upload(Bucket=vb, Key="dropped", UploadId=up["UploadId"])
    check("AbortMultipartUpload", not vh.list_multipart_uploads(Bucket=vb).get("Uploads"))

    pdone = ps.create_multipart_upload(Bucket=pb, Key="p/k y")
    pe = ps.upload_part(Bucket=pb, Key="p/k y", UploadId=pdone["UploadId"], PartNumber=1, Body=b"p")["ETag"]
    pres = ps.complete_multipart_upload(Bucket=pb, Key="p/k y", UploadId=pdone["UploadId"],
                                        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": pe}]})
    check("path style's Location is the bucket and key under the host",
          pres.get("Location") == "http://localhost:%d/%s/p/k%%20y" % (PORT, pb), pres.get("Location"))

    print("=== presigned URLs in both styles ===")
    for style in ("virtual", "path"):
        c = client(style, "s3v4")
        url = c.generate_presigned_url("put_object", Params={"Bucket": vb, "Key": "pre/" + style}, ExpiresIn=300)
        host_ok = url.startswith("http://%s.localhost:%d/pre/" % (vb, PORT)) if style == "virtual" else \
            url.startswith("http://localhost:%d/%s/pre/" % (PORT, vb))
        st, _ = fetch(url, "PUT", b"presigned " + style.encode())
        check("a presigned PUT, %s style, is accepted" % style, host_ok and st == 200, (st, url))
        url = c.generate_presigned_url("get_object", Params={"Bucket": vb, "Key": "pre/" + style}, ExpiresIn=300)
        st, body = fetch(url)
        check("a presigned GET, %s style, reads it" % style, st == 200 and body == b"presigned " + style.encode(), (st, body[:100], url))
        bent = re.sub(r"X-Amz-Signature=(.)", lambda m: "X-Amz-Signature=" + ("0" if m.group(1) != "0" else "1"), url)
        st, body = fetch(bent)
        check("and with its signature altered is refused, %s style" % style, st == 403 and b"SignatureDoesNotMatch" in body, (st, body[:200]))

    print("=== a form upload, virtual style ===")
    v4 = client("virtual", "s3v4")
    form = v4.generate_presigned_post(vb, "form/${filename}", Fields={"success_action_status": "201"},
                                      Conditions=[{"success_action_status": "201"}], ExpiresIn=300)
    check("boto3 posts the form to the bucket's host", form["url"] == "http://%s.localhost:%d/" % (vb, PORT), form["url"])
    b = uuid.uuid4().hex
    body = b"".join(b"--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n" % (b.encode(), k.encode(), v.encode())
                    for k, v in form["fields"].items())
    body += (b"--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f x.txt\"\r\n"
             b"Content-Type: text/plain\r\n\r\nform body\r\n--%s--\r\n" % (b.encode(), b.encode()))
    st, hd, data = raw("POST", urllib.parse.urlsplit(form["url"]).netloc, "/", body=body, signed=False,
                       headers={"Content-Type": "multipart/form-data; boundary=" + b})
    want = "http://%s.localhost:%d/form/f%%20x.txt" % (vb, PORT)
    check("it is stored, and the PostResponse and Location header give its virtual-hosted URL",
          st == 201 and hd.get("location") == want and ("<Location>%s</Location>" % want).encode() in data and
          ("<Bucket>%s</Bucket>" % vb).encode() in data, (st, hd.get("location"), data[:300]))
    check("and it reads back", vh.get_object(Bucket=vb, Key="form/f x.txt")["Body"].read() == b"form body")

    print("=== CORS, virtual style ===")
    vh.put_bucket_cors(Bucket=vb, CORSConfiguration={"CORSRules": [
        {"AllowedOrigins": ["http://app.example"], "AllowedMethods": ["GET", "PUT"], "AllowedHeaders": ["*"]}]})
    check("GetBucketCors reads the rule back", vh.get_bucket_cors(Bucket=vb)["CORSRules"][0]["AllowedOrigins"] == ["http://app.example"])
    pre = {"Origin": "http://app.example", "Access-Control-Request-Method": "PUT"}
    st, hd, _ = raw("OPTIONS", "%s.localhost:%d" % (vb, PORT), "/some/key", headers=pre, signed=False)
    check("a preflight to the bucket's host is allowed by its rule",
          st == 200 and hd.get("access-control-allow-origin") == "http://app.example", (st, hd))
    st, hd, _ = raw("OPTIONS", "localhost:%d" % PORT, "/%s/some/key" % vb, headers=pre, signed=False)
    check("and to the same bucket path style", st == 200 and hd.get("access-control-allow-origin") == "http://app.example", (st, hd))
    st, _, _ = raw("OPTIONS", "%s.localhost:%d" % (pb, PORT), "/some/key", headers=pre, signed=False)
    check("a preflight to a bucket with no rule is refused", st == 403, st)
    st, hd, _ = raw("GET", "%s.localhost:%d" % (vb, PORT), "/copy", headers={"Origin": "http://app.example"})
    check("an actual GET from the origin carries the rule", st == 200 and hd.get("access-control-allow-origin") == "http://app.example",
          (st, hd))

    print("=== DeleteObjects and DeleteBucket, virtual style ===")
    keys = [o["Key"] for o in ps.list_objects_v2(Bucket=vb).get("Contents", [])]
    res = vh.delete_objects(Bucket=vb, Delete={"Objects": [{"Key": k} for k in keys if k != "copy"]})
    check("DeleteObjects removes what it names", len(res.get("Deleted", [])) == len(keys) - 1 and
          [o["Key"] for o in vh.list_objects_v2(Bucket=vb).get("Contents", [])] == ["copy"], res.get("Errors"))
    check("a missing bucket is NoSuchBucket", code_of(lambda: vh.head_object(Bucket="vh-none", Key="k")) in ("404", "NoSuchBucket"))
    vh.create_bucket(Bucket="vh-gone")
    vh.delete_bucket(Bucket="vh-gone")
    check("DeleteBucket", code_of(lambda: vh.head_bucket(Bucket="vh-gone")) in ("404", "NoSuchBucket"))

    print("=== a dotted bucket ===")
    db = "vh.dotted.bucket"
    ps.create_bucket(Bucket=db)
    ps.put_object(Bucket=db, Key="k", Body=b"dotted")
    check("a dotted bucket is served path style", ps.get_object(Bucket=db, Key="k")["Body"].read() == b"dotted")
    sent.clear()
    got = vh.get_object(Bucket=db, Key="k")["Body"].read()
    chose = "virtual" if sent and sent[-1].startswith("http://%s.localhost" % db) else "path"
    check("and through a virtual-style client, which sent it %s style" % chose, got == b"dotted", sent)
    st, _, data = raw("GET", "%s.localhost:%d" % (db, PORT), "/k")
    check("and with the dotted name in the Host", st == 200 and data == b"dotted", (st, data[:200]))
    finish()


# ─── Hosts chosen by hand ───────────────────────────────────────────────────

def raw_mode():
    b = "vh-raw"
    lh = "localhost:%d" % PORT
    st, hd, data = raw("PUT", lh, "/" + b)
    check("CreateBucket path style answers Location /bucket", st == 200 and hd.get("location") == "/" + b, (st, hd, data[:200]))
    st, hd, data = raw("PUT", "vh-raw2.localhost:%d" % PORT, "/")
    check("and virtual-hosted style its URL", st == 200 and hd.get("location") == "http://vh-raw2.localhost:%d/" % PORT,
          (st, hd, data[:200]))

    st, _, _ = raw("PUT", "%s.localhost:%d" % (b, PORT), "/a%20b/c", body=b"one")
    check("a signed PUT with the bucket in the Host and a percent-encoded key", st == 200, st)
    st, _, data = raw("GET", "127.0.0.1:%d" % PORT, "/%s/a%%20b/c" % b)
    check("an address as Host is path style", st == 200 and data == b"one", (st, data[:200]))
    st, _, data = raw("GET", "objects.example.org:%d" % PORT, "/%s/a%%20b/c" % b)
    check("an unknown name as Host is path style", st == 200 and data == b"one", (st, data[:200]))
    st, _, data = raw("GET", "objects.example.org", "/%s/a%%20b/c" % b)
    check("and without a port", st == 200 and data == b"one", (st, data[:200]))
    st, _, data = raw("GET", lh, "/")
    check("the domain itself at / is ListBuckets", st == 200 and b"<ListAllMyBucketsResult" in data and b"vh-raw2" in data, data[:200])
    st, _, data = raw("GET", "s3.vh.test", "/")
    check("and so is the second domain", st == 200 and b"<ListAllMyBucketsResult" in data, data[:200])
    st, _, data = raw("GET", "%s.s3.vh.test" % b, "/a%20b/c")
    check("a bucket under the second domain", st == 200 and data == b"one", (st, data[:200]))
    st, _, data = raw("GET", "%s.vh.test" % b, "/%s/a%%20b/c" % b)
    check("a host that only ends like a domain is path style", st == 200 and data == b"one", (st, data[:200]))
    st, _, data = raw("GET", "VH-RAW.LocalHost:%d" % PORT, "/a%20b/c")
    check("a Host in upper case names the same bucket", st == 200 and data == b"one", (st, data[:200]))
    st, _, data = raw("GET", "%s.localhost.:%d" % (b, PORT), "/a%20b/c")
    check("and one with a trailing dot", st == 200 and data == b"one", (st, data[:200]))
    st, _, data = raw("GET", "%s.localhost:%d" % (b, PORT), "/", query="list-type=2")
    check("GET / on the bucket's host lists the bucket", st == 200 and b"<Name>vh-raw</Name>" in data and b"<Key>a b/c</Key>" in data,
          data[:300])
    st, _, data = raw("GET", "%s.localhost:%d" % (b, PORT), "/%s/a%%20b/c" % b)
    check("on the bucket's host the bucket's name in the path is part of the key", st == 404 and code_of_body(data) == "NoSuchKey",
          (st, data[:200]))
    st, _, data = raw("GET", "vh-nobucket.localhost:%d" % PORT, "/")
    check("a host naming no bucket is NoSuchBucket, naming it",
          st == 404 and code_of_body(data) == "NoSuchBucket" and b"<BucketName>vh-nobucket</BucketName>" in data, (st, data[:300]))
    st, _, data = raw("GET", "a.b.c.localhost:%d" % PORT, "/k")
    check("a dotted name before the domain is the bucket", st == 404 and b"<BucketName>a.b.c</BucketName>" in data, (st, data[:300]))

    st, _, data = raw("GET", "%s.localhost:%d" % (b, PORT), "/a%20b/c", sign_path="/%s/a%%20b/c" % b)
    check("a virtual-hosted request signed over the path-style URI is SignatureDoesNotMatch",
          st == 403 and code_of_body(data) == "SignatureDoesNotMatch", (st, data[:200]))
    s = sig.sign("GET", "/a%20b/c", "", "%s.localhost:%d" % (b, PORT), ACCESS, SECRET, sig.EMPTY)
    hdrs = dict(s.headers)
    hdrs["Host"] = "vh-raw2.localhost:%d" % PORT
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    c.request("GET", "/a%20b/c", headers=hdrs)
    r = c.getresponse()
    data = r.read()
    c.close()
    check("and one sent to another bucket's host than it signed is too", r.status == 403 and code_of_body(data) == "SignatureDoesNotMatch",
          (r.status, data[:200]))
    finish()


def after_mode():
    st, _, data = raw("GET", "vh-bucket.localhost:%d" % PORT, "/copy")
    check("after a restart the bucket's host still addresses it", st == 200 and data == b"copied across", (st, data[:200]))
    st, _, data = raw("GET", "localhost:%d" % PORT, "/vh-bucket/copy")
    check("and path style still does too", st == 200 and data == b"copied across", (st, data[:200]))
    finish()


{"boto3": boto3_mode, "raw": raw_mode, "after": after_mode}[MODE]()
