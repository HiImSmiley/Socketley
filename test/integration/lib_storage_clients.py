#!/usr/bin/env python3
"""What real S3 clients and Ceph's s3-tests asked of the storage runtime and once did not get, through boto3.

usage: lib_storage_clients.py PORT ACCESS SECRET

Prints one PASS or FAIL line per assertion and a final "Results:" line, and exits
with the number of failures (at most 100).  Every request is signed, since a
runtime with credentials is what each of these was found against.
"""
import email.utils
import sys
import xml.etree.ElementTree as ET

PORT = int(sys.argv[1])
ACCESS = sys.argv[2]
SECRET = sys.argv[3]

passed = failed = 0

def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, str(detail)[:400]))

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError
except ImportError:
    print("  SKIP: boto3 is not installed")
    sys.exit(0)

def client():
    return boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % PORT, region_name="us-east-1",
                        aws_access_key_id=ACCESS, aws_secret_access_key=SECRET,
                        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}))

s3 = client()

def code_of(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["ResponseMetadata"]["HTTPStatusCode"]
    return None, None

def with_headers(c, op, headers):
    """A client that adds `headers` to every `op` before it is signed, for what this boto3 has no parameter for."""
    c.meta.events.register("before-call.s3." + op, lambda **kw: kw["params"]["headers"].update(headers))
    return c

def with_query(c, op, query):
    """A client that appends `query` to every `op`'s URL before it is signed."""
    def add(request, **kw):
        request.url += ("&" if "?" in request.url else "?") + query
    c.meta.events.register("before-sign.s3." + op, add)
    return c

def raw_list_buckets(query):
    """The ListBuckets document for `query`, signed."""
    c = with_query(client(), "ListBuckets", query)
    holder = {}
    c.meta.events.register("after-call.s3.ListBuckets",
                           lambda http_response, **kw: holder.__setitem__("body", http_response.content))
    try:
        c.list_buckets()
    except ClientError as e:
        return e.response["ResponseMetadata"]["HTTPStatusCode"], e.response["Error"].get("Code")
    return 200, ET.fromstring(holder["body"])

NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"

# ─── DeleteBucket of a bucket that holds only uploads never completed ───────
# s3-tests: every later test on a worker errored in setup once one test left an upload open.
def delete_bucket_with_uploads():
    print("=== DeleteBucket aborts the uploads its bucket holds ===")
    s3.create_bucket(Bucket="cl-drop")
    held = s3.create_multipart_upload(Bucket="cl-drop", Key="left/open")["UploadId"]
    s3.upload_part(Bucket="cl-drop", Key="left/open", UploadId=held, PartNumber=1, Body=b"p" * 100)
    check("a bucket holding only an open upload is deleted", code_of(lambda: s3.delete_bucket(Bucket="cl-drop")) == (None, None))
    check("and the bucket is gone", code_of(lambda: s3.head_bucket(Bucket="cl-drop"))[1] == 404)

# ─── The Date header as botocore writes it ──────────────────────────────────
# s3-tests test_object_create_date_and_amz_date: botocore signs with "Date: ... -0000" and no x-amz-date.
def date_header():
    print("=== a request dated by Date alone, in RFC 2822 form ===")
    s3.create_bucket(Bucket="cl-misc")
    dated = with_headers(client(), "PutObject", {"Date": email.utils.formatdate(usegmt=True)})
    sent = {}
    dated.meta.events.register("before-send.s3.PutObject",
                               lambda request, **kw: sent.update({k.lower(): v for k, v in request.headers.items()}))
    check("a put signed with only Date: ... -0000 is accepted",
          code_of(lambda: dated.put_object(Bucket="cl-misc", Key="dated", Body=b"d")) == (None, None))
    check("and it really carried no x-amz-date", "x-amz-date" not in sent and "date" in sent, sent.keys())

# ─── Content-MD5 present and empty ──────────────────────────────────────────
def empty_content_md5():
    print("=== an empty Content-MD5 ===")
    empty_md5 = with_headers(client(), "PutObject", {"Content-MD5": ""})
    check("is InvalidDigest, not a put without one",
          code_of(lambda: empty_md5.put_object(Bucket="cl-misc", Key="md5", Body=b"bar")) == ("InvalidDigest", 400))
    check("and nothing was stored", code_of(lambda: s3.head_object(Bucket="cl-misc", Key="md5"))[1] == 404)

# ─── aws-chunked named on a body with no framing ────────────────────────────
def aws_chunked_coding():
    print("=== Content-Encoding: aws-chunked on an empty body ===")
    check("is stored, with the coding taken off",
          code_of(lambda: s3.put_object(Bucket="cl-misc", Key="enc", ContentEncoding="aws-chunked")) == (None, None) and
          "ContentEncoding" not in s3.head_object(Bucket="cl-misc", Key="enc"))
    s3.put_object(Bucket="cl-misc", Key="enc", ContentEncoding="gzip, aws-chunked")
    check("and another coding beside it is kept", s3.head_object(Bucket="cl-misc", Key="enc").get("ContentEncoding") == "gzip")

# ─── ListBuckets in pages ───────────────────────────────────────────────────
def list_buckets_paged():
    print("=== ListBuckets with max-buckets, continuation-token and prefix ===")
    for b in ("cl-page-a", "cl-page-b", "cl-page-c"):
        s3.create_bucket(Bucket=b)
    st, doc = raw_list_buckets("max-buckets=2&prefix=cl-page-")
    names = [e.text for e in doc.iter(NS + "Name")] if st == 200 else []
    token = doc.findtext(NS + "ContinuationToken") if st == 200 else None
    check("max-buckets=2 with a prefix answers the first two", names == ["cl-page-a", "cl-page-b"], (st, names))
    check("with a continuation token and the prefix echoed", bool(token) and doc.findtext(NS + "Prefix") == "cl-page-",
          token)
    st, doc = raw_list_buckets("max-buckets=2&prefix=cl-page-&continuation-token=" + (token or ""))
    names = [e.text for e in doc.iter(NS + "Name")] if st == 200 else []
    check("the token gives the rest, with no token after it",
          names == ["cl-page-c"] and doc.findtext(NS + "ContinuationToken") is None, (st, names))
    check("max-buckets=0 is InvalidArgument", raw_list_buckets("max-buckets=0") == (400, "InvalidArgument"))
    st, doc = raw_list_buckets("")
    check("a plain ListBuckets still lists every bucket", st == 200 and
          {"cl-misc", "cl-page-a", "cl-page-c"} <= {e.text for e in doc.iter(NS + "Name")})

# ─── GetObjectAttributes ────────────────────────────────────────────────────
def object_attributes():
    print("=== GetObjectAttributes ===")
    ALL = ["ETag", "Checksum", "ObjectParts", "StorageClass", "ObjectSize"]
    put = s3.put_object(Bucket="cl-misc", Key="attr", Body=b"foo", ChecksumAlgorithm="SHA256")
    a = s3.get_object_attributes(Bucket="cl-misc", Key="attr", ObjectAttributes=ALL)
    check("a single-part object: ETag, size, storage class and no parts",
          a.get("ETag") == put["ETag"].strip('"') and a.get("ObjectSize") == 3 and a.get("StorageClass") == "STANDARD" and
          "ObjectParts" not in a, a)
    check("and the checksum it was stored with", a.get("Checksum", {}).get("ChecksumSHA256") == put.get("ChecksumSHA256"),
          a.get("Checksum"))
    a = s3.get_object_attributes(Bucket="cl-misc", Key="attr", ObjectAttributes=["ObjectSize"])
    check("only what was asked for", set(a) - {"ResponseMetadata", "LastModified"} == {"ObjectSize"}, set(a))
    check("an attribute S3 does not have is InvalidArgument",
          code_of(lambda: with_headers(client(), "GetObjectAttributes", {"x-amz-object-attributes": "Colour"})
                  .get_object_attributes(Bucket="cl-misc", Key="attr", ObjectAttributes=["ETag"])) == ("InvalidArgument", 400))
    check("a missing key is NoSuchKey",
          code_of(lambda: s3.get_object_attributes(Bucket="cl-misc", Key="nope", ObjectAttributes=ALL)) == ("NoSuchKey", 404))

    part = b"m" * (5 << 20)
    uid = s3.create_multipart_upload(Bucket="cl-misc", Key="mp")["UploadId"]
    etags = [s3.upload_part(Bucket="cl-misc", Key="mp", UploadId=uid, PartNumber=n, Body=part if n < 4 else b"tail")["ETag"]
             for n in range(1, 5)]
    done = s3.complete_multipart_upload(Bucket="cl-misc", Key="mp", UploadId=uid,
                                        MultipartUpload={"Parts": [{"PartNumber": n, "ETag": e} for n, e in enumerate(etags, 1)]})
    a = s3.get_object_attributes(Bucket="cl-misc", Key="mp", ObjectAttributes=ALL, MaxParts=2, PartNumberMarker=1)
    op = a.get("ObjectParts", {})
    check("a multipart object: its parts counted and paged", op.get("TotalPartsCount", op.get("PartsCount")) == 4 and
          [(p["PartNumber"], p["Size"]) for p in op.get("Parts", [])] == [(2, 5 << 20), (3, 5 << 20)] and
          op.get("IsTruncated") is True and op.get("NextPartNumberMarker") == 3, op)
    check("with the multipart ETag", a.get("ETag") == done["ETag"].strip('"'), a.get("ETag"))

    s3.create_bucket(Bucket="cl-ver")
    s3.put_bucket_versioning(Bucket="cl-ver", VersioningConfiguration={"Status": "Enabled"})
    v1 = s3.put_object(Bucket="cl-ver", Key="k", Body=b"one")["VersionId"]
    s3.put_object(Bucket="cl-ver", Key="k", Body=b"three")
    a = s3.get_object_attributes(Bucket="cl-ver", Key="k", VersionId=v1, ObjectAttributes=["ObjectSize"])
    check("an older version by its id", a.get("VersionId") == v1 and a.get("ObjectSize") == 3, a)

# ─── Conditional writes ─────────────────────────────────────────────────────
def conditional_writes():
    print("=== PutObject and CompleteMultipartUpload under If-Match and If-None-Match ===")

    def put_if(key, body, **headers):
        return code_of(lambda: with_headers(client(), "PutObject", headers).put_object(Bucket="cl-misc", Key=key, Body=body))

    first = s3.put_object(Bucket="cl-misc", Key="cond", Body=b"first")["ETag"]
    check("If-Match on a missing key is NoSuchKey", put_if("cond-none", b"x", **{"If-Match": "*"}) == ("NoSuchKey", 404))
    check("If-Match with another ETag is PreconditionFailed",
          put_if("cond", b"x", **{"If-Match": '"0123"'}) == ("PreconditionFailed", 412))
    check("and the object is unchanged", s3.get_object(Bucket="cl-misc", Key="cond")["Body"].read() == b"first")
    check("If-Match with its ETag replaces it", put_if("cond", b"second", **{"If-Match": first}) == (None, None) and
          s3.get_object(Bucket="cl-misc", Key="cond")["Body"].read() == b"second")
    second = s3.head_object(Bucket="cl-misc", Key="cond")["ETag"]
    check("If-None-Match with its current ETag is PreconditionFailed",
          put_if("cond", b"x", **{"If-None-Match": second}) == ("PreconditionFailed", 412))
    check("If-None-Match with an older ETag replaces it", put_if("cond", b"third", **{"If-None-Match": first}) == (None, None))
    check("If-None-Match: * still refuses an existing key", put_if("cond", b"x", **{"If-None-Match": "*"}) == ("PreconditionFailed", 412))

    def mpu_if(key, **headers):
        u = s3.create_multipart_upload(Bucket="cl-misc", Key=key)["UploadId"]
        e = s3.upload_part(Bucket="cl-misc", Key=key, UploadId=u, PartNumber=1, Body=b"mpu-body")["ETag"]
        c = with_headers(client(), "CompleteMultipartUpload", headers)
        return code_of(lambda: c.complete_multipart_upload(Bucket="cl-misc", Key=key, UploadId=u,
                                                           MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": e}]}))

    check("a completion under If-None-Match: * of an existing key is PreconditionFailed",
          mpu_if("cond", **{"If-None-Match": "*"}) == ("PreconditionFailed", 412))
    check("and under If-Match of a missing key is NoSuchKey", mpu_if("cond-mpu-none", **{"If-Match": "*"}) == ("NoSuchKey", 404))
    cur = s3.head_object(Bucket="cl-misc", Key="cond")["ETag"]
    check("and under If-Match of its ETag it completes", mpu_if("cond", **{"If-Match": cur}) == (None, None) and
          s3.get_object(Bucket="cl-misc", Key="cond")["Body"].read() == b"mpu-body")

# ─── A completion sent again ────────────────────────────────────────────────
# s3-tests test_multipart_upload: an SDK retries a completion whose answer it lost, and S3 answers it again.
def completion_sent_twice():
    print("=== CompleteMultipartUpload sent twice ===")
    uid = s3.create_multipart_upload(Bucket="cl-misc", Key="twice")["UploadId"]
    parts = [{"PartNumber": n, "ETag": s3.upload_part(Bucket="cl-misc", Key="twice", UploadId=uid, PartNumber=n,
                                                       Body=(b"t" * (5 << 20)) if n == 1 else b"end")["ETag"]}
             for n in (1, 2)]
    done = s3.complete_multipart_upload(Bucket="cl-misc", Key="twice", UploadId=uid, MultipartUpload={"Parts": parts})
    again = s3.complete_multipart_upload(Bucket="cl-misc", Key="twice", UploadId=uid, MultipartUpload={"Parts": parts})
    check("answers the ETag of the object it made", again.get("ETag") == done["ETag"], again.get("ETag"))
    s3.put_object(Bucket="cl-misc", Key="twice", Body=b"replaced")
    check("and once the key holds something else it is NoSuchUpload",
          code_of(lambda: s3.complete_multipart_upload(Bucket="cl-misc", Key="twice", UploadId=uid,
                  MultipartUpload={"Parts": parts})) == ("NoSuchUpload", 404))

# ─── A multipart object's checksum of its whole bytes ───────────────────────
# s3-tests test_multipart_use_cksum_helper_*: an SDK asks for FULL_OBJECT and checks the CRC of the whole object.
def full_object_checksums():
    print("=== CreateMultipartUpload with x-amz-checksum-type ===")
    import base64
    import zlib
    one, two = b"a" * (5 << 20), b"tail-bytes"
    want = base64.b64encode(zlib.crc32(one + two).to_bytes(4, "big")).decode()

    def upload(key, headers, promised=None):
        c = with_headers(client(), "CreateMultipartUpload", headers)
        made = c.create_multipart_upload(Bucket="cl-misc", Key=key, ChecksumAlgorithm="CRC32")
        parts = [{"PartNumber": n, "ETag": r["ETag"], "ChecksumCRC32": r["ChecksumCRC32"]}
                 for n, r in ((n, s3.upload_part(Bucket="cl-misc", Key=key, UploadId=made["UploadId"], PartNumber=n,
                                                 Body=b, ChecksumAlgorithm="CRC32")) for n, b in ((1, one), (2, two)))]
        extra = {"ChecksumCRC32": promised} if promised else {}
        return made, lambda: s3.complete_multipart_upload(Bucket="cl-misc", Key=key, UploadId=made["UploadId"],
                                                          MultipartUpload={"Parts": parts}, **extra)

    made, finish = upload("full", {"x-amz-checksum-type": "FULL_OBJECT"}, want)
    hdrs = made["ResponseMetadata"]["HTTPHeaders"]
    check("the answer names the algorithm and the type",
          hdrs.get("x-amz-checksum-algorithm") == "CRC32" and hdrs.get("x-amz-checksum-type") == "FULL_OBJECT", hdrs)
    done = finish()
    check("the completion's CRC32 is that of the whole object, with no -N", done.get("ChecksumCRC32") == want,
          (done.get("ChecksumCRC32"), want))
    head = s3.head_object(Bucket="cl-misc", Key="full", ChecksumMode="ENABLED")["ResponseMetadata"]["HTTPHeaders"]
    check("and HEAD says so", head.get("x-amz-checksum-crc32") == want and head.get("x-amz-checksum-type") == "FULL_OBJECT",
          head)
    made, finish = upload("composite", {})
    check("without a type the upload is COMPOSITE",
          made["ResponseMetadata"]["HTTPHeaders"].get("x-amz-checksum-type") == "COMPOSITE")
    check("and its checksum has -2", finish().get("ChecksumCRC32", "").endswith("-2"))
    _, finish = upload("promised", {"x-amz-checksum-type": "FULL_OBJECT"}, "AAAAAA==")
    check("a whole-object checksum the parts do not make is BadDigest", code_of(finish) == ("BadDigest", 400))
    check("and stores nothing", code_of(lambda: s3.head_object(Bucket="cl-misc", Key="promised"))[1] == 404)
    bad = with_headers(client(), "CreateMultipartUpload", {"x-amz-checksum-type": "FULL_OBJECT"})
    check("FULL_OBJECT with a digest is InvalidRequest",
          code_of(lambda: bad.create_multipart_upload(Bucket="cl-misc", Key="x", ChecksumAlgorithm="SHA256")) ==
          ("InvalidRequest", 400))


# ─── x-amz-expiration ───────────────────────────────────────────────────────
# s3-tests test_lifecycle_expiration_header_*: an object a rule will expire says when, and by which rule.
def expiration_header():
    print("=== x-amz-expiration on PutObject, HeadObject and GetObject ===")
    s3.create_bucket(Bucket="cl-exp")
    s3.put_bucket_lifecycle_configuration(Bucket="cl-exp", LifecycleConfiguration={"Rules": [
        {"ID": "soon", "Status": "Enabled", "Filter": {"Prefix": "tmp/"}, "Expiration": {"Days": 1}},
        {"ID": "later", "Status": "Enabled", "Filter": {"Prefix": "tmp/"}, "Expiration": {"Days": 30}},
        {"ID": "tagged", "Status": "Enabled", "Filter": {"Tag": {"Key": "gone", "Value": "yes"}},
         "Expiration": {"Days": 2}}]})

    def exp(resp):
        return resp["ResponseMetadata"]["HTTPHeaders"].get("x-amz-expiration", "")

    put = exp(s3.put_object(Bucket="cl-exp", Key="tmp/a", Body=b"x"))
    check("a put a rule covers is told when it expires, by the earliest rule",
          put.startswith('expiry-date="') and put.endswith(' GMT", rule-id="soon"'), put)
    check("and HEAD and GET say the same", put != "" and exp(s3.head_object(Bucket="cl-exp", Key="tmp/a")) == put and
          exp(s3.get_object(Bucket="cl-exp", Key="tmp/a")) == put and
          exp(s3.get_object(Bucket="cl-exp", Key="tmp/a")) == put)
    check("an object no rule covers is told nothing", exp(s3.put_object(Bucket="cl-exp", Key="keep", Body=b"x")) == "" and
          exp(s3.get_object(Bucket="cl-exp", Key="keep")) == "")
    s3.put_object_tagging(Bucket="cl-exp", Key="keep", Tagging={"TagSet": [{"Key": "gone", "Value": "yes"}]})
    check("until it is tagged for a rule", 'rule-id="tagged"' in exp(s3.head_object(Bucket="cl-exp", Key="keep")))
    s3.delete_bucket_lifecycle(Bucket="cl-exp")
    check("and nothing once the rules are gone", put != "" and exp(s3.get_object(Bucket="cl-exp", Key="tmp/a")) == "")


# ─── ACLs, as S3 answers them on a bucket whose ACLs are disabled ───────────
# rclone and s3fs send x-amz-acl: private by default; s3-tests' ACL tests sent public-read and it was dropped silently.
def acls_disabled():
    print("=== ACLs: the owner's full control, and nothing else ===")
    s3.create_bucket(Bucket="cl-acl", ACL="private")
    acl = s3.get_bucket_acl(Bucket="cl-acl")
    check("GetBucketAcl answers one grant, FULL_CONTROL to the owner",
          [g["Permission"] for g in acl["Grants"]] == ["FULL_CONTROL"] and acl["Grants"][0]["Grantee"]["ID"] == acl["Owner"]["ID"],
          acl.get("Grants"))
    check("a put with x-amz-acl: private is taken", code_of(lambda: s3.put_object(Bucket="cl-acl", Key="k", Body=b"x",
                                                                                  ACL="private")) == (None, None))
    check("GetObjectAcl of it says the same", s3.get_object_acl(Bucket="cl-acl", Key="k")["Grants"] == acl["Grants"])
    check("GetObjectAcl of a missing key is NoSuchKey",
          code_of(lambda: s3.get_object_acl(Bucket="cl-acl", Key="nope")) == ("NoSuchKey", 404))
    check("a put asking for public-read is AccessControlListNotSupported, not stored private",
          code_of(lambda: s3.put_object(Bucket="cl-acl", Key="pub", Body=b"x", ACL="public-read")) ==
          ("AccessControlListNotSupported", 400) and code_of(lambda: s3.head_object(Bucket="cl-acl", Key="pub"))[1] == 404)
    check("as is a grant to anyone else",
          code_of(lambda: s3.put_object(Bucket="cl-acl", Key="pub", Body=b"x", GrantRead='uri="http://acs.amazonaws.com/groups/global/AllUsers"')) ==
          ("AccessControlListNotSupported", 400))
    check("CreateBucket with public-read is InvalidBucketAclWithObjectOwnership",
          code_of(lambda: s3.create_bucket(Bucket="cl-acl-pub", ACL="public-read")) ==
          ("InvalidBucketAclWithObjectOwnership", 400))
    check("PutBucketAcl of private is taken, of public-read refused",
          code_of(lambda: s3.put_bucket_acl(Bucket="cl-acl", ACL="private")) == (None, None) and
          code_of(lambda: s3.put_bucket_acl(Bucket="cl-acl", ACL="public-read")) == ("AccessControlListNotSupported", 400))
    own = s3.get_bucket_ownership_controls(Bucket="cl-acl")["OwnershipControls"]["Rules"]
    check("and the ownership controls say BucketOwnerEnforced", own == [{"ObjectOwnership": "BucketOwnerEnforced"}], own)


# ─── A bucket's own tags ────────────────────────────────────────────────────
# s3-tests test_set_bucket_tagging: PutBucketTagging was 501.
def bucket_tags():
    print("=== PutBucketTagging, GetBucketTagging, DeleteBucketTagging ===")
    s3.create_bucket(Bucket="cl-btag")
    check("a bucket without tags is NoSuchTagSet", code_of(lambda: s3.get_bucket_tagging(Bucket="cl-btag")) ==
          ("NoSuchTagSet", 404))
    tags = [{"Key": "team", "Value": "storage"}, {"Key": "cost centre", "Value": "42"}]
    s3.put_bucket_tagging(Bucket="cl-btag", Tagging={"TagSet": tags})
    check("the tags set are read back, in their order", s3.get_bucket_tagging(Bucket="cl-btag")["TagSet"] == tags)
    fifty = [{"Key": "k%d" % i, "Value": "v"} for i in range(50)]
    check("fifty tags are a bucket's limit", code_of(lambda: s3.put_bucket_tagging(Bucket="cl-btag",
                                                                                   Tagging={"TagSet": fifty})) == (None, None))
    check("and fifty-one are InvalidTag, leaving the fifty",
          code_of(lambda: s3.put_bucket_tagging(Bucket="cl-btag", Tagging={"TagSet": fifty + [{"Key": "x", "Value": "y"}]})) ==
          ("InvalidTag", 400) and len(s3.get_bucket_tagging(Bucket="cl-btag")["TagSet"]) == 50)
    check("a key beginning aws: is InvalidTag", code_of(lambda: s3.put_bucket_tagging(
        Bucket="cl-btag", Tagging={"TagSet": [{"Key": "aws:x", "Value": "y"}]}))[0] == "InvalidTag")
    s3.delete_bucket_tagging(Bucket="cl-btag")
    check("DeleteBucketTagging removes them", code_of(lambda: s3.get_bucket_tagging(Bucket="cl-btag"))[0] == "NoSuchTagSet")
    s3.put_bucket_tagging(Bucket="cl-btag", Tagging={"TagSet": tags})
    s3.delete_bucket(Bucket="cl-btag")
    s3.create_bucket(Bucket="cl-btag")
    check("and a bucket made again under the name has none",
          code_of(lambda: s3.get_bucket_tagging(Bucket="cl-btag"))[0] == "NoSuchTagSet")
    check("a missing bucket is NoSuchBucket", code_of(lambda: s3.get_bucket_tagging(Bucket="cl-nobucket"))[0] == "NoSuchBucket")


# A section that raises fails as one assertion and the next still runs, so a runtime without the feature reads red, not dead.
for section in (delete_bucket_with_uploads, date_header, empty_content_md5, aws_chunked_coding, list_buckets_paged,
                object_attributes, conditional_writes, completion_sent_twice, full_object_checksums,
                expiration_header, acls_disabled, bucket_tags):
    try:
        section()
    except Exception as e:
        check("%s ran to its end" % section.__name__, False, repr(e))

print("  Results: %d passed, %d failed" % (passed, failed))
sys.exit(min(failed, 100))
