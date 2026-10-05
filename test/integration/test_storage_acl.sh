#!/usr/bin/env bash
# Integration test: ACLs and object ownership -- buckets that take them by their ownership controls or by --acls,
# canned ACLs, grant headers and documents, who they admit, and the public access block's say over them.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * an ACL taken where ownership disables ACLs, or refused where it takes them
#   * a grant that admits nobody, or one that admits who it does not name: a
#     user by id or email, every signed user, everyone
#   * an object's owner not its writer under ObjectWriter, or not the bucket's
#     owner under BucketOwnerPreferred with bucket-owner-full-control
#   * a grantee that is no one taken
#   * a public grant taken where the bucket blocks them, or counted where it
#     ignores them
#   * the default --acls gives not what RGW and the old S3 gave
#   * a group's grant listed after a user's, which a client sorting by
#     DisplayName stops at; an ACL put on a version refused
#   * a request whose x-amz-expected-bucket-owner names another owner done;
#     an anonymous request to a bucket that is not there refused as 403
# suite: isolated
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgacl
P1=$((SL_PORT_BASE+1891))
P2=$((SL_PORT_BASE+1893))

cleanup() {
    for r in acl1 acl2; do "$BIN" stop "$r" >/dev/null 2>&1; "$BIN" remove "$r" >/dev/null 2>&1; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: storage ACLs and ownership ==="
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
daemon_start "$BIN"
T="$SOCKETLEY_TMPD"
cat > "$T/creds" <<'CREDS'
[main]
name = Main
email = main@example.org
AKIAACLMAIN000000001:acl/main/secret
[alt]
name = Alt
email = alt@example.org
AKIAACLALT0000000001:acl/alt/secret
CREDS
"$BIN" create storage acl1 -p "$P1" --dir "$T/one" --credentials "$T/creds" --shards 2 -s >/dev/null 2>&1 \
    || { echo "  FAIL [create]: the runtime was not created"; exit 1; }
"$BIN" create storage acl2 -p "$P2" --dir "$T/two" --credentials "$T/creds" --acls -s >/dev/null 2>&1 \
    || { echo "  FAIL [create]: the --acls runtime was not created"; exit 1; }
for p in "$P1" "$P2"; do for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$p/" && break; sleep 0.1; done; done

python3 - "$P1" "$P2" <<'PY'
import sys, urllib.request, urllib.error
import boto3
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError
p1, p2 = int(sys.argv[1]), int(sys.argv[2])
cfg = Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1})
def mk(port, ak=None, sk=None):
    if ak is None:
        return boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % port, region_name="us-east-1",
                            config=Config(signature_version=UNSIGNED, s3={"addressing_style": "path"},
                                          retries={"max_attempts": 1}))
    return boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % port, region_name="us-east-1",
                        aws_access_key_id=ak, aws_secret_access_key=sk, config=cfg)
main, alt, anon = (mk(p1, "AKIAACLMAIN000000001", "acl/main/secret"), mk(p1, "AKIAACLALT0000000001", "acl/alt/secret"),
                   mk(p1))
passed = failed = 0
def check(name, got, want):
    global passed, failed
    ok = got == want
    passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)
    print(("  PASS: " if ok else "  FAIL [%s]: " % name) + (name if ok else "got %r, want %r" % (got, want)), flush=True)
def code(f):
    try:
        f()
        return "ok"
    except ClientError as e:
        return e.response["Error"]["Code"]
def owner(c, b, k):
    return c.get_object_acl(Bucket=b, Key=k)["Owner"]["ID"]
def grants(c, b, k=None):
    r = c.get_object_acl(Bucket=b, Key=k) if k else c.get_bucket_acl(Bucket=b)
    return sorted((g["Grantee"].get("ID") or g["Grantee"].get("URI"), g["Permission"]) for g in r["Grants"])
AU = "http://acs.amazonaws.com/groups/global/AllUsers"

# ── ACLs disabled, every bucket's default ──
check("a public ACL on CreateBucket is InvalidBucketAclWithObjectOwnership",
      code(lambda: main.create_bucket(Bucket="aclsdis", ACL="public-read")), "InvalidBucketAclWithObjectOwnership")
main.create_bucket(Bucket="aclsdis")
check("a bucket given no controls is BucketOwnerEnforced",
      main.get_bucket_ownership_controls(Bucket="aclsdis")["OwnershipControls"]["Rules"][0]["ObjectOwnership"],
      "BucketOwnerEnforced")
check("a public ACL on an object there is AccessControlListNotSupported",
      code(lambda: main.put_object(Bucket="aclsdis", Key="k", Body=b"x", ACL="public-read")), "AccessControlListNotSupported")
check("bucket-owner-full-control is taken", code(lambda: main.put_object(Bucket="aclsdis", Key="k", Body=b"x",
                                                                          ACL="bucket-owner-full-control")), "ok")
check("and the object stays its owner's alone", code(lambda: anon.get_object(Bucket="aclsdis", Key="k")), "AccessDenied")

# ── ObjectWriter, by CreateBucket's header ──
main.create_bucket(Bucket="aclsow", ObjectOwnership="ObjectWriter", ACL="public-read-write")
check("CreateBucket sets ObjectWriter",
      main.get_bucket_ownership_controls(Bucket="aclsow")["OwnershipControls"]["Rules"][0]["ObjectOwnership"], "ObjectWriter")
check("and the bucket's ACL", grants(main, "aclsow"), sorted([("main", "FULL_CONTROL"), (AU, "READ"),
                                                          (AU, "WRITE")]))
check("everyone may list a public-read-write bucket", code(lambda: anon.list_objects_v2(Bucket="aclsow")), "ok")
check("and write to it", code(lambda: anon.put_object(Bucket="aclsow", Key="anon", Body=b"a")), "ok")
alt.put_object(Bucket="aclsow", Key="mine", Body=b"alt's")
check("an object is its writer's", owner(main, "aclsow", "mine"), "alt")
check("which the bucket's public READ does not read",
      code(lambda: anon.get_object(Bucket="aclsow", Key="mine")), "AccessDenied")
alt.put_object_acl(Bucket="aclsow", Key="mine", ACL="public-read")
check("until its writer makes it public-read", anon.get_object(Bucket="aclsow", Key="mine")["Body"].read(), b"alt's")
alt.put_object(Bucket="aclsow", Key="granted", Body=b"g", GrantRead="emailAddress=main@example.org",
               GrantFullControl='id="alt"')
check("a grant by email names the user", grants(main, "aclsow", "granted"), sorted([("alt", "FULL_CONTROL"), ("main", "READ")]))
check("an email that is nobody's is UnresolvableGrantByEmailAddress",
      code(lambda: alt.put_object(Bucket="aclsow", Key="x", Body=b"x", GrantRead="emailAddress=nobody@example.org")),
      "UnresolvableGrantByEmailAddress")
check("an id that is nobody's is InvalidArgument",
      code(lambda: alt.put_object(Bucket="aclsow", Key="x", Body=b"x", GrantRead='id="nobody"')), "InvalidArgument")
check("a canned ACL beside grants is InvalidRequest",
      code(lambda: alt.put_object(Bucket="aclsow", Key="x", Body=b"x", ACL="private", GrantRead='id="main"')),
      "InvalidRequest")
main.put_object(Bucket="aclsow", Key="auth", Body=b"t", ACL="authenticated-read")
check("authenticated-read reads to a signed user", alt.get_object(Bucket="aclsow", Key="auth")["Body"].read(), b"t")
check("and not to everyone", code(lambda: anon.get_object(Bucket="aclsow", Key="auth")), "AccessDenied")
check("BucketOwnerEnforced is refused while the bucket's ACL is public",
      code(lambda: main.put_bucket_ownership_controls(Bucket="aclsow", OwnershipControls={
          "Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]})), "InvalidBucketAclWithObjectOwnership")

# ── BucketOwnerPreferred, by PutBucketOwnershipControls ──
main.create_bucket(Bucket="aclsbp")
main.put_bucket_ownership_controls(Bucket="aclsbp", OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]})
main.put_bucket_acl(Bucket="aclsbp", GrantWrite='id="alt"', GrantFullControl='id="main"')
check("a grant of WRITE lets another user write", code(lambda: alt.put_object(Bucket="aclsbp", Key="a", Body=b"1")), "ok")
alt.put_object(Bucket="aclsbp", Key="b", Body=b"2", ACL="bucket-owner-full-control")
check("whose object is its own", owner(main, "aclsbp", "a"), "alt")
check("unless it gave the bucket's owner full control", owner(main, "aclsbp", "b"), "main")
check("a grant of WRITE is no READ of the bucket", code(lambda: alt.list_objects_v2(Bucket="aclsbp")), "AccessDenied")
main.put_public_access_block(Bucket="aclsbp", PublicAccessBlockConfiguration={
    "BlockPublicAcls": True, "IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False})
check("a public ACL where the bucket blocks them is AccessDenied",
      code(lambda: alt.put_object(Bucket="aclsbp", Key="c", Body=b"3", ACL="public-read")), "AccessDenied")
main.put_object(Bucket="aclsow", Key="pub", Body=b"p", ACL="public-read")
main.put_public_access_block(Bucket="aclsow", PublicAccessBlockConfiguration={
    "BlockPublicAcls": False, "IgnorePublicAcls": True, "BlockPublicPolicy": False, "RestrictPublicBuckets": False})
check("and a public grant counts for nothing where it ignores them",
      code(lambda: anon.get_object(Bucket="aclsow", Key="pub")), "AccessDenied")
main.delete_bucket_ownership_controls(Bucket="aclsbp")
check("removed controls leave the default", main.get_bucket_ownership_controls(Bucket="aclsbp")["OwnershipControls"]
      ["Rules"][0]["ObjectOwnership"], "BucketOwnerEnforced")

# ── --acls, RGW's default ──
m2, a2 = mk(p2, "AKIAACLMAIN000000001", "acl/main/secret"), mk(p2)
check("a public ACL on CreateBucket is taken", code(lambda: m2.create_bucket(Bucket="aclsr", ACL="public-read")), "ok")
check("and the bucket has no ownership controls",
      code(lambda: m2.get_bucket_ownership_controls(Bucket="aclsr")), "OwnershipControlsNotFoundError")
m2.put_object(Bucket="aclsr", Key="o", Body=b"o", ACL="public-read")
check("its public object reads to everyone", a2.get_object(Bucket="aclsr", Key="o")["Body"].read(), b"o")
check("and its listing", code(lambda: a2.list_objects(Bucket="aclsr")), "ok")
check("a group's grants are listed before a user's",
      [g["Grantee"]["Type"] for g in m2.get_bucket_acl(Bucket="aclsr")["Grants"]], ["Group", "CanonicalUser"])
m2.put_bucket_versioning(Bucket="aclsr", VersioningConfiguration={"Status": "Enabled"})
v1 = m2.put_object(Bucket="aclsr", Key="v", Body=b"1")["VersionId"]
m2.put_object(Bucket="aclsr", Key="v", Body=b"2")
check("an ACL is put on a version that is not the latest",
      code(lambda: m2.put_object_acl(Bucket="aclsr", Key="v", VersionId=v1, ACL="public-read")), "ok")
check("which reads to everyone by its version", code(lambda: a2.get_object(Bucket="aclsr", Key="v", VersionId=v1)), "ok")
check("and leaves the latest its owner's", code(lambda: a2.get_object(Bucket="aclsr", Key="v")), "AccessDenied")
check("a request expecting another bucket owner is AccessDenied",
      code(lambda: a2.list_objects(Bucket="aclsr", ExpectedBucketOwner="alt")), "AccessDenied")
check("and one expecting the owner is done", code(lambda: a2.list_objects(Bucket="aclsr", ExpectedBucketOwner="main")), "ok")
check("a copy expecting another owner of its source is AccessDenied",
      code(lambda: m2.copy_object(Bucket="aclsr", Key="c", CopySource={"Bucket": "aclsr", "Key": "o"},
                                  ExpectedSourceBucketOwner="alt")), "AccessDenied")
check("an anonymous request to a bucket that is not there is NoSuchBucket",
      code(lambda: a2.delete_object(Bucket="aclsgone", Key="k")), "NoSuchBucket")
print("  Results: %d/%d passed (%d failed)" % (passed, passed + failed, failed))
sys.exit(failed)
PY
rc=$?
[ "$rc" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$rc"
