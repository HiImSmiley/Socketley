#!/usr/bin/env bash
# Integration test: DeleteObject and DeleteObjects with conditions -- If-Match, x-amz-if-match-last-modified-time and
# x-amz-if-match-size, and the same per key in a DeleteObjects document -- on a runtime of two shards, so a condition
# crosses to the shard that owns its key.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a delete whose condition does not match its object made anyway, or one
#     that matches refused
#   * a condition on a key that is not there answered as an error
#   * a condition lost on its way to the shard that owns the key
#   * the latest of a versioned key not the version a condition is asked of,
#     a delete marker included; a version named by its id asked instead
#   * a time or a size that is no time or no size taken
# suite: isolated
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgdelcond
P=$((SL_PORT_BASE+1977))
export ADMIN_AK="AKIADELCONDADMIN0001"
export ADMIN_SK="delcond/admin/secret"
trap '"$BIN" stop dc >/dev/null 2>&1; "$BIN" remove dc >/dev/null 2>&1; daemon_stop' EXIT

echo "=== Integration: conditional deletes ==="
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
daemon_start "$BIN"
printf '[admin]\n%s:%s\nadmin = true\n' "$ADMIN_AK" "$ADMIN_SK" > "$SOCKETLEY_TMPD/creds"
"$BIN" create storage dc -p "$P" --dir "$SOCKETLEY_TMPD/data" --credentials "$SOCKETLEY_TMPD/creds" --shards 2 -s \
    >/dev/null 2>&1 || { echo "  FAIL [create]: the runtime was not created"; exit 1; }
for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 0.1; done

python3 - "$P" <<'PY'
import datetime, email.utils, os, sys, urllib.error, urllib.request
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.config import Config
from botocore.credentials import Credentials
from botocore.exceptions import ClientError
port = int(sys.argv[1])
creds = Credentials(os.environ["ADMIN_AK"], os.environ["ADMIN_SK"])
c = boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % port, region_name="us-east-1",
                 aws_access_key_id=creds.access_key, aws_secret_access_key=creds.secret_key,
                 config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}))
passed = failed = 0
def check(name, cond, detail=""):
    global passed, failed
    passed, failed = (passed + 1, failed) if cond else (passed, failed + 1)
    print(("  PASS: " if cond else "  FAIL [%s]: " % name) + (name if cond else str(detail)[:300]), flush=True)
def signed(method, path, headers=None, body=b""):
    """A request signed as the admin, with headers the installed boto3 may not know: its status and body."""
    url = "http://127.0.0.1:%d%s" % (port, path)
    req = AWSRequest(method=method, url=url, data=body, headers=dict(headers or {}))
    req.headers["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD"
    SigV4Auth(creds, "s3", "us-east-1").add_auth(req)
    r = urllib.request.Request(url, data=body or None, method=method, headers=dict(req.headers))
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
def delete(bucket, key, version=None, **cond):
    h = {}
    if "etag" in cond:
        h["If-Match"] = cond["etag"]
    if "mtime" in cond:
        h["x-amz-if-match-last-modified-time"] = email.utils.format_datetime(cond["mtime"].astimezone(datetime.timezone.utc), usegmt=True)
    if "size" in cond:
        h["x-amz-if-match-size"] = str(cond["size"])
    st, body = signed("DELETE", "/%s/%s%s" % (bucket, key, "?versionId=" + version if version else ""), h)
    return "PreconditionFailed" if "<Code>PreconditionFailed</Code>" in body else st, body
def there(b, k, v=None):
    try:
        c.head_object(Bucket=b, Key=k, **({"VersionId": v} if v else {}))
        return True
    except ClientError:
        return False
bad_time = datetime.datetime(2015, 1, 1, tzinfo=datetime.timezone.utc)

c.create_bucket(Bucket="plain")
# Keys spread over both shards, so half the conditions cross to the other.
for i in range(6):
    k = "k%d" % i
    etag = c.put_object(Bucket="plain", Key=k, Body=b"x" * (i + 1))["ETag"]
    mtime = c.head_object(Bucket="plain", Key=k)["LastModified"]
    check("%s: an If-Match of another ETag is PreconditionFailed" % k,
          delete("plain", k, etag='"0123"')[0] == "PreconditionFailed" and there("plain", k))
    check("%s: a time it was not written at is PreconditionFailed" % k,
          delete("plain", k, mtime=bad_time)[0] == "PreconditionFailed")
    check("%s: a size it does not have is PreconditionFailed" % k,
          delete("plain", k, size=999)[0] == "PreconditionFailed" and there("plain", k))
    check("%s: its own ETag, time and size delete it" % k,
          delete("plain", k, etag=etag, mtime=mtime, size=i + 1)[0] == 204 and not there("plain", k))
    check("%s: a condition on a key that is not there is no error" % k, delete("plain", k, etag='"0123"')[0] == 204)

c.put_object(Bucket="plain", Key="star", Body=b"s")
check("If-Match: * deletes what is there", delete("plain", "star", etag="*")[0] == 204 and not there("plain", "star"))

etags = {}
for i in range(4):
    etags["m%d" % i] = c.put_object(Bucket="plain", Key="m%d" % i, Body=b"m" * 10)["ETag"]
doc = ('<Delete><Object><Key>m0</Key><ETag>"0123"</ETag></Object>'
       '<Object><Key>m1</Key><ETag>%s</ETag></Object>'
       '<Object><Key>m2</Key><Size>3</Size></Object>'
       '<Object><Key>m3</Key><LastModifiedTime>%s</LastModifiedTime></Object></Delete>'
       % (etags["m1"], email.utils.format_datetime(bad_time, usegmt=True))).encode()
st, body = signed("POST", "/plain?delete=", {"Content-Type": "application/xml"}, doc)
check("DeleteObjects refuses each key whose condition does not match, and deletes the one that does",
      st == 200 and body.count("<Code>PreconditionFailed</Code>") == 3 and "<Deleted><Key>m1</Key>" in body and
      there("plain", "m0") and not there("plain", "m1") and there("plain", "m2"), body)
iso = ('<Delete><Object><Key>m3</Key><LastModifiedTime>%s</LastModifiedTime></Object></Delete>'
       % c.head_object(Bucket="plain", Key="m3")["LastModified"].strftime("%Y-%m-%dT%H:%M:%S.000Z")).encode()
st, body = signed("POST", "/plain?delete=", {"Content-Type": "application/xml"}, iso)
check("and takes a time in ISO 8601 as well", st == 200 and not there("plain", "m3"), body)

c.create_bucket(Bucket="kept")
c.put_bucket_versioning(Bucket="kept", VersioningConfiguration={"Status": "Enabled"})
for i in range(4):
    k = "v%d" % i
    r = c.put_object(Bucket="kept", Key=k, Body=b"v")
    v, etag = r["VersionId"], r["ETag"]
    check("%s: a delete marker is not made over a latest the condition does not match" % k,
          delete("kept", k, etag='"0123"')[0] == "PreconditionFailed" and there("kept", k))
    st, _ = delete("kept", k, etag=etag)
    check("%s: and is made over one it matches" % k, st == 204 and not there("kept", k))
    check("%s: behind the marker, a condition other than * is PreconditionFailed" % k,
          delete("kept", k, size=999)[0] == "PreconditionFailed")
    check("%s: a version named by its id is asked by its own ETag" % k,
          delete("kept", k, v, etag='"0123"')[0] == "PreconditionFailed" and there("kept", k, v))
    check("%s: and removed when it matches" % k, delete("kept", k, v, etag=etag)[0] == 204 and not there("kept", k, v))

st, body = signed("DELETE", "/plain/m0", {"x-amz-if-match-size": "many"})
check("a size that is no number is refused before anything is deleted", st == 400 and there("plain", "m0"), body)
st, body = signed("DELETE", "/plain/m0", {"x-amz-if-match-last-modified-time": "yesterday"})
check("and a time that is none", st == 400 and there("plain", "m0"), body)
print("  Results: %d/%d passed (%d failed)" % (passed, passed + failed, failed))
sys.exit(failed)
PY
rc=$?
[ "$rc" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$rc"
