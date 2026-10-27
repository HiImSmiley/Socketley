#!/usr/bin/env bash
# Integration test: libraries in the web interface -- whose they are, how one is
# deleted with what it holds, keys for a user of the credentials file, and the
# library a user's repositories go to.
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: libraries in the web interface ==="
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
. "$HERE/lib_verdicts.sh"

daemon_isolate stguilib
trap 'daemon_stop' EXIT
daemon_start "$BIN"
P1=$((SL_PORT_BASE + 1910))
U="http://127.0.0.1:$P1"
cat > "$SOCKETLEY_TMPD/creds" <<EOF
[root]
admin = true
AKIAUILIBROOT0000000:uilibrootsecretuilibrootsecretuilibroot0
[jonas]
AKIAUILIBJONAS000000:uilibjonassecretuilibjonassecretuilibjon
EOF
"$BIN" create storage ul -p "$P1" --dir "$SOCKETLEY_TMPD/ul" --credentials "$SOCKETLEY_TMPD/creds" -s >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/")" != 000 ] && break; sleep 0.1; done

python3 - "$P1" > "$SOCKETLEY_TMPD/out" 2>&1 <<'PY'
import sys, json, time, base64, re, urllib.request, urllib.error
import xml.etree.ElementTree as ET
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
url = "http://127.0.0.1:%s" % sys.argv[1]
cfg = Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1})
ROOT = ("AKIAUILIBROOT0000000", "uilibrootsecretuilibrootsecretuilibroot0")
JONAS = ("AKIAUILIBJONAS000000", "uilibjonassecretuilibjonassecretuilibjon")
def mk(svc, k, region="us-east-1"):
    return boto3.client(svc, endpoint_url=url, region_name=region, aws_access_key_id=k[0], aws_secret_access_key=k[1], config=cfg)
def code(f):
    try:
        f()
        return "ok"
    except ClientError as e:
        return e.response["Error"]["Code"]
def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))
def owners_of(x):
    out = {}
    for r in ET.fromstring(x).findall("{DAV:}response"):
        n, o = r.find(".//{DAV:}displayname"), r.find(".//{urn:socketley:storage}owner")
        if n is not None and n.text and o is not None:
            out[n.text] = o.text
    return out
def http(method, path, key=None, cookie=None, body=None, ui=False):
    h = {}
    if key:
        h["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % key).encode()).decode()
    if cookie:
        h["Cookie"] = cookie
    if ui:
        h["X-Socketley-UI"] = "1"
    if method == "PROPFIND":
        h["Depth"] = "1"
    data = json.dumps(body).encode() if isinstance(body, dict) else body
    if data is not None:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read().decode(), r.headers.get("Set-Cookie", "")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), ""

root_s3, jonas_s3 = mk("s3", ROOT), mk("s3", JONAS)
root_s3.create_bucket(Bucket="rootlib")
jonas_s3.create_bucket(Bucket="jonaslib")

# ── whose a library is ──
st, x, _ = http("PROPFIND", "/~dav/", key=ROOT)
owners = owners_of(x)
check("the root listing names each library's owner", (st, owners.get("rootlib"), owners.get("jonaslib")), (207, "root", "jonas"))
st, x, _ = http("PROPFIND", "/~dav/", key=JONAS)
check("a user is listed its own and not another's", ("jonaslib" in x, "rootlib" in x), (True, False))

# ── a library deleted with what it holds ──
root_s3.create_bucket(Bucket="purge-me")
root_s3.put_bucket_versioning(Bucket="purge-me", VersioningConfiguration={"Status": "Enabled"})
for body in (b"one", b"two"):
    root_s3.put_object(Bucket="purge-me", Key="a/film.mp4", Body=body)
root_s3.put_object(Bucket="purge-me", Key="b.txt", Body=b"b")
root_s3.delete_object(Bucket="purge-me", Key="b.txt")
st, body, _ = http("DELETE", "/~dav/purge-me/", key=ROOT)
check("deleting a library that holds files is refused, and says why", (st, "delete it with its contents" in body), (409, True))
st, _, _ = http("DELETE", "/~dav/rootlib/?contents", key=JONAS)
check("another user's library is not deleted with its contents", st, 403)
check("and is still there", code(lambda: root_s3.head_bucket(Bucket="rootlib")), "ok")
st, body, _ = http("DELETE", "/~dav/purge-me/?contents", key=ROOT)
check("with ?contents every version goes and the library with it", (st, body), (204, ""))
check("the library is gone", code(lambda: root_s3.head_bucket(Bucket="purge-me")), "404")

# ── keys for a user of the credentials file ──
jonas_iam = mk("iam", JONAS, region="")
st = code(lambda: jonas_iam.list_access_keys())
check("a user of the credentials file lists the keys of its own", st, "ok")
made = jonas_iam.create_access_key()["AccessKey"]
check("and makes one", made["UserName"], "jonas")
time.sleep(0.3)
extra = (made["AccessKeyId"], made["SecretAccessKey"])
check("which signs as that user", code(lambda: mk("s3", extra).create_bucket(Bucket="made-with-new-key")), "ok")
st, x, _ = http("PROPFIND", "/~dav/", key=ROOT)
owners = owners_of(x)
check("and what it makes is that user's", owners.get("made-with-new-key"), "jonas")
jonas_iam.create_access_key()
check("two keys is the most", code(lambda: jonas_iam.create_access_key()), "LimitExceeded")
check("the credentials file's own key still signs", code(lambda: jonas_s3.list_buckets()), "ok")

# ── the library a user's repositories go to ──
st, _, sc = http("POST", "/~ui/session", key=JONAS, ui=True)
jc = sc.split(";")[0] if sc else None
st, body, _ = http("POST", "/~ui/git", cookie=jc, ui=True, body={"action": "add", "url": "https://example.invalid/tools.git"})
check("a repository is added without a library named", st, 200)
st, body, _ = http("GET", "/~ui/git", cookie=jc, ui=True)
buckets = re.findall(r'"bucket":"([^"]*)"', body)
check("and goes to a library of the user's own", buckets, ["git-jonas"])

# ── who sees other people's libraries ──
def sees(cookie):
    st, body, _ = http("GET", "/~ui/session", cookie=cookie, ui=True)
    return json.loads(body).get("show_others") if st == 200 else st
st, _, sc = http("POST", "/~ui/session", key=ROOT, ui=True)
rc = sc.split(";")[0] if sc else None
check("nobody sees other people's libraries until it is turned on", (sees(jc), sees(rc)), (False, False))
st, _, _ = http("POST", "/~ui/notifications", cookie=jc, ui=True, body={"action": "settings", "user": "root", "show_others": True})
check("a user who is no admin does not turn it on for another", (st, sees(rc)), (403, False))
st, _, _ = http("POST", "/~ui/notifications", cookie=rc, ui=True, body={"action": "settings", "user": "jonas", "show_others": True})
check("an admin turns it on for a user", (st, sees(jc)), (204, True))
st, body, _ = http("GET", "/~ui/users", cookie=rc, ui=True)
check("and sees it in the list of users", [u.get("show_others") for u in json.loads(body)["users"] if u["id"] == "jonas"], [True])
st, _, _ = http("POST", "/~ui/notifications", cookie=jc, ui=True, body={"action": "settings", "show_others": False})
check("and the user turns it off again", (st, sees(jc)), (204, False))
st, _, _ = http("POST", "/~ui/notifications", cookie=rc, ui=True, body={"action": "settings", "user": "nobody", "show_others": True})
check("a user that is none is refused", st, 404)

# ── a library shared with a user ──
st, body, _ = http("POST", "/~ui/access", cookie=rc, ui=True, body={"bucket": "rootlib", "user": "jonas", "access": "read"})
check("a library is shared with a user to view", st, 204)
st, x, _ = http("PROPFIND", "/~dav/", key=JONAS)
check("and the user is listed it, as the owner's", owners_of(x).get("rootlib"), "root")

# ── the page ──
st, page, _ = http("GET", "/~ui/", key=ROOT)
check("the logo leads home", ('id="homeLogo"' in page, "$('#homeLogo').onclick" in page), (True, True))
check("a library has a menu of its own", ("function libActions(" in page, "function deleteLibrary(" in page), (True, True))
PY
PY_RC=$?
tally < "$SOCKETLEY_TMPD/out"
[ "$PY_RC" -eq 0 ] || bad "the checks ran to their end" "python exited $PY_RC"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
