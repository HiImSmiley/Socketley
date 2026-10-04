#!/usr/bin/env bash
# Integration test: a bucket's public access block (?publicAccessBlock)
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# BlockPublicPolicy refuses a bucket policy that lets anyone in, and
# RestrictPublicBuckets keeps a public policy already there from letting in a
# request with no credentials, the website's included, while the runtime's
# users keep what their credentials give them.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a configuration S3 refuses taken, or one taken and not read back
#   * a public policy set past BlockPublicPolicy, or a policy naming a user
#     refused by it
#   * a request with no credentials, or the website, let in by a public policy
#     past RestrictPublicBuckets, or a signed request refused by it
#   * a block lost by a restart, kept after DELETE, or set by a user who may not
# suite: isolated
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: public access block ==="
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }
tally() { while IFS= read -r line; do case "$line" in ok\ *) ok ;; bad\ *) bad "${line#bad }" "" ;; *) echo "  $line" ;; esac; done; }

daemon_isolate stgpab
trap 'daemon_stop' EXIT
daemon_start "$BIN"
P1=$((SL_PORT_BASE + 1898))
U="http://127.0.0.1:$P1"
CREDS="$SOCKETLEY_TMPD/creds"
cat > "$CREDS" <<EOF
AKIAPABADMIN00000000:pabadminsecretpabadminsecretpabadmin0000
[bob]
AKIAPABBOB0000000000:pabbobsecretpabbobsecretpabbobsecret00000
EOF
"$BIN" create storage pab -p "$P1" --dir "$SOCKETLEY_TMPD/pab" --credentials "$CREDS" --shards 2 \
    --website-domain web.test -s >/dev/null 2>&1
up() { for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/")" != 000 ] && return 0; sleep 0.1; done; return 1; }
up || bad "the runtime serves" "no answer on $P1"

# One Python step per phase, each line "ok NAME" or "bad NAME: DETAIL".
step() {
    python3 - "$P1" "$1" "$HERE" > "$SOCKETLEY_TMPD/step" 2>&1 <<'PY'
import sys, json
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
port, phase = sys.argv[1], sys.argv[2]
cfg = Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"max_attempts": 1})
def s3(keys, checked=True):
    return boto3.client("s3", endpoint_url="http://127.0.0.1:%s" % port, region_name="us-east-1",
                        aws_access_key_id=keys[0], aws_secret_access_key=keys[1],
                        config=cfg if checked else cfg.merge(Config(parameter_validation=False)))
ADMIN = s3(("AKIAPABADMIN00000000", "pabadminsecretpabadminsecretpabadmin0000"))
BOB = s3(("AKIAPABBOB0000000000", "pabbobsecretpabbobsecretpabbobsecret00000"))
def code_of(fn):
    try:
        fn()
        return "ok"
    except ClientError as e:
        return e.response["Error"]["Code"]
def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))
PUBLIC = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*",
                     "Action": "s3:GetObject", "Resource": "arn:aws:s3:::pub/*"}]})
BOBS = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "bob"},
                   "Action": "s3:GetObject", "Resource": "arn:aws:s3:::pub/*"}]})
ALL = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
if phase == "setup":
    ADMIN.create_bucket(Bucket="pub")
    ADMIN.put_object(Bucket="pub", Key="index.html", Body=b"hello")
    ADMIN.put_bucket_website(Bucket="pub", WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}})
    check("a bucket without a block answers NoSuchPublicAccessBlockConfiguration",
          code_of(lambda: ADMIN.get_public_access_block(Bucket="pub")), "NoSuchPublicAccessBlockConfiguration")
    import http.client
    sys.path.insert(0, sys.argv[3])
    import lib_s3_signing as sig
    def raw_put(body):
        s = sig.sign("PUT", "/pub", "publicAccessBlock", "127.0.0.1:%s" % port, "AKIAPABADMIN00000000",
                     "pabadminsecretpabadminsecretpabadmin0000", sig.sha256hex(body))
        c = http.client.HTTPConnection("127.0.0.1", int(port))
        c.request("PUT", "/pub?publicAccessBlock", body=body, headers=s.headers)
        r = c.getresponse(); data = r.read(); c.close()
        return r.status, b"<Code>MalformedXML</Code>" in data
    check("a document that is no block is MalformedXML", raw_put(b"<X/>"), (400, True))
    check("and so is a flag that is not true or false", raw_put(
          b"<PublicAccessBlockConfiguration><BlockPublicPolicy>yes</BlockPublicPolicy></PublicAccessBlockConfiguration>"), (400, True))
    check("a block is set", code_of(lambda: ADMIN.put_public_access_block(Bucket="pub",
          PublicAccessBlockConfiguration={"BlockPublicPolicy": True})), "ok")
    got = ADMIN.get_public_access_block(Bucket="pub")["PublicAccessBlockConfiguration"]
    check("and read back, what was left out false", got,
          {"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": True, "RestrictPublicBuckets": False})
    check("a public policy is refused", code_of(lambda: ADMIN.put_bucket_policy(Bucket="pub", Policy=PUBLIC)), "AccessDenied")
    check("one naming a user is not", code_of(lambda: ADMIN.put_bucket_policy(Bucket="pub", Policy=BOBS)), "ok")
    check("bob reads by it", BOB.get_object(Bucket="pub", Key="index.html")["Body"].read(), b"hello")
    check("a user who does not own the bucket may not lift the block",
          code_of(lambda: BOB.delete_public_access_block(Bucket="pub")), "AccessDenied")
    check("its owner may", code_of(lambda: ADMIN.delete_public_access_block(Bucket="pub")), "ok")
    check("after which there is none", code_of(lambda: ADMIN.get_public_access_block(Bucket="pub")),
          "NoSuchPublicAccessBlockConfiguration")
    check("and a public policy is taken", code_of(lambda: ADMIN.put_bucket_policy(Bucket="pub", Policy=PUBLIC)), "ok")
elif phase == "restrict":
    check("every setting is taken", code_of(lambda: ADMIN.put_public_access_block(Bucket="pub",
          PublicAccessBlockConfiguration=ALL)), "ok")
elif phase == "signed":
    check("a signed read is not restricted", ADMIN.get_object(Bucket="pub", Key="index.html")["Body"].read(), b"hello")
    check("nor bob's, whom the policy lets in by Principal *",
          code_of(lambda: BOB.get_object(Bucket="pub", Key="index.html")), "ok")
    check("the block outlives a restart", ADMIN.get_public_access_block(Bucket="pub")["PublicAccessBlockConfiguration"], ALL)
elif phase == "lift":
    check("lifting it lets the public in again", code_of(lambda: ADMIN.delete_public_access_block(Bucket="pub")), "ok")
PY
    local rc=$?; tally < "$SOCKETLEY_TMPD/step"; check "the $1 step ran to its end" "$rc" 0
}

step setup
check "with no block a public policy lets anyone read" "$(curl -s "$U/pub/index.html")" hello
check "and the website" "$(curl -s -H "Host: pub.web.test:$P1" "http://127.0.0.1:$P1/")" hello
step restrict
check "RestrictPublicBuckets keeps out a request with no credentials" "$(curl -s -o /dev/null -w '%{http_code}' "$U/pub/index.html")" 403
check "and the website" "$(curl -s -o /dev/null -w '%{http_code}' -H "Host: pub.web.test:$P1" "http://127.0.0.1:$P1/")" 403
"$BIN" stop pab >/dev/null 2>&1; "$BIN" start pab >/dev/null 2>&1; up
check "still after a restart" "$(curl -s -o /dev/null -w '%{http_code}' "$U/pub/index.html")" 403
step signed
step lift
check "and anyone reads again" "$(curl -s "$U/pub/index.html")" hello
check "an object has no block" "$(curl -s -o /dev/null -w '%{http_code}' "$U/pub/index.html?publicAccessBlock")" 501

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
