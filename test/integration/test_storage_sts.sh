#!/usr/bin/env bash
# Integration test: STS temporary credentials (GetSessionToken, AssumeRole)
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# POST / with an STS form gives a user temporary credentials: a key, a secret
# and a session token sealed with the user's own secret, which every shard and
# every restart checks with nothing kept, which end when they expire or the
# user's key is taken away, and which an AssumeRole policy bounds further.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * an STS request taken without a signature, or a session that cannot ask
#     for more refused nothing
#   * temporary credentials that do not sign for their user, or that sign
#     beyond what the user may do
#   * a token taken that its user's secret did not seal, for another key, or
#     past its expiry
#   * a session policy that does not bound the session
#   * a session lost by a restart, or kept past its user's key being removed
#   * a presigned URL with a session token not served
#   * a duration or a policy STS refuses taken
# suite: isolated
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: STS temporary credentials ==="
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }
# Counts what a Python step printed: "ok NAME" or "bad NAME: DETAIL" per line, and shows anything else.
. "$HERE/lib_verdicts.sh"

daemon_isolate stgsts
trap 'daemon_stop' EXIT
daemon_start "$BIN"
P1=$((SL_PORT_BASE + 1897))
U="http://127.0.0.1:$P1"
CREDS="$SOCKETLEY_TMPD/creds"
write_creds() {
    cat > "$CREDS" <<EOF
AKIASTSADMIN00000000:stsadminsecretstsadminsecretstsadmin0000
$1
EOF
}
write_creds '[bob]
AKIASTSBOB0000000000:stsbobsecretstsbobsecretstsbobsecret00000'
"$BIN" create storage sts -p "$P1" --dir "$SOCKETLEY_TMPD/sts" --credentials "$CREDS" --shards 2 -s >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/")" != 000 ] && break; sleep 0.1; done

check "an STS request without a signature is refused" \
    "$(curl -s -X POST "$U/" --data 'Action=GetSessionToken&Version=2011-06-15' | grep -c '<Code>MissingAuthenticationToken</Code>')" 1

STATE="$SOCKETLEY_TMPD/session.json"
python3 - "$P1" "$STATE" > "$SOCKETLEY_TMPD/step1" 2>&1 <<'PY'
import sys, json, base64, hmac, hashlib, struct, time, urllib.request
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
port, state = sys.argv[1], sys.argv[2]
url = "http://127.0.0.1:%s" % port
cfg = Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"max_attempts": 1})
ADMIN = ("AKIASTSADMIN00000000", "stsadminsecretstsadminsecretstsadmin0000")
BOB = ("AKIASTSBOB0000000000", "stsbobsecretstsbobsecretstsbobsecret00000")
def sts(keys, token=None, checked=True):
    return boto3.client("sts", endpoint_url=url, region_name="us-east-1", aws_access_key_id=keys[0],
                        aws_secret_access_key=keys[1], aws_session_token=token,
                        config=cfg if checked else cfg.merge(Config(parameter_validation=False)))
def s3(keys, token=None):
    return boto3.client("s3", endpoint_url=url, region_name="us-east-1", aws_access_key_id=keys[0],
                        aws_secret_access_key=keys[1], aws_session_token=token, config=cfg)
def check(name, cond, detail=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + str(detail)))
def code_of(fn):
    try:
        fn()
        return "ok"
    except ClientError as e:
        return e.response["Error"]["Code"]

s3(ADMIN).create_bucket(Bucket="adminb")
s3(ADMIN).put_object(Bucket="adminb", Key="k", Body=b"admin-object")

# GetSessionToken
c = sts(ADMIN).get_session_token()["Credentials"]
check("GetSessionToken gives an ASIA key", c["AccessKeyId"].startswith("ASIA") and len(c["AccessKeyId"]) == 20, c["AccessKeyId"])
left = c["Expiration"].timestamp() - time.time()
check("for twelve hours by default", 43000 < left < 43300, left)
sess = (c["AccessKeyId"], c["SecretAccessKey"])
tok = c["SessionToken"]
check("the session reads as its user", s3(sess, tok).get_object(Bucket="adminb", Key="k")["Body"].read() == b"admin-object")
s3(sess, tok).create_bucket(Bucket="sessb")
s3(sess, tok).put_object(Bucket="sessb", Key="x", Body=b"by-session")
check("and writes as its user", s3(ADMIN).get_object(Bucket="sessb", Key="x")["Body"].read() == b"by-session")
ok_all = all(s3(sess, tok).head_object(Bucket="sessb", Key="x")["ContentLength"] == 10 for _ in range(8))
check("on whichever shard answers", ok_all)
check("a session may not ask for another", code_of(lambda: sts(sess, tok).get_session_token()) == "AccessDenied")
check("a session key without its token is unknown", code_of(lambda: s3(sess).list_buckets()) == "InvalidAccessKeyId")
check("a token with a byte changed is refused",
      code_of(lambda: s3(sess, tok[:-6] + ("A" if tok[-6] != "A" else "B") + tok[-5:]).list_buckets()) == "InvalidToken")
c2 = sts(ADMIN).get_session_token(DurationSeconds=900)["Credentials"]
check("a token is for its own key alone", code_of(lambda: s3((c2["AccessKeyId"], c2["SecretAccessKey"]), tok).list_buckets()) == "InvalidToken")
check("DurationSeconds is taken", 800 < c2["Expiration"].timestamp() - time.time() < 1000)
check("one under 900 is refused", code_of(lambda: sts(ADMIN, checked=False).get_session_token(DurationSeconds=60)) == "ValidationError")

# A token sealed for an expiry already past, by the user's own secret, as the runtime seals one.
def seal(parent, secret, akid, expires, policy=b""):
    p = bytes([1]) + struct.pack(">Q", expires) + bytes([len(parent)]) + parent.encode() + bytes([len(akid)]) + akid.encode()
    p += struct.pack(">H", len(policy)) + policy
    mac = hmac.new(secret.encode(), b"token\0" + p, hashlib.sha256).digest()
    sec = base64.urlsafe_b64encode(hmac.new(secret.encode(), b"secret\0" + p, hashlib.sha256).digest()).decode().rstrip("=")[:40]
    return base64.urlsafe_b64encode(p + mac).decode().rstrip("="), sec
t_live, s_live = seal(ADMIN[0], ADMIN[1], "ASIAAAAAAAAAAAAAAAAA", int(time.time()) + 600)
check("a token sealed as the runtime seals one is taken", code_of(lambda: s3(("ASIAAAAAAAAAAAAAAAAA", s_live), t_live).list_buckets()) == "ok")
t_old, s_old = seal(ADMIN[0], ADMIN[1], "ASIAAAAAAAAAAAAAAAAA", int(time.time()) - 5)
check("one past its expiry is ExpiredToken", code_of(lambda: s3(("ASIAAAAAAAAAAAAAAAAA", s_old), t_old).list_buckets()) == "ExpiredToken")
t_bad, s_bad = seal(ADMIN[0], "not-the-secret", "ASIAAAAAAAAAAAAAAAAA", int(time.time()) + 600)
check("one sealed with another secret is refused", code_of(lambda: s3(("ASIAAAAAAAAAAAAAAAAA", s_bad), t_bad).list_buckets()) == "InvalidToken")

# AssumeRole with a policy
pol = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                  "Resource": "arn:aws:s3:::adminb/*"}]})
check("a role no one made is NoSuchEntity, not the caller's own session",
      code_of(lambda: sts(ADMIN).assume_role(RoleArn="arn:aws:iam::000000000000:role/reader", RoleSessionName="reader-1",
                                             Policy=pol)) == "NoSuchEntity")
iam = boto3.client("iam", endpoint_url=url, region_name="us-east-1", aws_access_key_id=ADMIN[0],
                   aws_secret_access_key=ADMIN[1], config=cfg)
iam.create_role(RoleName="reader", AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}))
iam.put_role_policy(RoleName="reader", PolicyName="all", PolicyDocument=json.dumps({"Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}))
time.sleep(0.3)
r = sts(ADMIN).assume_role(RoleArn="arn:aws:iam::000000000000:role/reader", RoleSessionName="reader-1", Policy=pol)
rc = r["Credentials"]
rs, rt = (rc["AccessKeyId"], rc["SecretAccessKey"]), rc["SessionToken"]
check("AssumeRole names the session", r["AssumedRoleUser"]["Arn"].endswith("role/reader/reader-1"), r["AssumedRoleUser"])
check("for an hour by default", 3500 < rc["Expiration"].timestamp() - time.time() < 3700)
check("its policy lets it read what it names", s3(rs, rt).get_object(Bucket="adminb", Key="k")["Body"].read() == b"admin-object")
check("and nothing else, though its user may",
      code_of(lambda: s3(rs, rt).put_object(Bucket="adminb", Key="w", Body=b"x")) == "AccessDenied")
check("nor another bucket", code_of(lambda: s3(rs, rt).get_object(Bucket="sessb", Key="x")) == "AccessDenied")
check("nor a new bucket", code_of(lambda: s3(rs, rt).create_bucket(Bucket="rolebucket")) == "AccessDenied")
check("nor a bucket's policy, though its user is an admin",
      code_of(lambda: s3(rs, rt).get_bucket_policy(Bucket="adminb")) == "AccessDenied")
check("a policy that does not compile is refused",
      code_of(lambda: sts(ADMIN, checked=False).assume_role(RoleArn="arn:aws:iam::000000000000:role/reader", RoleSessionName="ab", Policy="{not json")) == "MalformedPolicyDocument")
check("AssumeRole longer than twelve hours is refused",
      code_of(lambda: sts(ADMIN, checked=False).assume_role(RoleArn="arn:x", RoleSessionName="ab", DurationSeconds=50000)) == "ValidationError")

# A user who is no admin
b = sts(BOB).get_session_token()["Credentials"]
bs, bt = (b["AccessKeyId"], b["SecretAccessKey"]), b["SessionToken"]
s3(bs, bt).create_bucket(Bucket="bobb")
check("bob's session owns what it makes", code_of(lambda: s3(bs, bt).put_object(Bucket="bobb", Key="y", Body=b"y")) == "ok")
check("and may not read an admin's bucket", code_of(lambda: s3(bs, bt).get_object(Bucket="adminb", Key="k")) == "AccessDenied")

# A presigned URL with a session token
link = s3(sess, tok).generate_presigned_url("get_object", Params={"Bucket": "adminb", "Key": "k"}, ExpiresIn=300)
check("a presigned URL carries the token", "X-Amz-Security-Token=" in link)
check("and is served", urllib.request.urlopen(link).read() == b"admin-object")

json.dump({"sess": list(sess), "tok": tok, "bob": list(bs), "bobtok": bt}, open(state, "w"))
PY
rc=$?; tally < "$SOCKETLEY_TMPD/step1"; check "the first step ran to its end" "$rc" 0

"$BIN" stop sts >/dev/null 2>&1; "$BIN" start sts >/dev/null 2>&1
for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/")" != 000 ] && break; sleep 0.1; done
# The credentials file is read again when it changes, so bob's key goes and the admin's stays.
sleep 1.1
write_creds ''
sleep 1.2

python3 - "$P1" "$STATE" > "$SOCKETLEY_TMPD/step2" 2>&1 <<'PY'
import sys, json
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
port, state = sys.argv[1], sys.argv[2]
st = json.load(open(state))
cfg = Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"max_attempts": 1})
def s3(keys, token):
    return boto3.client("s3", endpoint_url="http://127.0.0.1:%s" % port, region_name="us-east-1",
                        aws_access_key_id=keys[0], aws_secret_access_key=keys[1], aws_session_token=token, config=cfg)
def code_of(fn):
    try:
        fn()
        return "ok"
    except ClientError as e:
        return e.response["Error"]["Code"]
def check(name, cond, detail=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + str(detail)))
c = code_of(lambda: s3(st["sess"], st["tok"]).list_buckets())
check("a session outlives a restart", c == "ok", c)
c = code_of(lambda: s3(st["bob"], st["bobtok"]).list_buckets())
check("and ends with its user's key", c == "InvalidToken", c)
PY
rc=$?; tally < "$SOCKETLEY_TMPD/step2"; check "the second step ran to its end" "$rc" 0

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
