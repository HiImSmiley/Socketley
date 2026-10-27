#!/usr/bin/env bash
# Integration test: delegated IAM -- a user who is no admin calls the IAM actions its own policies allow
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * an iam: Allow not letting its holder call the action, or letting it call
#     the action on a resource the policy does not name
#   * ${aws:username} not read as the caller, or read as a prefix
#   * a key named by id alone judged as the caller's rather than its owner's,
#     which would let a delegate delete anybody's key
#   * an iam:List* wildcard not covering the List actions, or an explicit Deny
#     not winning over it
#   * a request with no UserName not acting on its caller, as IAM's does
#   * a delegate giving itself or anybody else IAM rights, by a policy, an
#     attached AdministratorAccess or a group
#   * an admin's own Deny of iam:* taking IAM from the admin
#   * a credentials-file user's file policy or IAM policy not delegating
#   * a session calling IAM, whatever its user's policies allow
#   * the refusal not in IAM's XML error format
# suite: isolated
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: delegated IAM ==="
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }
. "$HERE/lib_verdicts.sh"

daemon_isolate stgiamdel
trap 'daemon_stop' EXIT
daemon_start "$BIN"
P1=$((SL_PORT_BASE + 1886))
U="http://127.0.0.1:$P1"
cat > "$SOCKETLEY_TMPD/creds" <<'EOF'
AKIADELADMIN00000000:deladminsecretdeladminsecretdeladmin000
[root]
admin = true
AKIADELROOT000000000:delrootsecretdelrootsecretdelrootsecret00
[dana]
policy = {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*"}]}
AKIADELDANA000000000:deldanasecretdeldanasecretdeldanasecret00
[wide]
policy = {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
AKIADELWIDE000000000:delwidesecretdelwidesecretdelwidesecret00
EOF
"$BIN" create storage iamdel -p "$P1" --dir "$SOCKETLEY_TMPD/iamdel" --credentials "$SOCKETLEY_TMPD/creds" --shards 2 -s >/dev/null 2>&1
up() { for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/")" != 000 ] && return 0; sleep 0.1; done; return 1; }
up || bad "the runtime serves" "no answer on $P1"

python3 - "$P1" > "$SOCKETLEY_TMPD/step" 2>&1 <<'PY'
import sys, json, time
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
url = "http://127.0.0.1:%s" % sys.argv[1]
cfg = Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1})
ADMIN = ("AKIADELADMIN00000000", "deladminsecretdeladminsecretdeladmin000")
ROOT = ("AKIADELROOT000000000", "delrootsecretdelrootsecretdelrootsecret00")
DANA = ("AKIADELDANA000000000", "deldanasecretdeldanasecretdeldanasecret00")
def mk(svc, k, t=None, region="us-east-1"):
    return boto3.client(svc, endpoint_url=url, region_name=region, aws_access_key_id=k[0], aws_secret_access_key=k[1],
                        aws_session_token=t, config=cfg)
def iam_of(k, t=None):
    return mk("iam", k, t, region="")
def err(f):
    try:
        f()
        return ("ok", "")
    except ClientError as e:
        return (e.response["Error"]["Code"], e.response["Error"].get("Message", ""))
def code(f):
    return err(f)[0]
def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))
def settle():
    # Another shard takes an IAM change within 50 ms.
    time.sleep(0.15)
def doc(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": e, "Action": a, "Resource": r} for (e, a, r) in statements]})
iam = iam_of(ADMIN)

for n in ("alice", "bob"):
    iam.create_user(UserName=n)
ak = iam.create_access_key(UserName="alice")["AccessKey"]
alice = (ak["AccessKeyId"], ak["SecretAccessKey"])
bob_key = iam.create_access_key(UserName="bob")["AccessKey"]["AccessKeyId"]
settle()
ai = iam_of(alice)
check("a user with no iam: Allow may not call IAM", code(lambda: ai.list_users()), "AccessDenied")
wide = iam_of(("AKIADELWIDE000000000", "delwidesecretdelwidesecretdelwidesecret00"))
check("nor may one whose policy allows \"*\", which is S3's actions alone",
      code(lambda: wide.create_access_key(UserName="bob")), "AccessDenied")

iam.put_user_policy(UserName="alice", PolicyName="delegate", PolicyDocument=doc(
    ("Allow", ["iam:CreateAccessKey", "iam:ListAccessKeys", "iam:DeleteAccessKey", "iam:PutUserPolicy"],
     "arn:aws:iam:::user/${aws:username}"),
    ("Allow", "iam:List*", "*"),
    ("Deny", "iam:ListRoles", "*"),
    ("Allow", "iam:GetUser", "arn:aws:iam::123456789012:user/*"),
    ("Allow", ["iam:CreateUser", "iam:UpdateUser", "iam:PutUserPolicy", "iam:AttachUserPolicy"], "arn:aws:iam:::user/team/*"),
    ("Allow", "iam:AddUserToGroup", "arn:aws:iam:::group/*")))
iam.create_group(GroupName="readers")
iam.put_group_policy(GroupName="readers", PolicyName="r", PolicyDocument=doc(("Allow", "s3:GetObject", "*")))
iam.create_group(GroupName="iamers")
iam.put_group_policy(GroupName="iamers", PolicyName="i", PolicyDocument=doc(("Allow", "iam:*", "*")))
settle()

# Keys, by ${aws:username}.
k2 = code(lambda: ai.create_access_key(UserName="alice"))
check("iam:CreateAccessKey on user/${aws:username} makes the caller's own key", k2, "ok")
mine = [m["AccessKeyId"] for m in ai.list_access_keys(UserName="alice")["AccessKeyMetadata"]]
check("and lists its own keys", len(mine), 2)
check("but not another user's", code(lambda: ai.create_access_key(UserName="bob")), "AccessDenied")
check("though iam:List* on * lists them, as it covers every user", code(lambda: ai.list_access_keys(UserName="bob")), "ok")
check("a key named by id alone is judged as its owner's, so another's is refused",
      code(lambda: ai.delete_access_key(AccessKeyId=bob_key)), "AccessDenied")
check("and named for the caller it is not the caller's to delete",
      code(lambda: ai.delete_access_key(UserName="alice", AccessKeyId=bob_key)), "NoSuchEntity")
check("bob's key is still there", [m["AccessKeyId"] for m in iam.list_access_keys(UserName="bob")["AccessKeyMetadata"]], [bob_key])
spare = [k for k in mine if k != alice[0]][0]
check("a key of its own named by id alone is the caller's to delete", code(lambda: ai.delete_access_key(AccessKeyId=spare)), "ok")
nk = ai.create_access_key()["AccessKey"]
check("a request that names no user acts on the caller", nk["UserName"], "alice")
settle()
check("and the key it made signs", code(lambda: mk("s3", (nk["AccessKeyId"], nk["SecretAccessKey"])).list_buckets()), "ok")
check("GetUser with no UserName is the caller", ai.get_user()["User"]["UserName"], "alice")

# Wildcards, resources and an explicit Deny.
check("iam:List* lets the caller ListUsers, on either shard",
      [code(lambda: ai.list_users()) for _ in range(4)], ["ok"] * 4)
check("and ListGroups", sorted(g["GroupName"] for g in ai.list_groups()["Groups"]), ["iamers", "readers"])
e = err(lambda: ai.list_roles())
check("an explicit Deny wins over iam:List*", e[0], "AccessDenied")
check("and says it is one, in IAM's error", "iam:ListRoles" in e[1] and "explicit deny" in e[1], True)
check("a resource in any account names the user", ai.get_user(UserName="bob")["User"]["UserName"], "bob")
check("iam:CreateUser on user/team/* makes a user at that path", code(lambda: ai.create_user(UserName="t1", Path="/team/")), "ok")
e = err(lambda: ai.create_user(UserName="t2"))
check("and not at another", e[0], "AccessDenied")
check("naming the resource refused", "arn:aws:iam:::user/t2" in e[1], True)
check("iam:PutUserPolicy on another user is refused",
      code(lambda: ai.put_user_policy(UserName="bob", PolicyName="x", PolicyDocument=doc(("Allow", "s3:GetObject", "*")))),
      "AccessDenied")
check("a move within the resources the caller may change is made",
      code(lambda: ai.update_user(UserName="t1", NewPath="/team/x/")), "ok")
check("and a move out of them is refused, as a right over the user it makes",
      code(lambda: ai.update_user(UserName="t1", NewPath="/")), "AccessDenied")
check("as is UpdateUser of a user outside them", code(lambda: ai.update_user(UserName="bob", NewUserName="t3")), "AccessDenied")
check("and the user is where the allowed move put it", iam.get_user(UserName="t1")["User"]["Path"], "/team/x/")

# No delegate gives IAM rights.
check("a delegate puts an S3 policy on a user it may", code(lambda: ai.put_user_policy(
    UserName="t1", PolicyName="s3", PolicyDocument=doc(("Allow", "s3:GetObject", "*")))), "ok")
check("but not one that grants iam: actions", code(lambda: ai.put_user_policy(
    UserName="t1", PolicyName="up", PolicyDocument=doc(("Allow", "iam:ListUsers", "*")))), "AccessDenied")
check("nor gives itself IAM rights", code(lambda: ai.put_user_policy(
    UserName="alice", PolicyName="up", PolicyDocument=doc(("Allow", "iam:*", "*")))), "AccessDenied")
check("nor attaches AdministratorAccess", code(lambda: ai.attach_user_policy(
    UserName="t1", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")), "AccessDenied")
check("while an S3 managed policy is attached", code(lambda: ai.attach_user_policy(
    UserName="t1", PolicyArn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")), "ok")
check("a delegate adds a user to a group of S3 rights", code(lambda: ai.add_user_to_group(UserName="t1", GroupName="readers")), "ok")
check("but not to a group of IAM rights", code(lambda: ai.add_user_to_group(UserName="alice", GroupName="iamers")), "AccessDenied")
check("and alice's own policy is as the admin left it",
      sorted(iam.list_user_policies(UserName="alice")["PolicyNames"]), ["delegate"])

# A session calls no IAM, whatever its user's policies allow.
sc = mk("sts", alice).get_session_token()["Credentials"]
check("a session of a delegate may not call IAM",
      code(lambda: iam_of((sc["AccessKeyId"], sc["SecretAccessKey"]), sc["SessionToken"]).list_users()), "AccessDenied")

# Credentials-file users: the file's policy delegates, and so does the IAM API's beside it.
di = iam_of(DANA)
check("a credentials-file user's file policy delegates iam:ListUsers", code(lambda: di.list_users()), "ok")
check("and nothing it does not name", code(lambda: di.get_user(UserName="bob")), "AccessDenied")
iam.put_user_policy(UserName="dana", PolicyName="get", PolicyDocument=doc(("Allow", "iam:GetUser", "arn:aws:iam:::user/*")))
settle()
check("and its IAM policy beside the file's delegates more", code(lambda: di.get_user(UserName="bob")), "ok")
# A key of the IAM API beside the file's, which signs as that user.
dk = iam.create_access_key(UserName="dana")["AccessKey"]
settle()
check("a credentials-file user is given an IAM key, which signs as it",
      code(lambda: iam_of((dk["AccessKeyId"], dk["SecretAccessKey"])).list_users()), "ok")

# An admin keeps every right, whatever its own policies deny.
iam.put_user_policy(UserName="root", PolicyName="noiam", PolicyDocument=doc(("Deny", "iam:*", "*")))
settle()
ri = iam_of(ROOT)
check("an admin's own Deny of iam:* leaves it IAM, on either shard",
      [code(lambda: ri.list_users()) for _ in range(4)], ["ok"] * 4)
check("and it may still remove that policy", code(lambda: ri.delete_user_policy(UserName="root", PolicyName="noiam")), "ok")
check("an admin gives IAM rights", code(lambda: iam.add_user_to_group(UserName="t1", GroupName="iamers")), "ok")
tk = iam.create_access_key(UserName="t1")["AccessKey"]
settle()
check("which a user it made a member then has", code(lambda: iam_of((tk["AccessKeyId"], tk["SecretAccessKey"])).list_users()), "ok")
PY
rc=$?; tally < "$SOCKETLEY_TMPD/step"; check "the step ran to its end" "$rc" 0

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
