#!/usr/bin/env bash
# Integration test: the IAM API (users, access keys, groups, roles and their policies) and STS roles
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a user, key, group or role the API made not signing or not kept, or one
#     deleted still signing
#   * a user's, group's or attached managed policy not admitting what it names,
#     or admitting more
#   * IAM callable by a user who is no admin, or by a session
#   * a role assumed by a caller its trust policy does not name, or a role's
#     session holding other rights than the role's policies
#   * a credentials-file user's IAM policy not standing beside its own
#   * GetCallerIdentity naming a user the API made by its key, or without its path
#   * any of it lost by a restart, or not seen at once by the other shard
# suite: isolated
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: the IAM API ==="
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }
. "$HERE/lib_verdicts.sh"

daemon_isolate stgiam
trap 'daemon_stop' EXIT
daemon_start "$BIN"
P1=$((SL_PORT_BASE + 1895))
U="http://127.0.0.1:$P1"
cat > "$SOCKETLEY_TMPD/creds" <<EOF
AKIAIAMADMIN00000000:iamadminsecretiamadminsecretiamadmin000
[bob]
AKIAIAMBOB0000000000:iambobsecretiambobsecretiambobsecret00000
EOF
"$BIN" create storage iam -p "$P1" --dir "$SOCKETLEY_TMPD/iam" --credentials "$SOCKETLEY_TMPD/creds" --shards 2 -s >/dev/null 2>&1
up() { for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/")" != 000 ] && return 0; sleep 0.1; done; return 1; }
up || bad "the runtime serves" "no answer on $P1"
STATE="$SOCKETLEY_TMPD/state.json"

step() {
    python3 - "$P1" "$1" "$STATE" > "$SOCKETLEY_TMPD/step" 2>&1 <<'PY'
import sys, json, time
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
port, phase, state = sys.argv[1], sys.argv[2], sys.argv[3]
url = "http://127.0.0.1:%s" % port
cfg = Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1})
ADMIN = ("AKIAIAMADMIN00000000", "iamadminsecretiamadminsecretiamadmin000")
BOB = ("AKIAIAMBOB0000000000", "iambobsecretiambobsecretiambobsecret00000")
def mk(svc, k, t=None, region="us-east-1"):
    return boto3.client(svc, endpoint_url=url, region_name=region, aws_access_key_id=k[0], aws_secret_access_key=k[1],
                        aws_session_token=t, config=cfg)
def code(f):
    try:
        f()
        return "ok"
    except ClientError as e:
        return e.response["Error"]["Code"]
def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))
def settle():
    # Another shard takes an IAM change within 50 ms, as IAM's own changes reach every endpoint eventually.
    time.sleep(0.15)
def doc(effect, actions, resources):
    return json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": effect, "Action": actions, "Resource": resources}]})
# The IAM client signs for no region, as boto3's does for a global service it is given none for.
iam, s3 = mk("iam", ADMIN, region=""), mk("s3", ADMIN)

if phase == "main":
    s3.create_bucket(Bucket="data")
    s3.put_object(Bucket="data", Key="a", Body=b"alpha")
    u = iam.create_user(UserName="alice")["User"]
    check("CreateUser names the user", (u["UserName"], u["Arn"]), ("alice", "arn:aws:iam:::user/alice"))
    check("a second of the name is EntityAlreadyExists", code(lambda: iam.create_user(UserName="alice")), "EntityAlreadyExists")
    check("and one of a credentials-file user's", code(lambda: iam.create_user(UserName="bob")), "EntityAlreadyExists")
    k = iam.create_access_key(UserName="alice")["AccessKey"]
    alice = (k["AccessKeyId"], k["SecretAccessKey"])
    a3 = mk("s3", alice)
    check("a key the API made signs, on either shard", [code(lambda: a3.list_buckets()) for _ in range(6)], ["ok"] * 6)
    check("a user with no policy reads no bucket it does not own", code(lambda: a3.get_object(Bucket="data", Key="a")), "AccessDenied")
    iam.put_user_policy(UserName="alice", PolicyName="read", PolicyDocument=doc("Allow", "s3:GetObject", "arn:aws:s3:::data/*"))
    settle()
    check("an inline policy admits what it names", code(lambda: a3.get_object(Bucket="data", Key="a")), "ok")
    check("and nothing else", code(lambda: a3.put_object(Bucket="data", Key="b", Body=b"x")), "AccessDenied")
    check("a policy that does not compile is MalformedPolicyDocument",
          code(lambda: iam.put_user_policy(UserName="alice", PolicyName="bad", PolicyDocument="{nope")), "MalformedPolicyDocument")
    check("GetUserPolicy reads it back", json.loads(json.dumps(iam.get_user_policy(UserName="alice", PolicyName="read")["PolicyDocument"]))["Statement"][0]["Action"], "s3:GetObject")
    check("a user who is no admin may not call IAM", code(lambda: mk("iam", alice, region="").list_users()), "AccessDenied")
    iam.put_user_policy(UserName="alice", PolicyName="nolist", PolicyDocument=doc("Deny", "s3:ListAllMyBuckets", "*"))
    settle()
    check("a Deny of s3:ListAllMyBuckets refuses ListBuckets, on either shard",
          [code(lambda: a3.list_buckets()) for _ in range(6)], ["AccessDenied"] * 6)
    iam.delete_user_policy(UserName="alice", PolicyName="nolist")
    settle()
    check("and without it the user lists its buckets again", [code(lambda: a3.list_buckets()) for _ in range(6)], ["ok"] * 6)
    # Groups and managed policies.
    iam.create_group(GroupName="writers")
    iam.put_group_policy(GroupName="writers", PolicyName="w", PolicyDocument=doc("Allow", "s3:PutObject", "arn:aws:s3:::data/*"))
    iam.add_user_to_group(UserName="alice", GroupName="writers")
    settle()
    check("a group's policy is its members'", code(lambda: a3.put_object(Bucket="data", Key="g", Body=b"g")), "ok")
    iam.create_user(UserName="carol")
    ck = iam.create_access_key(UserName="carol")["AccessKey"]
    c3 = mk("s3", (ck["AccessKeyId"], ck["SecretAccessKey"]))
    iam.attach_user_policy(UserName="carol", PolicyArn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")
    settle()
    check("an attached AWS managed policy admits reads", code(lambda: c3.get_object(Bucket="data", Key="a")), "ok")
    check("and no writes", code(lambda: c3.put_object(Bucket="data", Key="c", Body=b"c")), "AccessDenied")
    check("an unknown managed policy is NoSuchEntity",
          code(lambda: iam.attach_user_policy(UserName="carol", PolicyArn="arn:aws:iam::aws:policy/Nope")), "NoSuchEntity")
    # A credentials-file user's IAM policy stands beside its own.
    iam.put_user_policy(UserName="bob", PolicyName="r", PolicyDocument=doc("Allow", "s3:GetObject", "arn:aws:s3:::data/*"))
    settle()
    check("a credentials-file user is given an IAM policy", code(lambda: mk("s3", BOB).get_object(Bucket="data", Key="a")), "ok")
    check("and is not listed as an IAM user", sorted(x["UserName"] for x in iam.list_users()["Users"]), ["alice", "carol"])
    # Roles.
    trust = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam:::user/alice"},
                                                                "Action": "sts:AssumeRole"}]})
    role = iam.create_role(RoleName="cleaner", AssumeRolePolicyDocument=trust)["Role"]
    iam.put_role_policy(RoleName="cleaner", PolicyName="d", PolicyDocument=doc("Allow", "s3:DeleteObject", "arn:aws:s3:::data/*"))
    settle()
    check("a role its trust policy does not name the caller in is refused",
          code(lambda: mk("sts", ADMIN).assume_role(RoleArn=role["Arn"], RoleSessionName="x1")), "AccessDenied")
    cr = mk("sts", alice).assume_role(RoleArn=role["Arn"], RoleSessionName="alice-cleans")["Credentials"]
    r3 = mk("s3", (cr["AccessKeyId"], cr["SecretAccessKey"]), cr["SessionToken"])
    check("the role's session holds the role's policy", code(lambda: r3.delete_object(Bucket="data", Key="g")), "ok")
    check("and not the caller's", code(lambda: r3.get_object(Bucket="data", Key="a")), "AccessDenied")
    ident = mk("sts", (cr["AccessKeyId"], cr["SecretAccessKey"]), cr["SessionToken"]).get_caller_identity()
    check("GetCallerIdentity names the assumed role", ident["Arn"], "arn:aws:sts:::assumed-role/cleaner")
    # A Deny with a condition this runtime does not weigh is read as holding: skipped, it let in whom it kept out.
    guarded = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam:::user/alice"}, "Action": "sts:AssumeRole"},
        {"Effect": "Deny", "Principal": {"AWS": "arn:aws:iam:::user/alice"}, "Action": "sts:AssumeRole",
         "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}}]})
    grole = iam.create_role(RoleName="guarded", AssumeRolePolicyDocument=guarded)["Role"]
    settle()
    check("a trust policy's Deny under a condition refuses as if it held",
          code(lambda: mk("sts", alice).assume_role(RoleArn=grole["Arn"], RoleSessionName="g1")), "AccessDenied")
    d = iam.create_user(UserName="dave", Path="/team/")["User"]
    dk = iam.create_access_key(UserName="dave")["AccessKey"]
    settle()
    ident = mk("sts", (dk["AccessKeyId"], dk["SecretAccessKey"])).get_caller_identity()
    check("GetCallerIdentity names a user the API made by its UserId and its ARN with the path",
          (ident["UserId"], ident["Arn"]), (d["UserId"], "arn:aws:iam:::user/team/dave"))
    iam.delete_access_key(UserName="dave", AccessKeyId=dk["AccessKeyId"])
    iam.delete_user(UserName="dave")
    check("a role session makes no bucket its policies do not allow", code(lambda: r3.create_bucket(Bucket="role-made")),
          "AccessDenied")
    check("nor does a user the API made with no policy that allows it", code(lambda: a3.create_bucket(Bucket="alice-made")),
          "AccessDenied")
    iam.put_user_policy(UserName="alice", PolicyName="mk", PolicyDocument=doc("Allow", "s3:CreateBucket", "*"))
    settle()
    check("which it makes once one does", code(lambda: a3.create_bucket(Bucket="alice-made")), "ok")
    iam.delete_user_policy(UserName="alice", PolicyName="mk")
    s3.delete_bucket(Bucket="alice-made")
    check("a role session may not call IAM",
          code(lambda: mk("iam", (cr["AccessKeyId"], cr["SecretAccessKey"]), cr["SessionToken"], region="").list_users()), "AccessDenied")
    json.dump({"alice": list(alice), "carol": [ck["AccessKeyId"], ck["SecretAccessKey"]], "role": cr}, open(state, "w"), default=str)
elif phase == "after":
    st = json.load(open(state))
    alice = tuple(st["alice"])
    a3 = mk("s3", alice)
    check("users, keys and policies outlive a restart", code(lambda: a3.get_object(Bucket="data", Key="a")), "ok")
    check("and groups", code(lambda: a3.put_object(Bucket="data", Key="g2", Body=b"g")), "ok")
    cr = st["role"]
    r3 = mk("s3", (cr["AccessKeyId"], cr["SecretAccessKey"]), cr["SessionToken"])
    check("and a role's session", code(lambda: r3.delete_object(Bucket="data", Key="g2")), "ok")
    check("a user with a key is DeleteConflict", code(lambda: iam.delete_user(UserName="alice")), "DeleteConflict")
    iam.delete_access_key(UserName="alice", AccessKeyId=alice[0])
    settle()
    check("a deleted key no longer signs, on either shard", [code(lambda: a3.list_buckets()) for _ in range(6)],
          ["InvalidAccessKeyId"] * 6)
    iam.delete_user_policy(UserName="alice", PolicyName="read")
    iam.remove_user_from_group(UserName="alice", GroupName="writers")
    check("a user with nothing left is deleted", code(lambda: iam.delete_user(UserName="alice")), "ok")
    iam.delete_role_policy(RoleName="cleaner", PolicyName="d")
    iam.delete_role(RoleName="cleaner")
    settle()
    check("a session of a deleted role no longer signs", code(lambda: r3.list_buckets()), "InvalidToken")
PY
    local rc=$?; tally < "$SOCKETLEY_TMPD/step"; check "the $1 step ran to its end" "$rc" 0
}

step main
"$BIN" stop iam >/dev/null 2>&1; "$BIN" start iam >/dev/null 2>&1; up
step after

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
