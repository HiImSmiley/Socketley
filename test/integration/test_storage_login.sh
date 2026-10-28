#!/usr/bin/env bash
# Integration test: users of the web interface -- login profiles, the IAM API through the interface, and invitations
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a password not signing in, a wrong one or an unknown name signing in, or
#     a weak one taken; its hash kept as the password itself
#   * a session of a password outliving a new password, or a sign-in made
#     with an old one
#   * a user changing more of itself than IAM's console lets it -- its
#     quota, its admin-ness, another user, an invitation -- or less: its own
#     password and keys without a policy
#   * a delegate of IAM rights setting an admin's password
#   * the tags the runtime reads not read: the name shown, the quota held to,
#     disabled meaning neither password nor key signs in, nor a share link reads
#   * the IAM group of admins not making an admin
#   * an invitation used twice, made by a non-admin, or not making the user
#     it says
#   * the users listed to a non-admin with more than their names
#   * a WebDAV client's Basic name and password not signing in
#   * any of it lost by a restart, or not seen at once by the other shard
# suite: isolated
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: users of the web interface ==="
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
. "$HERE/lib_verdicts.sh"

daemon_isolate stglogin
trap 'daemon_stop' EXIT
daemon_start "$BIN"
P1=$((SL_PORT_BASE + 1900))
U="http://127.0.0.1:$P1"
cat > "$SOCKETLEY_TMPD/creds" <<EOF
[root]
admin = true
AKIALOGINROOT0000000:loginrootsecretloginrootsecretloginroot0
EOF
"$BIN" create storage lg -p "$P1" --dir "$SOCKETLEY_TMPD/lg" --credentials "$SOCKETLEY_TMPD/creds" --shards 2 -s >/dev/null 2>&1
up() { for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/")" != 000 ] && return 0; sleep 0.1; done; return 1; }
up || bad "the runtime serves" "no answer on $P1"
STATE="$SOCKETLEY_TMPD/state.json"

step() {
    python3 - "$P1" "$1" "$STATE" > "$SOCKETLEY_TMPD/step" 2>&1 <<'PY'
import sys, json, time, base64, urllib.request, urllib.error, re
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
port, phase, state = sys.argv[1], sys.argv[2], sys.argv[3]
url = "http://127.0.0.1:%s" % port
cfg = Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1})
ROOT = ("AKIALOGINROOT0000000", "loginrootsecretloginrootsecretloginroot0")
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
def settle():
    time.sleep(0.15)
iam, s3 = mk("iam", ROOT, region=""), mk("s3", ROOT)

# The interface: a request and its status, body and the cookie it set.
def ui(method, path, body=None, cookie=None, basic=None, ui_header=True):
    h = {}
    if ui_header:
        h["X-Socketley-UI"] = "1"
    if cookie:
        h["Cookie"] = cookie
    if basic:
        h["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % basic).encode()).decode()
    data = json.dumps(body).encode() if isinstance(body, dict) else body
    if data is not None:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read().decode(), r.headers.get("Set-Cookie", "")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), ""
def sign_in(user, pw):
    st, body, sc = ui("POST", "/~ui/session", basic=(user, pw))
    return st, (sc.split(";")[0] if sc else None), (json.loads(body) if st == 200 else None)
def act(cookie, action, **fields):
    st, body, _ = ui("POST", "/~ui/iam", dict(Action=action, **fields), cookie=cookie)
    m = re.search(r"<Code>([^<]*)", body)
    return "ok" if st == 200 else (m.group(1) if m else str(st))

if phase == "main":
    iam.create_user(UserName="alice")
    check("a password too short is refused", code(lambda: iam.create_login_profile(UserName="alice", Password="short")), "PasswordPolicyViolation")
    lp = iam.create_login_profile(UserName="alice", Password="alicepassword1")["LoginProfile"]
    check("CreateLoginProfile answers as IAM does", (lp["UserName"], lp["PasswordResetRequired"]), ("alice", False))
    check("a second is EntityAlreadyExists", code(lambda: iam.create_login_profile(UserName="alice", Password="alicepassword2")), "EntityAlreadyExists")
    check("the password is kept as a hash, never as itself",
          ("alicepassword1" in open(sys.argv[3].replace("state.json", "lg/.iam.json")).read(), "$scrypt$" in open(sys.argv[3].replace("state.json", "lg/.iam.json")).read()), (False, True))
    settle()
    st, alice, me = sign_in("alice", "alicepassword1")
    check("a user signs in with its name and password", (st, me and me["user"], me and me["by_password"], me and me["password"]), (200, "alice", True, True))
    check("a wrong password does not", sign_in("alice", "alicepassword9")[0], 401)
    check("nor an unknown name", sign_in("nobody", "alicepassword1")[0], 401)
    check("the session is good on either shard", [ui("GET", "/~ui/session", cookie=alice)[0] for _ in range(6)], [200] * 6)
    # A browser sends one cookie of a name per domain it was set for, so a forged one beside the real one must not win.
    check("a forged session cookie sent before the real one does not shut it out",
          ui("GET", "/~ui/session", cookie="skl_ui=Zm9y.1.9999999999999.00; " + alice)[0], 200)
    check("nor one sent after it", ui("GET", "/~ui/session", cookie=alice + "; skl_ui=Zm9y.1.9999999999999.00")[0], 200)
    check("a WebDAV client's Basic name and password sign in", ui("PROPFIND", "/~dav/", basic=("alice", "alicepassword1"), ui_header=False)[0], 207)

    # What a user does to itself without a policy, and what it may not.
    check("a user makes its own key without a policy", act(alice, "CreateAccessKey"), "ok")
    keys = iam.list_access_keys(UserName="alice")["AccessKeyMetadata"]
    check("which is its own", [k["UserName"] for k in keys], ["alice"])
    check("but no other user", act(alice, "CreateUser", UserName="mallory"), "AccessDenied")
    check("nor its own quota", act(alice, "TagUser", UserName="alice", **{"Tags.member.1.Key": "socketley:max-bytes", "Tags.member.1.Value": "1"}), "AccessDenied")
    check("nor itself an admin", act(alice, "AddUserToGroup", UserName="alice", GroupName="admins"), "AccessDenied")
    check("nor an invitation", act(alice, "socketley:CreateInvitation"), "AccessDenied")
    check("nor reaches an invitation's taking through IAM", ui("POST", "/~ui/iam", {"Action": "socketley:AcceptInvitation"}, cookie=alice)[0], 400)
    check("a change of password needs the old one", act(alice, "ChangePassword", OldPassword="wrong-one-1", NewPassword="alicepassword2"), "InvalidUserType")
    check("and changes it", act(alice, "ChangePassword", OldPassword="alicepassword1", NewPassword="alicepassword2"), "ok")
    settle()
    check("a session of the old password ends with it", ui("GET", "/~ui/session", cookie=alice)[0], 401)
    check("the old password no longer signs in", sign_in("alice", "alicepassword1")[0], 401)
    st, alice, _ = sign_in("alice", "alicepassword2")
    check("the new one does", st, 200)

    # A delegate of IAM rights changes no admin.
    iam.create_user(UserName="dave")
    iam.create_login_profile(UserName="dave", Password="davepassword1")
    iam.put_user_policy(UserName="dave", PolicyName="pw", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["iam:UpdateLoginProfile", "iam:CreateLoginProfile"], "Resource": "*"}]}))
    settle()
    _, dave, _ = sign_in("dave", "davepassword1")
    check("a delegate sets the password of a user its policy names", act(dave, "UpdateLoginProfile", UserName="alice", Password="alicepassword3"), "ok")
    check("but not an admin's", act(dave, "CreateLoginProfile", UserName="root", Password="rootpassword1"), "AccessDenied")
    iam.update_login_profile(UserName="alice", Password="alicepassword2", PasswordResetRequired=True)
    settle()
    st, alice, me = sign_in("alice", "alicepassword2")
    check("a password set for a user says it must be changed", (st, me and me.get("password_reset")), (200, True))

    # The tags the runtime reads, and the group of admins.
    iam.tag_user(UserName="alice", Tags=[{"Key": "socketley:display-name", "Value": "Alice Adams"}, {"Key": "socketley:max-bytes", "Value": "1000"}])
    check("a tag the runtime reads is checked", code(lambda: iam.tag_user(UserName="alice", Tags=[{"Key": "socketley:max-bytes", "Value": "lots"}])), "InvalidInput")
    check("and none of its prefix is made up", code(lambda: iam.tag_user(UserName="alice", Tags=[{"Key": "socketley:colour", "Value": "x"}])), "InvalidInput")
    settle()
    check("the name shown is the tag's", json.loads(ui("GET", "/~ui/session", cookie=alice)[1])["name"], "Alice Adams")
    k = iam.create_access_key(UserName="alice")["AccessKey"]
    a3 = mk("s3", (k["AccessKeyId"], k["SecretAccessKey"]))
    settle()
    check("an IAM user makes no library without a policy that lets it", code(lambda: a3.create_bucket(Bucket="alices")), "AccessDenied")
    iam.put_user_policy(UserName="alice", PolicyName="socketley-libraries",
                        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:CreateBucket","Resource":"*"}]}')
    settle()
    check("the interface's policy lets it", code(lambda: a3.create_bucket(Bucket="alices")), "ok")
    check("the quota of the tag is held to", code(lambda: a3.put_object(Bucket="alices", Key="big", Body=b"x" * 2000)), "QuotaExceeded")
    iam.create_group(GroupName="admins")
    iam.add_user_to_group(UserName="alice", GroupName="admins")
    settle()
    check("a member of admins is an admin", json.loads(ui("GET", "/~ui/session", cookie=alice)[1])["admin"], True)
    iam.remove_user_from_group(UserName="alice", GroupName="admins")
    a3.put_object(Bucket="alices", Key="shared.txt", Body=b"hi")
    st, body, _ = ui("POST", "/~share", {"bucket": "alices", "key": "shared.txt"}, basic=("alice", "alicepassword2"))
    link = "/~share/" + (json.loads(body)["id"] if st == 201 else "none")
    check("a user's share link reads", ui("GET", link, ui_header=False)[:2], (200, "hi"))
    iam.tag_user(UserName="alice", Tags=[{"Key": "socketley:disabled", "Value": "true"}])
    settle()
    check("a disabled user's password signs in no more", sign_in("alice", "alicepassword2")[0], 401)
    check("nor does its share link read", ui("GET", link, ui_header=False)[0], 410)
    check("nor its key", code(lambda: a3.list_buckets()), "InvalidAccessKeyId")
    check("but its name is still a user's", "alice" in [u["id"] for u in json.loads(ui("GET", "/~ui/users", cookie=dave)[1])["users"]], True)
    iam.untag_user(UserName="alice", TagKeys=["socketley:disabled"])
    settle()
    check("let in again, it signs in", sign_in("alice", "alicepassword2")[0], 200)
    check("and its link reads again", ui("GET", link, ui_header=False)[:2], (200, "hi"))

    # Invitations.
    _, root, _ = sign_in("AKIALOGINROOT0000000", "loginrootsecretloginrootsecretloginroot0")
    st, body, _ = ui("POST", "/~ui/iam", {"Action": "socketley:CreateInvitation", "Admin": "true", "MaxBytes": "5000"}, cookie=root)
    token = re.search(r"<Token>([^<]*)", body).group(1)
    check("an admin's invitation is a token of 32 characters", (st, len(token)), (200, 32))
    check("which holds", json.loads(ui("GET", "/~ui/invite?token=" + token)[1])["valid"], True)
    check("a token that is none does not", json.loads(ui("GET", "/~ui/invite?token=" + "x" * 32)[1])["valid"], False)
    check("a weak password is refused when it is taken",
          ui("POST", "/~ui/invite", {"token": token, "user": "erin", "password": "short"}, ui_header=False)[0], 400)
    # The name of the owner every bucket with none recorded belongs to is no one's to take.
    check("an invitation does not make the buckets' default owner",
          ui("POST", "/~ui/invite", {"token": token, "user": "socketley", "password": "socketleypass1"}, ui_header=False)[0], 409)
    check("the invitation makes the user", ui("POST", "/~ui/invite", {"token": token, "user": "erin", "password": "erinpassword1", "name": "Erin E"}, ui_header=False)[0], 200)
    settle()
    st, erin, me = sign_in("erin", "erinpassword1")
    check("who signs in as it said: an admin, named, with its quota", (st, me and me["admin"], me and me["name"]), (200, True, "Erin E"))
    check("its quota", [t["Value"] for t in iam.list_user_tags(UserName="erin")["Tags"] if t["Key"] == "socketley:max-bytes"], ["5000"])
    check("and libraries of its own to make", iam.list_user_policies(UserName="erin")["PolicyNames"], ["socketley-libraries"])
    check("an invitation is taken once", ui("POST", "/~ui/invite", {"token": token, "user": "frank", "password": "frankpassword1"}, ui_header=False)[0], 404)

    # Who is listed to whom.
    users = json.loads(ui("GET", "/~ui/users", cookie=dave)[1])
    check("a non-admin is told each user's name and nothing else", (users["admin"], sorted(set(k for u in users["users"] for k in u)), "invites" in users), (False, ["id", "name"], False))
    users = json.loads(ui("GET", "/~ui/users", cookie=root)[1])
    check("an admin sees how each signs in", {u["id"]: (u["password"], u["admin"], u["file"]) for u in users["users"]}["root"], (False, True, True))

    # A user goes only with what it holds.
    check("a user with a login profile is not deleted", code(lambda: iam.delete_user(UserName="dave")), "DeleteConflict")
    iam.delete_user_policy(UserName="dave", PolicyName="pw")
    iam.delete_login_profile(UserName="dave")
    check("without it, it is", code(lambda: iam.delete_user(UserName="dave")), "ok")
    json.dump({"alice_key": [k["AccessKeyId"], k["SecretAccessKey"]]}, open(state, "w"))
elif phase == "after":
    check("a password signs in after a restart", sign_in("alice", "alicepassword2")[0], 200)
    check("and an invited user's", sign_in("erin", "erinpassword1")[0], 200)
    check("and a deleted user's does not", sign_in("dave", "davepassword1")[0], 401)
PY
    local rc=$?; tally < "$SOCKETLEY_TMPD/step"
    [ "$rc" -eq 0 ] && ok || bad "the $1 step ran to its end" "python exited $rc"
}

step main
"$BIN" stop lg >/dev/null 2>&1
"$BIN" start lg >/dev/null 2>&1
up || bad "the runtime serves again" "no answer on $P1"
step after

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
