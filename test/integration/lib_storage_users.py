#!/usr/bin/env python3
"""A storage runtime's users: ownership, ListBuckets, cross-user access and how it is granted and denied.

usage: lib_storage_users.py MODE ARGS...

  basic   TARGET             alice and bob make buckets, see only their own, are refused each
                             other's, and the admin and a legacy key may do everything
  grant   TARGET             bob let in by alice's bucket policy (by user ARN and by access key)
                             and by his own identity policy, and no further
  deny    TARGET             an explicit Deny wins: a bucket policy's over the owner, an identity
                             policy's over the owner and over a bucket policy's Allow
  persist TARGET...          what basic and grant left holds through every target
  shards  NODE0 NODE1        a bucket made through either shard is its maker's on both
  reload  TARGET CREDS POLICY
                             an edit of the credentials file and of a policy file is taken
                             without a restart
  legacy  TARGET             a file without users: every key is the one owner of every bucket

A TARGET is a port or a unix socket path.  The keys come from the environment: AKA/SKA
(alice), AKA2/SKA2 (alice's second key), AKB/SKB (bob), AKR/SKR (root, an admin user),
AKL/SKL (a key outside any user), and LK1/LSK1 and LK2/LSK2 for the legacy file.
Every mode prints one PASS or FAIL line per assertion and exits with the number of failures.
"""
import json
import os
import sys
import time
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib_storage_policy as lp  # noqa: E402

check = lp.check
req = lp.req

E = os.environ
ALICE = (E.get("AKA", "AKIAUSERSALICE000001"), E.get("SKA", "alice/secret/1"))
ALICE2 = (E.get("AKA2", "AKIAUSERSALICE000002"), E.get("SKA2", "alice/secret/2"))
BOB = (E.get("AKB", "AKIAUSERSBOB00000001"), E.get("SKB", "bob/secret/1"))
ROOT = (E.get("AKR", "AKIAUSERSROOT0000001"), E.get("SKR", "root/secret/1"))
LEGACY = (E.get("AKL", "AKIAUSERSLEGACY00001"), E.get("SKL", "legacy/secret/1"))
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


def xml(r):
    try:
        return ET.fromstring(r.body)
    except ET.ParseError:
        return ET.Element("none")


def buckets(target, key):
    r = req(target, "GET", "/", key=key)
    root = xml(r)
    names = sorted(b.findtext(NS + "Name") for b in root.iter(NS + "Bucket"))
    owner = (root.findtext(NS + "Owner/" + NS + "ID"), root.findtext(NS + "Owner/" + NS + "DisplayName"))
    return r.status, names, owner


def acl_owner(target, path, key):
    r = req(target, "GET", path, "acl", key=key)
    root = xml(r)
    return (r.status, root.findtext(NS + "Owner/" + NS + "ID"), root.findtext(NS + "Owner/" + NS + "DisplayName"),
            root.findtext(".//" + NS + "Grantee/" + NS + "ID"))


def status(target, method, path, key, query="", body=b"", headers=None):
    r = req(target, method, path, query, body, key, headers)
    return r.status, r.code()


def denied(name, target, method, path, key, query="", body=b"", headers=None):
    got = status(target, method, path, key, query, body, headers)
    # A HEAD has no body to carry the code in.
    check(name, got == (403, "AccessDenied") or (method == "HEAD" and got == (403, "")), "got %r" % (got,))


def allowed(name, target, method, path, key, query="", body=b"", headers=None, want=(200, 204)):
    got = status(target, method, path, key, query, body, headers)
    check(name, got[0] in want, "got %r" % (got,))


def policy(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def stmt(effect, principal, action, resource):
    return {"Effect": effect, "Principal": {"AWS": principal}, "Action": action, "Resource": resource}


# ─── basic ──────────────────────────────────────────────────────────────────

def mode_basic(T):
    allowed("alice makes alice-a", T, "PUT", "/alice-a", ALICE)
    allowed("bob makes bob-b", T, "PUT", "/bob-b", BOB)
    allowed("root makes root-r", T, "PUT", "/root-r", ROOT)
    allowed("a key outside any user makes legacy-l", T, "PUT", "/legacy-l", LEGACY)
    allowed("alice puts an object in her bucket", T, "PUT", "/alice-a/doc.txt", ALICE, body=b"alice's")
    allowed("bob puts an object in his", T, "PUT", "/bob-b/doc.txt", BOB, body=b"bob's")
    allowed("alice's second key works on her bucket", T, "GET", "/alice-a/doc.txt", ALICE2)

    st, names, owner = buckets(T, ALICE)
    check("ListBuckets shows alice her buckets alone", (st, names) == (200, ["alice-a"]), "%d %r" % (st, names))
    check("and names her as the owner, with her display name", owner == ("alice", "Alice Example"), repr(owner))
    st, names, owner = buckets(T, ALICE2)
    check("alice's second key is alice", names == ["alice-a"] and owner[0] == "alice", "%r %r" % (names, owner))
    st, names, owner = buckets(T, BOB)
    check("ListBuckets shows bob his", names == ["bob-b"] and owner == ("bob", "bob"), "%r %r" % (names, owner))
    st, names, owner = buckets(T, ROOT)
    check("an admin is shown every bucket", names == ["alice-a", "bob-b", "legacy-l", "root-r"], repr(names))
    st, names, owner = buckets(T, LEGACY)
    check("as is a key outside any user, the default owner", names == ["alice-a", "bob-b", "legacy-l", "root-r"]
          and owner == ("socketley", "socketley"), "%r %r" % (names, owner))

    got = acl_owner(T, "/alice-a", ALICE)
    check("GetBucketAcl names alice as the owner and grantee", got == (200, "alice", "Alice Example", "alice"),
          repr(got))
    got = acl_owner(T, "/alice-a/doc.txt", ALICE)
    check("GetObjectAcl names alice too", got == (200, "alice", "Alice Example", "alice"), repr(got))
    got = acl_owner(T, "/legacy-l", LEGACY)
    check("a bucket of the default owner names socketley", got[1:3] == ("socketley", "socketley"), repr(got))
    r = req(T, "GET", "/alice-a", "list-type=2&fetch-owner=true", key=ALICE)
    owner = xml(r).findtext(".//" + NS + "Contents/" + NS + "Owner/" + NS + "ID")
    check("ListObjectsV2 FetchOwner names alice", r.status == 200 and owner == "alice", repr(r))
    r = req(T, "GET", "/alice-a", "versions", key=ALICE)
    owner = xml(r).findtext(".//" + NS + "Owner/" + NS + "DisplayName")
    check("ListObjectVersions names her display name", r.status == 200 and owner == "Alice Example", repr(r))
    r = req(T, "PUT", "/alice-a/acl.txt", "", b"x", ALICE, {"x-amz-grant-full-control": 'id="alice"'})
    check("a write granting the owner full control by her id is taken", r.status == 200, repr(r))
    r = req(T, "PUT", "/alice-a/acl2.txt", "", b"x", ALICE, {"x-amz-grant-full-control": 'id="socketley"'})
    check("and one granting it to the old single owner is refused", r.status == 400, repr(r))

    # Another user's bucket is closed to bob in every direction.
    denied("bob may not read alice's object", T, "GET", "/alice-a/doc.txt", BOB)
    denied("nor HEAD it", T, "HEAD", "/alice-a/doc.txt", BOB)
    denied("nor write into her bucket", T, "PUT", "/alice-a/bob.txt", BOB, body=b"bob was here")
    denied("nor delete from it", T, "DELETE", "/alice-a/doc.txt", BOB)
    denied("nor list it", T, "GET", "/alice-a", BOB)
    denied("nor HEAD it", T, "HEAD", "/alice-a", BOB)
    denied("nor read its ACL", T, "GET", "/alice-a", BOB, "acl")
    denied("nor read its policy", T, "GET", "/alice-a", BOB, "policy")
    denied("nor set one", T, "PUT", "/alice-a", BOB, "policy", policy(stmt("Allow", "*", "s3:*", "arn:aws:s3:::alice-a/*")))
    denied("nor its versioning", T, "GET", "/alice-a", BOB, "versioning")
    denied("nor its ownership controls", T, "GET", "/alice-a", BOB, "ownershipControls")
    denied("nor delete the bucket", T, "DELETE", "/alice-a", BOB)
    denied("nor start an upload in it", T, "POST", "/alice-a/mp", BOB, "uploads")
    denied("nor copy from it into his own bucket", T, "PUT", "/bob-b/stolen", BOB,
           headers={"x-amz-copy-source": "/alice-a/doc.txt"})
    denied("and alice may not read bob's", T, "GET", "/bob-b/doc.txt", ALICE)
    allowed("alice still reads hers", T, "GET", "/alice-a/doc.txt", ALICE)
    allowed("and copies within her own bucket", T, "PUT", "/alice-a/copy.txt", ALICE,
            headers={"x-amz-copy-source": "/alice-a/doc.txt"})
    check("a bucket that is not there is NoSuchBucket to anybody", status(T, "GET", "/nobody-here/x", BOB) ==
          (404, "NoSuchBucket"), repr(status(T, "GET", "/nobody-here/x", BOB)))

    got = status(T, "PUT", "/bob-b", ALICE)
    check("alice making bob's bucket is BucketAlreadyExists", got == (409, "BucketAlreadyExists"), repr(got))
    got = status(T, "PUT", "/bob-b", BOB)
    check("bob making it again is BucketAlreadyOwnedByYou", got == (409, "BucketAlreadyOwnedByYou"), repr(got))
    got = status(T, "PUT", "/bob-b", ROOT)
    check("so is an admin making it, since it is not the admin's", got == (409, "BucketAlreadyExists"), repr(got))

    # An admin and a key outside any user may do everything to everyone's buckets.
    allowed("root reads alice's object", T, "GET", "/alice-a/doc.txt", ROOT)
    allowed("root lists her bucket", T, "GET", "/alice-a", ROOT)
    allowed("root writes into bob's", T, "PUT", "/bob-b/root.txt", ROOT, body=b"root")
    allowed("a legacy key reads bob's object", T, "GET", "/bob-b/doc.txt", LEGACY)
    got = acl_owner(T, "/bob-b", ROOT)
    check("the owner of bob's bucket is bob whoever asks", got[1] == "bob", repr(got))


# ─── grant ──────────────────────────────────────────────────────────────────

def mode_grant(T):
    doc = policy(stmt("Allow", "arn:aws:iam::123456789012:user/bob", "s3:GetObject", "arn:aws:s3:::alice-a/pub/*"),
                 stmt("Allow", BOB[0], "s3:PutObject", "arn:aws:s3:::alice-a/drop/*"))
    allowed("alice sets a policy on alice-a", T, "PUT", "/alice-a", ALICE, "policy", doc)
    allowed("alice puts pub/x", T, "PUT", "/alice-a/pub/x", ALICE, body=b"public to bob")
    allowed("alice puts priv/x", T, "PUT", "/alice-a/priv/x", ALICE, body=b"not to bob")
    allowed("bob reads pub/x, granted by user ARN", T, "GET", "/alice-a/pub/x", BOB)
    denied("and not priv/x", T, "GET", "/alice-a/priv/x", BOB)
    denied("a key there is not, which he may not list, is AccessDenied to him", T, "GET", "/alice-a/pub/none", BOB)
    allowed("bob writes drop/y, granted by his access key", T, "PUT", "/alice-a/drop/y", BOB, body=b"from bob")
    denied("and not elsewhere", T, "PUT", "/alice-a/other", BOB, body=b"from bob")
    allowed("alice reads what bob dropped", T, "GET", "/alice-a/drop/y", ALICE)
    allowed("bob copies pub/x into his bucket, the source granted", T, "PUT", "/bob-b/copied", BOB,
            headers={"x-amz-copy-source": "/alice-a/pub/x"})
    denied("and not priv/x", T, "PUT", "/bob-b/copied2", BOB, headers={"x-amz-copy-source": "/alice-a/priv/x"})

    # Bob's own identity policy lets him read and list alice-s, and nothing more there.
    allowed("alice makes alice-s", T, "PUT", "/alice-s", ALICE)
    allowed("alice puts x in it", T, "PUT", "/alice-s/x", ALICE, body=b"shared by identity policy")
    allowed("bob reads it, granted by his identity policy", T, "GET", "/alice-s/x", BOB)
    allowed("bob lists it", T, "GET", "/alice-s", BOB)
    got = status(T, "GET", "/alice-s/none", BOB)
    check("a key there is not is NoSuchKey to him, since he may list", got == (404, "NoSuchKey"), repr(got))
    denied("bob may not write into it", T, "PUT", "/alice-s/y", BOB, body=b"no")
    denied("nor read alice-a's priv/ through it", T, "GET", "/alice-a/priv/x", BOB)
    st, names, _ = buckets(T, BOB)
    check("a grant does not put alice's buckets in bob's ListBuckets", names == ["bob-b"], repr(names))


# ─── deny ───────────────────────────────────────────────────────────────────

def mode_deny(T):
    # A Deny in the bucket policy refuses even the owner.
    doc = policy(stmt("Deny", "arn:aws:iam::123456789012:user/alice", "s3:GetObject", "arn:aws:s3:::alice-d/locked/*"))
    allowed("alice makes alice-d", T, "PUT", "/alice-d", ALICE)
    allowed("alice puts locked/x and open/x", T, "PUT", "/alice-d/locked/x", ALICE, body=b"x")
    allowed("and open/x", T, "PUT", "/alice-d/open/x", ALICE, body=b"x")
    allowed("alice denies herself locked/*", T, "PUT", "/alice-d", ALICE, "policy", doc)
    denied("the owner is refused what a Deny names", T, "GET", "/alice-d/locked/x", ALICE)
    denied("through her second key too", T, "GET", "/alice-d/locked/x", ALICE2)
    allowed("and not the rest", T, "GET", "/alice-d/open/x", ALICE)
    allowed("an admin is not named by it", T, "GET", "/alice-d/locked/x", ROOT)
    shut = policy(stmt("Deny", "*", "s3:*", "arn:aws:s3:::alice-d/*"),
                  stmt("Deny", "*", "s3:*", "arn:aws:s3:::alice-d"))
    allowed("alice shuts everyone out", T, "PUT", "/alice-d", ALICE, "policy", shut)
    denied("which shuts out an admin", T, "GET", "/alice-d/open/x", ROOT)
    denied("and herself", T, "GET", "/alice-d/open/x", ALICE)
    denied("bob may not remove that policy", T, "DELETE", "/alice-d", BOB, "policy")
    allowed("and the owner may", T, "DELETE", "/alice-d", ALICE, "policy")
    allowed("after which she reads again", T, "GET", "/alice-d/open/x", ALICE)

    # A Deny in bob's identity policy refuses him on his own bucket.
    allowed("bob puts keep/x in his bucket", T, "PUT", "/bob-b/keep/x", BOB, body=b"keep")
    denied("his own policy denies him deleting it", T, "DELETE", "/bob-b/keep/x", BOB)
    allowed("and not anything else", T, "DELETE", "/bob-b/doc.txt", BOB)
    denied("it denies him making a bucket it names", T, "PUT", "/forbidden-1", BOB)
    allowed("and not another", T, "PUT", "/bob-c", BOB)
    allowed("the same bucket is alice's to make", T, "PUT", "/forbidden-1", ALICE)

    # It denies him the policy operations on bob-b though he owns it, and a lockout it does not name is his to undo.
    share = policy(stmt("Allow", "arn:aws:iam::1:user/alice", "s3:GetObject", "arn:aws:s3:::bob-b/*"))
    denied("his own policy denies him setting a policy on his bucket", T, "PUT", "/bob-b", BOB, "policy", share)
    denied("so alice is not let in", T, "GET", "/bob-b/keep/x", ALICE)
    denied("and removing one", T, "DELETE", "/bob-b", BOB, "policy")
    shut = policy(stmt("Deny", "*", "s3:*", "arn:aws:s3:::bob-c/*"), stmt("Deny", "*", "s3:*", "arn:aws:s3:::bob-c"))
    allowed("bob shuts everyone out of bob-c, which his policy does not name", T, "PUT", "/bob-c", BOB, "policy", shut)
    denied("which shuts him out", T, "GET", "/bob-c", BOB)
    allowed("and he still removes it", T, "DELETE", "/bob-c", BOB, "policy")
    allowed("after which he lists it again", T, "GET", "/bob-c", BOB)

    # And it wins over an Allow in a bucket policy.
    doc = policy(stmt("Allow", "arn:aws:iam::1:user/bob", ["s3:DeleteObject", "s3:PutObject"],
                      "arn:aws:s3:::alice-s/*"))
    allowed("alice lets bob delete and write in alice-s", T, "PUT", "/alice-s", ALICE, "policy", doc)
    allowed("bob writes there now", T, "PUT", "/alice-s/bobs", BOB, body=b"bob")
    denied("but his identity policy's Deny of deleting there wins", T, "DELETE", "/alice-s/bobs", BOB)
    allowed("alice deletes it", T, "DELETE", "/alice-s/bobs", ALICE)


# ─── persist ────────────────────────────────────────────────────────────────

def mode_persist(targets):
    for T in targets:
        t = " (%s)" % T
        st, names, owner = buckets(T, ALICE)
        check("alice still owns alice-a and her others" + t, names == ["alice-a", "alice-d", "alice-s", "forbidden-1"]
              and owner[0] == "alice", "%r %r" % (names, owner))
        st, names, _ = buckets(T, BOB)
        check("bob still owns his" + t, names == ["bob-b", "bob-c"], repr(names))
        got = acl_owner(T, "/alice-a", ROOT)
        check("the ACL still names alice" + t, got[1:3] == ("alice", "Alice Example"), repr(got))
        got = acl_owner(T, "/legacy-l", ROOT)
        check("and legacy-l the default owner" + t, got[1] == "socketley", repr(got))
        denied("bob is still refused alice's priv/x" + t, T, "GET", "/alice-a/priv/x", BOB)
        allowed("and still granted pub/x" + t, T, "GET", "/alice-a/pub/x", BOB)
        allowed("and alice-s by his identity policy" + t, T, "GET", "/alice-s/x", BOB)
        allowed("alice still reads her own" + t, T, "GET", "/alice-a/doc.txt", ALICE)
        got = status(T, "PUT", "/alice-a", BOB)
        check("bob making alice-a is still BucketAlreadyExists" + t, got == (409, "BucketAlreadyExists"), repr(got))


# ─── shards ─────────────────────────────────────────────────────────────────

def mode_shards(n0, n1):
    allowed("alice makes s-alice through shard 1", n1, "PUT", "/s-alice", ALICE)
    allowed("bob makes s-bob through shard 0", n0, "PUT", "/s-bob", BOB)
    for i, n in enumerate((n0, n1)):
        t = " (shard %d)" % i
        st, names, _ = buckets(n, ALICE)
        check("alice owns s-alice alone" + t, names == ["s-alice"], repr(names))
        st, names, _ = buckets(n, BOB)
        check("bob owns s-bob alone" + t, names == ["s-bob"], repr(names))
        got = acl_owner(n, "/s-alice", ROOT)
        check("the ACL of s-alice names alice" + t, got[1] == "alice", repr(got))
        got = status(n, "PUT", "/s-alice", BOB)
        check("bob making s-alice is BucketAlreadyExists" + t, got == (409, "BucketAlreadyExists"), repr(got))
        got = status(n, "PUT", "/s-alice", ALICE)
        check("alice making it again is BucketAlreadyOwnedByYou" + t, got == (409, "BucketAlreadyOwnedByYou"), repr(got))
    # Keys land on both shards, so every key is judged by both.
    for k in range(8):
        allowed("alice puts k%d" % k, n0, "PUT", "/s-alice/k%d" % k, ALICE, body=b"x")
    for i, n in enumerate((n0, n1)):
        refused = [k for k in range(8) if status(n, "GET", "/s-alice/k%d" % k, BOB) != (403, "AccessDenied")]
        check("bob is refused every key of s-alice through shard %d" % i, refused == [], repr(refused))
        read = [k for k in range(8) if status(n, "GET", "/s-alice/k%d" % k, ALICE)[0] != 200]
        check("and alice reads every one through shard %d" % i, read == [], repr(read))


def mode_shards_persist(n0, n1):
    for i, n in enumerate((n0, n1)):
        t = " after a restart (shard %d)" % i
        st, names, _ = buckets(n, ALICE)
        check("alice still owns s-alice alone" + t, names == ["s-alice"], repr(names))
        st, names, _ = buckets(n, BOB)
        check("bob still owns s-bob alone" + t, names == ["s-bob"], repr(names))
        refused = [k for k in range(8) if status(n, "GET", "/s-alice/k%d" % k, BOB) != (403, "AccessDenied")]
        check("bob is still refused every key of s-alice" + t, refused == [], repr(refused))


# ─── reload ─────────────────────────────────────────────────────────────────

def wait_for(pred, secs=6.0):
    end = time.time() + secs
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.2)
    return pred()


def mode_reload(T, creds, policy_file):
    import http.client
    keep = http.client.HTTPConnection("127.0.0.1", int(T), timeout=30) if str(T).isdigit() else None
    if keep:
        keep.request("GET", "/")
        keep.getresponse().read()
    text = open(creds).read()
    new_key = ("AKIAUSERSALICE000003", "alice/secret/3")
    text = text.replace("name = Alice Example", "name = Alice Renamed\n%s:%s" % new_key)
    open(creds, "w").write(text)
    check("a key added to alice works without a restart",
          wait_for(lambda: buckets(T, new_key)[0] == 200), repr(buckets(T, new_key)))
    st, names, owner = buckets(T, new_key)
    check("and is alice", "alice-a" in names and owner == ("alice", "Alice Renamed"), "%r %r" % (names, owner))
    got = acl_owner(T, "/alice-a", ALICE)
    check("her new display name is in the ACL", got[2] == "Alice Renamed", repr(got))
    if keep:
        try:
            keep.request("GET", "/")
            r = keep.getresponse()
            r.read()
            check("a connection open before the reload is still served", r.status in (200, 403), str(r.status))
        except Exception as e:
            check("a connection open before the reload is still served", False, repr(e))
        keep.close()

    allowed("bob reads alice-s by his identity policy", T, "GET", "/alice-s/x", BOB)
    doc = json.load(open(policy_file))
    open(policy_file, "w").write("{ not json")
    time.sleep(1.5)
    allowed("a policy file that does not compile leaves the set as it was", T, "GET", "/alice-s/x", BOB)
    doc["Statement"] = [s for s in doc["Statement"] if s.get("Sid") != "ReadShared"]
    open(policy_file, "w").write(json.dumps(doc))
    check("an edit of his policy file alone takes that away without a restart",
          wait_for(lambda: status(T, "GET", "/alice-s/x", BOB) == (403, "AccessDenied")),
          repr(status(T, "GET", "/alice-s/x", BOB)))
    open(policy_file, "w").write("{ not json")
    time.sleep(1.5)
    allowed("a policy file that does not compile leaves the owner's own bucket served", T, "GET", "/alice-a/doc.txt", ALICE)
    denied("including what it took away", T, "GET", "/alice-s/x", BOB)


# ─── legacy ─────────────────────────────────────────────────────────────────

def mode_legacy(T):
    K1 = (E.get("LK1", "AKIALEGACYKEYONE0001"), E.get("LSK1", "legacy/one"))
    K2 = (E.get("LK2", "AKIALEGACYKEYTWO0002"), E.get("LSK2", "legacy/two"))
    allowed("the first key makes old-1", T, "PUT", "/old-1", K1)
    allowed("and puts an object in it", T, "PUT", "/old-1/x", K1, body=b"x")
    allowed("the second key reads it", T, "GET", "/old-1/x", K2)
    allowed("and writes into it", T, "PUT", "/old-1/y", K2, body=b"y")
    got = status(T, "PUT", "/old-1", K2)
    check("and making it again is BucketAlreadyOwnedByYou to it", got == (409, "BucketAlreadyOwnedByYou"), repr(got))
    st, names, owner = buckets(T, K2)
    check("ListBuckets shows every bucket to either key", names == ["old-1"] and owner == ("socketley", "socketley"),
          "%r %r" % (names, owner))
    got = acl_owner(T, "/old-1", K1)
    check("the owner is socketley", got[1:] == ("socketley", "socketley", "socketley"), repr(got))


def main():
    mode, a = sys.argv[1], sys.argv[2:]
    tgt = [int(x) if x.isdigit() else x for x in a]
    if mode == "basic":
        mode_basic(tgt[0])
    elif mode == "grant":
        mode_grant(tgt[0])
    elif mode == "deny":
        mode_deny(tgt[0])
    elif mode == "persist":
        mode_persist(tgt)
    elif mode == "shards":
        mode_shards(tgt[0], tgt[1])
    elif mode == "shardspersist":
        mode_shards_persist(tgt[0], tgt[1])
    elif mode == "reload":
        mode_reload(tgt[0], a[1], a[2])
    elif mode == "legacy":
        mode_legacy(tgt[0])
    else:
        print("unknown mode " + mode)
        sys.exit(1)
    lp.finish()


if __name__ == "__main__":
    main()
