#!/usr/bin/env python3
"""S3 bucket versioning on the storage runtime.

usage: lib_storage_versioning.py MODE ARGS...

  main PORT DATA       an anonymous runtime over TCP: the configuration, versions made by
                       PUT, CopyObject and CompleteMultipartUpload, GET, HEAD, DELETE and
                       tagging by version id, delete markers and undelete, the suspended
                       null version, ListObjectVersions and its paging, DeleteObjects with
                       versions, and boto3
  recovery PORT DATA   what main left, after a clean restart, after a SIGKILL with every
                       journal removed, and after a start that finds a version under both
                       of its names: every version and marker comes back, in order
  shards NODE0 NODE1   two shards, one unix node each: every version through both nodes,
                       one of which does not own the key, and no stale latest from memory

Prints one PASS or FAIL line per assertion and exits with the number of failures.
"""
import hashlib
import http.client
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

MODE = sys.argv[1]
BIN = os.environ.get("BIN", "")
RUNTIME = os.environ.get("RUNTIME", "ver")
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
B = "verb"
STATE = "versioning-expected.json"

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, detail))


def wait_for(fn, timeout):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.2)
    return fn()


class UnixConn(http.client.HTTPConnection):
    def __init__(self, path, timeout=60):
        super().__init__("localhost", timeout=timeout)
        self.unix_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.unix_path)


NODE = None


def req(method, path, body=None, headers=None, node=None):
    node = node or NODE
    c = UnixConn(node) if isinstance(node, str) else http.client.HTTPConnection("127.0.0.1", node, timeout=60)
    try:
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
    finally:
        c.close()


def xml_code(body):
    try:
        return ET.fromstring(body).findtext("Code")
    except ET.ParseError:
        return None


def md5(b):
    return hashlib.md5(b).hexdigest()


def vid_ok(v):
    return v is not None and re.fullmatch(r"[0-9a-f]{32}", v) is not None


def put(key, body, node=None, bucket=B, headers=None):
    st, h, _ = req("PUT", "/%s/%s" % (bucket, key), body, headers, node=node)
    return st, h.get("x-amz-version-id")


def get(key, vid=None, node=None, bucket=B, method="GET"):
    path = "/%s/%s" % (bucket, key) + ("?versionId=" + vid if vid is not None else "")
    return req(method, path, node=node)


def delete(key, vid=None, node=None, bucket=B):
    path = "/%s/%s" % (bucket, key) + ("?versionId=" + vid if vid is not None else "")
    st, h, body = req("DELETE", path, node=node)
    return st, h.get("x-amz-delete-marker"), h.get("x-amz-version-id")


def set_versioning(status, node=None, bucket=B, extra=""):
    doc = ('<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
           "<Status>%s</Status>%s</VersioningConfiguration>" % (status, extra))
    return req("PUT", "/%s?versioning" % bucket, doc.encode(), node=node)


def get_versioning(node=None, bucket=B):
    st, _, body = req("GET", "/%s?versioning" % bucket, node=node)
    if st != 200:
        return st, None
    return st, ET.fromstring(body).findtext(NS + "Status")


def list_versions(node=None, bucket=B, **q):
    """One page: entries as (kind, key, vid, latest, etag), prefixes, truncated, next markers."""
    names = {"prefix": "prefix", "delimiter": "delimiter", "key_marker": "key-marker",
             "version_marker": "version-id-marker", "max_keys": "max-keys"}
    qs = "&".join("%s=%s" % (names[k], v) for k, v in q.items() if v is not None)
    st, _, body = req("GET", "/%s?versions%s" % (bucket, "&" + qs if qs else ""), node=node)
    if st != 200:
        return st, None
    root = ET.fromstring(body)
    entries = []
    for el in root:
        tag = el.tag[len(NS):]
        if tag in ("Version", "DeleteMarker"):
            entries.append(("V" if tag == "Version" else "M", el.findtext(NS + "Key"), el.findtext(NS + "VersionId"),
                            el.findtext(NS + "IsLatest") == "true", (el.findtext(NS + "ETag") or "").strip('"')))
    prefixes = [p.findtext(NS + "Prefix") for p in root.findall(NS + "CommonPrefixes")]
    return st, {"entries": entries, "prefixes": prefixes, "truncated": root.findtext(NS + "IsTruncated") == "true",
                "next_key": root.findtext(NS + "NextKeyMarker"), "next_vid": root.findtext(NS + "NextVersionIdMarker")}


def all_versions(node=None, bucket=B, page=None, prefix=None):
    """Every entry, page by page with max-keys=page, as the paging markers lead."""
    out, km, vm, pages = [], None, None, 0
    while True:
        st, p = list_versions(node, bucket, prefix=prefix, key_marker=km, version_marker=vm, max_keys=page)
        if st != 200:
            return None
        out += p["entries"]
        pages += 1
        if not p["truncated"] or pages > 10000:
            return out
        km, vm = p["next_key"], p["next_vid"]


def boto(port):
    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config
    return boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % port, region_name="us-east-1",
                        config=Config(signature_version=UNSIGNED, s3={"addressing_style": "path"},
                                      retries={"max_attempts": 1}))


def multipart(key, parts, node=None, bucket=B):
    st, _, body = req("POST", "/%s/%s?uploads" % (bucket, key), node=node)
    uid = ET.fromstring(body).findtext(NS + "UploadId")
    etags = []
    for i, p in enumerate(parts, 1):
        _, h, _ = req("PUT", "/%s/%s?partNumber=%d&uploadId=%s" % (bucket, key, i, uid), p, node=node)
        etags.append(h.get("etag"))
    doc = "<CompleteMultipartUpload>" + "".join(
        "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>" % (i, e) for i, e in enumerate(etags, 1)) + \
        "</CompleteMultipartUpload>"
    st, h, body = req("POST", "/%s/%s?uploadId=%s" % (bucket, key, uid), doc.encode(), node=node)
    return st, h.get("x-amz-version-id")


def blob(n, seed):
    out = bytearray()
    x = hashlib.sha256(seed.encode()).digest()
    while len(out) < n:
        x = hashlib.sha256(x).digest()
        out += x
    return bytes(out[:n])


# ─── main ───────────────────────────────────────────────────────────────────

def mode_main(port, data):
    global NODE
    NODE = port
    expect = {}   # key -> list of (vid, md5 or None for a marker), newest first

    st, _, _ = req("PUT", "/" + B)
    check("the bucket is made", st == 200, st)
    st, status = get_versioning()
    check("a bucket never versioned answers an empty VersioningConfiguration", (st, status) == (200, None), (st, status))
    st, h, _ = req("GET", "/%s/x?versioning" % B)
    check("versioning of an object is refused", st == 501, st)

    # An object from before versioning is the null version.
    st, vid = put("pre", b"before versioning")
    check("a PUT to an unversioned bucket names no version", (st, vid) == (200, None), (st, vid))
    st, h, _ = get("pre")
    check("a GET from an unversioned bucket names no version", "x-amz-version-id" not in h, h)
    # Read twice, so a held copy has its headers rendered before the bucket is versioned.
    put("keep", b"kept from before")
    for _ in range(2):
        st, h, _ = get("keep")

    st, _, body = set_versioning("Enabled", extra="<MfaDelete>Enabled</MfaDelete>")
    check("MFA delete is refused", (st, xml_code(body)) == (501, "NotImplemented"), (st, body[:200]))
    st, _, body = set_versioning("Sometimes")
    check("a status other than Enabled or Suspended is MalformedXML", (st, xml_code(body)) == (400, "MalformedXML"),
          (st, body[:200]))
    st, status = get_versioning()
    check("a refused configuration leaves the bucket unversioned", status is None, status)
    st, _, _ = set_versioning("Enabled", extra="<MfaDelete>Disabled</MfaDelete>")
    check("versioning is enabled", st == 200, st)
    check("GetBucketVersioning says Enabled", get_versioning() == (200, "Enabled"), get_versioning())

    # An object from before versioning is named as the null version once the bucket is versioned, held copy or not.
    named = [get("keep")[1].get("x-amz-version-id") for _ in range(3)]
    named.append(get("keep", method="HEAD")[1].get("x-amz-version-id"))
    named.append(req("GET", "/%s/keep?tagging" % B)[1].get("x-amz-version-id"))
    check("GET, HEAD and GetObjectTagging of an object from before versioning say x-amz-version-id: null",
          named == ["null"] * 5, named)
    expect["keep"] = [("null", md5(b"kept from before"))]

    # Three versions of one key.
    bodies = [blob(1000 + i, "k%d" % i) for i in range(3)]
    vids = []
    for b in bodies:
        st, v = put("k", b)
        vids.append(v)
    check("every PUT is a version with an id of its own", all(vid_ok(v) for v in vids) and len(set(vids)) == 3, vids)
    expect["k"] = [(v, md5(b)) for v, b in zip(reversed(vids), reversed(bodies))]
    st, h, body = get("k")
    check("GET without a version id is the latest, and names it",
          (st, body, h.get("x-amz-version-id")) == (200, bodies[2], vids[2]), (st, len(body), h.get("x-amz-version-id")))
    ok = True
    for v, b in zip(vids, bodies):
        st, h, body = get("k", v)
        ok = ok and (st, body, h.get("x-amz-version-id")) == (200, b, v)
    check("GET of every version by its id is that version's bytes", ok)
    st, h, body = get("k", vids[0], method="HEAD")
    check("HEAD by version id is that version", (st, h.get("etag"), h.get("content-length"), h.get("x-amz-version-id")) ==
          (200, '"%s"' % md5(bodies[0]), str(len(bodies[0])), vids[0]), (st, h))
    st, h, body = req("GET", "/%s/k?versionId=%s" % (B, vids[1]), headers={"Range": "bytes=10-19"})
    check("a range of an old version", (st, body) == (206, bodies[1][10:20]), (st, body[:20]))
    st, _, body = get("k", "nope")
    check("a malformed version id is 400 InvalidArgument", (st, xml_code(body)) == (400, "InvalidArgument"), (st, body[:200]))
    st, _, body = get("k", "0" * 32)
    check("an unknown version id is 404 NoSuchVersion", (st, xml_code(body)) == (404, "NoSuchVersion"), (st, body[:200]))
    st, _, body = get("pre", "null")
    check("the object from before versioning is the null version", (st, body) == (200, b"before versioning"), st)

    # A delete marker, and undelete.
    st, dm, mid = delete("k")
    check("DELETE without a version id puts a delete marker", (st, dm) == (204, "true") and vid_ok(mid), (st, dm, mid))
    expect["k"].insert(0, (mid, None))
    st, h, body = get("k")
    check("GET of a deleted key is 404 NoSuchKey with x-amz-delete-marker",
          (st, xml_code(body), h.get("x-amz-delete-marker"), h.get("x-amz-version-id")) == (404, "NoSuchKey", "true", mid),
          (st, h))
    st, h, _ = get("k", method="HEAD")
    check("HEAD of a deleted key says the same", (st, h.get("x-amz-delete-marker")) == (404, "true"), (st, h))
    st, h, body = get("k", mid)
    check("GET of the delete marker by its id is 405", (st, xml_code(body), h.get("x-amz-delete-marker")) ==
          (405, "MethodNotAllowed", "true"), (st, h))
    st, _, body = get("k", vids[1])
    check("an older version is still read by its id", (st, body) == (200, bodies[1]), st)
    st, _, body = req("GET", "/%s?list-type=2" % B)
    check("ListObjectsV2 leaves a deleted key out", b"<Key>k</Key>" not in body and b"<Key>pre</Key>" in body, body[:300])
    st, _, body = req("DELETE", "/" + B)
    check("a bucket holding versions is not empty", (st, xml_code(body)) == (409, "BucketNotEmpty"), (st, body[:200]))
    st, dm, v = delete("k", mid)
    check("removing the delete marker says it was one", (st, dm, v) == (204, "true", mid), (st, dm, v))
    expect["k"].pop(0)
    st, h, body = get("k")
    check("removing the delete marker undeletes the key", (st, body, h.get("x-amz-version-id")) == (200, bodies[2], vids[2]),
          (st, h))

    # The latest removed for good: the one behind it is the latest.
    st, dm, v = delete("k", vids[2])
    check("DELETE of the latest version by its id", (st, dm, v) == (204, None, vids[2]), (st, dm, v))
    expect["k"].pop(0)
    st, h, body = get("k")
    check("the version behind it becomes the latest", (st, body, h.get("x-amz-version-id")) == (200, bodies[1], vids[1]),
          (st, h))
    st, dm, v = delete("k", vids[0])
    expect["k"].pop()
    st, _, body = get("k", vids[0])
    check("a noncurrent version removed for good is gone", (st, xml_code(body)) == (404, "NoSuchVersion"), st)
    st, dm, v = delete("k", "0" * 32)
    check("DELETE of a version the key does not have is a quiet 204", st == 204, st)

    # A pre-versioning object written again keeps its null version behind.
    st, v = put("pre", b"after")
    check("a PUT over the null version makes a new one", vid_ok(v), v)
    expect["pre"] = [(v, md5(b"after")), ("null", md5(b"before versioning"))]
    st, _, body = get("pre", "null")
    check("the null version is behind it", (st, body) == (200, b"before versioning"), st)

    # Tags by version.
    tags = b'<Tagging><TagSet><Tag><Key>era</Key><Value>old</Value></Tag></TagSet></Tagging>'
    st, h, _ = req("PUT", "/%s/pre?tagging&versionId=null" % B, tags)
    check("PutObjectTagging by version id names the version", (st, h.get("x-amz-version-id")) == (200, "null"), (st, h))
    st, h, body = req("GET", "/%s/pre?tagging&versionId=null" % B)
    check("GetObjectTagging by version id reads that version's tags", st == 200 and b"<Value>old</Value>" in body, body)
    st, _, body = req("GET", "/%s/pre?tagging" % B)
    check("the latest's tags are its own", st == 200 and b"<Value>old</Value>" not in body, body)
    st, h, _ = req("HEAD", "/%s/pre?versionId=null" % B)
    check("HEAD of the tagged version counts its tag", h.get("x-amz-tagging-count") == "1", h)
    st, _, _ = req("DELETE", "/%s/pre?tagging&versionId=null" % B)
    st, _, body = req("GET", "/%s/pre?tagging&versionId=null" % B)
    check("DeleteObjectTagging by version id", st == 200 and b"<Value>old</Value>" not in body, body)
    st, _, tm = delete("tm")
    st, _, body = req("GET", "/%s/tm?tagging&versionId=%s" % (B, tm))
    check("tags of a delete marker are 405", st == 405, (st, body[:200]))
    st, _, body = req("PUT", "/%s/tm?tagging&versionId=%s" % (B, tm), tags)
    check("and cannot be set", st == 405, (st, body[:200]))
    delete("tm2")
    expect["tm"] = None   # filled from the listing below
    expect["tm2"] = None

    # Multipart and copy each make a version.
    parts = [blob(5 << 20, "p1"), blob(1 << 20, "p2")]
    st, mv1 = multipart("mp", parts)
    st2, mv2 = multipart("mp", [blob(5 << 20, "q1"), blob(100, "q2")])
    check("each CompleteMultipartUpload is a version", st == 200 and st2 == 200 and vid_ok(mv1) and vid_ok(mv2) and
          mv1 != mv2, (st, st2, mv1, mv2))
    st, _, body = get("mp", mv1)
    check("the first upload is read by its version id", (st, md5(body)) == (200, md5(b"".join(parts))), st)
    st, h, body = req("PUT", "/%s/cp" % B, headers={"x-amz-copy-source": "/%s/k" % B})
    cv1 = h.get("x-amz-version-id")
    check("CopyObject into a versioned bucket is a version", st == 200 and vid_ok(cv1), (st, h))
    st, h, body = req("PUT", "/%s/cp" % B, headers={"x-amz-copy-source": "/%s/pre?versionId=null" % B})
    cv2 = h.get("x-amz-version-id")
    check("CopyObject from a version id copies that version and names it",
          st == 200 and vid_ok(cv2) and h.get("x-amz-copy-source-version-id") == "null", (st, h))
    st, _, body = get("cp")
    check("the copy is the version it was made from", (st, body) == (200, b"before versioning"), (st, body[:40]))
    st, _, body = get("cp", cv1)
    check("the first copy is behind it", (st, body) == (200, bodies[1]), st)
    st, h, body = req("PUT", "/%s/cp2" % B, headers={"x-amz-copy-source": "/%s/k?versionId=%s" % (B, mid)})
    check("a delete marker is no copy source", st in (400, 404), (st, body[:200]))
    st, h, _ = req("PUT", "/%s/cp" % B, headers={"x-amz-copy-source": "/%s/cp?versionId=%s" % (B, cv1)})
    cv3 = h.get("x-amz-version-id")
    st2, _, body = get("cp")
    check("a version copied over its own key is the new latest", st == 200 and vid_ok(cv3) and body == bodies[1],
          (st, h, body[:20]))

    # Suspended: the null version.
    st, _, _ = set_versioning("Suspended")
    check("versioning is suspended", st == 200 and get_versioning() == (200, "Suspended"), get_versioning())
    st, v1 = put("s", b"one")
    st, v2 = put("s", b"two")
    check("a PUT while suspended is the null version", (v1, v2) == ("null", "null"), (v1, v2))
    st, p = list_versions(prefix="s")
    check("a second null version replaced the first", [(e[1], e[2]) for e in p["entries"]] == [("s", "null")],
          p["entries"])
    st, nv = put("k", b"k null")
    check("a suspended PUT over a key with versions is its null version", nv == "null", nv)
    st, _, body = get("k", vids[1])
    check("the versions written while enabled stay", (st, body) == (200, bodies[1]), st)
    st, dm, dv = delete("k")
    check("a suspended DELETE is a null delete marker", (st, dm, dv) == (204, "true", "null"), (st, dm, dv))
    st, _, body = get("k", "null")
    check("which replaced the null version", st == 405, (st, body[:200]))
    st, _, _ = set_versioning("Enabled")
    st, kv = put("k", b"k again")
    check("enabled again, a PUT has an id of its own", vid_ok(kv), kv)
    st, _, body = get("k", "null")
    check("and the null delete marker is behind it", st == 405, st)
    expect["k"] = [(kv, md5(b"k again")), ("null", None), (vids[1], md5(bodies[1]))]

    # DeleteObjects with versions.
    st, v_a = put("d/a", b"a1")
    st, v_b = put("d/a", b"a2")
    st, v_c = put("d/c", b"c1")
    doc = ("<Delete><Object><Key>d/a</Key><VersionId>%s</VersionId></Object>"
           "<Object><Key>d/c</Key></Object><Object><Key>d/x</Key><VersionId>%s</VersionId></Object></Delete>"
           % (v_a, "1" * 32)).encode()
    st, _, body = req("POST", "/%s?delete" % B, doc)
    root = ET.fromstring(body) if st == 200 else None
    deleted = {} if root is None else {(d.findtext(NS + "Key"), d.findtext(NS + "VersionId")):
                                       (d.findtext(NS + "DeleteMarker"), d.findtext(NS + "DeleteMarkerVersionId"))
                                       for d in root.findall(NS + "Deleted")}
    dmv = deleted.get(("d/c", None), (None, None))[1]
    check("DeleteObjects removes a version and puts a marker in front of a key",
          deleted.get(("d/a", v_a)) == (None, None) and deleted.get(("d/c", None), (None,))[0] == "true" and vid_ok(dmv)
          and ("d/x", "1" * 32) in deleted, (st, body[:600]))
    st, _, body = get("d/a", v_a)
    st2, _, body2 = get("d/a")
    check("the version it named is gone and the key's latest is not", st == 404 and (st2, body2) == (200, b"a2"),
          (st, st2))
    st, h, _ = get("d/c")
    check("the key it named alone is deleted", (st, h.get("x-amz-delete-marker")) == (404, "true"), (st, h))
    expect["d/a"] = [(v_b, md5(b"a2"))]
    expect["d/c"] = [(dmv, None), (v_c, md5(b"c1"))]

    # Racing writers of one key: each answered PUT is a version, and the order is the order of the commits, which a
    # writer's version taken before its body was synced does not decide.
    race_ids, race_bad = [], []

    def racer(t):
        for i in range(4):
            st, v = put("race", blob(3000 + t, "race%d-%d" % (t, i)))
            (race_ids if st == 200 and vid_ok(v) else race_bad).append(v if st == 200 else st)
    import threading
    ths = [threading.Thread(target=racer, args=(t,)) for t in range(16)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    st, p = list_versions(prefix="race")
    listed = [e[2] for e in p["entries"]] if p else []
    st2, h, _ = get("race")
    check("16 racing writers of one key: every answered PUT is one version, listed once",
          not race_bad and len(race_ids) == 64 and sorted(listed) == sorted(race_ids), (race_bad, len(race_ids), len(listed)))
    # The first sixteen hex digits of an id are its version's order, so newest first is descending.
    seqs = [v[:16] for v in listed]
    check("and newest first, the latest being the one GET reads",
          seqs == sorted(seqs, reverse=True) and len(set(seqs)) == len(seqs) and h.get("x-amz-version-id") == listed[0],
          (listed[:4], h.get("x-amz-version-id")))
    expect["race"] = [(e[2], e[4]) for e in p["entries"]] if p else None

    # The listing, whole and paged.
    full = all_versions()
    by_key = {}
    for kind, key, vid, latest, etag in full or []:
        by_key.setdefault(key, []).append((vid, None if kind == "M" else etag))
    for k in ("tm", "tm2"):
        expect[k] = by_key.get(k)
    expect["s"] = [("null", md5(b"two"))]
    expect["mp"] = by_key.get("mp")
    expect["cp"] = by_key.get("cp")
    keys = [e[1] for e in full or []]
    check("ListObjectVersions is in key order", keys == sorted(keys), keys)
    latest_ok = all(sum(1 for e in full if e[1] == k and e[3]) == 1 and next(e for e in full if e[1] == k)[3]
                    for k in set(keys))
    check("each key's first entry is its one latest", latest_ok, full)
    mismatch = [(k, by_key.get(k), v) for k, v in expect.items() if by_key.get(k) != v]
    check("each key's versions are listed newest first, markers among them", not mismatch, mismatch[:3])
    for page in (1, 2, 3, 7):
        got = all_versions(page=page)
        check("paged %d at a time by key-marker and version-id-marker, the listing is the same" % page, got == full,
              (len(got or []), len(full)))
    st, p = list_versions(delimiter="/")
    check("a delimiter rolls keys up into common prefixes", p["prefixes"] == ["d/"] and
          not any(e[1].startswith("d/") for e in p["entries"]), p)
    st, p = list_versions(delimiter="/", max_keys=3)
    st2, p2 = list_versions(delimiter="/", max_keys=1000, key_marker=p["next_key"], version_marker=p["next_vid"])
    combined = p["entries"] + p2["entries"]
    check("paging with a delimiter goes on after the last entry", [e for e in combined] ==
          list_versions(delimiter="/")[1]["entries"], (p, p2))
    st, _, body = req("GET", "/%s?versions&version-id-marker=%s" % (B, "0" * 32))
    check("a version-id-marker without a key-marker is refused", st == 400, st)

    # boto3.
    try:
        s3 = boto(port)
        pages = s3.get_paginator("list_object_versions").paginate(Bucket=B, PaginationConfig={"PageSize": 2})
        seen = []
        for pg in pages:
            # A page's versions and markers are two lists in boto3, so they are put back in the order of the whole.
            for v in pg.get("Versions", []) + pg.get("DeleteMarkers", []):
                seen.append((v["Key"], v["VersionId"]))
        check("boto3's paginator sees every version and marker", sorted(seen) == sorted((e[1], e[2]) for e in full),
              (len(seen), len(full)))
        r = s3.put_object(Bucket=B, Key="bt", Body=b"boto one")
        r2 = s3.put_object(Bucket=B, Key="bt", Body=b"boto two")
        old = s3.get_object(Bucket=B, Key="bt", VersionId=r["VersionId"])["Body"].read()
        check("boto3 reads a version by VersionId", old == b"boto one" and r["VersionId"] != r2["VersionId"],
              (r.get("VersionId"), old))
        d = s3.delete_object(Bucket=B, Key="bt")
        check("boto3 sees the delete marker", d.get("DeleteMarker") is True and vid_ok(d.get("VersionId")), d)
        s3.delete_object(Bucket=B, Key="bt", VersionId=d["VersionId"])
        got = s3.get_object(Bucket=B, Key="bt")["Body"].read()
        check("and its removal undeletes", got == b"boto two", got)
        vs = s3.get_bucket_versioning(Bucket=B)
        check("boto3 reads the status", vs.get("Status") == "Enabled", vs)
        expect["bt"] = [(r2["VersionId"], md5(b"boto two")), (r["VersionId"], md5(b"boto one"))]
    except ImportError:
        print("  SKIP: boto3 is not installed")
        expect["bt"] = None

    with open(os.path.join(data, STATE), "w") as f:
        json.dump({k: v for k, v in expect.items() if v is not None}, f)
    lifecycle()
    policy()


def policy():
    pb = "verpol"
    req("PUT", "/" + pb)
    set_versioning("Enabled", bucket=pb)
    st, v1 = put("k", b"one", bucket=pb)
    st, v2 = put("k", b"two", bucket=pb)
    st, w1 = put("w", b"w", bucket=pb)
    doc = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Deny", "Principal": "*", "Resource": "arn:aws:s3:::%s/*" % pb,
         "Action": ["s3:GetObjectVersion", "s3:DeleteObjectVersion", "s3:GetObjectVersionTagging"]},
        {"Effect": "Deny", "Principal": "*", "Resource": "arn:aws:s3:::%s" % pb,
         "Action": ["s3:ListBucketVersions", "s3:PutBucketVersioning"]}]})
    st, _, body = req("PUT", "/%s?policy" % pb, doc.encode())
    check("a policy naming the versioning actions is taken", st == 204, (st, body[:300]))
    st, _, body = get("k", bucket=pb)
    st2, _, _ = get("k", v1, bucket=pb)
    st3, _, _ = get("k", v1, bucket=pb, method="HEAD")
    check("a Deny of s3:GetObjectVersion refuses GET and HEAD by version id and not the latest",
          (st, body, st2, st3) == (200, b"two", 403, 403), (st, st2, st3))
    st, _, _ = req("GET", "/%s/k?tagging&versionId=%s" % (pb, v1))
    st2, _, _ = req("GET", "/%s/k?tagging" % pb)
    check("a Deny of s3:GetObjectVersionTagging refuses tags by version id only", (st, st2) == (403, 200), (st, st2))
    st, _, _ = req("PUT", "/%s/c" % pb, headers={"x-amz-copy-source": "/%s/k?versionId=%s" % (pb, v1)})
    st2, _, _ = req("PUT", "/%s/c" % pb, headers={"x-amz-copy-source": "/%s/k" % pb})
    check("a copy from a source version is judged as s3:GetObjectVersion of it", (st, st2) == (403, 200), (st, st2))
    st, _, _ = req("GET", "/%s?versions" % pb)
    st2, _, _ = req("GET", "/%s?list-type=2" % pb)
    st3, _, _ = set_versioning("Suspended", bucket=pb)
    st4, _ = get_versioning(bucket=pb)
    check("a Deny of s3:ListBucketVersions and s3:PutBucketVersioning refuses those and nothing else",
          (st, st2, st3, st4) == (403, 200, 403, 200), (st, st2, st3, st4))
    st, dm, _ = delete("k", v1, bucket=pb)
    st2, dm2, _ = delete("k", bucket=pb)
    check("a Deny of s3:DeleteObjectVersion refuses a DELETE by version id and not a delete marker",
          (st, st2, dm2) == (403, 204, "true"), (st, st2, dm2))
    body = ("<Delete><Object><Key>w</Key><VersionId>%s</VersionId></Object><Object><Key>w</Key></Object></Delete>"
            % w1).encode()
    st, _, out = req("POST", "/%s?delete" % pb, body)
    root = ET.fromstring(out) if st == 200 else None
    errors = [] if root is None else [(e.findtext(NS + "Key"), e.findtext(NS + "Code")) for e in root.findall(NS + "Error")]
    deleted = [] if root is None else [d.findtext(NS + "DeleteMarker") for d in root.findall(NS + "Deleted")]
    check("DeleteObjects refuses the entry that names a version and does the one that does not",
          errors == [("w", "AccessDenied")] and deleted == ["true"], (st, out[:500]))
    st2, _, body2 = get("w", w1, bucket=pb)
    req("DELETE", "/%s?policy" % pb)
    st3, _, body3 = get("w", w1, bucket=pb)
    check("the version it refused is still there, and readable once the policy is gone",
          st2 == 403 and (st3, body3) == (200, b"w"), (st2, st3))


def lifecycle():
    lb = "verlc"
    req("PUT", "/" + lb)
    set_versioning("Enabled", bucket=lb)
    put("a/x", b"x1", bucket=lb)
    st, x2 = put("a/x", b"x2", bucket=lb)
    put("keep/y", b"y1", bucket=lb)
    put("keep/y", b"y2", bucket=lb)
    delete("m/z", bucket=lb)
    put("m/w", b"w1", bucket=lb)
    delete("m/w", bucket=lb)
    rules = ("<LifecycleConfiguration>"
             "<Rule><ID>nc</ID><Filter><Prefix>a/</Prefix></Filter><Status>Enabled</Status>"
             "<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule>"
             "<Rule><ID>dm</ID><Filter><Prefix>m/</Prefix></Filter><Status>Enabled</Status>"
             "<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule>"
             "</LifecycleConfiguration>")
    st, _, body = req("PUT", "/%s?lifecycle" % lb, rules.encode())
    check("a lifecycle with NoncurrentVersionExpiration and ExpiredObjectDeleteMarker is taken", st == 200,
          (st, body[:200]))
    st, _, body = req("GET", "/%s?lifecycle" % lb)
    check("and read back", st == 200 and b"<NoncurrentDays>1</NoncurrentDays>" in body and
          b"<ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker>" in body, body[:400])

    def keys_versions():
        got = {}
        for kind, key, vid, latest, etag in all_versions(bucket=lb) or []:
            got.setdefault(key, []).append(kind)
        return got
    done = wait_for(lambda: (lambda g: g if g.get("a/x") == ["V"] and "m/z" not in g else None)(keys_versions()), 30)
    got = keys_versions()
    check("the version behind a latest in the rule's prefix is removed some days after it became noncurrent",
          got.get("a/x") == ["V"], got)
    check("a delete marker with no version behind it is removed", "m/z" not in got, got)
    check("versions outside the rules stay", got.get("keep/y") == ["V", "V"] and got.get("m/w") == ["M", "V"], got)
    st, h, body = get("a/x", bucket=lb)
    check("the latest a noncurrent rule leaves is whole", (st, body, h.get("x-amz-version-id")) == (200, b"x2", x2),
          (st, body))


# ─── recovery ───────────────────────────────────────────────────────────────

def stats():
    out = subprocess.run([BIN, "stats", RUNTIME], capture_output=True, text=True).stdout
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d


def worker_stat(name):
    """A figure of the running worker, once its count of requests moves: until then stats may show the last one's."""
    before = stats().get("requests")

    def live():
        probe(NODE)
        d = stats()
        return d if d.get("requests") not in (None, before) else None
    s = wait_for(live, 20)
    return s.get(name) if s else None


def remove_journals(data):
    removed = 0
    for root, _, files in os.walk(data):
        for f in files:
            if f.startswith("index.") or f.startswith(".clean."):
                os.unlink(os.path.join(root, f))
                removed += 1
    return removed


def probe(port):
    try:
        return req("GET", "/", node=port)[0] == 200
    except OSError:
        return False


def snapshot():
    """The listing, and every version's bytes read back by its id."""
    full = all_versions(page=4)
    if full is None:
        return None
    bodies = {}
    for kind, key, vid, latest, etag in full:
        if kind == "V":
            st, _, body = get(key, vid)
            bodies[(key, vid)] = (st, md5(body))
    return full, bodies


def compare(label, expect, snap, ref=None):
    full, bodies = snap
    by_key = {}
    for kind, key, vid, latest, etag in full:
        by_key.setdefault(key, []).append((vid, None if kind == "M" else etag))
    mismatch = [(k, by_key.get(k), [tuple(x) for x in v]) for k, v in expect.items()
                if by_key.get(k) != [tuple(x) for x in v]]
    check(label + ": every version and marker is listed, in order", not mismatch, mismatch[:3])
    # A single part's ETag is the MD5 of its bytes, and every version reads what it read before.
    etag = {(k, v): e for k, vs in by_key.items() for v, e in vs}
    wrong = [(k, v, b) for (k, v), b in bodies.items()
             if b[0] != 200 or ("-" not in etag[(k, v)] and b[1] != etag[(k, v)]) or
             (ref is not None and ref[1].get((k, v)) != b)]
    check(label + ": every version reads back its own bytes", not wrong, wrong[:3])


def latest_files(data, bucket):
    out = []
    base = os.path.join(data, bucket, "data")
    for root, _, files in os.walk(base):
        out += [os.path.join(root, f) for f in files]
    return out


def mode_recovery(port, data):
    global NODE
    NODE = port
    with open(os.path.join(data, STATE)) as f:
        expect = json.load(f)
    before = snapshot()
    compare("before any restart", expect, before)

    subprocess.run([BIN, "stop", RUNTIME], capture_output=True)
    time.sleep(0.5)
    subprocess.run([BIN, "start", RUNTIME], capture_output=True)
    check("it starts again", wait_for(lambda: probe(port), 30))
    compare("after a clean restart", expect, snapshot(), before)
    check("GetBucketVersioning survives a restart", get_versioning() == (200, "Enabled"), get_versioning())
    read = worker_stat("start_files_read")
    check("a clean restart of a versioned bucket reads its journal and not one file", read == "0", read)

    # A crash with every journal gone: the files are all there is.
    pid = stats().get("pid")
    removed = remove_journals(data)
    os.kill(int(pid), signal.SIGKILL)
    newpid = wait_for(lambda: (lambda p: p if p and p != pid and probe(port) else None)(stats().get("pid")), 40)
    check("a SIGKILL with %d journal files removed is restarted" % removed, newpid and removed > 0, (pid, newpid, removed))
    compare("after a SIGKILL with the journals removed", expect, snapshot(), before)
    files = sum(len(fs) for _, _, fs in os.walk(os.path.join(data, B, "versions"))) + len(latest_files(data, B))
    read = worker_stat("start_files_read")
    # At least, since the other buckets' files are read too.
    check("and that start read the header of every file, versions/ included",
          read is not None and int(read) >= files, (read, files))
    st, h, _ = get("d/c")
    check("a delete marker is still the latest after the crash", (st, h.get("x-amz-delete-marker")) == (404, "true"),
          (st, h))

    # A version linked into versions/ and its replacement never renamed in: the copy at the usual path is kept.
    vkey = "k"
    vid = expect[vkey][0][0]
    h = hashlib.sha256(vkey.encode()).hexdigest()
    src = os.path.join(data, B, "data", h[:2], h)
    dup = os.path.join(data, B, "versions", h[:2], h + "." + vid)
    subprocess.run([BIN, "stop", RUNTIME], capture_output=True)
    time.sleep(0.5)
    os.link(src, dup)
    remove_journals(data)
    subprocess.run([BIN, "start", RUNTIME], capture_output=True)
    check("it starts with a version under both its names", wait_for(lambda: probe(port), 30))
    compare("after a start that found a version twice", expect, snapshot(), before)
    check("the second name is removed", not os.path.exists(dup), dup)
    rollforward(port, data)
    os.unlink(os.path.join(data, STATE))


def key_file(data, bucket, key):
    h = hashlib.sha256(key.encode()).hexdigest()
    return os.path.join(data, bucket, "data", h[:2], h)


def rollforward(port, data):
    """What a power cut leaves of a put answered at its rename, the rename lost and the pool file whole: in a bucket
    versioned since that put, and in one versioned before it, the next start puts it in place and keeps what it
    replaced."""
    import shutil
    rb = "verroll"
    req("PUT", "/" + rb)
    put("rf", b"the old latest", bucket=rb)
    old = open(key_file(data, rb, "rf"), "rb").read()
    put("rf", b"the answered put", bucket=rb)
    new = open(key_file(data, rb, "rf"), "rb").read()
    set_versioning("Enabled", bucket=rb)
    st, v_old = put("rv", b"the version it replaced")
    old_v = open(key_file(data, B, "rv"), "rb").read()
    st, v_new = put("rv", b"the answered version")
    new_v = open(key_file(data, B, "rv"), "rb").read()
    subprocess.run([BIN, "stop", RUNTIME], capture_output=True)
    time.sleep(0.5)
    # The rename never reached the disk: the old file at the key's path, the answered one under its pool name.
    for bucket, key, was, answered in ((rb, "rf", old, new), (B, "rv", old_v, new_v)):
        os.makedirs(os.path.join(data, bucket, "pool"), exist_ok=True)
        with open(os.path.join(data, bucket, "pool", "0.rolltest"), "wb") as f:
            f.write(answered)
        with open(key_file(data, bucket, key), "wb") as f:
            f.write(was)
    subprocess.run([BIN, "start", RUNTIME], capture_output=True)
    check("it starts with answered puts left in pool/", wait_for(lambda: probe(port), 30))
    st, h, body = get("rf", bucket=rb)
    st2, p = list_versions(bucket=rb, prefix="rf")
    check("a pooled put from before the bucket was versioned is rolled forward, as its null version",
          (st, body, h.get("x-amz-version-id")) == (200, b"the answered put", "null") and
          [(e[2], e[3]) for e in p["entries"]] == [("null", True)], (st, body, h, p))
    st, h, body = get("rv")
    st2, _, body2 = get("rv", v_old)
    st3, p = list_versions(prefix="rv")
    check("a pooled version is rolled forward over the latest, which is kept behind it",
          (st, body, h.get("x-amz-version-id"), st2, body2) == (200, b"the answered version", v_new, 200,
                                                                  b"the version it replaced") and
          [e[2] for e in p["entries"]] == [v_new, v_old], (st, h.get("x-amz-version-id"), st2, p))
    left = [b for b in (rb, B) if os.path.exists(os.path.join(data, b, "pool", "0.rolltest"))]
    check("and neither pool file is left", not left, left)


# ─── shards ─────────────────────────────────────────────────────────────────

def mode_shards(nodes):
    global NODE
    NODE = nodes[0]
    st, _, _ = req("PUT", "/" + B)
    check("the bucket is made", st == 200, st)
    pre = ["pre%d" % i for i in range(4)]
    for k in pre:
        put(k, b"from before", node=nodes[0])
        for n in nodes:
            get(k, node=n)
            get(k, node=n, method="HEAD")
    st, _, _ = set_versioning("Enabled", node=nodes[1])
    check("versioning enabled through shard 1 is every shard's",
          st == 200 and all(get_versioning(node=n) == (200, "Enabled") for n in nodes),
          [get_versioning(node=n) for n in nodes])
    named = [(k, n, m, get(k, node=n, method=m)[1].get("x-amz-version-id"))
             for k in pre for n in nodes for m in ("GET", "HEAD")]
    check("an object from before versioning is the null version through the owner and the other shard",
          all(v == "null" for _, _, _, v in named), [x for x in named if x[3] != "null"][:4])

    keys = ["sk%d" % i for i in range(8)]
    written = {}
    for i, k in enumerate(keys):
        for j in range(3):
            body = blob(500 + j, "%s-%d" % (k, j))
            st, v = put(k, body, node=nodes[(i + j) % 2])
            written.setdefault(k, []).insert(0, (v, body))
    check("every PUT through either shard is a version", all(vid_ok(v) for k in keys for v, _ in written[k]), written)
    wrong = []
    for k in keys:
        for n in nodes:
            st, h, body = get(k, node=n)
            if (st, body, h.get("x-amz-version-id")) != (200, written[k][0][1], written[k][0][0]):
                wrong.append((k, n, "latest", st))
            for v, b in written[k]:
                st, h, body = get(k, v, node=n)
                if (st, body) != (200, b):
                    wrong.append((k, n, v, st))
                st, h, _ = get(k, v, node=n, method="HEAD")
                if (st, h.get("etag")) != (200, '"%s"' % md5(b)):
                    wrong.append((k, n, v, "HEAD", st))
    check("every version of every key is read alike through the owner and the other shard", not wrong, wrong[:4])

    # The non-owner holds a small latest in memory; a new version and a marker must replace what it answers.
    stale = []
    for i, k in enumerate(keys):
        for _ in range(3):
            for n in nodes:
                get(k, node=n)
        body = blob(300, k + "-new")
        st, v = put(k, body, node=nodes[i % 2])
        written[k].insert(0, (v, body))
        for n in nodes:
            st, h, got = get(k, node=n)
            if (st, got) != (200, body):
                stale.append((k, n, st))
    check("no shard answers a latest that a new version replaced", not stale, stale[:4])
    marked = []
    for i, k in enumerate(keys[:4]):
        st, dm, mv = delete(k, node=nodes[(i + 1) % 2])
        written[k].insert(0, (mv, None))
        for n in nodes:
            st, h, _ = get(k, node=n)
            if (st, h.get("x-amz-delete-marker"), h.get("x-amz-version-id")) != (404, "true", mv):
                marked.append((k, n, st, h.get("x-amz-version-id")))
            st, h, _ = get(k, node=n, method="HEAD")
            if (st, h.get("x-amz-delete-marker")) != (404, "true"):
                marked.append((k, n, "HEAD", st))
    check("a delete marker made through either shard is every shard's 404", not marked, marked[:4])
    undone = []
    for i, k in enumerate(keys[:2]):
        st, dm, _ = delete(k, written[k][0][0], node=nodes[i % 2])
        written[k].pop(0)
        for n in nodes:
            st, _, got = get(k, node=n)
            if (st, got) != (200, written[k][0][1]):
                undone.append((k, n, st))
    check("removing the marker through either shard undeletes everywhere", not undone, undone)

    lists = [all_versions(node=n) for n in nodes]
    expect = []
    for k in pre:
        written[k] = [("null", b"from before")]
    for k in sorted(keys + pre):
        for v, b in written[k]:
            expect.append((k, v))
    check("ListObjectVersions through either shard merges both, in order",
          all([(e[1], e[2]) for e in l or []] == expect for l in lists), [(len(l or []), len(expect)) for l in lists])
    for page in (1, 3, 5):
        got = [all_versions(node=n, page=page) for n in nodes]
        check("paged %d at a time across shards, the listing is the same" % page,
              bool(lists[0]) and all(g == lists[0] for g in got), [len(g or []) for g in got])
    for i, k in enumerate(keys + pre):
        delete(k, node=nodes[i % 2])
    st, _, body = req("GET", "/%s?list-type=2" % B)
    st2, _, body2 = req("DELETE", "/" + B)
    check("a sharded bucket whose every key is deleted still holds its versions",
          b"<Key>" not in body and (st2, xml_code(body2)) == (409, "BucketNotEmpty"), (st2, body2[:200]))


if MODE == "main":
    mode_main(int(sys.argv[2]), sys.argv[3])
elif MODE == "recovery":
    mode_recovery(int(sys.argv[2]), sys.argv[3])
elif MODE == "shards":
    mode_shards(sys.argv[2:])
else:
    print("unknown mode " + MODE)
    sys.exit(2)
sys.exit(failed)
