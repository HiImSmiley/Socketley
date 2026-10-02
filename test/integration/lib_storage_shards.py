#!/usr/bin/env python3
"""A sharded storage runtime, driven through the node of each shard.

usage: lib_storage_shards.py MODE ARGS...

Every shard of a runtime made with --listen unix:PATH --shards N has a node of
its own, PATH with "#i" before the ".sock", so a request can be sent to a
chosen shard and the crossing it causes is the one the test asked for.  The
modes print one PASS or FAIL line per assertion and a final "Results:" line,
and exit with the number of failures.

  storm    BIN NODE...             one key put at once through every shard
  cross    BIN NODE...             keys put through their owner cross nothing,
                                   through any other shard cross exactly once
  populate NODE...                 a fixed set of keys, spread over the shards
  verify   PRIOR NODE...           every key of populate and the PRIOR later keys, read
                                   whole from every node and listed by every node,
                                   then one more key put
  equiv    -- NODES4... -- NODES1... a listing through each of the first nodes is
                                   the listing of the last, page for page
  copy     NODE...                 CopyObject and create-only puts through every shard
  owner    BUCKET KEY N            the shard that owns the key, printed
  slow_put NODE BUCKET KEY BYTES READY RELEASE
                                   a put whose body is sent in two halves
"""
import base64
import hashlib
import http.client
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET

import lib_s3_signing as sig

NS ="{http://s3.amazonaws.com/doc/2006-03-01/}"

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, detail))


def finish():
    print("Results: %d passed, %d failed" % (passed, failed))
    sys.exit(min(failed, 100))


# ── The owner of a key, as a client computes it ─────────────────────────────
def crc16(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def owner(bucket, key, n):
    slot = crc16((bucket + "/" + key).encode()) & 16383
    return 0 if n <= 1 else slot * n // 16384


# ── HTTP over a node ────────────────────────────────────────────────────────
class UnixConn(http.client.HTTPConnection):
    def __init__(self, path, timeout=30):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def req(node, method, path, body=None, headers=None):
    c = UnixConn(node)
    try:
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data
    finally:
        c.close()


def q(key):
    return urllib.parse.quote(key, safe="/")


def list_pages(node, bucket, prefix="", delimiter="", max_keys=1000, start_after=""):
    """Every page of one query, as (keys, prefixes, truncated), following the tokens."""
    pages = []
    token = None
    for _ in range(5000):
        params = {"list-type": "2", "max-keys": str(max_keys)}
        if prefix:
            params["prefix"] = prefix
        if delimiter:
            params["delimiter"] = delimiter
        if start_after:
            params["start-after"] = start_after
        if token:
            params["continuation-token"] = token
        status, _, body = req(node, "GET", "/%s?%s" % (bucket, urllib.parse.urlencode(params)))
        if status != 200:
            return None
        root = ET.fromstring(body)
        keys = [c.findtext(NS + "Key") for c in root.findall(NS + "Contents")]
        prefixes = [c.findtext(NS + "Prefix") for c in root.findall(NS + "CommonPrefixes")]
        trunc = root.findtext(NS + "IsTruncated") == "true"
        pages.append((keys, prefixes, trunc))
        if not trunc:
            break
        token = root.findtext(NS + "NextContinuationToken")
    return pages


def stats(binary):
    """The per-shard figures `stats` prints once they have stopped moving, as {shard: {name: value}}.

    The workers publish on an interval, so a read straight after a request can
    be a figure behind; two equal reads a moment apart are not.
    """
    last = None
    for _ in range(60):
        cur = stats_once(binary)
        if cur == last:
            return cur
        last = cur
        time.sleep(0.7)
    return last


def stats_once(binary):
    out = subprocess.run([binary, "stats", os.environ.get("STG_NAME", "stg")],
                         capture_output=True, text=True).stdout
    shards, cur = {}, None
    for line in out.splitlines():
        if line.startswith("[shard "):
            cur = int(line[7:].rstrip("]"))
            shards[cur] = {}
        elif cur is not None and ":" in line:
            k, v = line.split(":", 1)
            shards[cur][k] = v
    return shards


def total(shards, name):
    return sum(int(s.get(name, "0")) for s in shards.values())


def body_for(i):
    """A body that is a function of i, so a reader can say what it should hold."""
    seed = hashlib.sha256(b"body%d" % i).digest()
    n = 200 + (i * 7919) % 90000
    return (seed * (n // 32 + 1))[:n]


# ── modes ───────────────────────────────────────────────────────────────────
def mode_storm(binary, nodes):
    bucket = "storm"
    st, _, _ = req(nodes[0], "PUT", "/" + bucket)
    check("the bucket is made through shard 0", st == 200, st)

    rounds, per_node = 25, 4
    torn = 0
    disagreements = 0
    index_disagrees = 0
    unknown = 0
    for rnd in range(rounds):
        bodies = {}
        errors = []
        lock = threading.Lock()

        def writer(node, tag):
            b = hashlib.sha256(b"r%d-%s" % (rnd, tag.encode())).digest() * (4000 + 97 * len(tag))
            with lock:
                bodies[hashlib.md5(b).hexdigest()] = b
            try:
                s, _, _ = req(node, "PUT", "/%s/contended" % bucket, body=b)
                if s != 200:
                    errors.append(s)
            except Exception as e:      # noqa: BLE001
                errors.append(repr(e))

        threads = [threading.Thread(target=writer, args=(nodes[k % len(nodes)], "n%d-w%d" % (k % len(nodes), k)))
                   for k in range(per_node * len(nodes))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if errors:
            check("every put of round %d was answered 200" % rnd, False, errors)
            continue

        seen = []
        for node in nodes:
            s, h, b = req(node, "GET", "/%s/contended" % bucket)
            md5 = hashlib.md5(b).hexdigest()
            if s != 200 or h.get("etag", "").strip('"') != md5:
                torn += 1
            if md5 not in bodies or b != bodies[md5]:
                unknown += 1
            seen.append(md5)
            # The listing is the owner's index and the GET is the file, and they name one object.
            ls, _, lb = req(node, "GET", "/%s?list-type=2&prefix=contended" % bucket)
            etags = [c.findtext(NS + "ETag").strip('"') for c in ET.fromstring(lb).findall(NS + "Contents")] \
                if ls == 200 else []
            if etags != [md5]:
                index_disagrees += 1
        if len(set(seen)) != 1:
            disagreements += 1
    check("no read was torn: the ETag is the MD5 of the bytes read", torn == 0, "%d torn reads" % torn)
    check("every read was one of the bodies written, whole", unknown == 0, "%d unknown bodies" % unknown)
    check("in every round all four shards served the same object", disagreements == 0,
          "%d rounds disagreed" % disagreements)
    check("and every listing named the object the GET returned, once", index_disagrees == 0,
          "%d listings disagreed" % index_disagrees)

    pages = list_pages(nodes[-1], bucket)
    check("the key is listed exactly once through the last shard", pages and pages[0][0] == ["contended"], pages)
    sh = stats(binary)
    check("puts crossed between shards", total(sh, "shard_commits_sent") > 50, total(sh, "shard_commits_sent"))
    check("and every crossing was served by an owner",
          total(sh, "shard_commits_sent") == total(sh, "shard_commits_served"),
          "%d sent, %d served" % (total(sh, "shard_commits_sent"), total(sh, "shard_commits_served")))
    check("no crossing failed", total(sh, "shard_peer_failures") == 0, total(sh, "shard_peer_failures"))


def mode_cross(binary, nodes):
    n = len(nodes)
    bucket = "cross"
    st, _, _ = req(nodes[2 % n], "PUT", "/" + bucket)
    check("the bucket is made", st == 200, st)
    before = stats(binary)
    sent0 = total(before, "shard_commits_sent")

    keys = ["k%03d" % i for i in range(60)]
    for i, k in enumerate(keys):
        o = owner(bucket, k, n)
        s, _, _ = req(nodes[o], "PUT", "/%s/%s" % (bucket, k), body=body_for(i))
        if s != 200:
            check("put %s through its owner" % k, False, s)
    mid = stats(binary)
    check("keys put through their own shard cross nothing (owner computed by the client)",
          total(mid, "shard_commits_sent") == sent0,
          "%d crossed" % (total(mid, "shard_commits_sent") - sent0))

    served0 = {s: int(mid[s]["shard_commits_served"]) for s in mid}
    expect_at = {s: 0 for s in range(n)}
    for i, k in enumerate(keys):
        o = owner(bucket, k, n)
        landing = (o + 1) % n
        expect_at[o] += 1
        s, _, _ = req(nodes[landing], "PUT", "/%s/%s" % (bucket, k), body=body_for(i + 1000))
        if s != 200:
            check("put %s through another shard" % k, False, s)
    after = stats(binary)
    check("keys put through any other shard cross exactly once each",
          total(after, "shard_commits_sent") - sent0 == len(keys),
          total(after, "shard_commits_sent") - sent0)
    got_at = {s: int(after[s]["shard_commits_served"]) - served0[s] for s in after}
    check("and each is served by the shard the client computed", got_at == expect_at, "%s vs %s" % (got_at, expect_at))
    held = {s: int(after[s]["objects"]) - int(before[s]["objects"]) for s in after}
    check("each shard holds the keys it owns and no others", sum(held.values()) == len(keys) and all(
        held[s] == sum(1 for k in keys if owner(bucket, k, n) == s) for s in held), held)
    check("the keys are spread over the shards", all(v > 0 for v in held.values()), held)


def populate_keys():
    keys = []
    for d in range(5):
        for s in range(3):
            for f in range(8):
                keys.append("dir%d/sub%d/file%02d" % (d, s, f))
    keys += ["top%02d" % i for i in range(30)]
    keys += ["dir0", "dir0.txt", "dir1/", "a", "zzz", "dir4/sub2/file07x", "sp ace/na+me", "uni/éè"]
    return keys


def mode_populate(nodes):
    bucket = "pop"
    st, _, _ = req(nodes[0], "PUT", "/" + bucket)
    check("the bucket is made", st in (200, 409), st)
    bad = 0
    for i, k in enumerate(populate_keys()):
        s, _, _ = req(nodes[i % len(nodes)], "PUT", "/%s/%s" % (bucket, q(k)), body=body_for(i))
        bad += s != 200
    check("every key is put through a shard that rotates", bad == 0, "%d refused" % bad)


def mode_verify(prior, nodes):
    """Every key of populate and of the `prior` later keys, from every node; then one more key."""
    bucket = "pop"
    prior = int(prior)
    keys = populate_keys()
    later = ["later%d" % i for i in range(prior)]
    everything = keys + later
    for ni, node in enumerate(nodes):
        wrong = 0
        for i, k in enumerate(keys):
            s, h, b = req(node, "GET", "/%s/%s" % (bucket, q(k)))
            if s != 200 or b != body_for(i) or h.get("etag", "").strip('"') != hashlib.md5(body_for(i)).hexdigest():
                wrong += 1
        for k in later:
            s, _, b = req(node, "GET", "/%s/%s" % (bucket, k))
            wrong += s != 200 or b != b"later"
        check("node %d serves every key whole" % ni, wrong == 0, "%d wrong" % wrong)
        wrong = 0
        for i, k in enumerate(keys):
            s, h, b = req(node, "HEAD", "/%s/%s" % (bucket, q(k)))
            if s != 200 or int(h.get("content-length", "-1")) != len(body_for(i)) \
                    or h.get("etag", "").strip('"') != hashlib.md5(body_for(i)).hexdigest():
                wrong += 1
        check("node %d answers a HEAD for every key" % ni, wrong == 0, "%d wrong" % wrong)
        pages = list_pages(node, bucket)
        listed = sorted(k for p in pages for k in p[0]) if pages else None
        check("node %d lists exactly the keys" % ni, listed == sorted(everything),
              "%s vs %s" % (None if listed is None else len(listed), len(everything)))
        pages = list_pages(node, bucket, delimiter="/", max_keys=3)
        names = sorted(x for p in pages for x in p[0] + p[1]) if pages else None
        want = sorted({k.split("/")[0] + "/" if "/" in k else k for k in everything})
        check("node %d lists the top level page by page" % ni, names == want, "%s" % names)
    k = "later%d" % prior
    s, _, _ = req(nodes[prior % len(nodes)], "PUT", "/%s/%s" % (bucket, k), body=b"later")
    check("a put after the change lands through node %d" % (prior % len(nodes)), s == 200, s)


def mode_copy(nodes):
    """CopyObject asked of every shard, between keys whose owners differ."""
    n = len(nodes)
    bucket = "cpy"
    st, _, _ = req(nodes[0], "PUT", "/" + bucket)
    check("the bucket is made", st in (200, 409), st)
    bad = 0
    made = 0
    copied = []
    for i in range(40):
        src, dst = "src%d" % i, "dst%d" % i
        if n > 1 and owner(bucket, src, n) == owner(bucket, dst, n):
            continue
        body = body_for(i)
        s, _, _ = req(nodes[i % n], "PUT", "/%s/%s" % (bucket, src), body=body)
        if s != 200:
            bad += 1
            continue
        # Asked of a shard that owns neither, where there is one.
        landing = next((x for x in range(n) if x != owner(bucket, src, n) and x != owner(bucket, dst, n)), 0)
        s, _, cb = req(nodes[landing], "PUT", "/%s/%s" % (bucket, dst), headers={"x-amz-copy-source": "/%s/%s" % (bucket, src)})
        if s != 200 or hashlib.md5(body).hexdigest() not in cb.decode():
            bad += 1
            continue
        made += 1
        copied.append(i)
        for node in nodes:
            s, _, got = req(node, "GET", "/%s/%s" % (bucket, dst))
            bad += s != 200 or got != body
    check("copies made through a shard that owns neither key are whole on every shard", bad == 0 and made >= 10,
          "%d wrong, %d made" % (bad, made))
    # The default checksum a put is given wherever it lands, which its copy keeps, read alike through every shard.
    wrong = []
    for i in copied:
        for key in ("src%d" % i, "dst%d" % i):
            for node in nodes:
                s, h, _ = req(node, "HEAD", "/%s/%s" % (bucket, key), headers={"x-amz-checksum-mode": "ENABLED"})
                if (s, h.get("x-amz-checksum-crc64nvme")) != (200, sig.crc64nvme_b64(body_for(i))):
                    wrong.append((key, node, s, h.get("x-amz-checksum-crc64nvme")))
    check("every source and copy answers the CRC64NVME of its bytes through every shard", not wrong and made >= 10,
          wrong[:3])
    # A copy onto itself naming an algorithm is allowed through a shard that does not own the key.
    key = "dst%d" % copied[0]
    landing = next((x for x in range(n) if x != owner(bucket, key, n)), 0)
    s, _, cb = req(nodes[landing], "PUT", "/%s/%s" % (bucket, key),
                   headers={"x-amz-copy-source": "/%s/%s" % (bucket, key), "x-amz-checksum-algorithm": "SHA256"})
    want = base64.b64encode(hashlib.sha256(body_for(copied[0])).digest()).decode()
    got = [req(node, "HEAD", "/%s/%s" % (bucket, key), headers={"x-amz-checksum-mode": "ENABLED"})[1].get(
        "x-amz-checksum-sha256") for node in nodes]
    check("a copy onto itself naming SHA256 through another shard gives it the SHA-256 on every shard",
          s == 200 and got == [want] * n, (s, cb[:200], got))
    # A copy onto itself is refused, and so is a missing source, wherever they are asked.
    for node in nodes:
        s, _, _ = req(node, "PUT", "/%s/src1" % bucket, headers={"x-amz-copy-source": "/%s/nothing" % bucket})
        check("a missing copy source is NoSuchKey through every shard", s == 404, s)
    # If-None-Match: * is decided by the owner, wherever the put lands.
    for i, node in enumerate(nodes):
        s, _, _ = req(node, "PUT", "/%s/src1" % bucket, body=b"other", headers={"If-None-Match": "*"})
        check("a create-only put over an existing key is refused through shard %d" % i, s == 412, s)
    s, _, got = req(nodes[0], "GET", "/%s/src1" % bucket)
    check("and the object is as it was", s == 200 and got == body_for(1), s)
    codes = [req(node, "PUT", "/%s/fresh%d" % (bucket, i), body=b"x", headers={"If-None-Match": "*"})[0]
             for i, node in enumerate(nodes)]
    check("a create-only put of a new key succeeds through every shard", codes == [200] * n, codes)


def mode_equiv(args):
    # -- NODES4... -- NODES1...
    i = args.index("--", 1)
    many, one = args[1:i], args[i + 1:]
    bucket = "pop"
    queries = [
        ("", "", 1000, ""), ("", "", 7, ""), ("", "/", 1000, ""), ("", "/", 2, ""), ("", "/", 1, ""),
        ("dir1/", "/", 2, ""), ("dir1/", "", 10, ""), ("dir2/sub1/", "/", 3, ""), ("top", "", 11, ""),
        ("dir", "/", 4, ""), ("dir", "", 5, "dir1/sub1/file4"), ("", "/", 3, "dir2/"), ("", "sub", 6, ""),
        ("dir3/", "sub", 2, ""), ("nomatch", "", 10, ""),
    ]
    for (prefix, delim, mk, after) in queries:
        want = list_pages(one[0], bucket, prefix, delim, mk, after)
        label = "prefix=%r delimiter=%r max-keys=%d start-after=%r" % (prefix, delim, mk, after)
        check("one shard answers " + label, want is not None, want)
        for ni, node in enumerate(many):
            got = list_pages(node, bucket, prefix, delim, mk, after)
            check("shard %d gives the same pages: %s" % (ni, label), got == want,
                  "%s vs %s" % (got, want))


def mode_slow_put(node, bucket, key, nbytes, ready, release):
    nbytes = int(nbytes)
    body = (b"slow-body-" * (nbytes // 10 + 1))[:nbytes]
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(node)
    head = ("PUT /%s/%s HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % (bucket, q(key), nbytes)).encode()
    s.sendall(head + body[: nbytes // 2])
    open(ready, "w").write("1")
    for _ in range(600):
        if os.path.exists(release):
            break
        time.sleep(0.1)
    try:
        s.sendall(body[nbytes // 2:])
        data = s.recv(4096)
        print(data.split(b"\r\n", 1)[0].decode())
    except OSError as e:
        print("error", e)


def main():
    mode = sys.argv[1]
    if mode == "storm":
        mode_storm(sys.argv[2], sys.argv[3:])
    elif mode == "cross":
        mode_cross(sys.argv[2], sys.argv[3:])
    elif mode == "populate":
        mode_populate(sys.argv[2:])
    elif mode == "verify":
        mode_verify(sys.argv[2], sys.argv[3:])
    elif mode == "equiv":
        mode_equiv(sys.argv[1:])
    elif mode == "copy":
        mode_copy(sys.argv[2:])
    elif mode == "owner":
        print(owner(sys.argv[2], sys.argv[3], int(sys.argv[4])))
        return
    elif mode == "slow_put":
        mode_slow_put(*sys.argv[2:8])
        return
    else:
        print("unknown mode " + mode)
        sys.exit(99)
    finish()


main()
