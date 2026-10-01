#!/usr/bin/env python3
"""Multipart parts written where the object needs them, over the runtime's unix nodes.

usage: lib_storage_mpu_inplace.py MODE DATA NODE... [-- PID...]

MODE is one of
  bytes     an upload of equal parts in order, with the bytes the workers wrote read
            from /proc/<pid>/io: once the object's size, and not twice
  shapes    every way a client can send parts, each read back whole, by range and by ETag
  before    parts of an upload left open for a restart, described in $MPU_STATE
  after     the upload from `before` completed after the restart
  shards    every step through another shard's node, on a runtime of several

A NODE is the path of a unix socket a runtime listens on; with several, the
runtime's shards, in order.  Prints one PASS or FAIL line per assertion and a
final "Results:" line, and exits with the number of failures.
"""
import hashlib
import http.client
import json
import os
import socket
import sys
import threading
import xml.etree.ElementTree as ET

MiB = 1 << 20
B = "mpi"
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, detail))


class UnixConn(http.client.HTTPConnection):
    def __init__(self, path, timeout=120):
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


def create(node, key):
    status, _, body = req(node, "POST", "/%s/%s?uploads" % (B, key))
    if status != 200:
        raise RuntimeError("create %s: %d %r" % (key, status, body[:200]))
    return ET.fromstring(body).findtext(NS + "UploadId")


def put_part(node, key, uid, n, body):
    status, h, data = req(node, "PUT", "/%s/%s?partNumber=%d&uploadId=%s" % (B, key, n, uid), body)
    if status != 200:
        raise RuntimeError("part %d of %s: %d %r" % (n, key, status, data[:200]))
    return h["etag"].strip('"')


def complete(node, key, uid, parts):
    x = "<CompleteMultipartUpload>" + "".join(
        "<Part><PartNumber>%d</PartNumber><ETag>\"%s\"</ETag></Part>" % (n, e) for n, e in parts) + \
        "</CompleteMultipartUpload>"
    status, _, body = req(node, "POST", "/%s/%s?uploadId=%s" % (B, key, uid), x.encode())
    etag = ""
    if status == 200:
        etag = (ET.fromstring(body).findtext(NS + "ETag") or "").strip('"')
    return status, etag


def list_parts(node, key, uid):
    status, _, body = req(node, "GET", "/%s/%s?uploadId=%s" % (B, key, uid))
    if status != 200:
        return None
    root = ET.fromstring(body)
    return [(int(p.findtext(NS + "PartNumber")), p.findtext(NS + "ETag").strip('"'), int(p.findtext(NS + "Size")))
            for p in root.findall(NS + "Part")]


def md5(b):
    return hashlib.md5(b).hexdigest()


def mp_etag(parts):
    return "%s-%d" % (hashlib.md5(b"".join(hashlib.md5(p).digest() for p in parts)).hexdigest(), len(parts))


def upload_dir(data, uid):
    return os.path.join(data, B, "mpu", uid)


def data_size(data, uid):
    try:
        return os.path.getsize(os.path.join(upload_dir(data, uid), "data"))
    except OSError:
        return -1


def tmp_files(data):
    try:
        return os.listdir(os.path.join(data, B, "tmp"))
    except FileNotFoundError:
        return []


def wait_for(fn, timeout=10.0):
    import time
    end = time.time() + timeout
    while time.time() < end:
        if fn():
            return True
        time.sleep(0.1)
    return fn()


def object_is(nodes, key, parts, label):
    """The object reads back as the parts, whole, by range and by ETag, through every node."""
    want = b"".join(parts)
    etag = mp_etag(parts)
    for i, node in enumerate(nodes):
        status, h, body = req(node, "GET", "/%s/%s" % (B, key))
        check("%s: GET through node %d is the parts joined (%d bytes)" % (label, i, len(want)),
              status == 200 and body == want, (status, len(body), len(want)))
        check("%s: and its ETag is md5 of the part md5s -%d" % (label, len(parts)),
              h.get("etag", "").strip('"') == etag and h.get("x-amz-mp-parts-count") == str(len(parts)),
              (h.get("etag"), etag, h.get("x-amz-mp-parts-count")))
        if len(want) > 3:
            for lo, hi in ((0, 0), (len(want) // 3, 2 * len(want) // 3), (len(want) - 2, len(want) - 1)):
                status, _, part = req(node, "GET", "/%s/%s" % (B, key), headers={"Range": "bytes=%d-%d" % (lo, hi)})
                check("%s: a range %d-%d is those bytes" % (label, lo, hi), status == 206 and part == want[lo:hi + 1],
                      (status, len(part)))
    status, h, _ = req(nodes[0], "HEAD", "/%s/%s" % (B, key))
    check("%s: HEAD says its length" % label, status == 200 and int(h.get("content-length", -1)) == len(want),
          (status, h.get("content-length")))


def write_bytes(pids):
    total = 0
    for p in pids:
        with open("/proc/%d/io" % p) as f:
            for line in f:
                if line.startswith("write_bytes:"):
                    total += int(line.split()[1])
    return total


def upload_parallel(nodes, key, parts, threads=4):
    """Parts sent at once on their own connections, each through the next node, as warp and the SDKs do."""
    uid = create(nodes[0], key)
    tags = [None] * len(parts)
    errs = []
    lock = threading.Lock()
    queue = list(range(len(parts)))

    def worker():
        while True:
            with lock:
                if not queue:
                    return
                i = queue.pop(0)
            try:
                tags[i] = put_part(nodes[i % len(nodes)], key, uid, i + 1, parts[i])
            except Exception as e:  # noqa: BLE001
                errs.append(e)
                return

    ts = [threading.Thread(target=worker) for _ in range(threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    if errs:
        raise errs[0]
    return uid, tags


# ─── modes ───────────────────────────────────────────────────────────────────

def mode_bytes(data, nodes, pids):
    req(nodes[0], "PUT", "/" + B)
    size, nparts = 16 * MiB, 4
    parts = [os.urandom(size) for _ in range(nparts)]
    before = write_bytes(pids)
    uid, tags = upload_parallel(nodes, "bytes/a", parts)
    status, _ = complete(nodes[-1], "bytes/a", uid, list(zip(range(1, nparts + 1), tags)))
    after = write_bytes(pids)
    total = size * nparts
    ratio = (after - before) / total
    print("  info: %d MiB stored in %d parts of %d MiB, the workers wrote %.1f MiB (%.3fx)" %
          (total // MiB, nparts, size // MiB, (after - before) / MiB, ratio))
    check("an upload of equal parts completes", status == 200, status)
    check("its bytes are written once, not copied at the end (%.3fx the object, at most 1.10x)" % ratio,
          0.95 <= ratio <= 1.10, ratio)
    object_is(nodes, "bytes/a", parts, "bytes")
    check("nothing is left of the upload", wait_for(lambda: not os.path.exists(upload_dir(data, uid))))
    check("and nothing in tmp/", wait_for(lambda: tmp_files(data) == []), tmp_files(data))


def mode_shapes(data, nodes):
    n = nodes[0]
    req(n, "PUT", "/" + B)
    P = 5 * MiB
    blk = [os.urandom(P) for _ in range(6)]
    tail = os.urandom(123457)

    # Out of order: the last part first, then the rest backwards.
    uid = create(n, "s/order")
    tags = {}
    for i in (4, 3, 1, 2):
        tags[i] = put_part(n, "s/order", uid, i, tail if i == 4 else blk[i - 1])
    parts = [blk[0], blk[1], blk[2], tail]
    status, etag = complete(n, "s/order", uid, sorted(tags.items()))
    check("parts sent out of order, the last first, complete", status == 200 and etag == mp_etag(parts), (status, etag))
    object_is(nodes, "s/order", parts, "out of order")

    # The last part first while bigger than the minimum, so it fixes too small a part size.
    uid = create(n, "s/lastbig")
    big = [os.urandom(P + 65536), os.urandom(P + 65536)]
    t3 = put_part(n, "s/lastbig", uid, 3, blk[3])
    t1 = put_part(n, "s/lastbig", uid, 1, big[0])
    t2 = put_part(n, "s/lastbig", uid, 2, big[1])
    status, _ = complete(n, "s/lastbig", uid, [(1, t1), (2, t2), (3, t3)])
    check("a big last part first, then bigger ones, completes", status == 200, status)
    object_is(nodes, "s/lastbig", big + [blk[3]], "big last part first")

    # Unequal sizes.
    uid = create(n, "s/unequal")
    sizes = [P + 10, P + 1, P + 5, 777]
    bodies = [os.urandom(s) for s in sizes]
    ts = [put_part(n, "s/unequal", uid, i + 1, b) for i, b in enumerate(bodies)]
    status, _ = complete(n, "s/unequal", uid, list(zip(range(1, 5), ts)))
    check("parts of unequal sizes complete", status == 200, status)
    object_is(nodes, "s/unequal", bodies, "unequal")

    # Gaps in the numbers.
    uid = create(n, "s/gaps")
    ts = [put_part(n, "s/gaps", uid, num, blk[i]) for i, num in enumerate((2, 5, 9))]
    status, _ = complete(n, "s/gaps", uid, list(zip((2, 5, 9), ts)))
    check("parts numbered with gaps complete", status == 200, status)
    object_is(nodes, "s/gaps", blk[:3], "gaps")

    # A part sent again, the same size and another size.
    uid = create(n, "s/again")
    t1 = put_part(n, "s/again", uid, 1, blk[0])
    t2 = put_part(n, "s/again", uid, 2, blk[1])
    t2b = put_part(n, "s/again", uid, 2, blk[2])
    t1b = put_part(n, "s/again", uid, 1, blk[3])
    lp = list_parts(n, "s/again", uid)
    check("a part sent again has the new ETag in the list",
          lp == [(1, md5(blk[3]), P), (2, md5(blk[2]), P)], lp)
    status, _ = complete(n, "s/again", uid, [(1, t1b), (2, t2b)])
    check("and the upload completes with the parts as last sent", status == 200, status)
    object_is(nodes, "s/again", [blk[3], blk[2]], "sent again, same size")
    check("the old ETags were the old bodies'", t1 == md5(blk[0]) and t2 == md5(blk[1]))
    uid = create(n, "s/again2")
    t1 = put_part(n, "s/again2", uid, 1, blk[0])
    t2 = put_part(n, "s/again2", uid, 2, blk[1])
    small = os.urandom(4097)
    bigger = os.urandom(P + 3)
    t2b = put_part(n, "s/again2", uid, 2, small)
    t1b = put_part(n, "s/again2", uid, 1, bigger)
    status, _ = complete(n, "s/again2", uid, [(1, t1b), (2, t2b)])
    check("a part sent again with another size completes", status == 200, status)
    object_is(nodes, "s/again2", [bigger, small], "sent again, other size")

    # Two uploads of one number at once.
    uid = create(n, "s/race")
    t1 = put_part(n, "s/race", uid, 1, blk[0])
    racers = [os.urandom(P), os.urandom(P)]
    conns = []
    for i, body in enumerate(racers):
        c = UnixConn(nodes[i % len(nodes)])
        c.putrequest("PUT", "/%s/s/race?partNumber=2&uploadId=%s" % (B, uid))
        c.putheader("Content-Length", str(len(body)))
        c.endheaders()
        c.send(body[:len(body) // 2])
        conns.append(c)
    for c, body in zip(conns, racers):
        c.send(body[len(body) // 2:])
    codes = []
    for c in conns:
        r = c.getresponse()
        r.read()
        codes.append(r.status)
        c.close()
    check("two uploads of one part number at once are both answered", codes == [200, 200], codes)
    lp = list_parts(n, "s/race", uid)
    won = [b for b in racers if lp and len(lp) == 2 and lp[1][1] == md5(b)]
    check("and the part is one of them, whole", len(won) == 1, lp)
    status, _ = complete(n, "s/race", uid, [(1, t1), (2, md5(won[0]) if won else "")])
    check("the upload completes with it", status == 200, status)
    if won:
        object_is(nodes, "s/race", [blk[0], won[0]], "raced")

    # Abort.
    uid = create(n, "s/abort")
    put_part(n, "s/abort", uid, 1, blk[0])
    put_part(n, "s/abort", uid, 2, blk[1])
    check("an upload's parts are in its data file", data_size(data, uid) >= 2 * P)
    status, _, _ = req(n, "DELETE", "/%s/s/abort?uploadId=%s" % (B, uid))
    check("an abort answers 204", status == 204, status)
    check("and removes the upload with its data file", wait_for(lambda: not os.path.exists(upload_dir(data, uid))))
    status, _ = complete(n, "s/abort", uid, [(1, md5(blk[0]))])
    check("and completing it is NoSuchUpload", status == 404, status)

    check("nothing is left in tmp/", wait_for(lambda: tmp_files(data) == []), tmp_files(data))
    check("and no upload is left", wait_for(lambda: os.listdir(os.path.join(data, B, "mpu")) == []),
          os.listdir(os.path.join(data, B, "mpu")))


def mode_before(data, nodes):
    n = nodes[0]
    req(n, "PUT", "/" + B)
    parts = [os.urandom(8 * MiB), os.urandom(8 * MiB)]
    uid = create(n, "r/one")
    tags = [put_part(n, "r/one", uid, i + 1, p) for i, p in enumerate(parts)]
    check("parts before the restart are in the upload's data file",
          data_size(data, uid) >= 16 * MiB)
    with open(os.environ["MPU_STATE"], "w") as f:
        json.dump({"uid": uid, "tags": tags}, f)
    with open(os.environ["MPU_STATE"] + ".blobs", "wb") as f:
        f.write(b"".join(parts))


def mode_after(data, nodes):
    n = nodes[0]
    with open(os.environ["MPU_STATE"]) as f:
        st = json.load(f)
    with open(os.environ["MPU_STATE"] + ".blobs", "rb") as f:
        blobs = f.read()
    parts = [blobs[:8 * MiB], blobs[8 * MiB:]]
    lp = list_parts(n, "r/one", st["uid"])
    check("after a restart the upload lists the parts sent before it",
          lp == [(1, st["tags"][0], 8 * MiB), (2, st["tags"][1], 8 * MiB)], lp)
    third = os.urandom(8 * MiB)
    last = os.urandom(1001)
    t3 = put_part(n, "r/one", st["uid"], 3, third)
    t4 = put_part(n, "r/one", st["uid"], 4, last)
    status, etag = complete(n, "r/one", st["uid"], [(1, st["tags"][0]), (2, st["tags"][1]), (3, t3), (4, t4)])
    check("and it completes with parts sent after it", status == 200 and etag == mp_etag(parts + [third, last]),
          (status, etag))
    object_is(nodes, "r/one", parts + [third, last], "across a restart")
    check("nothing is left of it", wait_for(lambda: not os.path.exists(upload_dir(data, st["uid"]))))


def mode_shards(data, nodes, pids):
    n = len(nodes)
    req(nodes[0], "PUT", "/" + B)
    P = 6 * MiB
    for round_ in range(4):
        key = "sh/k%d" % round_
        parts = [os.urandom(P) for _ in range(5)] + [os.urandom(12345)]
        # Every part through another node than the one before it, and the completion through yet another.
        uid = create(nodes[round_ % n], key)
        order = [6, 2, 1, 5, 3, 4] if round_ % 2 else [1, 2, 3, 4, 5, 6]
        tags = {}
        for j, num in enumerate(order):
            tags[num] = put_part(nodes[(round_ + j) % n], key, uid, num, parts[num - 1])
        status, etag = complete(nodes[(round_ + 3) % n], key, uid, sorted(tags.items()))
        check("round %d: parts through every shard complete through another" % round_,
              status == 200 and etag == mp_etag(parts), (status, etag))
        object_is(nodes, key, parts, "shards round %d" % round_)

    # The same part number through two shards at once.
    uid = create(nodes[1], "sh/race")
    t1 = put_part(nodes[2], "sh/race", uid, 1, os.urandom(P))
    racers = [os.urandom(P), os.urandom(P)]
    conns = []
    for i, body in enumerate(racers):
        c = UnixConn(nodes[i])
        c.putrequest("PUT", "/%s/sh/race?partNumber=2&uploadId=%s" % (B, uid))
        c.putheader("Content-Length", str(len(body)))
        c.endheaders()
        c.send(body[:len(body) // 2])
        conns.append(c)
    for c, body in zip(conns, racers):
        c.send(body[len(body) // 2:])
    codes = []
    for c in conns:
        r = c.getresponse()
        r.read()
        codes.append(r.status)
        c.close()
    check("two shards taking one part number at once both answer", codes == [200, 200], codes)
    lp = list_parts(nodes[3], "sh/race", uid)
    won = [b for b in racers if lp and len(lp) == 2 and lp[1][1] == md5(b)]
    check("and the part is one of them", len(won) == 1, lp)
    status, _ = complete(nodes[3], "sh/race", uid, [(1, t1), (2, md5(won[0]) if won else "")])
    check("and it completes", status == 200, status)
    if won:
        status, _, body = req(nodes[0], "GET", "/%s/sh/race" % B)
        check("with that part's bytes", status == 200 and body[P:] == won[0], (status, len(body)))

    # Abort through a shard that does not own the upload.
    uid = create(nodes[0], "sh/abort")
    put_part(nodes[1], "sh/abort", uid, 1, os.urandom(P))
    put_part(nodes[2], "sh/abort", uid, 2, os.urandom(P))
    status, _, _ = req(nodes[3], "DELETE", "/%s/sh/abort?uploadId=%s" % (B, uid))
    check("an abort through another shard answers 204", status == 204, status)
    check("and removes the upload with its data file", wait_for(lambda: not os.path.exists(upload_dir(data, uid))))

    # The bytes written, across every shard's worker.
    parts = [os.urandom(16 * MiB) for _ in range(4)]
    before = write_bytes(pids)
    uid, tags = upload_parallel(nodes, "sh/bytes", parts)
    status, _ = complete(nodes[2], "sh/bytes", uid, list(zip(range(1, 5), tags)))
    after = write_bytes(pids)
    ratio = (after - before) / (64 * MiB)
    print("  info: 64 MiB through %d shards, their workers wrote %.1f MiB (%.3fx)" % (n, (after - before) / MiB, ratio))
    check("on %d shards an upload of equal parts is written once too (%.3fx, at most 1.10x)" % (n, ratio),
          status == 200 and 0.95 <= ratio <= 1.10, (status, ratio))
    object_is(nodes[:1], "sh/bytes", parts, "shards bytes")
    check("nothing is left in tmp/", wait_for(lambda: tmp_files(data) == []), tmp_files(data))


def main():
    mode, data = sys.argv[1], sys.argv[2]
    rest = sys.argv[3:]
    pids = []
    if "--" in rest:
        k = rest.index("--")
        pids = [int(p) for p in rest[k + 1:]]
        rest = rest[:k]
    nodes = rest
    if mode == "bytes":
        mode_bytes(data, nodes, pids)
    elif mode == "shapes":
        mode_shapes(data, nodes)
    elif mode == "before":
        mode_before(data, nodes)
    elif mode == "after":
        mode_after(data, nodes)
    elif mode == "shards":
        mode_shards(data, nodes, pids)
    total = passed + failed
    print("  Results: %d/%d passed (%d failed)" % (passed, total, failed))
    sys.exit(min(failed, 100))


main()
