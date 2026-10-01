#!/usr/bin/env python3
"""A storage runtime whose disk fills, and what it keeps.

usage: lib_storage_diskfull.py LABEL PORT DATA_DIR MOUNT_DIR RUNTIME_NAME

DATA_DIR is on a small filesystem mounted at MOUNT_DIR (a tmpfs or an ext4 in a
loop file).  Uploads that run out of room must be answered with an S3 error
document rather than a hang or a reset, must leave no object and no temporary
file, and must not touch anything already stored; a disk that is full to the
last block must still be answerable; and once space comes back the same runtime,
without a restart, stores again.
"""
import hashlib
import http.client
import os
import re
import socket
import subprocess
import sys
import threading
import time

LABEL = sys.argv[1]
PORT = int(sys.argv[2])
DATA = sys.argv[3]
MNT = sys.argv[4]
NAME = sys.argv[5]
BIN = os.environ["BIN"]

passed = failed = 0
lock = threading.Lock()


def check(name, cond, detail=""):
    global passed, failed
    with lock:
        if cond:
            passed += 1
            print("  PASS: [%s] %s" % (LABEL, name), flush=True)
        else:
            failed += 1
            print("  FAIL [%s: %s]: %s" % (LABEL, name, str(detail)[:400]), flush=True)


def note(msg):
    print("  [%s] %s" % (LABEL, msg), flush=True)


def free_bytes():
    v = os.statvfs(MNT)
    return v.f_bavail * v.f_frsize


def stats():
    out = subprocess.run([BIN, "stats", NAME], capture_output=True, text=True).stdout
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d


def worker_fds():
    return len(os.listdir("/proc/%s/fd" % stats()["pid"]))


def request(method, path, body=None, headers=None, timeout=60):
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        data = r.read()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data
    finally:
        conn.close()


def code_of(body):
    m = re.search(rb"<Code>([^<]*)</Code>", body)
    return m.group(1).decode() if m else None


def streamed_put(path, size, extra=b"", piece=256 << 10):
    """A PUT of size bytes sent in pieces; returns (status, code, bytes actually sent, md5 of what was sent)."""
    s = socket.create_connection(("127.0.0.1", PORT), timeout=60)
    s.sendall(b"PUT %s HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n%s\r\n" % (path.encode(), size, extra))
    md5 = hashlib.md5()
    sent = 0
    block = os.urandom(piece)
    try:
        while sent < size:
            n = min(piece, size - sent)
            s.sendall(block[:n])
            md5.update(block[:n])
            sent += n
    except OSError:
        pass                              # the runtime answered early and closed
    data = b""
    s.settimeout(30)
    try:
        while b"\r\n\r\n" not in data:
            c = s.recv(65536)
            if not c:
                break
            data += c
    except OSError as e:
        data = data or repr(e).encode()
    try:
        body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
        if b"content-length" in data.lower():
            m = re.search(rb"(?i)content-length: (\d+)", data)
            want = int(m.group(1))
            s.settimeout(5)
            while len(body) < want:
                c = s.recv(65536)
                if not c:
                    break
                body += c
    except OSError:
        body = b""
    s.close()
    status = int(data.split(b" ", 2)[1]) if data.startswith(b"HTTP/") else -1
    return status, code_of(body), sent, md5.hexdigest()


def keys_of(bucket):
    st, _, body = request("GET", "/%s?list-type=2&max-keys=1000" % bucket)
    return sorted(k.decode() for k in re.findall(rb"<Key>([^<]*)</Key>", body)) if st == 200 else None


def tmp_files(bucket):
    try:
        return os.listdir(os.path.join(DATA, bucket, "tmp"))
    except FileNotFoundError:
        return []


def wait_for(fn, secs, step=0.1):
    end = time.time() + secs
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(step)
    return fn()


def restart_runtime():
    subprocess.run([BIN, "stop", NAME], capture_output=True)
    time.sleep(0.5)
    subprocess.run([BIN, "start", NAME], capture_output=True)
    for _ in range(100):
        try:
            if request("GET", "/", timeout=2)[0] == 200:
                return True
        except OSError:
            pass
        time.sleep(0.1)
    return False


print("=== [%s] a disk that fills ===" % LABEL)
request("PUT", "/full")
request("PUT", "/other")
seed = {}
for i in range(5):
    body = os.urandom(200000 + i * 1111)
    st, hd, _ = request("PUT", "/full/seed%d" % i, body=body, headers={"Content-Type": "application/x-seed"})
    seed["seed%d" % i] = body
    check("seed%d is stored" % i, st == 200)
free0 = free_bytes()
note("free on the filesystem after seeding: %d KiB" % (free0 >> 10))


def seeds_intact(what):
    bad = []
    for k, body in seed.items():
        st, hd, got = request("GET", "/full/" + k)
        if st != 200 or got != body or hd.get("content-type") != "application/x-seed":
            bad.append((k, st, len(got)))
    check("%s: every earlier object is served with its own bytes and headers" % what, not bad, bad)
    check("%s: the listing names exactly the earlier objects and what was acknowledged since" % what,
          keys_of("full") == sorted(list(seed) + sorted(extra_ok)), (keys_of("full"), sorted(seed)))


extra_ok = {}

# 1. One upload larger than the room left.
fds0 = worker_fds()
size = free0 + (4 << 20)
st, code, sent, _ = streamed_put("/full/too-big", size)
note("PUT of %d KiB into %d KiB free: %s %s after %d KiB sent" % (size >> 10, free0 >> 10, st, code, sent >> 10))
check("a PUT larger than the room left is answered with an S3 error document, 5xx StorageFull (507)",
      st == 507 and code == "StorageFull", (st, code))
check("it left no temporary file and no object", wait_for(lambda: not tmp_files("full"), 10) and
      request("HEAD", "/full/too-big")[0] == 404, tmp_files("full"))
seeds_intact("after one refused upload")
check("the runtime answers a small GET at once", request("GET", "/full/seed0")[0] == 200)

# 2. The same again: nothing leaks.
def refused_round(tag):
    for i in range(8):
        st, code, sent, _ = streamed_put("/full/too-big-%s-%d" % (tag, i), free0 + (1 << 20))
        if st != 507 or code != "StorageFull":
            check("refused upload %s-%d is StorageFull" % (tag, i), False, (st, code))
    wait_for(lambda: not tmp_files("full"), 10)
    return worker_fds()


fds1 = refused_round("a")
fds2 = refused_round("b")
note("worker descriptors: %d before, %d after eight refusals, %d after eight more" % (fds0, fds1, fds2))
check("eight more refused uploads add no descriptor to the worker (%d after the first eight, %d after the next)" %
      (fds1, fds2), fds2 <= fds1, (fds0, fds1, fds2))
check("and no temporary file", not tmp_files("full"), tmp_files("full"))

# 3. The disk full to the last block.
filler_dir = os.path.join(MNT, "filler")
os.makedirs(filler_dir, exist_ok=True)
n = 0
while True:
    try:
        with open(os.path.join(filler_dir, "f%d" % n), "wb") as f:
            for _ in range(64):
                f.write(b"\0" * 4096)
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        break
    n += 1
    if free_bytes() < 256 << 10:
        break
# Then the last blocks, a file at a time, down to nothing.
n2 = 0
while free_bytes() > 0:
    try:
        with open(os.path.join(filler_dir, "s%d" % n2), "wb") as f:
            f.write(b"\0" * min(4096, max(free_bytes(), 1)))
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        break
    n2 += 1
    if n2 > 5000:
        break
note("the filesystem is full: %d bytes free" % free_bytes())

st, hd, body = request("PUT", "/full/on-a-full-disk", body=b"small")
check("a PUT of 5 bytes to a full disk is a 5xx S3 error (507 StorageFull or 500 InternalError), not a hang or a reset",
      st in (500, 507) and code_of(body) in ("StorageFull", "InternalError"), (st, body[:200]))
check("and left nothing", request("HEAD", "/full/on-a-full-disk")[0] == 404 and wait_for(lambda: not tmp_files("full"), 5),
      tmp_files("full"))
st, hd, body = request("PUT", "/full/copy-of-seed", headers={"x-amz-copy-source": "/full/seed0"})
check("a CopyObject on a full disk is a 5xx S3 error and the source is untouched",
      st in (500, 507) and code_of(body) in ("StorageFull", "InternalError") and
      request("GET", "/full/seed0")[2] == seed["seed0"], (st, body[:200]))
check("and left no copy", request("HEAD", "/full/copy-of-seed")[0] == 404)
seeds_intact("on the full disk")
for k in ("seed4",):
    st, hd, body = request("DELETE", "/full/" + k)
    gst, _, gbody = request("GET", "/full/" + k)
    listed = k in (keys_of("full") or [])
    note("DELETE %s on the full disk: %d %s; afterwards GET %d, listed %s" % (k, st, code_of(body), gst, listed))
    check("a DELETE on a full disk is answered, and the object is either deleted for everyone or kept for everyone "
          "(GET %d, listed %s)" % (gst, listed),
          st in (204, 500, 507) and ((gst == 404 and not listed) or (gst == 200 and gbody == seed[k] and listed)),
          (st, gst, listed))
    if gst == 404:
        del seed[k]
st, hd, body = request("PUT", "/newbucket-on-full")
check("a CreateBucket on a full disk is answered (200, or a 5xx S3 error)", st in (200, 500, 507), (st, body[:200]))
check("the runtime still lists buckets", request("GET", "/")[0] == 200)

# 4. Space comes back.
for f in os.listdir(filler_dir):
    os.unlink(os.path.join(filler_dir, f))
os.rmdir(filler_dir)
free2 = free_bytes()
note("filler removed: %d KiB free" % (free2 >> 10))
body = os.urandom(300000)
st, hd, _ = request("PUT", "/full/after-space", body=body)
check("with the room back the same runtime stores again, no restart", st == 200, st)
extra_ok["after-space"] = body
check("and reads it", request("GET", "/full/after-space")[2] == body)
body = os.urandom(150000)
st, hd, _ = request("PUT", "/full/on-a-full-disk", body=body)
check("the key that was refused on the full disk can be stored now", st == 200, st)
extra_ok["on-a-full-disk"] = body
seeds_intact("after space came back")
check("the quota did not keep the refused bytes (a further %d KiB fits)" % ((free_bytes() // 2) >> 10),
      streamed_put("/full/fits", free_bytes() // 2)[0] == 200)
request("DELETE", "/full/fits")

# 5. Many uploads racing for what is left.
free3 = free_bytes()
per = max(free3 // 5, 300000)
results = {}


def uploader(i):
    results[i] = streamed_put("/full/race%d" % i, per)


threads = [threading.Thread(target=uploader, args=(i,)) for i in range(8)]
for t in threads:
    t.start()
for t in threads:
    t.join()
won = [i for i, r in results.items() if r[0] == 200]
lost = [i for i, r in results.items() if r[0] != 200]
note("8 uploads of %d KiB racing for %d KiB: %d stored, %d refused (%s)" %
     (per >> 10, free3 >> 10, len(won), len(lost), sorted(set((results[i][0], results[i][1]) for i in lost))))
check("every upload was answered, the winners 200 and the others StorageFull", all(
    r[0] == 200 or (r[0] == 507 and r[1] == "StorageFull") for r in results.values()), results)
check("the disk really was the limit: not every upload could be stored", lost, (won, lost))
bad = []
for i in won:
    st, hd, got = request("GET", "/full/race%d" % i)
    if st != 200 or hashlib.md5(got).hexdigest() != results[i][3]:
        bad.append(i)
check("every stored upload reads back whole with the MD5 it was sent", not bad, bad)
check("every refused one is absent", all(request("HEAD", "/full/race%d" % i)[0] == 404 for i in lost))
check("and no temporary file is left", wait_for(lambda: not tmp_files("full"), 10), tmp_files("full"))
# ext4 hands freed blocks back when its journal commits, seconds after the unlink.
room = free3 - len(won) * (per + 65536) - (512 << 10)
wait_for(lambda: free_bytes() >= room, 10)
check("the room the refused ones held was given back (%d KiB free of the %d KiB that only the %d stored took)" %
      (free_bytes() >> 10, free3 >> 10, len(won)), free_bytes() >= room,
      (free_bytes(), free3, len(won), per))
for i in won:
    extra_ok["race%d" % i] = None
seeds_intact("after the race")

# 6. A restart sees the same.
before_keys = keys_of("full")
before_hash = {}
for k in before_keys:
    before_hash[k] = hashlib.md5(request("GET", "/full/" + k)[2]).hexdigest()
check("the runtime restarts", restart_runtime())
after_keys = keys_of("full")
after_hash = {k: hashlib.md5(request("GET", "/full/" + k)[2]).hexdigest() for k in (after_keys or [])}
check("after a restart the same keys with the same bytes are there (%d)" % len(before_keys or []),
      after_keys == before_keys and after_hash == before_hash,
      (set(before_keys or []) ^ set(after_keys or []), [k for k in before_hash if after_hash.get(k) != before_hash[k]]))
check("and no temporary file", not tmp_files("full"), tmp_files("full"))

print("  Results: %d/%d passed (%d failed)" % (passed, passed + failed, failed))
sys.exit(min(failed, 100))
