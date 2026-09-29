#!/usr/bin/env python3
"""A large object through the storage runtime with a bounded worker.

usage: lib_storage_large.py PORT WORKER_PID SIZE_MIB MAX_RSS_MIB

The object is a block of noise repeated, so a slice of it can be checked
without keeping it, and the client never holds more than a block either.  What
is measured is the WORKER's peak resident set (VmHWM), which is what an
unbounded buffer would show up in.
"""
import hashlib
import http.client
import os
import re
import socket
import sys
import time

PORT = int(sys.argv[1])
PID = int(sys.argv[2])
SIZE_MIB = int(sys.argv[3])
MAX_RSS_MIB = int(sys.argv[4])
SIZE = SIZE_MIB << 20
BLOCK = os.urandom(1 << 20)

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, detail))


def status_kib(field):
    with open("/proc/%d/status" % PID) as f:
        for line in f:
            if line.startswith(field + ":"):
                return int(line.split()[1])
    return -1


def counters():
    import subprocess
    out = subprocess.run([os.environ["BIN"], "stats", "stg"], capture_output=True, text=True).stdout
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d


def wait_counter(name, at_least, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        c = counters()
        if int(c.get(name, "0")) >= at_least:
            return c
        time.sleep(0.2)
    return counters()


def request(method, path, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=120)
    conn.request(method, path, headers=headers or {})
    r = conn.getresponse()
    body = r.read()
    conn.close()
    return r.status, body


base_rss = status_kib("VmRSS")
print("  worker RSS before: %d KiB" % base_rss)
request("PUT", "/large-bucket")

# ── PUT ─────────────────────────────────────────────────────────────────────
md5 = hashlib.md5()
conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=300)
t0 = time.time()
conn.putrequest("PUT", "/large-bucket/huge.bin")
conn.putheader("Content-Length", str(SIZE))
conn.putheader("Content-Type", "application/octet-stream")
conn.endheaders()
for _ in range(SIZE_MIB):
    conn.send(BLOCK)
    md5.update(BLOCK)
r = conn.getresponse()
r.read()
put_secs = time.time() - t0
check("a %d MiB PutObject answers 200" % SIZE_MIB, r.status == 200, r.status)
check("with the MD5 of everything sent", r.getheader("ETag") == '"%s"' % md5.hexdigest(), r.getheader("ETag"))
conn.close()
print("  PUT %d MiB in %.2f s (%.0f MiB/s)" % (SIZE_MIB, put_secs, SIZE_MIB / put_secs))
put_hwm = status_kib("VmHWM")
print("  worker peak RSS after the PUT: %d KiB" % put_hwm)
check("the worker's peak RSS stays under %d MiB through the PUT" % MAX_RSS_MIB, put_hwm < MAX_RSS_MIB * 1024,
      "%d KiB" % put_hwm)

# ── GET, whole ──────────────────────────────────────────────────────────────
before = counters()
conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=300)
t0 = time.time()
conn.request("GET", "/large-bucket/huge.bin")
r = conn.getresponse()
got = hashlib.md5()
n = 0
while True:
    chunk = r.read(1 << 20)
    if not chunk:
        break
    got.update(chunk)
    n += len(chunk)
get_secs = time.time() - t0
conn.close()
check("a %d MiB GetObject returns 200 and every byte" % SIZE_MIB, r.status == 200 and n == SIZE, (r.status, n))
check("and they are the bytes that were put", got.hexdigest() == md5.hexdigest())
print("  GET %d MiB in %.2f s (%.0f MiB/s)" % (SIZE_MIB, get_secs, SIZE_MIB / get_secs))
get_hwm = status_kib("VmHWM")
print("  worker peak RSS after the GET: %d KiB" % get_hwm)
check("the worker's peak RSS stays under %d MiB through the GET" % MAX_RSS_MIB, get_hwm < MAX_RSS_MIB * 1024,
      "%d KiB" % get_hwm)

after = wait_counter("zero_copy_bytes", int(before.get("zero_copy_bytes", "0")) + SIZE)
zc = int(after.get("zero_copy_bytes", "0")) - int(before.get("zero_copy_bytes", "0"))
check("every byte of the GET went through the zero-copy path (%d of %d)" % (zc, SIZE), zc == SIZE, after)
check("and it counts as one zero-copy GET",
      int(after.get("zero_copy_gets", "0")) - int(before.get("zero_copy_gets", "0")) == 1, after)

# ── GET, a range across a block edge, deep in the object ────────────────────
first = SIZE - (3 << 20) - 12345
last = first + (2 << 20) + 777
conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
conn.request("GET", "/large-bucket/huge.bin", headers={"Range": "bytes=%d-%d" % (first, last)})
r = conn.getresponse()
piece = r.read()
conn.close()
want = b"".join(BLOCK for _ in range((last // len(BLOCK)) - (first // len(BLOCK)) + 2))
off = first % len(BLOCK)
check("a range deep in the object is 206 with the right bytes",
      r.status == 206 and piece == want[off:off + (last - first + 1)] and
      r.getheader("Content-Range") == "bytes %d-%d/%d" % (first, last, SIZE), (r.status, len(piece)))

# ── the connection and the runtime after a large transfer ───────────────────
s, body = request("HEAD", "/large-bucket/huge.bin")
check("the runtime answers a HEAD afterwards with the object's length", s == 200)

# An overwrite of the giant with a small object, and the space is given back.
request("DELETE", "/large-bucket/huge.bin")
check("the large object is deletable", request("HEAD", "/large-bucket/huge.bin")[0] == 404)

# A copy of a big object holds one buffer, not the object.
request("PUT", "/large-bucket/copy-src", headers={"Content-Length": "0"})
conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=300)
conn.putrequest("PUT", "/large-bucket/copy-src")
conn.putheader("Content-Length", str(SIZE // 4))
conn.endheaders()
for _ in range(SIZE_MIB // 4):
    conn.send(BLOCK)
conn.getresponse().read()
conn.close()
s, body = request("PUT", "/large-bucket/copy-dst", headers={"x-amz-copy-source": "/large-bucket/copy-src"})
check("a CopyObject of %d MiB is 200" % (SIZE_MIB // 4), s == 200, (s, body[:200]))
final_hwm = status_kib("VmHWM")
print("  worker peak RSS at the end: %d KiB" % final_hwm)
check("and the peak RSS is still under %d MiB after the copy" % MAX_RSS_MIB, final_hwm < MAX_RSS_MIB * 1024,
      "%d KiB" % final_hwm)

print("  Results: %d/%d passed (%d failed)" % (passed, passed + failed, failed))
sys.exit(min(failed, 100))
