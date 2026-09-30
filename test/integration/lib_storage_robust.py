#!/usr/bin/env python3
"""Clients that misbehave, and what the storage runtime keeps through them.

usage: lib_storage_robust.py PORT DATA_DIR WORKER_PID

The worker's own /proc entries are the instrument: its descriptors, its
resident set, and the temporary files its uploads leave under DATA_DIR/<bucket>/tmp.
A stalled uploader must not stop the runtime serving anyone else and must be let
go after the body deadline; an uploader that disconnects, by FIN or by RST, in
the head, in the body or in a chunk, must leave no object, no index entry and no
temporary file, and must not touch the object it was replacing; a thousand idle
connections must cost descriptors and a little memory and give them back; and a
gigabyte through boto3 must never be held.
"""
import hashlib
import http.client
import os
import socket
import struct
import sys
import threading
import time

from lib_asan import rss_check

PORT = int(sys.argv[1])
DATA = sys.argv[2]
PID = int(sys.argv[3])
BIN = os.environ["BIN"]
BODY_STALL_SECS = int(os.environ.get("SOCKETLEY_STORAGE_BODY_STALL_SECS", "60"))
BIG_MIB = int(os.environ.get("SOCKETLEY_STORAGE_ROBUST_MIB", "1024"))
BIG_RSS_MIB = int(os.environ.get("SOCKETLEY_STORAGE_ROBUST_RSS_MIB", "30"))
NAME = os.environ.get("SOCKETLEY_STORAGE_NAME", "stgr")

passed = failed = 0
lock = threading.Lock()


def check(name, cond, detail=""):
    global passed, failed
    with lock:
        if cond:
            passed += 1
            print("  PASS: " + name, flush=True)
        else:
            failed += 1
            print("  FAIL [%s]: %s" % (name, str(detail)[:400]), flush=True)


def note(msg):
    with lock:
        print("  " + msg, flush=True)


def status_kib(field):
    with open("/proc/%d/status" % PID) as f:
        for line in f:
            if line.startswith(field + ":"):
                return int(line.split()[1])
    return -1


def fds():
    return len(os.listdir("/proc/%d/fd" % PID))


def tmp_files(bucket):
    try:
        return sorted(os.listdir(os.path.join(DATA, bucket, "tmp")))
    except FileNotFoundError:
        return []


def wait_for(fn, secs, step=0.05):
    end = time.time() + secs
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(step)
    return fn()


def counters():
    import subprocess
    out = subprocess.run([BIN, "stats", NAME], capture_output=True, text=True).stdout
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d


def request(method, path, body=None, headers=None, timeout=30):
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        data = r.read()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data
    finally:
        conn.close()


def dial():
    return socket.create_connection(("127.0.0.1", PORT), timeout=30)


def rst_close(s):
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()


def put_head(bucket, key, length, extra=""):
    return ("PUT /%s/%s HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n%s\r\n" % (bucket, key, length, extra)).encode()


def keys_of(bucket):
    import re
    st, _, body = request("GET", "/%s?list-type=2&max-keys=1000" % bucket)
    return re.findall(rb"<Key>([^<]*)</Key>", body)


# ─── Uploaders that stall and that leave ────────────────────────────────────
print("=== a stalled uploader, and uploaders that disconnect ===")
request("PUT", "/upl")
old = os.urandom(300000)
st, hd, _ = request("PUT", "/upl/keep", body=old)
old_etag = hd.get("etag")
check("the object an interrupted upload will try to replace is stored", st == 200 and old_etag == '"%s"' % hashlib.md5(old).hexdigest())

stall_result = {}


def stall_waiter(sock):
    """A client that sent part of a body and stops, until the server lets it go."""
    sock.settimeout(BODY_STALL_SECS + 40)
    t0 = stall_t0
    try:
        data = sock.recv(65536)
        stall_result["closed"] = True
        stall_result["data"] = data
    except socket.timeout:
        stall_result["closed"] = False
    except OSError as e:
        stall_result["closed"] = True
        stall_result["data"] = b""
        stall_result["err"] = repr(e)
    stall_result["secs"] = time.time() - t0


stalled = dial()
stalled.sendall(put_head("upl", "stalled", 8 << 20) + os.urandom(1 << 20))
stall_t0 = time.time()
stall_result["t0"] = stall_t0
tmp_seen = wait_for(lambda: tmp_files("upl"), 5)
check("a body in flight has a temporary file under the bucket's tmp", len(tmp_seen) == 1, tmp_seen)
stalled_tmp = tmp_seen[0] if tmp_seen else None


def others():
    """The temporary files of every upload but the stalled one."""
    return [f for f in tmp_files("upl") if f != stalled_tmp]


stall_thread = threading.Thread(target=stall_waiter, args=(stalled,))
stall_thread.start()

head_result = {}


def head_waiter():
    """A client that starts a request head and never finishes it, until the server lets it go."""
    s = dial()
    s.sendall(b"GET /upl/keep HTTP/1.1\r\nHost: x\r\nX-Slow: ")
    t0 = time.time()
    s.settimeout(60)
    try:
        head_result["data"] = s.recv(4096)
        head_result["closed"] = True
    except OSError:
        head_result["closed"] = False
    head_result["secs"] = time.time() - t0
    s.close()


head_thread = threading.Thread(target=head_waiter)
head_thread.start()

lat = []
errs = []
for i in range(30):
    t0 = time.time()
    st, hd, b = request("GET", "/upl/keep")
    st2, hd2, b2 = request("PUT", "/upl/small%d" % i, body=b"s" * 100)
    lat.append(time.time() - t0)
    if st != 200 or b != old or st2 != 200:
        errs.append((i, st, st2))
check("with an upload stalled the runtime answers 30 GETs and 30 PUTs from other clients", not errs, errs[:3])
note("latency of a GET and a PUT beside the stalled upload: max %.0f ms, median %.0f ms" %
     (max(lat) * 1000, sorted(lat)[len(lat) // 2] * 1000))
check("and none of them waits on it (each pair under 2 s)", max(lat) < 2.0, max(lat))
check("the stalled key is not visible and the temporary file is still there",
      b"stalled" not in keys_of("upl") and len(tmp_files("upl")) == 1, (keys_of("upl")[:3], tmp_files("upl")))


def cut_fin(key, length, sent, extra=""):
    s = dial()
    s.sendall(put_head("upl", key, length, extra) + os.urandom(sent))
    time.sleep(0.05)
    s.close()


def cut_rst(key, length, sent, extra=""):
    s = dial()
    s.sendall(put_head("upl", key, length, extra) + os.urandom(sent))
    time.sleep(0.05)
    rst_close(s)


cut_fin("cut-fin", 8 << 20, 3 << 20)
cut_rst("cut-rst", 8 << 20, 3 << 20)
cut_fin("keep", 5 << 20, 2 << 20)           # would replace the stored object
cut_rst("keep", 5 << 20, 1 << 20)
cut_fin("cut-tiny", 100000, 10)
cut_fin("cut-zero-body", 100000, 0)
# In the head, mid-way.
s = dial()
s.sendall(b"PUT /upl/cut-head HTTP/1.1\r\nHost: x\r\nContent-Le")
time.sleep(0.05)
rst_close(s)
# After Expect: 100-continue, before any body.
s = dial()
s.sendall(put_head("upl", "cut-expect", 4 << 20, "Expect: 100-continue\r\n"))
s.settimeout(5)
got = s.recv(200)
check("Expect: 100-continue is answered before the body", got.startswith(b"HTTP/1.1 100"), got[:60])
s.close()
# Chunked, cut inside a chunk.
s = dial()
s.sendall(b"PUT /upl/cut-chunked HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" +
          b"100000\r\n" + os.urandom(0x100000 // 2))
time.sleep(0.05)
s.close()
# A body that continues past the length it promised, then leaves.
s = dial()
s.sendall(put_head("upl", "cut-over", 1000) + os.urandom(3000))
s.settimeout(5)
try:
    first = s.recv(4096)
except OSError:
    first = b""
s.close()
check("a body longer than its Content-Length is answered (200 for the first 1000 bytes) or refused, not hung",
      first.startswith(b"HTTP/1.1 "), first[:40])
request("DELETE", "/upl/cut-over")

only_stalled = wait_for(lambda: not others(), 10)
check("every interrupted upload's temporary file is gone within 10 s (only the stalled one is left)",
      only_stalled, others())
have = set(keys_of("upl"))
check("none of the interrupted uploads left a key", not (have & {b"cut-fin", b"cut-rst", b"cut-tiny", b"cut-zero-body",
                                                                b"cut-head", b"cut-expect", b"cut-chunked", b"stalled"}),
      sorted(have)[:8])
st, hd, b = request("GET", "/upl/keep")
check("the object two interrupted uploads meant to replace is untouched (bytes and ETag)",
      st == 200 and b == old and hd.get("etag") == old_etag, (st, len(b), hd.get("etag")))
st, hd, b = request("HEAD", "/upl/cut-fin")
check("HEAD of an interrupted key is 404", st == 404, st)
check("and the runtime still serves after all of them",
      request("PUT", "/upl/after", body=b"ok")[0] == 200 and request("GET", "/upl/after")[2] == b"ok")

# ─── Many uploaders in flight at once ───────────────────────────────────────
print("=== many uploads in flight ===")
base_fds = fds()
base_rss = status_kib("VmRSS")
socks = []
N_UP = 200
for i in range(N_UP):
    s = dial()
    s.sendall(put_head("upl", "many%03d" % i, 8 << 20) + os.urandom(64 << 10))
    socks.append(s)
wait_for(lambda: len(others()) >= N_UP, 20)
n_tmp = len(others())
rss_many = status_kib("VmRSS")
note("%d uploads in flight, each with 64 KiB sent of 8 MiB: %d temporary files, RSS %d KiB (was %d), fds %d (was %d)" %
     (N_UP, n_tmp, rss_many, base_rss, fds(), base_fds))
check("%d concurrent uploads each hold a temporary file" % N_UP, n_tmp == N_UP, n_tmp)
rss_check(check, PID, "their resident set stays under 150 MiB in total (worker RSS %d KiB)" % rss_many, rss_many < 150 * 1024, rss_many)
st, hd, b = request("GET", "/upl/keep")
check("with %d uploads in flight a GET is served" % N_UP, st == 200 and b == old)
for s in socks[:100]:
    s.close()
for s in socks[100:]:
    rst_close(s)
check("when they all leave, their temporary files go",
      wait_for(lambda: not others(), 15), len(others()))
check("and their descriptors (fds %d, was %d before them)" % (fds(), base_fds),
      wait_for(lambda: fds() <= base_fds, 10), (fds(), base_fds))
check("no key was created by any of them", not [k for k in keys_of("upl") if k.startswith(b"many")])

# What an upload holds once its body is really flowing: two staging buffers of a megabyte each.
N_FULL = 100
socks = []
rss_before_full = status_kib("VmRSS")
piece = os.urandom(1 << 20)
for i in range(N_FULL):
    s = dial()
    s.sendall(put_head("upl", "full%03d" % i, 8 << 20) + piece * 3)
    socks.append(s)
time.sleep(2.0)
rss_full = status_kib("VmRSS")
note("%d uploads each with 3 MiB of 8 sent: RSS %d KiB (was %d), %.2f MiB per upload" %
     (N_FULL, rss_full, rss_before_full, (rss_full - rss_before_full) / 1024.0 / N_FULL))
check("an upload with its body flowing holds under 3 MiB of the worker's memory (%d uploads grew it %d KiB)" %
      (N_FULL, rss_full - rss_before_full), rss_full - rss_before_full < N_FULL * 3 * 1024, rss_full - rss_before_full)
for s in socks:
    s.close()
check("they leave, and their temporary files with them", wait_for(lambda: not others(), 15), len(others()))

# More uploads than the runtime admits.
import select

MAX_UPLOADS = 512          # storage_run::m_max_active_puts


def flood(n, label):
    socks = []
    for i in range(n):
        s = dial()
        # Past the 1 MiB a pooled file takes, so each upload's file is one in tmp/.
        s.sendall(put_head("upl", "flood%03d" % i, (1 << 20) + 4096) + b"x" * 100)
        socks.append(s)
    # Answers arrive only from the refused ones; the admitted are waiting for their body.
    heard = {}
    end = time.time() + 6
    pending = {s.fileno(): (i, s) for i, s in enumerate(socks)}
    while pending and time.time() < end:
        r, _, _ = select.select([s for _, s in pending.values()], [], [], 0.5)
        for s in r:
            i, _ = pending.pop(s.fileno())
            try:
                d = s.recv(4096)
            except OSError as e:
                d = repr(e).encode()
            heard[i] = d
    refused = [i for i, d in heard.items() if d.startswith(b"HTTP/1.1 503")]
    other = [(i, d[:40]) for i, d in heard.items() if not d.startswith(b"HTTP/1.1 503")]
    live = len(socks) - len(heard)
    note("%s: %d uploads started at once: %d answered 503, %d waiting on their body, %d otherwise (%s)" %
         (label, n, len(refused), live, len(other), other[:2]))
    return socks, refused, other, live


# The stalled upload, while it lives, is one of the admitted.
held = 1 if stalled_tmp in tmp_files("upl") else 0
socks, refused, other, live = flood(MAX_UPLOADS + 48, "flood 1")
check("uploads beyond the runtime's bound of %d concurrent ones are answered SlowDown 503 (%d were, %d expected)" %
      (MAX_UPLOADS, len(refused), 48 + held), len(refused) == 48 + held and not other, (len(refused), other[:2]))
check("the admitted ones each hold a temporary file (%d)" % len(others()),
      wait_for(lambda: len(others()) == MAX_UPLOADS - held, 5), len(others()))
st, hd, b = request("PUT", "/upl/at-the-bound", body=b"x")
check("a new upload at the bound is refused with a body a client can read (SlowDown), not hung", st == 503 and
      b"<Code>SlowDown</Code>" in b, (st, b[:100]))
check("while a GET is still served", request("GET", "/upl/keep")[0] == 200)
for s in socks:
    s.close()
check("when they all leave their temporary files go", wait_for(lambda: not others(), 20), len(others()))
socks, refused, other, live = flood(MAX_UPLOADS + 48, "flood 2")
held = 1 if stalled_tmp in tmp_files("upl") else 0
check("a second flood is admitted and refused in the same numbers (nothing leaked from the first): %d refused" %
      len(refused), len(refused) == 48 + held and not other, (len(refused), other[:2]))
for s in socks:
    s.close()
wait_for(lambda: not others(), 20)
ok = all(request("PUT", "/upl/after-flood%d" % i, body=b"served")[0] == 200 for i in range(20))
check("after both floods 20 sequential PUTs are all served", ok)

# ─── A thousand idle connections ────────────────────────────────────────────
print("=== 1000 idle connections ===")
import resource
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
if soft < 4096:
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 4096), hard))
request("PUT", "/idle")
request("PUT", "/idle/obj", body=b"served amid the idle")
with open("/proc/%d/limits" % PID) as f:
    limits = [l for l in f if l.startswith("Max open files")]
note("worker: %s" % limits[0].strip() if limits else "worker limits unknown")


def one_cycle(label):
    fds0, rss0 = fds(), status_kib("VmRSS")
    idle = [dial() for _ in range(1000)]
    partial = []
    for s in idle[:100]:
        s.sendall(b"GET /idle/obj HTT")           # a head that never finishes
        partial.append(s)
    wait_for(lambda: fds() >= fds0 + 1000, 10)
    fds1, rss1 = fds(), status_kib("VmRSS")
    note("%s: 1000 connections (100 mid-head): fds %d -> %d, RSS %d -> %d KiB" % (label, fds0, fds1, rss0, rss1))
    check("%s: the worker holds a descriptor per connection and no more than a few extra (%d)" % (label, fds1 - fds0),
          fds0 + 995 <= fds1 <= fds0 + 1000 + 8, (fds0, fds1))
    check("%s: 1000 idle connections cost under 20 MiB of resident memory (%d KiB)" % (label, rss1 - rss0),
          rss1 - rss0 < 20 * 1024, rss1 - rss0)
    lat = []
    ok = True
    for _ in range(50):
        t0 = time.time()
        st, hd, b = request("GET", "/idle/obj")
        lat.append(time.time() - t0)
        ok = ok and st == 200 and b == b"served amid the idle"
    note("%s: 50 GETs among them: max %.0f ms, median %.0f ms" % (label, max(lat) * 1000, sorted(lat)[25] * 1000))
    check("%s: requests are served beside 1000 idle connections, each under 1 s" % label, ok and max(lat) < 1.0,
          (ok, max(lat)))
    # One of the idle ones still works when it finally speaks.
    idle[500].sendall(b"GET /idle/obj HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    idle[500].settimeout(5)
    data = b""
    try:
        while True:
            c = idle[500].recv(65536)
            if not c:
                break
            data += c
    except OSError:
        pass
    check("%s: an idle connection that finally sends a request is answered" % label,
          data.startswith(b"HTTP/1.1 200") and data.endswith(b"served amid the idle"), data[:80])
    for s in idle[:500]:
        s.close()
    for s in idle[500:]:
        rst_close(s)
    gone = wait_for(lambda: fds() <= fds0 + 1, 15)
    fds2, rss2 = fds(), status_kib("VmRSS")
    check("%s: when they are gone so are the descriptors (%d, was %d)" % (label, fds2, fds0), gone, (fds0, fds2))
    return rss2


r1 = one_cycle("cycle 1")
r2 = one_cycle("cycle 2")
r3 = one_cycle("cycle 3")
note("resident set after each cycle: %d, %d, %d KiB" % (r1, r2, r3))
check("a thousand connections opened and closed three times do not grow the resident set (%d KiB over the first)" %
      (r3 - r1), r3 - r1 < 8 * 1024, (r1, r2, r3))

# ─── The stalled uploader is let go ─────────────────────────────────────────
print("=== the stalled uploader after the body deadline ===")
# The rest of this file has taken some of the deadline already; wait out what is left.
left = BODY_STALL_SECS + 30 - (time.time() - stall_t0)
stall_thread.join(timeout=max(left, 1) + 60)
check("the stalled upload's connection was closed by the runtime",
      stall_result.get("closed") is True, stall_result)
note("the stalled upload sent 1 MiB of 8 and then nothing; the runtime let it go after %.0f s (deadline %d s)" %
     (stall_result.get("secs", -1), BODY_STALL_SECS))
note("what the stalled upload was sent when it was let go: %r" % stall_result.get("data", b"")[:80])
head_thread.join(timeout=30)
note("a request head begun and never finished was let go after %.0f s (deadline 10 s), sent %r" %
     (head_result.get("secs", -1), head_result.get("data", b"")[:60]))
check("a request head that never finishes is closed by the runtime near its 10 s deadline",
      head_result.get("closed") is True and 9 <= head_result.get("secs", 0) <= 15, head_result)
check("and not before the deadline nor long after it", BODY_STALL_SECS - 1 <= stall_result.get("secs", 0) <= BODY_STALL_SECS + 5,
      stall_result.get("secs"))
check("its temporary file is gone", wait_for(lambda: not tmp_files("upl"), 10), tmp_files("upl"))
check("and it left no key", b"stalled" not in keys_of("upl"))
c = counters()
check("the runtime counts the timeout", int(c.get("timeouts", "0")) >= 1, c)
st, hd, b = request("GET", "/upl/keep")
check("the replaced-by-nobody object is still the original", st == 200 and b == old and hd.get("etag") == old_etag)

# ─── A gigabyte through boto3 ───────────────────────────────────────────────
print("=== %d MiB streamed through boto3 with the worker's RSS sampled ===" % BIG_MIB)
try:
    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config
except ImportError:
    boto3 = None
    print("  SKIP: boto3 is not installed")

if boto3:
    s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % PORT, region_name="us-east-1",
                      aws_access_key_id=os.environ.get("S3_TEST_ACCESS_KEY") or None,
                      aws_secret_access_key=os.environ.get("S3_TEST_SECRET_KEY") or None,
                      config=Config(signature_version=None if os.environ.get("S3_TEST_ACCESS_KEY") else UNSIGNED,
                                    s3={"addressing_style": "path"}, retries={"max_attempts": 1},
                                    read_timeout=300, connect_timeout=30))
    BLOCK = os.urandom(1 << 20)
    SIZE = BIG_MIB << 20

    class Blocks:
        """A file-like of SIZE bytes made of one block repeated, that keeps only a hash."""

        def __init__(self):
            self.pos = 0

        def read(self, n=-1):
            if n is None or n < 0 or n > SIZE - self.pos:
                n = SIZE - self.pos
            if n == 0:
                return b""
            out = bytearray()
            while n > 0:
                off = self.pos % len(BLOCK)
                k = min(n, len(BLOCK) - off)
                out += BLOCK[off:off + k]
                self.pos += k
                n -= k
            return bytes(out)

        def seek(self, off, whence=0):
            self.pos = off if whence == 0 else (self.pos + off if whence == 1 else SIZE + off)
            return self.pos

        def tell(self):
            return self.pos

    samples = []
    peak = [0, 0]
    stop = threading.Event()

    def sampler():
        while not stop.is_set():
            try:
                samples.append(status_kib("VmRSS"))
                peak[0] = max(peak[0], samples[-1])
                peak[1] = max(peak[1], fds())
            except OSError:
                pass
            time.sleep(0.05)

    free_mib = os.statvfs(DATA).f_bavail * os.statvfs(DATA).f_frsize >> 20
    if free_mib < BIG_MIB * 2 + 512:
        print("  SKIP: needs %d MiB free under %s and has %d" % (BIG_MIB * 2 + 512, DATA, free_mib))
    else:
        s3.create_bucket(Bucket="gig")
        # The high-water mark is reset, so the phases before this one cannot have set it.
        with open("/proc/%d/clear_refs" % PID, "w") as f:
            f.write("5")
        rss_before = status_kib("VmRSS")
        th = threading.Thread(target=sampler)
        th.start()
        t0 = time.time()
        r = s3.put_object(Bucket="gig", Key="huge", Body=Blocks(), ContentLength=SIZE, ContentType="application/x-big",
                          Metadata={"why": "bounded"})
        put_secs = time.time() - t0
        h = hashlib.md5()
        for _ in range(BIG_MIB):
            h.update(BLOCK)
        check("a %d MiB put_object through boto3 is 200 with the MD5 of the stream" % BIG_MIB,
              r["ETag"] == '"%s"' % h.hexdigest(), r["ETag"])
        t0 = time.time()
        g = s3.get_object(Bucket="gig", Key="huge")
        got = hashlib.md5()
        n = 0
        for chunk in g["Body"].iter_chunks(1 << 20):
            got.update(chunk)
            n += len(chunk)
        get_secs = time.time() - t0
        stop.set()
        th.join()
        check("the get_object streams back every byte, and they are the bytes put", n == SIZE and got.hexdigest() == h.hexdigest(),
              (n, SIZE))
        check("with its stored type and metadata", g["ContentType"] == "application/x-big" and g["Metadata"] == {"why": "bounded"})
        note("PUT %d MiB in %.1f s, GET in %.1f s, %d RSS samples; worker RSS %d KiB before, peak sampled %d KiB, "
             "VmHWM %d KiB, peak fds %d" % (BIG_MIB, put_secs, get_secs, len(samples), rss_before, peak[0], status_kib("VmHWM"), peak[1]))
        check("the worker's sampled RSS never grew more than %d MiB through the put and the get (grew %d KiB)" %
              (BIG_RSS_MIB, peak[0] - rss_before), peak[0] - rss_before < BIG_RSS_MIB * 1024, (peak[0], rss_before))
        check("and its high-water mark stayed under %d MiB above what it held before (%d KiB)" %
              (BIG_RSS_MIB, status_kib("VmHWM") - rss_before), status_kib("VmHWM") - rss_before < BIG_RSS_MIB * 1024)
        # A range from the far end, and a HEAD, after the transfer.
        first = SIZE - (5 << 20) - 3
        g = s3.get_object(Bucket="gig", Key="huge", Range="bytes=%d-%d" % (first, first + 999999))
        body = g["Body"].read()
        want = b"".join(BLOCK for _ in range(3))
        off = first % len(BLOCK)
        check("a range near the end of it is the right slice", body == want[off:off + 1000000])
        s3.delete_object(Bucket="gig", Key="huge")
        check("the giant is deletable and its space is given back (no data file left under the bucket)",
              wait_for(lambda: not any(fs for _, _, fs in os.walk(os.path.join(DATA, "gig", "data"))), 10))

print("  Results: %d/%d passed (%d failed)" % (passed, passed + failed, failed))
sys.exit(min(failed, 100))
