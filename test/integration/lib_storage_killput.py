#!/usr/bin/env python3
"""A storage worker killed with SIGKILL in the middle of uploads, over and over.

usage: lib_storage_killput.py PORT DATA_DIR RUNTIME_NAME ROUNDS

Each round starts large uploads (new keys and overwrites of stored ones, sent in
pieces so they are in flight) beside a stream of small puts and deletes that
are acknowledged one at a time, kills the runtime's worker at a random moment,
waits for the supervisor to bring a worker back, and then holds the runtime to
what a crash may and may not leave:

  * an operation that was acknowledged before the kill is in effect,
  * a key whose operation was in flight is in the state before it or the state
    after it -- a whole old object, a whole new one or none -- never a torn one,
  * every listed key reads back with the size and ETag the listing gave it, and
    every object file has a listed key,
  * no temporary file is left.
"""
import hashlib
import http.client
import os
import random
import re
import signal
import socket
import subprocess
import sys
import threading
import time

PORT = int(sys.argv[1])
DATA = sys.argv[2]
NAME = sys.argv[3]
ROUNDS = int(sys.argv[4])
BIN = os.environ["BIN"]
SEED = int(os.environ.get("SOCKETLEY_STORAGE_KILL_SEED", str(random.randrange(1 << 30))))
rng = random.Random(SEED)

passed = failed = 0
lock = threading.Lock()
ABSENT = "ABSENT"


def check(name, cond, detail=""):
    global passed, failed
    with lock:
        if cond:
            passed += 1
            print("  PASS: " + name, flush=True)
        else:
            failed += 1
            print("  FAIL [%s]: %s" % (name, str(detail)[:500]), flush=True)


def note(msg):
    print("  " + msg, flush=True)


def stats():
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


def wait_for(fn, secs, step=0.1):
    end = time.time() + secs
    while time.time() < end:
        try:
            v = fn()
        except OSError:
            v = None
        if v:
            return v
        time.sleep(step)
    return None


def md5(b):
    return hashlib.md5(b).hexdigest()


BUCKETS = ["kill-a", "kill-b"]
for b in BUCKETS:
    request("PUT", "/" + b)

# What the world must look like: definite[(bucket, key)] = md5 or ABSENT; maybe[...] = extra states allowed.
definite = {}
maybe = {}
mlock = threading.Lock()


def put_ack(bucket, key, body):
    with mlock:
        definite[(bucket, key)] = md5(body)
        maybe.pop((bucket, key), None)


def del_ack(bucket, key):
    with mlock:
        definite[(bucket, key)] = ABSENT
        maybe.pop((bucket, key), None)


def begin(bucket, key, state):
    with mlock:
        definite.setdefault((bucket, key), ABSENT)
        maybe.setdefault((bucket, key), set()).add(state)


acked_big = []


def slow_put(bucket, key, body, piece, gap, stop_at=None):
    """A PUT whose body trickles, so the worker is killed with it in flight."""
    s = socket.create_connection(("127.0.0.1", PORT), timeout=30)
    try:
        s.sendall(("PUT /%s/%s HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nContent-Type: text/x-kill\r\n"
                   "x-amz-meta-round: r\r\n\r\n" % (bucket, key, len(body))).encode())
        off = 0
        while off < len(body):
            s.sendall(body[off:off + piece])
            off += piece
            time.sleep(gap)
        data = s.recv(4096)
        if data.startswith(b"HTTP/1.1 200"):
            put_ack(bucket, key, body)
            acked_big.append(key)
            return True
    except OSError:
        pass
    finally:
        s.close()
    return False


def small_stream(stop, tag):
    """Puts and deletes, one at a time, each acknowledged before the next; the one in flight at the kill is `maybe`."""
    n = 0
    while not stop.is_set():
        bucket = BUCKETS[n % 2]
        key = "small/%s/%03d" % (tag, n % 40)
        if n % 5 == 4:
            begin(bucket, key, ABSENT)
            try:
                st, _, _ = request("DELETE", "/%s/%s" % (bucket, key), timeout=5)
                if st == 204:
                    del_ack(bucket, key)
            except OSError:
                return
        else:
            body = os.urandom(rng.randrange(1, 60000))
            begin(bucket, key, md5(body))
            try:
                st, hd, _ = request("PUT", "/%s/%s" % (bucket, key), body=body, timeout=5)
                if st == 200:
                    put_ack(bucket, key, body)
            except OSError:
                return
        n += 1


def worker_pid():
    return stats().get("pid")


def ready(old_pid):
    def probe():
        p = worker_pid()
        if p and p != old_pid and os.path.isdir("/proc/%s" % p) and request("GET", "/", timeout=2)[0] == 200:
            return p
        return None
    return wait_for(probe, 40)


def tmp_files():
    out = []
    for b in BUCKETS:
        try:
            out += os.listdir(os.path.join(DATA, b, "tmp"))
        except FileNotFoundError:
            pass
    return out


def list_bucket(bucket):
    keys = {}
    token = None
    while True:
        path = "/%s?list-type=2&max-keys=500" % bucket + ("&continuation-token=" + token if token else "")
        st, _, body = request("GET", path)
        if st != 200:
            return None
        for m in re.finditer(rb"<Contents><Key>([^<]*)</Key>.*?<ETag>&quot;([0-9a-f]+)&quot;</ETag><Size>(\d+)</Size>", body):
            keys[m.group(1).decode()] = (m.group(2).decode(), int(m.group(3)))
        m = re.search(rb"<NextContinuationToken>([^<]*)</NextContinuationToken>", body)
        if not m:
            return keys
        token = m.group(1).decode()


def data_files(bucket):
    n = 0
    for root, _, files in os.walk(os.path.join(DATA, bucket, "data")):
        n += len(files)
    return n


print("=== a worker killed with SIGKILL mid-upload, %d rounds (seed %d) ===" % (ROUNDS, SEED))

# Stored beforehand: big keys the rounds will overwrite, so an old whole object always exists to fall back to.
base_bodies = {}
for i in range(6):
    body = os.urandom(3 << 20)
    key = "big/over%d" % i
    st, _, _ = request("PUT", "/kill-a/" + key, body=body)
    check("the object big/over%d is stored beforehand" % i, st == 200)
    base_bodies[key] = body
    put_ack("kill-a", key, body)

# The daemon leaves a runtime failed when a sixth restart comes less than ten seconds after the fifth
# (proxy_supervisor.h), so a clean stop and start, which starts the count again, comes after every four kills.
MIN_GAP = 1.5
last_kill = 0.0
KILLS_PER_START = 4
in_flight_at_kill = 0
kills_since_start = 0


def clean_restart():
    before = {b: list_bucket(b) for b in BUCKETS}
    subprocess.run([BIN, "stop", NAME], capture_output=True)
    time.sleep(0.5)
    subprocess.run([BIN, "start", NAME], capture_output=True)
    wait_for(lambda: request("GET", "/", timeout=2)[0] == 200, 20)
    after = {b: list_bucket(b) for b in BUCKETS}
    return before == after, [(b, set(before[b] or {}) ^ set(after[b] or {})) for b in BUCKETS]



total_maybe_resolved = {"old": 0, "new": 0, "absent": 0}
for rnd in range(ROUNDS):
    time.sleep(max(0.0, last_kill + MIN_GAP - time.time()))
    stop = threading.Event()
    pid_before = worker_pid()
    del acked_big[:]
    threads = []
    # Large uploads in flight: overwrites of stored keys and new keys.
    bigs = {}
    for i in range(6):
        key = "big/over%d" % i
        body = os.urandom(rng.choice([2, 6, 10]) << 20)
        bigs[("kill-a", key)] = body
        begin("kill-a", key, md5(body))
        threads.append(threading.Thread(target=slow_put, args=("kill-a", key, body, 128 << 10, 0.02)))
    for i in range(6):
        key = "big/new-r%d-%d" % (rnd, i)
        body = os.urandom(rng.choice([1, 4, 9]) << 20)
        bigs[("kill-b", key)] = body
        begin("kill-b", key, md5(body))
        threads.append(threading.Thread(target=slow_put, args=("kill-b", key, body, 128 << 10, 0.02)))
    for i in range(3):
        threads.append(threading.Thread(target=small_stream, args=(stop, "r%dt%d" % (rnd, i))))
    for t in threads:
        t.start()
    delay = rng.uniform(0.1, 1.4)
    time.sleep(delay)
    os.kill(int(pid_before), signal.SIGKILL)
    last_kill = time.time()
    kills_since_start += 1
    stop.set()
    for t in threads:
        t.join(timeout=60)
    new_pid = ready(pid_before)
    in_flight_at_kill += 12 - len(acked_big)
    check("round %d: killed worker %s after %.2f s with %d of 12 large uploads unfinished; the supervisor brought back %s" %
          (rnd, pid_before, delay, 12 - len(acked_big), new_pid),
          new_pid is not None, (pid_before, new_pid))
    if new_pid is None:
        break

    check("round %d: no temporary file is left after the restart" % rnd, bool(wait_for(lambda: not tmp_files(), 10)), tmp_files())

    bad = []
    counts = {"old": 0, "new": 0, "absent": 0}
    for bucket in BUCKETS:
        listing = list_bucket(bucket)
        if listing is None:
            bad.append((bucket, "listing failed"))
            continue
        # Every listed key reads back as the listing said.
        for key, (etag, size) in listing.items():
            st, hd, got = request("GET", "/%s/%s" % (bucket, key))
            if st != 200 or md5(got) != etag or len(got) != size or hd.get("etag") != '"%s"' % etag:
                bad.append((bucket, key, "listed but read back wrong", st, len(got), size))
        # Every key the model knows is in an allowed state.
        with mlock:
            known = [(k, v) for k, v in definite.items() if k[0] == bucket]
            maybes = {k: set(v) for k, v in maybe.items() if k[0] == bucket}
        for (b, key), state in known:
            allowed = {state} | maybes.get((b, key), set())
            have = listing[key][0] if key in listing else ABSENT
            if have not in allowed:
                bad.append((b, key, "state not allowed", have[:8], [a[:8] for a in allowed]))
            else:
                if have == state:
                    counts["old" if have != ABSENT else "absent"] += 1
                else:
                    counts["new"] += 1
            with mlock:
                definite[(b, key)] = have          # what survived is now what is durable
                maybe.pop((b, key), None)
        # A key nobody has heard of must not exist.
        for key in listing:
            if (bucket, key) not in dict(known):
                bad.append((bucket, key, "a key no operation ever named"))
        nfiles = data_files(bucket)
        if nfiles != len(listing):
            bad.append((bucket, "object files", nfiles, "listed", len(listing)))
    check("round %d: every acknowledged operation is in effect, every in-flight key is whole old, whole new or absent, "
          "every listed key reads back as listed, every object file is listed" % rnd, not bad, bad[:5])
    for k in counts:
        total_maybe_resolved[k] += counts[k]
    if kills_since_start >= KILLS_PER_START and rnd + 1 < ROUNDS:
        same, diff = clean_restart()
        check("round %d: a clean stop and start after the crashes keeps every key with its ETag and size" % rnd, same, diff)
        kills_since_start = 0

st, hd, _ = request("PUT", "/kill-b/after-all", body=b"still writable")
check("after all rounds the runtime accepts a put and serves it",
      st == 200 and request("GET", "/kill-b/after-all")[2] == b"still writable")

# One more restart by the book: the state the crashes left survives a clean stop and start.
same, diff = clean_restart()
check("a clean stop and start after the last crash keeps every key with its ETag and size", same, diff)
note("keys seen in each state across the rounds: %s; large uploads cut by a kill: %d" %
     (total_maybe_resolved, in_flight_at_kill))
check("the kills did land on uploads in flight (%d large uploads were cut)" % in_flight_at_kill, in_flight_at_kill >= ROUNDS,
      in_flight_at_kill)

print("  Results: %d/%d passed (%d failed)" % (passed, passed + failed, failed))
sys.exit(min(failed, 100))
