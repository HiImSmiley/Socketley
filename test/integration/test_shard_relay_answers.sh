#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Answers between shards relayed through the daemon, two of 7 MiB at once for the same shard.
#
# What each part would catch:
#   * the second of two large answers refused by the owning shard's writer or by the daemon's writer to the asking
#     shard, past a backlog of one frame, so its client waits out the 30 s the channel gives an answer
#   * a request the daemon refuses because the stopped shard's backlog is full, told to its client as
#     "no such runtime" rather than as the overload it is
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
. "$HERE/lib_ready.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
. "$HERE/lib_verdicts.sh"

echo "=== Integration: large answers between shards through the daemon ==="
P=$((SL_PORT_BASE + 1970))
daemon_isolate relayanswers
trap 'daemon_stop' EXIT
export SOCKETLEY_NO_SHARD_MESH=1
daemon_start "$BIN"
"$BIN" create cache big -p "$P" --shards 2 --resp -s >/dev/null 2>&1 \
    && ok || bad "a cache of two shards is made with no mesh" "$(tail -3 "$SOCKETLEY_DLOG")"
ready_tcp 127.0.0.1 "$P" || bad "it listens" "$(tail -5 "$SOCKETLEY_DLOG")"

run() {
    PYTHONPATH="$HERE" python3 - "$P" "$BIN" 2>&1 <<'PY'

import os, re, signal, socket, subprocess, sys, threading, time
port, binary = int(sys.argv[1]), sys.argv[2]
SIZE = 7 << 20

def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))

def cmd(*a):
    out = b"*%d\r\n" % len(a)
    for x in a:
        x = x if isinstance(x, bytes) else x.encode()
        out += b"$%d\r\n%s\r\n" % (len(x), x)
    return out

def reply(s, timeout):
    deadline, buf = time.time() + timeout, b""
    while b"\r\n" not in buf:
        s.settimeout(max(0.01, deadline - time.time()))
        d = s.recv(1 << 16)
        if not d:
            return None
        buf += d
    head, _, rest = buf.partition(b"\r\n")
    if head[:1] != b"$" or int(head[1:]) < 0:
        return head
    want = int(head[1:])
    while len(rest) < want + 2:
        s.settimeout(max(0.01, deadline - time.time()))
        d = s.recv(1 << 20)
        if not d:
            return None
        rest += d
    return rest[:want]

def per_shard(name):
    out = subprocess.run([binary, "stats", "big"], capture_output=True, timeout=30).stdout.decode()
    got, shard = {}, None
    for line in out.splitlines():
        m = re.match(r"\[shard (\d+)\]", line)
        if m:
            shard = int(m.group(1))
        elif shard is not None and line.partition(":")[0] == name:
            got[shard] = int(line.partition(":")[2])
    return got

def settled(name, want):
    # A shard's figures reach the daemon a moment after they change.
    for _ in range(100):
        got = per_shard(name)
        if sum(got.values()) == want:
            return got
        time.sleep(0.1)
    return per_shard(name)

def pid_of(c):
    out = subprocess.run(["ss", "-tnpH", "sport = :%d and dport = :%d" % (port, c.getsockname()[1])],
                         capture_output=True, timeout=10).stdout.decode()
    m = re.search(r"pid=(\d+)", out)
    return int(m.group(1)) if m else None

try:
    # Which shard owns each key, by whose count of keys grows.
    w = socket.create_connection(("127.0.0.1", port))
    owner = {}
    for i in range(6):
        before = settled("keys", i)
        for at in range(0, SIZE, 256 << 10):
            w.sendall(cmd("APPEND", "big%d" % i, bytes([65 + i]) * min(256 << 10, SIZE - at)))
            reply(w, 30)
        after = settled("keys", i + 1)
        owner[i] = next(s for s in after if after[s] > before.get(s, 0))
    w.close()
    held = max((0, 1), key=lambda s: sum(1 for k in owner if owner[k] == s))
    keys = [k for k in owner if owner[k] == held][:2]
    # Two connections on the other shard, and the process of each shard.
    conns, pids = [], {}
    for _ in range(40):
        c = socket.create_connection(("127.0.0.1", port))
        now = settled("shard_connections", len(conns) + 1)
        shard = next(s for s in now if now[s] > sum(1 for x in conns if x[1] == s))
        pids[shard] = pid_of(c)
        if shard != held and len(conns) < 2:
            conns.append((c, shard))
        else:
            c.close()
            settled("shard_connections", len(conns))
        if len(conns) == 2 and held in pids:
            break
    check("two connections land on the shard that does not hold the keys", (len(conns), held in pids), (2, True))
    # Both asked while the shard that owns the keys is stopped, so it answers both at once.
    got = {}
    def get(i, c, k):
        t = time.time()
        c.sendall(cmd("GET", "big%d" % k))
        r = reply(c, 40)
        got[i] = (r == bytes([65 + k]) * SIZE, time.time() - t)
    os.kill(pids[held], signal.SIGSTOP)
    try:
        ts = [threading.Thread(target=get, args=(i, c, k)) for i, ((c, _), k) in enumerate(zip(conns, keys))]
        for t in ts:
            t.start()
            time.sleep(0.05)
        time.sleep(0.5)
    finally:
        os.kill(pids[held], signal.SIGCONT)
    for t in ts:
        t.join()
    check("both answers of 7 MiB arrive whole", [got[0][0], got[1][0]], [True, True])
    slow = max(got[0][1], got[1][1])
    print(("ok " if slow < 10 else "bad ") + "and promptly" + ("" if slow < 10 else ": %.1f s" % slow))

    # Past the 68 MiB the daemon queues for a stopped shard, one APPEND of 448 KiB from each of 200 connections on
    # the other shard, and the APPENDs past it are refused at once, their clients told why.
    opened = [socket.create_connection(("127.0.0.1", port)) for _ in range(440)]
    out = subprocess.run(["ss", "-tnpH", "sport = :%d" % port], capture_output=True, timeout=10).stdout.decode()
    by_port = {}
    for line in out.splitlines():
        f = line.split()
        m = re.search(r"pid=(\d+)", line)
        if len(f) >= 5 and m:
            by_port[int(f[4].rpartition(":")[2])] = int(m.group(1))
    more = [c for c in opened if by_port.get(c.getsockname()[1]) not in (pids[held], None)][:200]
    for c in opened:
        if c not in more:
            c.close()
    check("two hundred connections land on the shard that does not hold the key", len(more), 200)
    answers = []
    os.kill(pids[held], signal.SIGSTOP)
    try:
        chunk = cmd("APPEND", "big%d" % keys[0], b"Z" * (448 << 10))
        for c in more:
            c.sendall(chunk)
        time.sleep(1)
        for c in more:
            c.setblocking(False)
            try:
                d = c.recv(1 << 16)
            except BlockingIOError:
                d = None
            if d:
                answers.append(d)
    finally:
        os.kill(pids[held], signal.SIGCONT)
    refused = [a for a in answers if a.startswith(b"-")]
    print(("ok " if refused else "bad ") + "an APPEND past the stopped shard's backlog is refused at once"
          + ("" if refused else ": answers %r" % [a[:80] for a in answers]))
    told = refused[0] if refused else b""
    print("# told: %r (%d of %d refused)" % (told[:120], len(refused), len(answers)))
    check("its client is told the worker is overloaded, not that there is no such runtime",
          (b"overloaded" in told, b"no such runtime" in told, told[:100]), (True, False, told[:100]))
    for c in more:
        c.close()
except Exception as e:
    print("bad the script ran: %s %s" % (type(e).__name__, e))
PY
}
tally < <(run)
unset SOCKETLEY_NO_SHARD_MESH

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
