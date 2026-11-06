#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: what many connections cross for in one turn goes to each sibling as one frame, and every answer
# in that frame still reaches the connection and the place in its pipeline that asked for it.
#
# A shard reading forty connections' pipelines in one turn used to post one crossing per connection and sibling;
# they now share one frame per sibling, whose answers carry the batch each belongs to.  The shards are stopped while
# the pipelines are written, so each one's first turn after SIGCONT reads all of them at once.
#
# What it would catch:
#   * an answer filled into another connection's batch, or into the wrong slot of its own: every reply is compared
#     byte for byte, and each connection's values name the connection
#   * a batch left waiting because the frame it went into was never posted or never settled: a connection answered
#     short times out
#   * a connection that closes with its pipeline in the frame taking its neighbours' answers with it
#   * one crossing per connection still: the crossings counted over the burst are fewer than the connections
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "=== Integration: a turn's crossings share one frame per sibling ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v ss >/dev/null 2>&1 || { echo "  SKIP: ss is required"; exit 0; }
daemon_isolate cacheturncross
P=$((SL_PORT_BASE + 1500))
cleanup() {
    for p in $(ss -ltnpH "sport = :$P" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u); do
        kill -CONT "$p" 2>/dev/null || true
    done
    "$BIN" stop tc >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT
daemon_start "$BIN"
"$BIN" create cache tc -p "$P" --shards 4 --resp -s >/dev/null 2>&1 || bad "a cache of four shards is made"

crossings() { "$BIN" stats tc 2>/dev/null | awk -F: '/^mesh_direct:/ {s+=$2} /^mesh_relayed:/ {s+=$2} END{print s+0}'; }

OUT=$(python3 - "$P" "$BIN" <<'PY'
import os, re, signal, socket, subprocess, sys, time
port, binary = int(sys.argv[1]), sys.argv[2]
CONNS, CMDS = 40, 60

def cmd(*a):
    a = [x if isinstance(x, bytes) else str(x).encode() for x in a]
    return b"*%d\r\n" % len(a) + b"".join(b"$%d\r\n%s\r\n" % (len(x), x) for x in a)

def bulk(v):
    return b"$%d\r\n%s\r\n" % (len(v), v)

def workers():
    out = subprocess.run(["ss", "-ltnpH", "sport = :%d" % port], capture_output=True, timeout=10).stdout.decode()
    return sorted({int(p) for p in re.findall(r"pid=(\d+)", out)})

def crossings():
    out = subprocess.run([binary, "stats", "tc"], capture_output=True, timeout=30).stdout.decode()
    return sum(int(l.partition(":")[2] or 0) for l in out.splitlines()
               if l.startswith("mesh_direct:") or l.startswith("mesh_relayed:"))

for _ in range(80):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=1); s.sendall(cmd("PING")); s.recv(64); s.close()
        if len(workers()) == 4:
            break
    except OSError:
        pass
    time.sleep(0.25)
pids = workers()
print("workers %d" % len(pids))

socks = []
for c in range(CONNS + 1):
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    s.sendall(cmd("PING"))
    assert s.recv(64) == b"+PONG\r\n"
    socks.append(s)

# Per connection: SETs of keys that fall on every shard, then GETs, an INCR, an MGET across shards and a DEL, so
# a frame carries single-part and multi-part answers of several kinds for several connections at once.
expect = []
pipes = []
for c in range(CONNS):
    p = b""; e = b""
    for i in range(CMDS // 3):
        k = b"tc:%d:%d" % (c, i); v = b"v%d.%d" % (c, i) * (1 + i % 3)
        p += cmd("SET", k, v); e += b"+OK\r\n"
    for i in range(CMDS // 3):
        k = b"tc:%d:%d" % (c, i); v = b"v%d.%d" % (c, i) * (1 + i % 3)
        p += cmd("GET", k); e += bulk(v)
    p += cmd("INCRBY", b"tc:n:%d" % c, c + 1); e += b":%d\r\n" % (c + 1)
    keys = [b"tc:%d:%d" % (c, i) for i in range(4)]
    p += cmd("MGET", *keys)
    e += b"*4\r\n" + b"".join(bulk(b"v%d.%d" % (c, i) * (1 + i % 3)) for i in range(4))
    p += cmd("DEL", b"tc:%d:0" % c, b"tc:%d:1" % c); e += b":2\r\n"
    p += cmd("GET", b"tc:%d:0" % c); e += b"$-1\r\n"
    pipes.append(p); expect.append(e)

before = crossings()
for pid in pids:
    os.kill(pid, signal.SIGSTOP)
try:
    # The one that leaves: its whole pipeline goes into the frames and its socket closes before any answer.
    socks[CONNS].sendall(b"".join(cmd("SET", b"tc:gone:%d" % i, b"x") for i in range(30)))
    socks[CONNS].close()
    for c in range(CONNS):
        socks[c].sendall(pipes[c])
    time.sleep(0.3)
finally:
    for pid in pids:
        os.kill(pid, signal.SIGCONT)

wrong = 0; short = 0
for c in range(CONNS):
    got = b""
    s = socks[c]; s.settimeout(10)
    try:
        while len(got) < len(expect[c]):
            d = s.recv(1 << 16)
            if not d:
                break
            got += d
    except socket.timeout:
        pass
    if len(got) < len(expect[c]):
        short += 1
    elif got != expect[c]:
        wrong += 1
print("short %d" % short)
print("wrong %d" % wrong)
time.sleep(1.2)   # a worker publishes its figures on an interval
print("crossings %d" % (crossings() - before))
print("conns %d" % CONNS)
PY
)
echo "$OUT" | sed 's/^/    /'

val() { echo "$OUT" | awk -v k="$1" '$1==k {print $2}'; }
[ "$(val workers)" = 4 ] && ok "four shards answer on one port" || bad "four shards answer on one port"
[ "$(val short)" = 0 ] && ok "every connection got every answer" || bad "every connection got every answer (short: $(val short))"
[ "$(val wrong)" = 0 ] && ok "every answer is its own connection's, in its order" \
                       || bad "every answer is its own connection's, in its order (wrong: $(val wrong))"
C=$(val crossings); N=$(val conns)
if [ -n "$C" ] && [ "$C" -gt 0 ] && [ "$C" -lt "${N:-0}" ]; then
    ok "the burst crossed in fewer frames than it had connections ($C for $N)"
else
    bad "the burst crossed in fewer frames than it had connections (${C:-?} for ${N:-?})"
fi

echo
echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
