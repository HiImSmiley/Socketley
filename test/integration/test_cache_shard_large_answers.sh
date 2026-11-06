#!/usr/bin/env bash
# suite: isolated -- its own daemons, sockets, state directories and port window, so it runs beside the others
# Commands whose answer, or whose request, is past the 8 MiB one frame between processes holds, sent to a shard that
# does not own their keys: relayed through the daemon (no mesh) and over the mesh.
#
# What each part would catch:
#   * two 7 MiB GETs pipelined in one turn, which go to the owning shard as one request whose answer is 14 MiB, refused
#     on the way back through the daemon and answered "-ERR ... a framing this build does not read"
#   * one GET of a 20 MiB value, an answer past one frame on its own
#   * a SET of a 10 MiB value, a request past one frame, refused at the asking shard's way to the daemon
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

P=$((SL_PORT_BASE + 1988))

run() {
    PYTHONPATH="$HERE" python3 - "$P" "$BIN" "$1" 2>&1 <<'PY'

import re, socket, subprocess, sys, time
port, binary, mode = int(sys.argv[1]), sys.argv[2], sys.argv[3]

def check(name, got, want):
    name = "%s: %s" % (mode, name)
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))

def cmd(*a):
    out = b"*%d\r\n" % len(a)
    for x in a:
        x = x if isinstance(x, bytes) else x.encode()
        out += b"$%d\r\n%s\r\n" % (len(x), x)
    return out

class conn:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", port))
        self.buf = b""

    def more(self, deadline):
        self.s.settimeout(max(0.01, deadline - time.time()))
        d = self.s.recv(1 << 20)
        if not d:
            raise EOFError("closed")
        self.buf += d

    def reply(self, timeout=30):
        deadline = time.time() + timeout
        while b"\r\n" not in self.buf:
            self.more(deadline)
        head, _, rest = self.buf.partition(b"\r\n")
        if head[:1] != b"$" or int(head[1:]) < 0:
            self.buf = rest
            return head
        want = int(head[1:])
        while len(self.buf) < len(head) + 2 + want + 2:
            self.more(deadline)
        body = self.buf[len(head) + 2:len(head) + 2 + want]
        self.buf = self.buf[len(head) + 4 + want:]
        return body

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

def fill(c, key, byte, size):
    for at in range(0, size, 256 << 10):
        c.s.sendall(cmd("APPEND", key, bytes([byte]) * min(256 << 10, size - at)))
        c.reply()

try:
    # Every key under one hash tag, so one shard owns them all, found by whose count of keys grows.
    w = conn()
    fill(w, "{t}a", 65, 7 << 20)
    owner = settled("keys", 1)
    held = next(s for s in owner if owner[s] == 1)
    fill(w, "{t}b", 66, 7 << 20)
    fill(w, "{t}c", 67, 20 << 20)
    w.s.close()
    check("the three values are on one shard", settled("keys", 3).get(held), 3)

    # A connection on the other shard, which relays every command below.
    c = None
    for _ in range(40):
        x = conn()
        now = settled("shard_connections", 1)
        if now.get(held, 0) == 0:
            c = x
            break
        x.s.close()
    check("a connection lands on the shard that does not hold the keys", c is not None, True)

    c.s.sendall(cmd("GET", "{t}a") + cmd("GET", "{t}b"))
    got = [c.reply(), c.reply()]
    check("two GETs of 7 MiB in one turn, both whole",
          [len(got[0]), got[0] == b"A" * (7 << 20), len(got[1]), got[1] == b"B" * (7 << 20)],
          [7 << 20, True, 7 << 20, True])

    c.s.sendall(cmd("GET", "{t}c"))
    r = c.reply()
    check("a GET of 20 MiB, whole", [len(r), r == b"C" * (20 << 20)], [20 << 20, True])

    c.s.sendall(cmd("GET", "{t}c") + cmd("GET", "{t}a") + cmd("PING"))
    got = [c.reply(), c.reply(), c.reply()]
    check("27 MiB in one turn, then PING", [len(got[0]), len(got[1]), got[2]], [20 << 20, 7 << 20, b"+PONG"])

    c.s.sendall(cmd("SET", "{t}d", b"D" * (10 << 20)))
    check("a SET of 10 MiB", c.reply(), b"+OK")
    c.s.sendall(cmd("STRLEN", "{t}d"))
    check("and it is on the owning shard, whole", [c.reply(), settled("keys", 4).get(held)], [b":%d" % (10 << 20), 4])
    c.s.close()
except Exception as e:
    print("bad %s: the script ran: %s %s" % (mode, type(e).__name__, e))
PY
}

for mode in relayed mesh; do
    echo "=== Integration: cache answers and requests past one frame between shards ($mode) ==="
    daemon_isolate largeanswers
    trap 'daemon_stop' EXIT
    if [ "$mode" = relayed ]; then
        export SOCKETLEY_NO_SHARD_MESH=1
    else
        # The handoff would move the connection to the shard that owns its keys, and nothing would cross.
        export SOCKETLEY_CACHE_HANDOFF=0
    fi
    daemon_start "$BIN"
    "$BIN" create cache big -p "$P" --shards 2 --resp --read-buffer 32M -s >/dev/null 2>&1 \
        && ok || bad "$mode: a cache of two shards" "$(tail -3 "$SOCKETLEY_DLOG")"
    ready_tcp 127.0.0.1 "$P" || bad "$mode: it listens" "$(tail -5 "$SOCKETLEY_DLOG")"
    tally < <(run "$mode")
    daemon_stop
    trap - EXIT
    unset SOCKETLEY_NO_SHARD_MESH SOCKETLEY_CACHE_HANDOFF
done

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
