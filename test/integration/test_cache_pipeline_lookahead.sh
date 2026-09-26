#!/usr/bin/env bash
# Integration test: a pipeline over a keyspace large enough for the RESP loop
# to parse ahead is answered exactly as it would be one command at a time
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# Past 64K slots the RESP loop parses up to eight commands ahead of the one it
# runs, to fetch their keys' lines early.  Below that it does not, so every
# pipelining test that loads a few keys runs the old path and says nothing
# about this one.  Here the keyspace is loaded past the threshold first, and
# then a stream is sent that walks every edge the lookahead has: commands with
# more arguments than it holds, a command split across two reads, a write
# followed at once by a read of the same key, and errors in the middle.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the lookahead never engaging -- the keyspace must be past the threshold
#   * any reply out of order, missing, duplicated or wrong, against a model of
#     the store computed alongside the stream
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
PASS=0; FAIL=0; TOTAL=0
cleanup(){ daemon_stop; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: a pipeline read ahead is answered as one read in order ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

P=$((SL_PORT_BASE + 133))
daemon_isolate pipelookahead
daemon_start "$BIN"
"$BIN" create cache la -p "$P" -s >/dev/null 2>&1 || true
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done

OUT=$(timeout 300 python3 - "$P" <<'PY'
import socket, sys, random
port = int(sys.argv[1])
rnd = random.Random(7)

def enc(*a):
    out = b"*%d\r\n" % len(a)
    for x in a:
        x = x if isinstance(x, bytes) else str(x).encode()
        out += b"$%d\r\n%s\r\n" % (len(x), x)
    return out

def read_reply(f):
    line = f.readline()
    t, body = line[:1], line[1:-2]
    if t in (b"+", b"-", b":"):
        return line[:-2]
    if t == b"$":
        n = int(body)
        if n < 0:
            return b"$-1"
        data = f.read(n + 2)
        return b"$" + data[:-2]
    if t == b"*":
        return b"*" + b"|".join(read_reply(f) for _ in range(int(body)))
    raise RuntimeError("unexpected reply %r" % line)

s = socket.create_connection(("127.0.0.1", port), 30)
f = s.makefile("rb")

# 60,000 keys, which takes the table to 131,072 slots.
N = 60000
model = {}
load = b"".join(enc("SET", "k:%d" % i, "v:%d" % i) for i in range(N))
s.sendall(load)
for i in range(N):
    assert read_reply(f) == b"+OK"
    model["k:%d" % i] = "v:%d" % i

cmds, want = [], []
def cmd(args, reply):
    cmds.append(enc(*args)); want.append(reply)

for step in range(30000):
    r = rnd.random()
    k = "k:%d" % rnd.randrange(N + 2000)
    if r < 0.45:
        v = model.get(k)
        cmd(("GET", k), b"$-1" if v is None else b"$" + v.encode())
    elif r < 0.65:
        v = "w:%d" % step
        cmd(("SET", k, v), b"+OK"); model[k] = v
        # A read of the key just written, one command behind it.
        cmd(("GET", k), b"$" + v.encode())
    elif r < 0.72:
        # Nine pairs is nineteen arguments, more than the lookahead holds.
        pairs = []
        for j in range(9):
            kk = "k:%d" % rnd.randrange(N); vv = "m:%d:%d" % (step, j)
            pairs += [kk, vv]; model[kk] = vv
        cmd(["MSET"] + pairs, b"+OK")
    elif r < 0.80:
        n = 1 if k in model else 0
        model.pop(k, None)
        cmd(("DEL", k), b":%d" % n)
    elif r < 0.88:
        ks = ["k:%d" % rnd.randrange(N + 2000) for _ in range(12)]
        parts = [b"$-1" if model.get(x) is None else b"$" + model[x].encode() for x in ks]
        cmd(["MGET"] + ks, b"*" + b"|".join(parts))
    elif r < 0.94:
        c = "cnt:%d" % rnd.randrange(50)
        cur = int(model.get(c, "0")) + 1; model[c] = str(cur)
        cmd(("INCR", c), b":%d" % cur)
    else:
        cmd(("NOSUCHCOMMAND", k), None)

# Sent in pieces cut at random bytes, so commands straddle reads.
stream = b"".join(cmds)
import threading
def send():
    i = 0
    while i < len(stream):
        n = rnd.randrange(1, 9000)
        s.sendall(stream[i:i + n]); i += n
t = threading.Thread(target=send); t.start()
bad = 0
first = None
for idx, w in enumerate(want):
    got = read_reply(f)
    ok = got.startswith(b"-") if w is None else got == w
    if not ok:
        bad += 1
        if first is None:
            first = "reply %d: want %r got %r" % (idx, w, got[:80])
t.join()
print("%d %d %s" % (len(want), bad, first or "-"))
PY
) || OUT="0 -1 python-failed"
read -r SENT BAD FIRST <<<"$OUT"
echo "  $SENT pipelined commands over 60,000 keys: $BAD wrong"

# ── 1. every reply is the one the model predicts, in order ─────────────────
if [ "$BAD" = 0 ] && [ "$SENT" -gt 0 ]; then pass
else fail "every pipelined reply matches, in order" "$BAD of $SENT wrong" "first: $FIRST"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
