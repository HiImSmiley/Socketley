#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a GET of a large value is sent from the store, and every answer still says what the cache held
# when its command ran, in the order the commands came.
#
# What each part would catch:
#   * a later command of the same read changing what an earlier GET answers, which an answer that points into the
#     store and is sent only after the read is done would do
#   * the replies ahead of a large value sent after it, or the part a full socket did not take sent twice or lost,
#     which a client that reads slowly and asks for many large values in one write sees
#   * a large value inside MULTI/EXEC, or between small replies, out of its place in the answer
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a large GET is sent from the store, in order and as it was ==="
daemon_isolate bigget
P=$((SL_PORT_BASE + 740))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"

"$BIN" create cache bg -p "$P" -s >/dev/null 2>&1 || bad "the cache is made" "$(tail -3 "$SOCKETLEY_DLOG")"

out=$(python3 -I - "$P" <<'EOF'
import socket, sys, time
port = int(sys.argv[1])

def cmd(*a):
    out = b"*%d\r\n" % len(a)
    for x in a:
        x = x if isinstance(x, bytes) else x.encode()
        out += b"$%d\r\n%s\r\n" % (len(x), x)
    return out

class Reader:
    def __init__(self, s, slow=False):
        self.s, self.buf, self.slow = s, b"", slow
    def fill(self):
        if self.slow:
            time.sleep(0.002)
        b = self.s.recv(16384 if self.slow else 1 << 20)
        if not b:
            raise EOFError
        self.buf += b
    def line(self):
        while b"\r\n" not in self.buf:
            self.fill()
        l, self.buf = self.buf.split(b"\r\n", 1)
        return l
    def reply(self):
        l = self.line()
        t = l[:1]
        if t in (b"+", b"-", b":"):
            return l
        if t == b"$":
            n = int(l[1:])
            if n < 0:
                return None
            while len(self.buf) < n + 2:
                self.fill()
            v, self.buf = self.buf[:n], self.buf[n + 2:]
            return v
        if t == b"*":
            return [self.reply() for _ in range(int(l[1:]))]
        raise ValueError(l[:40])

def conn(slow=False):
    s = socket.create_connection(("127.0.0.1", port))
    if slow:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
    return s, Reader(s, slow)

def val(tag, n=300000):
    return (tag * (n // len(tag) + 1))[:n]

results = []
def check(name, cond):
    results.append(("ok" if cond else "FAIL") + " " + name)

s, r = conn()
A, B = val(b"A1"), val(b"B2")
s.sendall(cmd("SET", "big", A))
check("set", r.reply() == b"+OK")

# One write: the GET must answer A even though the SET behind it replaces the value in the same read.
s.sendall(cmd("PING") + cmd("GET", "big") + cmd("SET", "big", B) + cmd("APPEND", "big", "tail") + cmd("GET", "big") + cmd("PING"))
got = [r.reply() for _ in range(6)]
check("a GET answers the value as it was when it ran, not as a later command of the same read left it",
      got[1] == A and got[4] == B + b"tail")
check("the small replies around large ones keep their places", got[0] == b"+PONG" and got[2] == b"+OK" and got[5] == b"+PONG")

# Inside a transaction.
s.sendall(cmd("MULTI") + cmd("GET", "big") + cmd("SET", "big", A) + cmd("GET", "big") + cmd("EXEC"))
got = [r.reply() for _ in range(5)]
check("a large GET inside MULTI/EXEC answers in the transaction's array",
      got[0] == b"+OK" and got[1] == b"+QUEUED" and isinstance(got[4], list) and len(got[4]) == 3
      and got[4][0] == B + b"tail" and got[4][1] == b"+OK" and got[4][2] == A)

# A slow reader asks for 40 large values in one write, each different, so a part sent twice or lost shows.
for i in range(8):
    s.sendall(cmd("SET", "k%d" % i, val(b"%02d" % i, 200000 + i * 1000)))
    r.reply()
s2, r2 = conn(slow=True)
want = []
req = b""
for j in range(40):
    i = j % 8
    req += cmd("GET", "k%d" % i) + cmd("PING")
    want.append(val(b"%02d" % i, 200000 + i * 1000))
s2.sendall(req)
good = True
for j in range(40):
    v = r2.reply()
    p = r2.reply()
    if v != want[j] or p != b"+PONG":
        good = False
        break
check("a reader that takes a large answer in pieces gets every byte once and in order", good)
s2.sendall(cmd("PING"))
check("the slow connection still answers after it", r2.reply() == b"+PONG")
print("\n".join(results))
EOF
)
while IFS= read -r line; do
    case "$line" in
        ok\ *) ok ;;
        FAIL\ *) bad "${line#FAIL }" "the client saw it go wrong" ;;
        *) bad "client" "$line" ;;
    esac
done <<<"$out"
[ "$PASS" -ge 6 ] || bad "the client" "ran $PASS checks of 6"

echo ""
echo "=== Results: $PASS/$((PASS+FAIL)) passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
