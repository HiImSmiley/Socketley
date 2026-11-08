#!/usr/bin/env bash
# Integration test: self.group_send reaches every member of a large group once,
# in order and byte for byte, and nobody else
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A group's message is written once into a shared segment and each member's
# queue holds a slice of it, grown in place while the next message follows the
# last -- the relay's path, which group_send takes.  What can go wrong is bytes,
# not counts: a slice grown by the wrong length sends a line twice or drops it,
# a slice of the wrong segment sends another message, and a segment that moved
# under a slice sends freed memory.  Every line is numbered and sized by its
# number, so any of those shows as a wrong byte at a known position.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * members reading at once and members reading a second late, which is what
#     makes the queues deep enough to span many segments
#   * websocket members, whose frames live in a segment of their own
#   * a member that leaves part way: what was sent before, nothing after
#   * a member that closes part way: the others are not disturbed
#   * a connection that never joined, and the sender, hear nothing
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1
daemon_isolate groupsend
PASS=0; FAIL=0; TOTAL=0
WORK=$(mktemp -d)
cleanup(){ rm -rf "$WORK"; daemon_stop; }
trap cleanup EXIT
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

echo "=== Integration: group_send reaches every member of a large group in order ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 not available"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }

cat > "$WORK/room.lua" <<'LUA'
function on_client_message(id, msg)
    if msg == "join" then
        self.join_group(id, "room")
        self.send(id, "joined")
    elseif msg == "leave" then
        self.leave_group(id, "room")
        self.send(id, "left")
    elseif msg == "hello" then
        self.send(id, "hi")
    else
        self.group_send("room", msg)
    end
    return true
end
LUA

P=$((SL_PORT_BASE + 121))
daemon_start "$BIN"
"$BIN" create server grp -p "$P" --lua "$WORK/room.lua" -s >/dev/null 2>&1 || true
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done

timeout 180 python3 - "$P" > "$WORK/out" <<'PY'
import base64, os, socket, sys, threading, time
port = int(sys.argv[1])
N = 6000
TCP, WS = 96, 32          # members of each kind, half of each reading late
LEAVE_AT, CLOSE_AT = 2000, 3000

def line(i):
    return b"seq:%06d:" % i + bytes([97 + i % 26]) * (i % 173) + b"\n"
lines = [line(i) for i in range(N)]
want = b"".join(lines)

def conn():
    s = socket.create_connection(("127.0.0.1", port), 10); s.settimeout(30)
    return s

class tcp_reader:
    def __init__(self, s): self.s, self.buf = s, b""
    def msg(self):
        while b"\n" not in self.buf:
            b = self.s.recv(1 << 16)
            if not b: raise EOFError
            self.buf += b
        m, self.buf = self.buf.split(b"\n", 1)
        return m + b"\n"
    def send(self, m): self.s.sendall(m + b"\n")

class ws_reader:
    def __init__(self, s):
        self.s = s
        key = base64.b64encode(os.urandom(16))
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                  b"Sec-WebSocket-Key: " + key + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += s.recv(4096)
        self.buf = buf.split(b"\r\n\r\n", 1)[1]
    def msg(self):
        while True:
            if len(self.buf) >= 2:
                ln = self.buf[1] & 0x7f; h = 2
                if ln == 126: ln = int.from_bytes(self.buf[2:4], "big"); h = 4
                elif ln == 127: ln = int.from_bytes(self.buf[2:10], "big"); h = 10
                if len(self.buf) >= h + ln:
                    m = self.buf[h:h + ln]; self.buf = self.buf[h + ln:]
                    return m + b"\n"
            b = self.s.recv(1 << 16)
            if not b: raise EOFError
            self.buf += b
    def send(self, m):
        mask = os.urandom(4)
        self.s.sendall(bytes([0x81, 0x80 | len(m)]) + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(m)))

out = {}
left, published = threading.Event(), threading.Event()
joined = threading.Barrier(TCP + WS + 2 + 1)
def member(idx, ws, delay, stop=None, how=None):
    r = (ws_reader if ws else tcp_reader)(conn())
    r.send(b"join")
    ok = r.msg() == b"joined\n"
    joined.wait()
    time.sleep(delay)
    got = []
    try:
        while len(got) < N:
            got.append(r.msg())
            if stop is not None and len(got) == stop:
                if how == "leave":
                    # The rest is published only once the leave is through, and none of it may arrive.
                    r.send(b"leave")
                    while (m := r.msg()) != b"left\n":
                        got.append(m)
                    left.set()
                    published.wait()
                    r.s.settimeout(2)
                    got.append(r.msg())
                else:
                    r.s.close()
                break
    except (socket.timeout, EOFError, OSError):
        pass
    out[idx] = (ok, b"".join(got))

ts = []
for i in range(TCP):
    ts.append(threading.Thread(target=member, args=("tcp%d" % i, False, 1.0 if i % 2 else 0)))
for i in range(WS):
    ts.append(threading.Thread(target=member, args=("ws%d" % i, True, 1.0 if i % 2 else 0)))
ts.append(threading.Thread(target=member, args=("leaver", False, 0, LEAVE_AT, "leave")))
ts.append(threading.Thread(target=member, args=("closer", True, 0, CLOSE_AT, "close")))
for t in ts: t.start()

outsider = tcp_reader(conn())
outsider.send(b"hello")
outsider_hi = outsider.msg() == b"hi\n"
pub = conn()
joined.wait()
pub.sendall(b"".join(lines[:LEAVE_AT]))
left.wait(60)
pub.sendall(b"".join(lines[LEAVE_AT:]))
published.set()
for t in ts: t.join()

outsider.s.settimeout(1); pub.settimeout(1)
def heard(s):
    try:
        return len(s.recv(1 << 16))
    except socket.timeout:
        return 0
print("outsider greeted %s heard %d" % (outsider_hi, heard(outsider.s) + len(outsider.buf)))
print("publisher heard %d" % heard(pub))

def first_diff(g, w):
    return next((k for k in range(min(len(g), len(w))) if g[k] != w[k]), min(len(g), len(w)))
whole = 0
for idx, (ok, g) in sorted(out.items()):
    if idx == "leaver":
        n = g.count(b"\n")
        pre = b"".join(lines[:n])
        print("leaver %s got %d lines, %s" % ("joined" if ok else "NOT joined", n,
              "a prefix" if g == pre and n == LEAVE_AT else
              "differs at byte %d" % first_diff(g, pre) if g != pre else "not %d" % LEAVE_AT))
    elif idx == "closer":
        print("closer %s" % ("a prefix" if g == b"".join(lines[:CLOSE_AT]) else "differs"))
    elif ok and g == want:
        whole += 1
    else:
        print("%s %s, differs at byte %d of %d (got %d)" % (idx, "joined" if ok else "NOT joined",
              first_diff(g, want), len(want), len(g)))
print("whole %d of %d" % (whole, TCP + WS))
PY
sed 's/^/  /' "$WORK/out"

# ── 1. every member, prompt and late, TCP and websocket ─────────────────────
if grep -q "^whole 128 of 128" "$WORK/out"; then pass
else fail "every member receives every message once and in order" "$(grep -v '^whole' "$WORK/out" | head -5)" "$(grep '^whole' "$WORK/out" || echo 'no result')"; fi
# ── 2. a member that leaves part way ────────────────────────────────────────
if grep -q "^leaver joined got [0-9]* lines, a prefix" "$WORK/out"; then pass
else fail "a member that leaves receives what was sent before, then nothing" "$(grep '^leaver' "$WORK/out" || echo 'no result')"; fi
# ── 3. a member that closes part way ────────────────────────────────────────
if grep -q "^closer a prefix" "$WORK/out"; then pass
else fail "a member that closes had what it read in order" "$(grep '^closer' "$WORK/out" || echo 'no result')"; fi
# ── 4-5. nobody outside the group ───────────────────────────────────────────
if grep -q "^outsider greeted True heard 0" "$WORK/out"; then pass
else fail "a connection that never joined hears nothing" "$(grep '^outsider' "$WORK/out" || echo 'no result')"; fi
if grep -q "^publisher heard 0" "$WORK/out"; then pass
else fail "the sender, not a member, hears nothing" "$(grep '^publisher' "$WORK/out" || echo 'no result')"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
