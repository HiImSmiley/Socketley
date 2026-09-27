#!/usr/bin/env bash
# Integration test: a client hands its script exactly the lines its peer sent,
# however the reads cut them.
#
# ─── WHY THIS EXISTS ────────────────────────────────────────────────────────
#
# The client frames lines straight out of the kernel's provided buffer and
# keeps only the unfinished line in `partial`, so a line can arrive whole in
# one read, finish a line an earlier read began, or leave a tail for the next.
# Every one of those is a different branch, and the peer here cuts its bytes
# to reach each of them, pacing on the client's ACKs so each cut is its own
# read.
#
# ─── WHAT IT ASSERTS ────────────────────────────────────────────────────────
#
#   a line split over three reads          arrives once, whole
#   several lines in one read              arrive in order
#   a read that finishes one line, holds   both halves joined, the middle ones
#     more, and leaves a tail                in order, the tail kept
#   CRLF, and a CR the next read ends      the CR stripped, a mid-line CR kept
#   empty lines, bare and CRLF             never reach the script
#   a 40000-byte line finished by a read   joined, with the two short lines
#     that carries two more lines            after it
#   a line of exactly --read-buffer bytes  delivered
#   one byte more                          refused, the connection closed
#   socketley.stop() from on_message with  no line after it reaches the script,
#     two more lines in the same read        and a start brings the client back
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate lineframe

PORT=$((SL_PORT_BASE+1776))
STATUS="$SOCKETLEY_TMPD/peer.status"
EXPECT="$SOCKETLEY_TMPD/expected.txt"
GOT="$SOCKETLEY_TMPD/got.txt"
LUA="$SOCKETLEY_TMPD/framing.lua"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop   lf_cli >/dev/null 2>&1 || true
    "$BIN" remove lf_cli >/dev/null 2>&1 || true
    [ -n "${PEER_PID:-}" ] && kill "$PEER_PID" 2>/dev/null
    daemon_stop
}
trap cleanup EXIT

status_has() {
    local what=$1 deadline=$(( $(date +%s) + ${2:-20} ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        grep -qxF "$what" "$STATUS" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

echo "=== Integration: a client's line framing across reads ==="
daemon_start "$BIN"

# The peer: three connections, one per phase, each step waiting for the ACKs
# of the lines before it so the next cut lands in a read of its own.
python3 - "$PORT" "$STATUS" "$EXPECT" <<'PY' >"$SOCKETLEY_TMPD/peer.log" 2>&1 &
import socket, sys, time

port, status_path, expect_path = int(sys.argv[1]), sys.argv[2], sys.argv[3]

def say(s):
    with open(status_path, "a") as f:
        f.write(s + "\n")

def pattern(n):
    return "".join(chr(97 + i % 26) for i in range(n)).encode()

def digest(b):
    s = 0
    for c in b:
        s = (s * 31 + c) % 1000000007
    return s

mid_line   = pattern(40000)
limit_line = pattern(65535)      # with its newline, exactly 64 KiB
over_line  = pattern(65536)      # one byte past it

with open(expect_path, "w") as f:
    for s in ["hello world", "one", "two", "three", "four", "five", "six",
              "seven", "crlf1", "crlf2", "crsplit", "after-empty", "mid<CR>cr"]:
        f.write("LFRAME got=[%s]\n" % s)
    f.write("LFRAME long len=%d sum=%d\n" % (len(mid_line), digest(mid_line)))
    f.write("LFRAME got=[tail-a]\n")
    f.write("LFRAME got=[tail-b]\n")
    f.write("LFRAME long len=%d sum=%d\n" % (len(limit_line), digest(limit_line)))
    f.write("LFRAME got=[before-stop]\n")
    f.write("LFRAME got=[STOP-NOW]\n")
    f.write("LFRAME got=[back]\n")

class Peer:
    def __init__(self, c):
        self.c, self.buf, self.acks = c, b"", 0
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def send(self, *parts):
        for i, p in enumerate(parts):
            if i:
                time.sleep(0.25)
            self.c.sendall(p)

    def acked(self, n, t=10):
        deadline = time.time() + t
        while self.acks < n:
            left = deadline - time.time()
            if left <= 0:
                return False
            self.c.settimeout(left)
            try:
                d = self.c.recv(65536)
            except socket.timeout:
                return False
            if not d:
                return False
            self.buf += d
            while b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                if line.startswith(b"ACK"):
                    self.acks += 1
        return True

    def closed(self, t=10):
        deadline = time.time() + t
        while True:
            left = deadline - time.time()
            if left <= 0:
                return False
            self.c.settimeout(left)
            try:
                if not self.c.recv(65536):
                    return True
            except socket.timeout:
                return False
            except OSError:
                return True

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(4)
srv.settimeout(40)

# ─── A: every cut of the byte stream ────────────────────────────────────────
p = Peer(srv.accept()[0])
say("A connected")
time.sleep(0.3)
steps = [
    ((b"hel", b"lo wor", b"ld\n"), 1),
    ((b"one\ntwo\nthree\n",), 4),
    ((b"four\nfiv", b"e\nsix\nsev", b"en\n"), 8),
    ((b"crlf1\r\ncrlf2\r\ncrsplit\r", b"\n"), 11),
    ((b"\n\r\n\nafter-empty\n",), 12),
    ((b"mid\rcr\n",), 13),
    ((mid_line[:20000], mid_line[20000:] + b"\ntail-a\ntail-b\n"), 16),
    ((limit_line + b"\n",), 17),
]
for parts, want in steps:
    p.send(*parts)
    if not p.acked(want):
        say("A stalled at %d acks, wanted %d" % (p.acks, want))
        sys.exit(1)
say("A delivered")
try:
    p.send(over_line + b"\n")
except OSError:
    pass
say("A closed" if p.closed() else "A still open")

# ─── B: the script stops the runtime with more lines in the same read ───────
p = Peer(srv.accept()[0])
say("B connected")
time.sleep(0.3)
p.send(b"before-stop\nSTOP-NOW\nafter-stop-1\nafter-stop-2\n")
say("B closed" if p.closed() else "B still open")

# ─── C: started again, it is an ordinary client ─────────────────────────────
srv.settimeout(60)
p = Peer(srv.accept()[0])
say("C connected")
time.sleep(0.3)
p.send(b"back\n")
say("C ok" if p.acked(1) else "C stalled")
PY
PEER_PID=$!

for i in $(seq 1 60); do
    ss -ltnH "sport = :$PORT" 2>/dev/null | grep -q . && break
    sleep 0.1
done

cat > "$LUA" <<'LUAEOF'
-- Long lines as a length and a digest the peer computes the same way, so the
-- log carries the proof and not the payload.
function on_message(msg)
    if #msg > 80 then
        local s = 0
        for i = 1, #msg do s = (s * 31 + msg:byte(i)) % 1000000007 end
        socketley.log("LFRAME long len=" .. #msg .. " sum=" .. s)
    else
        socketley.log("LFRAME got=[" .. (msg:gsub("\r", "<CR>")) .. "]")
    end
    if msg == "STOP-NOW" then
        socketley.stop(self.name)
        return
    end
    self.send("ACK")
end
LUAEOF

"$BIN" create client lf_cli -t "127.0.0.1:$PORT" --lua "$LUA" \
    --read-buffer 64K --reconnect >/dev/null 2>&1
"$BIN" start lf_cli >/dev/null 2>&1

# ─── A ──────────────────────────────────────────────────────────────────────
if status_has "A delivered" 30; then ok; else
    bad "every cut of the stream is delivered and acknowledged" \
        "peer says: $(tr '\n' ';' < "$STATUS" 2>/dev/null)"
fi
if status_has "A closed" 15; then ok; else
    bad "a line one byte past --read-buffer closes the connection" \
        "peer says: $(tr '\n' ';' < "$STATUS" 2>/dev/null)"
fi

# ─── B ──────────────────────────────────────────────────────────────────────
if status_has "B closed" 30; then ok; else
    bad "the client reconnects and a stop from on_message closes it" \
        "peer says: $(tr '\n' ';' < "$STATUS" 2>/dev/null)"
fi
# The stop is a worker round trip, so the lines it must have suppressed are
# given a moment to show up if they were going to.
sleep 1

# ─── C ──────────────────────────────────────────────────────────────────────
"$BIN" start lf_cli >/dev/null 2>&1
if status_has "C ok" 30; then ok; else
    bad "a client stopped from inside on_message starts again and reads" \
        "peer says: $(tr '\n' ';' < "$STATUS" 2>/dev/null)"
fi
sleep 0.5

# ─── What the script saw, in order ──────────────────────────────────────────
grep -a 'LFRAME ' "$SOCKETLEY_DLOG" 2>/dev/null | sed 's/.*LFRAME /LFRAME /' > "$GOT"
if cmp -s "$EXPECT" "$GOT"; then ok; else
    bad "the script receives exactly the lines sent, in order" \
        "diff expected got:" \
        "$(diff "$EXPECT" "$GOT" 2>&1 | head -20)"
fi

# Named on its own, because this is the line a missing liveness check delivers.
if grep -q 'after-stop' "$GOT" 2>/dev/null; then
    bad "no line after the stop reaches on_message" \
        "$(grep 'after-stop' "$GOT" | tr '\n' ';')"
else
    ok
fi

if grep -qE 'AddressSanitizer|runtime error:|killed by signal' "$SOCKETLEY_DLOG" 2>/dev/null; then
    bad "no worker crashed" \
        "$(grep -E 'AddressSanitizer|runtime error:|killed by signal' "$SOCKETLEY_DLOG" | head -3)"
else
    ok
fi

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
