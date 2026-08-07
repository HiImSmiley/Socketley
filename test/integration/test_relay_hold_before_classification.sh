#!/usr/bin/env bash
# Integration test: relay traffic is held until a connection is classified, and
# then delivered — behind the handshake response, and through the connection's
# own framing.
#
# ─── WHAT IS BEING TESTED, AND WHY IT IS NOT OBVIOUS ─────────────────────────
#
# A server in the default --mode inout is a relay: every client's messages go to
# every other client.  A connection joins that relay set the moment it is
# accepted, which is *before* its first read has said what protocol it speaks.
#
# So there is a window in which the server will write relay bytes to a client it
# knows nothing about.  For a client whose opening move is a WebSocket upgrade,
# those bytes do not merely arrive early — they arrive in front of the
# "HTTP/1.1 101" that client is parsing for, and the handshake is corrupted.
# test/benchmark/repro_ws_crosstalk.py measures this under load: 8 of 2000 mixed
# operations, every one the same shape.
#
# The fix holds relay traffic for an unclassified connection and releases it
# once the protocol is settled.  That creates a second way to be wrong which is
# much harder to see than the first, and this file exists mainly to close it:
#
#   * dropping the held bytes silently would make the reproduction green.  It
#     would also lose messages the client was entitled to — an inout server
#     relays to every client, and this one goes on receiving exactly this
#     traffic for the rest of its life.  So "no relay bytes before the 101" is
#     only half an assertion; the other half is that they ARRIVE.
#
#   * flushing them raw behind the 101 would trade one corrupted stream for
#     another.  The client reads the 101, switches to frame parsing, and is
#     handed plain text.  So they must arrive FRAMED.
#
#   * flushing them out of order, or losing the middle of the run, would be
#     invisible to any check that only looks for one message.  So the assertion
#     is on the whole sequence, in order.
#
# The last section covers the bound.  A connection that never sends is never
# classified, so its hold is not a transient and has to be capped; the policy is
# to drop the OLDEST, which is checked directly by asserting that the first
# message is gone and the last one survived.  A test that only asserted "some
# messages arrived" would pass equally well against a cap that dropped the
# newest, which is the choice that would strand a listener on stale traffic.
#
# ─── WHY THE SEQUENCING IS NOT A SLEEP ───────────────────────────────────────
#
# Every step waits on a figure the server publishes rather than on a duration.
# The window under test is "accepted but not yet classified", and a sleep long
# enough to be safe on a loaded machine is also long enough to hide a fix that
# only works when nothing else is happening.  bytes_in proves the server read
# the partial header (so the connection is accepted AND unclassified);
# total_messages proves the relayed lines were processed.  Neither is a proxy
# for the other and both are needed.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
daemon_isolate relayhold
PORT=19395
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop relayhold 2>/dev/null || true
    sleep 0.3
    "$BIN" remove relayhold 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

assert_eq() {
    TOTAL=$((TOTAL+1))
    local got="$1" expected="$2" label="$3"
    if [ "$got" = "$expected" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$label]: got '$got', expected '$expected'"
    fi
}

echo "=== Integration: relay traffic held until classification ==="

if ! command -v python3 >/dev/null 2>&1; then echo "  SKIP: python3 required"; exit 0; fi

daemon_start "$BIN"
create_ok "server created" "$BIN" create server relayhold -p "$PORT" -s
sleep 0.3

TMPD_T=$(mktemp -d "${TMPDIR:-/tmp}/relayhold-XXXXXX")
trap 'rm -rf "$TMPD_T"; cleanup' EXIT

cat > "$TMPD_T/drive.py" <<'PYEOF'
"""Drive the three scenarios and print one `key=value` line per finding.

Nothing is asserted here -- the shell owns the assertions, so a driver crash
cannot be mistaken for a pass.  Every wait is on a published figure with a
deadline; a wait that times out prints what it was waiting for and gives up,
which shows as a missing key rather than as a hang.
"""
import socket, subprocess, sys, time

BIN, PORT = sys.argv[1], int(sys.argv[2])

def stat(key):
    out = subprocess.run([BIN, "stats", "relayhold"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if line.startswith(key + ":"):
            try:    return int(line.split(":", 1)[1])
            except ValueError: return None
    return None

def wait_until(key, target, what, deadline=15.0):
    """Wait for a published figure to reach `target`.

    The figures a runtime in a worker process publishes are pushed on an
    interval, so this polls rather than reads once; the deadline is generous
    because the interval, not the work, is what it is waiting out.
    """
    end = time.time() + deadline
    while time.time() < end:
        v = stat(key)
        if v is not None and v >= target:
            return True
        time.sleep(0.05)
    print("timeout_waiting=%s(%s>=%d,last=%s)" % (what, key, target, stat(key)))
    return False

def conn():
    s = socket.create_connection(("127.0.0.1", PORT), 5.0)
    s.settimeout(2.0)
    return s

def read_for(s, seconds=1.2):
    """Everything the peer sends within a window, not just the first segment.

    A single recv() would answer the ordering question with whatever happened to
    be in one TCP segment, which is exactly the kind of accident that makes an
    ordering test pass by luck.
    """
    end, buf = time.time() + seconds, b""
    s.settimeout(0.3)
    while time.time() < end:
        try:
            b = s.recv(65536)
            if not b: break
            buf += b
        except socket.timeout:
            pass
    return buf

def ws_frames(buf):
    """Unmasked server->client text frames as (opcode, payload) pairs."""
    out, i = [], 0
    while i + 2 <= len(buf):
        b0, b1 = buf[i], buf[i+1]
        ln = b1 & 0x7F
        j = i + 2
        if ln == 126:
            if j + 2 > len(buf): break
            ln = int.from_bytes(buf[j:j+2], "big"); j += 2
        elif ln == 127:
            if j + 8 > len(buf): break
            ln = int.from_bytes(buf[j:j+8], "big"); j += 8
        if b1 & 0x80:      # masked: a server frame must not be
            j += 4
        if j + ln > len(buf): break
        out.append((b0, buf[j:j+ln]))
        i = j + ln
    return out

# The upgrade, split so the server sees a request it cannot finish classifying.
HEAD = (b"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
        b"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n")
TAIL = b"\r\n"

# ── Scenario 1: held traffic arrives behind the 101, framed, in order ───────
base_in = stat("bytes_in") or 0
u = conn()
u.sendall(HEAD)
# The server has read the partial header: the connection is accepted (so it is
# in the relay set) and still unclassified (headers are incomplete).  This is
# the exact window the defect lived in.
wait_until("bytes_in", base_in + len(HEAD), "partial upgrade read")

base_msgs = stat("total_messages") or 0
s = conn()
RELAYED = [b"relay-alpha", b"relay-beta", b"relay-gamma"]
for m in RELAYED:
    s.sendall(m + b"\n")
wait_until("total_messages", base_msgs + len(RELAYED), "relayed lines processed")

# Only now does the client finish its handshake.
u.sendall(TAIL)
buf = read_for(u)

hdr_end = buf.find(b"\r\n\r\n")
print("starts_with_101=%s" % ("yes" if buf.startswith(b"HTTP/1.1 101") else "no"))
print("bytes_before_101=%d" % buf.find(b"HTTP/1.1 101"))
if hdr_end >= 0:
    frames = ws_frames(buf[hdr_end+4:])
    print("frame_count=%d" % len(frames))
    print("all_text_opcode=%s" % ("yes" if frames and all(f[0] == 0x81 for f in frames) else "no"))
    print("payloads=%s" % b",".join(f[1] for f in frames).decode("latin-1"))
else:
    print("frame_count=-1"); print("all_text_opcode=no"); print("payloads=<no-header-end>")
u.close(); s.close()

# ── Scenario 2: a plain TCP client gets its held traffic too ────────────────
# Same window, different classification, to show the release is not something
# only the WebSocket path does.
time.sleep(0.3)
# The wait is on total_connections and not on a sleep for a reason worth
# stating: a silent client sends nothing, so bytes_in cannot say when it was
# accepted, and until it IS accepted it is not in the relay set and nothing is
# held for it.  A sleep here made this scenario pass or fail on how busy the
# machine was rather than on whether the hold works.
base_conns = stat("total_connections") or 0
t = conn()                      # silent: accepted, never classified
wait_until("total_connections", base_conns + 1, "silent listener accepted")
base_msgs = stat("total_messages") or 0
s2 = conn()
s2.sendall(b"tcp-one\ntcp-two\n")
wait_until("total_messages", base_msgs + 2, "tcp lines processed")
t.sendall(b"classify-me\n")     # first byte from t: now it is proto_tcp
tbuf = read_for(t)
print("tcp_payload=%s" % tbuf.decode("latin-1").replace("\n", "|").strip("|"))
t.close(); s2.close()

# ── Scenario 3: the bound drops the OLDEST ─────────────────────────────────
# 64 KB is the cap; 400 messages of 512 bytes is ~200 KB, comfortably past it.
time.sleep(0.3)
base_conns = stat("total_connections") or 0
h = conn()                      # silent listener: hold grows without release
wait_until("total_connections", base_conns + 1, "silent listener accepted")
base_msgs = stat("total_messages") or 0
s3 = conn()
N, FILL = 400, 512
for i in range(N):
    s3.sendall(b"seq%04d-%s\n" % (i, b"x" * FILL))
wait_until("total_messages", base_msgs + N, "flood processed", deadline=25.0)
h.sendall(b"classify-me\n")
hbuf = read_for(h, 2.0)
print("overflow_has_first=%s" % ("yes" if b"seq0000-" in hbuf else "no"))
print("overflow_has_last=%s"  % ("yes" if (b"seq%04d-" % (N-1)) in hbuf else "no"))
print("overflow_bytes=%d" % len(hbuf))
h.close(); s3.close()
PYEOF

OUT=$(python3 "$TMPD_T/drive.py" "$BIN" "$PORT" 2>&1) || {
    echo "  FAIL: driver did not complete"; echo "$OUT" | sed 's/^/    /'; exit 1
}
val() { printf '%s\n' "$OUT" | grep "^$1=" | head -1 | cut -d= -f2-; }

# ── Scenario 1 ──────────────────────────────────────────────────────────────
# The handshake response is the FIRST thing on the connection.  This is the
# assertion the reproduction makes under load; here it is deterministic.
assert_eq "$(val starts_with_101)" "yes" "101 is the first thing on the wire"
assert_eq "$(val bytes_before_101)" "0" "nothing precedes the 101"

# ...and the held traffic was delivered rather than discarded.  Without these
# three, a fix that simply threw the bytes away would pass this file.
assert_eq "$(val frame_count)" "3" "all three held messages delivered"
assert_eq "$(val all_text_opcode)" "yes" "delivered as WebSocket text frames, not raw"
assert_eq "$(val payloads)" "relay-alpha,relay-beta,relay-gamma" "delivered in the order sent"

# ── Scenario 2 ──────────────────────────────────────────────────────────────
assert_eq "$(val tcp_payload)" "tcp-one|tcp-two" "plain TCP client gets held traffic in order"

# ── Scenario 3 ──────────────────────────────────────────────────────────────
# Drop-oldest, checked in both directions.  Asserting only that the newest
# survived would also pass a cap that dropped nothing and grew without bound;
# asserting only that the oldest is gone would pass one that dropped everything.
assert_eq "$(val overflow_has_first)" "no"  "hold over its bound drops the oldest"
assert_eq "$(val overflow_has_last)" "yes"  "hold over its bound keeps the newest"

# The server is still serving after all of it.
OUT2=$("$BIN" ps 2>&1) || true
TOTAL=$((TOTAL+1))
if grep -q "relayhold" <<<"$OUT2"; then PASS=$((PASS+1)); else
    FAIL=$((FAIL+1)); echo "  FAIL [server still running]: not in ps"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
