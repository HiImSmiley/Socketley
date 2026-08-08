#!/usr/bin/env bash
# Integration test: relay traffic never precedes an HTTP response, and an HTTP
# connection is not in the relay set at all.
#
# ─── THE SAME ORDERING HAZARD, ONE CLASSIFICATION LATER ──────────────────────
#
# A server in the default --mode inout is a relay.  Holding relay traffic until a
# connection is classified fixed the case where those bytes landed in front of a
# WebSocket handshake response.  It did not fix the case where the connection has
# already been classified as HTTP, because "classified" is exactly what stops the
# hold -- and an HTTP connection spends most of its life classified with a
# request still in flight:
#
#   * Between the first four bytes of a request and its last.  "POST" settles the
#     protocol; the headers and body arrive over as many reads as the client
#     chooses to spend on them, and for every one of them the connection is a
#     member in good standing of the relay set.  Relay bytes written in that
#     window go into the write queue ahead of the response, and the client -- which
#     is waiting for a status line -- reads "relay-into-http" instead.
#
#   * On the first read of a keep-alive connection's NEXT request.  The protocol
#     is reset to unknown after each response, so relay traffic arriving in the
#     gap is held; the read that classifies the next request releases it, and if
#     that read did not also complete the request there is no response queued yet
#     for the flush to land behind.
#
# Both are the pre-existing defect with the handshake swapped for a status line,
# and the second is one the hold introduced rather than one it missed.
#
# ─── WHY THE FIX IS EXCLUSION AND NOT A LONGER HOLD ──────────────────────────
#
# The tree's rule is that a response to a request must not have unrelated bytes
# in front of it.  Applied to HTTP it does not produce a better hold, it produces
# an answer to a prior question: there is no moment in an HTTP connection's life
# at which a relayed line is well formed.  Before the response it preempts the
# status line.  After the response, on a keep-alive connection, the client is not
# reading -- and when it next does, having sent another request, it parses that
# relayed line as that response's status line.  HTTP frames bodies by
# Content-Length; a server-initiated line has nowhere to go in that framing.
#
# So an HTTP connection is not a relay target, and this file asserts that
# directly rather than asserting an ordering that would be vacuous once the
# traffic is not sent at all.  WebSocket is how a browser-facing client receives
# relay traffic, and scenario 4 shows that path is untouched: a ws:// client on
# the same server, upgraded from the same HTTP, still receives everything.
#
# ─── WHY THE SEQUENCING IS NOT A SLEEP ───────────────────────────────────────
#
# As in test_relay_hold_before_classification.sh: every step waits on a figure
# the server publishes rather than on a duration.  A sleep long enough to be safe
# on a loaded machine is also long enough to close the window under test by
# itself, which would make this file pass against the defect.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate relayhttp
PORT=$((SL_PORT_BASE+396))
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop relayhttp 2>/dev/null || true
    sleep 0.3
    "$BIN" remove relayhttp 2>/dev/null || true
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

echo "=== Integration: relay traffic never precedes an HTTP response ==="

if ! command -v python3 >/dev/null 2>&1; then echo "  SKIP: python3 required"; exit 0; fi

daemon_start "$BIN"
create_ok "server created" "$BIN" create server relayhttp -p "$PORT" -s
sleep 0.3

TMPD_T=$(mktemp -d "${TMPDIR:-/tmp}/relayhttp-XXXXXX")
trap 'rm -rf "$TMPD_T"; cleanup' EXIT

cat > "$TMPD_T/drive.py" <<'PYEOF'
"""Drive the four scenarios and print one `key=value` line per finding.

Nothing is asserted here -- the shell owns the assertions, so a driver crash
cannot be mistaken for a pass.
"""
import socket, subprocess, sys, time

BIN, PORT = sys.argv[1], int(sys.argv[2])

def stat(key):
    out = subprocess.run([BIN, "stats", "relayhttp"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if line.startswith(key + ":"):
            try:    return int(line.split(":", 1)[1])
            except ValueError: return None
    return None

def wait_until(key, target, what, deadline=15.0):
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
    """Everything the peer sends within a window, not just the first segment."""
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
    """Unmasked server->client frames as (opcode, payload) pairs."""
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
        if b1 & 0x80:
            j += 4
        if j + ln > len(buf): break
        out.append((b0, buf[j:j+ln]))
        i = j + ln
    return out

# POST rather than GET on purpose.  'G' sends the classifier down the
# proto_ws_upgrading branch, which counts as unsettled and is therefore already
# protected by the hold; 'P' settles the connection as proto_http on its first
# four bytes, which is the state under test.  Content-Length is what lets the
# request be left deliberately unfinished.
HEAD = b"POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n"
BODY_HEAD, BODY_TAIL = b"y" * 10, b"y" * 90

# ── Scenario 1: relay bytes must not precede the response to a request ─────
base_in = stat("bytes_in") or 0
a = conn()
a.sendall(HEAD + BODY_HEAD)
# The server has read a request it cannot finish: classified proto_http, body
# incomplete, response not yet produced.  This is the window.
wait_until("bytes_in", base_in + len(HEAD) + len(BODY_HEAD), "partial POST read")

base_msgs = stat("total_messages") or 0
b = conn()
b.sendall(b"relay-into-http\n")
wait_until("total_messages", base_msgs + 1, "relayed line processed")

a.sendall(BODY_TAIL)                 # completes the request
buf = read_for(a)
print("http_starts_with_status=%s" % ("yes" if buf.startswith(b"HTTP/1.1") else "no"))
print("http_bytes_before_status=%d" % buf.find(b"HTTP/1.1"))
print("http_relay_present=%s" % ("yes" if b"relay-into-http" in buf else "no"))
a.close(); b.close()

# ── Scenario 2: nor in the gap between two keep-alive requests ─────────────
time.sleep(0.3)
c = conn()
c.sendall(b"POST /1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
first = read_for(c, 1.0)
print("ka_first_ok=%s" % ("yes" if first.startswith(b"HTTP/1.1") else "no"))

# The connection is now between requests: its protocol has been reset, so relay
# traffic arriving here is held rather than written.
base_msgs = stat("total_messages") or 0
d = conn()
d.sendall(b"relay-between-requests\n")
wait_until("total_messages", base_msgs + 1, "gap line processed")

# The next request, split so the read that classifies it does not also complete
# it.  A hold released on classification has nothing queued to land behind.
c.sendall(b"POST /2 HTTP/1.1\r\nHost: localhost\r\nContent-Len")
time.sleep(0.4)
c.sendall(b"gth: 0\r\n\r\n")
second = read_for(c, 1.0)
print("ka_second_starts_with_status=%s" % ("yes" if second.startswith(b"HTTP/1.1") else "no"))
print("ka_second_relay_present=%s" % ("yes" if b"relay-between-requests" in second else "no"))
c.close(); d.close()

# ── Scenario 3: an idle HTTP connection is sent nothing at all ─────────────
# The question underneath both scenarios above, asked directly.  An HTTP
# connection that has answered its request and is sitting on keep-alive receives
# no relay traffic, because there is no point in its life at which a relayed
# line would be well formed -- not merely no traffic *before* a response.
time.sleep(0.3)
e = conn()
e.sendall(b"POST /3 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
read_for(e, 1.0)                     # its own response, consumed
base_msgs = stat("total_messages") or 0
f = conn()
f.sendall(b"relay-to-idle-http\n")
wait_until("total_messages", base_msgs + 1, "idle-http line processed")
# Longer than the relay-hold deadline, so a fix that merely delayed the bytes
# would still be caught here.
idle = read_for(e, 1.5)
print("idle_http_bytes=%d" % len(idle))
print("idle_http_relay_present=%s" % ("yes" if b"relay-to-idle-http" in idle else "no"))
e.close(); f.close()

# ── Scenario 4: a WebSocket client on the same server still gets everything ─
# The control.  Excluding HTTP from the relay set must not exclude a connection
# that began as an HTTP upgrade -- that is the supported way to receive relay
# traffic from a browser, and a fix that keyed on "spoke HTTP once" would break
# it.
time.sleep(0.3)
w = conn()
w.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
          b"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
          b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
hs = read_for(w, 1.0)
print("ws_upgraded=%s" % ("yes" if hs.startswith(b"HTTP/1.1 101") else "no"))
base_msgs = stat("total_messages") or 0
g = conn()
g.sendall(b"relay-to-ws\n")
wait_until("total_messages", base_msgs + 1, "ws line processed")
wbuf = read_for(w, 1.0)
frames = ws_frames(wbuf)
print("ws_frame_count=%d" % len(frames))
print("ws_payloads=%s" % b",".join(fr[1] for fr in frames).decode("latin-1"))
w.close(); g.close()
PYEOF

OUT=$(python3 "$TMPD_T/drive.py" "$BIN" "$PORT" 2>&1) || {
    echo "  FAIL: driver did not complete"; echo "$OUT" | sed 's/^/    /'; exit 1
}
val() { printf '%s\n' "$OUT" | grep "^$1=" | head -1 | cut -d= -f2-; }

# ── Scenario 1 ──────────────────────────────────────────────────────────────
assert_eq "$(val http_starts_with_status)" "yes" "response is the first thing on the wire"
assert_eq "$(val http_bytes_before_status)" "0" "nothing precedes the status line"
assert_eq "$(val http_relay_present)" "no"  "no relay bytes on an HTTP connection"

# ── Scenario 2 ──────────────────────────────────────────────────────────────
assert_eq "$(val ka_first_ok)" "yes" "keep-alive: first request answered"
assert_eq "$(val ka_second_starts_with_status)" "yes" "keep-alive: second response leads"
assert_eq "$(val ka_second_relay_present)" "no" "keep-alive: nothing relayed into the gap"

# ── Scenario 3 ──────────────────────────────────────────────────────────────
assert_eq "$(val idle_http_relay_present)" "no" "an idle HTTP connection is not a relay target"
assert_eq "$(val idle_http_bytes)" "0" "and receives no unsolicited bytes at all"

# ── Scenario 4 ──────────────────────────────────────────────────────────────
# The control.  Without these, "send HTTP clients nothing" would be satisfied by
# a fix that also silenced every WebSocket client, since both arrive over HTTP.
assert_eq "$(val ws_upgraded)" "yes" "websocket upgrade still answered"
assert_eq "$(val ws_frame_count)" "1" "websocket client still receives relay traffic"
assert_eq "$(val ws_payloads)" "relay-to-ws" "...with the payload intact"

# The server is still serving after all of it.
OUT2=$("$BIN" ps 2>&1) || true
TOTAL=$((TOTAL+1))
if grep -q "relayhttp" <<<"$OUT2"; then PASS=$((PASS+1)); else
    FAIL=$((FAIL+1)); echo "  FAIL [server still running]: not in ps"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
