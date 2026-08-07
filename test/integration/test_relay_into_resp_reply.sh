#!/usr/bin/env bash
# Integration test: relay traffic never precedes a RESP reply, and a RESP
# connection is not in the relay set at all.
#
# ─── THE SAME DEFECT AS test_relay_into_http_response.sh, ONE PROTOCOL OVER ───
#
# A server in the default --mode inout relays every client's messages to every
# other client.  Excluding HTTP connections from that set answered the question
# for one request/response protocol and left the other one standing: proto_resp
# is in the relay set on identical terms, so broadcast() writes relay bytes
# straight into the write queue of a connection whose client is waiting to be
# answered.  Three windows, all reproduced against the parent commit and all
# asserted below:
#
#   * Before the first reply.  "*1\r\n" settles the protocol on its four bytes;
#     the rest of the command arrives over as many reads as the client chooses to
#     spend, and for every one of them the connection is a member in good
#     standing of the relay set.  Measured: 16 bytes of relayed text ahead of
#     "+PONG" on a command left four bytes short.
#
#   * Between two pipelined commands.  The parse loop consumes whole commands
#     and stops at the first incomplete one, so a client that writes one command
#     and part of a second has a reply on the wire and another one owed.  Relay
#     bytes land in that gap.  Measured: 24 ahead of the second "+PONG".
#
#   * Between commands on an idle connection.  Unlike HTTP, `proto` is never
#     reset for RESP -- there is no keep-alive gap in which the connection reads
#     as unclassified -- so relay traffic is written the moment it arrives, and
#     it simply sits there.  Measured: 19 unsolicited bytes on a connection that
#     had already been answered, which are what its client reads as the reply to
#     its next command.
#
# A fourth path reaches the same place from the other side: a client whose first
# write stops short of four bytes and of a newline ("*1\r") is unclassified, so a
# broadcast in that gap is *held* -- and then flushed onto a connection that
# turned out to speak RESP.  Scenario 4 covers it, because "not written" and
# "not delivered" are two different pieces of code.
#
# ─── WHY THE FIX IS EXCLUSION AND NOT A LONGER HOLD ──────────────────────────
#
# The same answer as HTTP, for the same reason and one more of its own.  RESP2
# matches replies to commands by their order on the stream and by nothing else,
# so an unsolicited value is not early or late -- it is consumed as the answer to
# whatever that client asks next.  Waiting defers the corruption instead of
# avoiding it, exactly as it does for a keep-alive HTTP connection.
#
# And what the relay writes is not a RESP value at all: it is the message text
# with a newline, so a real Redis client reads a plain letter where a type byte
# belongs and answers with a protocol error.  Encoding it as one would not
# rescue it either -- the only channel RESP2 has for a server-initiated value is
# pub/sub, which a client enters with SUBSCRIBE and which a server runtime does
# not implement; the RESP branch joins argv with spaces and hands the result to
# process_message like any other line.
#
# So a RESP connection is not a relay target, and this file asserts that
# directly.  What it still receives is asserted too: its own replies, in every
# scenario below, because the exclusion is of the relay and not of the answer.
#
# ─── WHY THERE IS A LUA SCRIPT ──────────────────────────────────────────────
#
# A reply is the thing relay bytes get in front of, so there has to be one.  A
# server runtime does not answer RESP commands by itself -- it turns them into
# messages -- so the reply comes from on_client_message, which is what "custom
# RESP-based protocols" in the man page means.  on_client_message is deliberate
# and on_message is not usable here: defining on_message suppresses the default
# broadcast, and the broadcast is the thing under test.
#
# ─── WHY THE SEQUENCING IS NOT A SLEEP ───────────────────────────────────────
#
# As in test_relay_into_http_response.sh: every step waits on a figure the server
# publishes rather than on a duration.  A sleep long enough to be safe on a
# loaded machine is also long enough to close the window under test by itself,
# which would make this file pass against the defect.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
daemon_isolate relayresp
PORT=19397
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    "$BIN" stop relayresp 2>/dev/null || true
    sleep 0.3
    "$BIN" remove relayresp 2>/dev/null || true
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

echo "=== Integration: relay traffic never precedes a RESP reply ==="

if ! command -v python3 >/dev/null 2>&1; then echo "  SKIP: python3 required"; exit 0; fi

TMPD_T=$(mktemp -d "${TMPDIR:-/tmp}/relayresp-XXXXXX")

daemon_start "$BIN"
trap 'rm -rf "$TMPD_T"; cleanup' EXIT

# The answer half of the connection.  "+PONG\r" is a RESP simple string once
# self.send has appended the newline it always appends, so what the client reads
# is a well-formed reply and the assertions below are about what is in front of
# it rather than about whether it parses.
cat > "$TMPD_T/resp.lua" <<'LUAEOF'
function on_client_message(id, msg)
    if msg == "PING" then self.send(id, "+PONG\r") end
end
LUAEOF

create_ok "server created" "$BIN" create server relayresp \
    -p "$PORT" --lua "$TMPD_T/resp.lua" -s
sleep 0.3

cat > "$TMPD_T/drive.py" <<'PYEOF'
"""Drive the five scenarios and print one `key=value` line per finding.

Nothing is asserted here -- the shell owns the assertions, so a driver crash
cannot be mistaken for a pass.
"""
import socket, subprocess, sys, time

BIN, PORT = sys.argv[1], int(sys.argv[2])

def stat(key):
    out = subprocess.run([BIN, "stats", "relayresp"], capture_output=True, text=True).stdout
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

# One PING, split so the four bytes that settle the protocol arrive well before
# the last byte of the command.  "*1\r\n" is what the classifier reads; the
# remainder is what leaves the client owed a reply.
PING_HEAD, PING_TAIL = b"*1\r\n$4\r\nPI", b"NG\r\n"
PING_WHOLE = PING_HEAD + PING_TAIL

# ── Scenario 1: relay bytes must not precede the reply to a command ────────
base_in = stat("bytes_in") or 0
a = conn()
a.sendall(PING_HEAD)
# The server has read a command it cannot finish: classified proto_resp, four
# bytes short, no reply produced.  This is the window.
wait_until("bytes_in", base_in + len(PING_HEAD), "partial RESP command read")

base_msgs = stat("total_messages") or 0
b = conn()
b.sendall(b"relay-into-resp\n")
wait_until("total_messages", base_msgs + 1, "relayed line processed")

a.sendall(PING_TAIL)                 # completes the command
buf = read_for(a)
print("resp_starts_with_reply=%s" % ("yes" if buf.startswith(b"+PONG") else "no"))
print("resp_bytes_before_reply=%d" % buf.find(b"+PONG"))
print("resp_relay_present=%s" % ("yes" if b"relay-into-resp" in buf else "no"))
a.close(); b.close()

# ── Scenario 2: nor between two pipelined commands ─────────────────────────
# The parse loop consumes whole commands and stops at the first incomplete one,
# so this connection has been answered once and is owed a second answer.  A
# relayed line written here leads the reply the client is still waiting for.
time.sleep(0.3)
c = conn()
c.sendall(PING_WHOLE + PING_HEAD)
first = read_for(c, 1.0)
print("pipe_first_ok=%s" % ("yes" if first.startswith(b"+PONG") else "no"))

base_msgs = stat("total_messages") or 0
d = conn()
d.sendall(b"relay-between-pipelined\n")
wait_until("total_messages", base_msgs + 1, "pipelined gap line processed")

c.sendall(PING_TAIL)
second = read_for(c, 1.0)
print("pipe_second_starts_with_reply=%s" % ("yes" if second.startswith(b"+PONG") else "no"))
print("pipe_second_relay_present=%s" % ("yes" if b"relay-between-pipelined" in second else "no"))
c.close(); d.close()

# ── Scenario 3: an idle RESP connection is sent nothing at all ─────────────
# The question underneath the two scenarios above, asked directly.  `proto` is
# never reset for RESP, so there is no unclassified gap between commands and
# nothing is held: the bytes are written the moment they are relayed and sit on
# the connection until its client next reads -- which it will do after sending
# its next command, and it will read them as that command's reply.
time.sleep(0.3)
e = conn()
e.sendall(PING_WHOLE)
read_for(e, 1.0)                     # its own reply, consumed
base_msgs = stat("total_messages") or 0
f = conn()
f.sendall(b"relay-to-idle-resp\n")
wait_until("total_messages", base_msgs + 1, "idle-resp line processed")
# Longer than the relay-hold deadline, so a fix that merely delayed the bytes
# would still be caught here.
idle = read_for(e, 1.5)
print("idle_resp_bytes=%d" % len(idle))
print("idle_resp_relay_present=%s" % ("yes" if b"relay-to-idle-resp" in idle else "no"))
e.close(); f.close()

# ── Scenario 4: nor what was held before the protocol was known ────────────
# The other half, and a different piece of code: "*1\r" is three bytes with no
# newline, so the classifier declines to decide and the broadcast is *held*
# rather than written.  Held traffic is flushed the moment the protocol settles,
# so a fix that only guards broadcast() delivers these anyway -- behind the
# reply, which is worse rather than better: they become the head of whatever the
# client reads next.
#
# The client has spoken, so the 250 ms hold deadline does not apply to it and
# cannot release the hold on its own; the only thing that flushes here is the
# read that classifies the connection.
time.sleep(0.3)
base_in = stat("bytes_in") or 0
g = conn()
g.sendall(b"*1\r")
wait_until("bytes_in", base_in + 3, "sub-four-byte prefix read")

base_msgs = stat("total_messages") or 0
h = conn()
h.sendall(b"relay-while-unclassified\n")
wait_until("total_messages", base_msgs + 1, "unclassified-gap line processed")

g.sendall(b"\n$4\r\nPING\r\n")        # completes the command and classifies it
held = read_for(g, 1.2)
print("held_reply_present=%s" % ("yes" if b"+PONG" in held else "no"))
print("held_relay_present=%s" % ("yes" if b"relay-while-unclassified" in held else "no"))
g.close(); h.close()

# ── Scenario 5: a plain TCP client on the same server still gets everything ─
# The control.  Without it, "send RESP clients nothing" would be satisfied by a
# fix that silenced the relay altogether, and every assertion above would go
# green against a server that had stopped relaying.
time.sleep(0.3)
base_in = stat("bytes_in") or 0
t = conn()
t.sendall(b"tcp-hello\n")            # classifies it as a line client
wait_until("bytes_in", base_in + 10, "tcp client classified")
base_msgs = stat("total_messages") or 0
u = conn()
u.sendall(b"relay-to-tcp\n")
wait_until("total_messages", base_msgs + 1, "tcp line processed")
tbuf = read_for(t, 1.0)
print("tcp_relay_present=%s" % ("yes" if b"relay-to-tcp" in tbuf else "no"))
print("tcp_relay_payload=%s" % tbuf.decode("latin-1").strip())
t.close(); u.close()
PYEOF

OUT=$(python3 "$TMPD_T/drive.py" "$BIN" "$PORT" 2>&1) || {
    echo "  FAIL: driver did not complete"; echo "$OUT" | sed 's/^/    /'; exit 1
}
val() { printf '%s\n' "$OUT" | grep "^$1=" | head -1 | cut -d= -f2-; }

# ── Scenario 1 ──────────────────────────────────────────────────────────────
assert_eq "$(val resp_starts_with_reply)" "yes" "the reply is the first thing on the wire"
assert_eq "$(val resp_bytes_before_reply)" "0" "nothing precedes the reply"
assert_eq "$(val resp_relay_present)" "no" "no relay bytes on a RESP connection"

# ── Scenario 2 ──────────────────────────────────────────────────────────────
assert_eq "$(val pipe_first_ok)" "yes" "pipelining: the first command is answered"
assert_eq "$(val pipe_second_starts_with_reply)" "yes" "pipelining: the second reply leads"
assert_eq "$(val pipe_second_relay_present)" "no" "pipelining: nothing relayed into the gap"

# ── Scenario 3 ──────────────────────────────────────────────────────────────
assert_eq "$(val idle_resp_relay_present)" "no" "an idle RESP connection is not a relay target"
assert_eq "$(val idle_resp_bytes)" "0" "and receives no unsolicited bytes at all"

# ── Scenario 4 ──────────────────────────────────────────────────────────────
# The reply assertion is not decoration: it is what stops "no relay bytes" from
# being satisfied by a connection that was answered with nothing at all.
assert_eq "$(val held_reply_present)" "yes" "held: the command is still answered"
assert_eq "$(val held_relay_present)" "no" "held: what was held is dropped, not flushed"

# ── Scenario 5 ──────────────────────────────────────────────────────────────
assert_eq "$(val tcp_relay_present)" "yes" "a line client still receives relay traffic"
assert_eq "$(val tcp_relay_payload)" "relay-to-tcp" "...with the payload intact"

# The server is still serving after all of it.
OUT2=$("$BIN" ps 2>&1) || true
TOTAL=$((TOTAL+1))
if grep -q "relayresp" <<<"$OUT2"; then PASS=$((PASS+1)); else
    FAIL=$((FAIL+1)); echo "  FAIL [server still running]: not in ps"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
