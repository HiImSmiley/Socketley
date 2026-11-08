#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a group_send made by on_disconnect for a connection the end-of-turn fan-out flush itself closes
# reaches the room's members at once.
#
# What it would catch: the flush walking its list of due recipients while that close's on_disconnect appends to it,
# and then clearing the list, so the member queued from inside the walk kept its due mark with no write ever started
# -- it heard nothing until it next sent something itself, and no later fan-out reached it either.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a group_send from an on_disconnect the fan-out flush runs reaches the room ==="
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
python3 -c 'import ssl' >/dev/null 2>&1 || { echo "  SKIP: python3 ssl is required"; echo "  Results: 0/0 passed (0 failed)"; exit 0; }
daemon_isolate fanoutclose
unset SOCKETLEY_CONFIG
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 103))
trap 'daemon_stop' EXIT
daemon_start "$BIN"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=localhost \
    -keyout "$T/k.pem" -out "$T/c.pem" >/dev/null 2>&1

# The first connection is the victim: it joins "room" and never finishes its handshake, so a fan-out to it queues
# bytes no write can take and the flush is what closes it once the script has disconnected it.
cat > "$T/room.lua" <<'LUA'
local victim = nil
function on_connect(id)
    if not victim then
        victim = id
        self.join_group(id, "room")
    end
end
function on_disconnect(id)
    if id == victim then self.group_send("lobby", "left") end
end
function on_client_message(id, msg)
    if msg == "lobby" then
        self.join_group(id, "lobby")
        self.send(id, "inlobby")
    elseif msg == "go" then
        self.group_send("room", "hello")
        self.disconnect(victim)
        self.send(id, "gone")
    elseif msg == "ping" then
        self.send(id, "pong")
    end
    return true
end
LUA
"$BIN" create server room -p "$P" --lua "$T/room.lua" --tls --cert "$T/c.pem" --key "$T/k.pem" -s >/dev/null 2>&1
for _ in $(seq 1 100); do ss -ltn 2>/dev/null | grep -q ":$P " && break; sleep 0.1; done

timeout 30 python3 - "$P" > "$T/out" <<'PY'
import socket, ssl, sys, time
port = int(sys.argv[1])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def tls():
    s = socket.create_connection(("127.0.0.1", port), 5)
    s = ctx.wrap_socket(s, server_hostname="localhost")
    s.settimeout(5)
    return s

def until(s, word, wait):
    s.settimeout(wait)
    buf = b""
    try:
        while word not in buf:
            d = s.recv(4096)
            if not d:
                break
            buf += d
    except (socket.timeout, ssl.SSLError):
        pass
    return word in buf

victim = socket.create_connection(("127.0.0.1", port), 5)
time.sleep(0.3)
member = tls()
member.sendall(b"lobby\n")
print("lobby", "yes" if until(member, b"inlobby\n", 5) else "no")
sender = tls()
sender.sendall(b"go\n")
print("gone", "yes" if until(sender, b"gone\n", 5) else "no")
# The member sends nothing here: what it hears is only what the server started writing on its own.
heard = until(member, b"left\n", 2)
print("left", "yes" if heard else "no")
if not heard:
    # Whether the bytes were queued and only never started, which the member's own read then starts.
    member.sendall(b"ping\n")
    print("left after its own message", "yes" if until(member, b"left\n", 2) else "no")
victim.close()
PY
cat "$T/out" | sed 's/^/  /'
grep -q '^lobby yes$' "$T/out" && ok || bad "setup" "the member was not answered on joining the lobby"
grep -q '^gone yes$' "$T/out" && ok || bad "setup" "the sender was not answered on disconnecting the victim"
grep -q '^left yes$' "$T/out" && ok || bad "on_disconnect's group_send" "the lobby member did not hear it within 2 s"

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
