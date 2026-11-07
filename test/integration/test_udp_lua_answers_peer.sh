#!/usr/bin/env bash
# Integration test: a UDP server's script hears each datagram in
# on_client_message, with a peer id it can answer with self.send.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# A Lua script on a UDP server could not answer the peer that spoke.
# handle_udp_read() dispatched every datagram with no sender, so
# on_client_message never fired, and self.send refused outright on a UDP
# server ("use self.broadcast").  A request/response protocol over UDP --
# the commonest thing a datagram server is -- was not expressible.
#
# ─── THE ASSERTIONS ────────────────────────────────────────────────────────
#
# Two peers each send twice.  Each must get its own answers and only those:
# the id handed to on_client_message names the sender, not the other peer and
# not everyone.  The two answers to one peer must carry the same id, because
# an index into the peer table moves when a peer leaves and a script keeps
# the id.  Neither peer may hear the other's datagram, because the handler
# returns true and the relay stays out of it.
# And an id no peer holds answers false with a reason naming the peer, which a
# send that silently went nowhere would not.
#
# Then the table moving under the ids: three peers, the first falls silent and
# --idle-timeout forgets it, which moves the last peer into its slot.  The
# moved peer's id must still reach that peer -- an id resolved through a stale
# index names somebody else's address or none -- and the forgotten id must
# answer false.  This waits for one tick of the 30-second sweep.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: a UDP server's script answers the peer that spoke ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

PS=$((SL_PORT_BASE+1853))
PF=$((SL_PORT_BASE+1854))

daemon_isolate udpluapeer
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

SCRIPT="$SOCKETLEY_TMPD/peer.lua"
cat > "$SCRIPT" <<'LUAEOF'
function on_client_message(id, msg)
    if msg == "stranger" then
        local ok, err = self.send(999999, "x")
        socketley.log("ULP stranger ok=" .. tostring(ok) .. " err=" .. tostring(err))
        return true
    end
    self.send(id, "re:" .. id .. ":" .. msg)
    return true
end
LUAEOF

"$BIN" create server ulp -p "$PS" --udp --lua "$SCRIPT" -s >/dev/null 2>&1

cat > "$SOCKETLEY_TMPD/forget.lua" <<'LUAEOF'
function on_client_message(id, msg)
    local to = msg:match("^ask (%d+)$")
    if to then
        local ok = self.send(tonumber(to), "for:" .. to)
        socketley.log("ULF ask " .. to .. " ok=" .. tostring(ok))
    elseif msg == "who" then
        self.send(id, "id:" .. id)
    end
    return true
end
LUAEOF
"$BIN" create server ulf -p "$PF" --udp --idle-timeout 2 --lua "$SOCKETLEY_TMPD/forget.lua" -s >/dev/null 2>&1
sleep 1.5

OUT=$(python3 -c "
import socket, time
a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); a.bind(('127.0.0.1', 0)); a.settimeout(0.5)
b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); b.bind(('127.0.0.1', 0)); b.settimeout(0.5)
dst = ('127.0.0.1', $PS)
a.sendto(b'a1\n', dst); time.sleep(0.2)
b.sendto(b'b1\n', dst); time.sleep(0.2)
a.sendto(b'a2\n', dst); time.sleep(0.2)
b.sendto(b'b2\n', dst); time.sleep(0.2)
b.sendto(b'stranger\n', dst); time.sleep(0.4)
def drain(s):
    got = []
    while True:
        try: got.append(s.recv(65536).decode())
        except Exception: return got
print('A ' + ' '.join(drain(a)))
print('B ' + ' '.join(drain(b)))
print('D ' + ' '.join(drain(d)))
" 2>/dev/null)
A=$(printf '%s\n' "$OUT" | sed -n 's/^A //p')
B=$(printf '%s\n' "$OUT" | sed -n 's/^B //p')

# re:<id>:a1 re:<id>:a2, with one id, and nothing else.
if [[ "$A" =~ ^re:([0-9]+):a1\ re:([0-9]+):a2$ ]] && [ "${BASH_REMATCH[1]}" = "${BASH_REMATCH[2]}" ]; then
    IDA=${BASH_REMATCH[1]}
    ok "the first peer got its own two answers under one id ($A)"
else
    IDA=""
    bad "on_client_message names a datagram's sender and self.send answers it" \
        "the first peer received '${A:-<nothing>}', wanted re:<id>:a1 re:<id>:a2;" \
        "the other peer's datagrams and no answer is the defect -- on_client_message" \
        "never fired for a datagram, self.send refused, and the relay ran"
fi
if [[ "$B" =~ ^re:([0-9]+):b1\ re:([0-9]+):b2$ ]] && [ "${BASH_REMATCH[1]}" = "${BASH_REMATCH[2]}" ] \
   && [ "${BASH_REMATCH[1]}" != "$IDA" ]; then
    ok "the second peer got its own answers under a different id ($B)"
else
    bad "each peer is answered alone, under an id of its own" \
        "the second peer received '${B:-<nothing>}' (first peer's id '${IDA:-?}');" \
        "a1 or a2 here is the relay running beside the script"
fi

STR=$(grep -o 'ULP stranger ok=[a-z]* err=.*' "$SOCKETLEY_DLOG" | tail -1) || true
if [[ "$STR" == "ULP stranger ok=false err="*"peer 999999"* ]]; then
    ok "an id no peer holds answers false and names the peer"
else
    bad "self.send to an unknown peer says so" \
        "the script was told '${STR:-<no line>}'"
fi

FOUT=$(python3 -c "
import socket, time
dst = ('127.0.0.1', $PF)
ss = []
for _ in range(3):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.1', 0)); s.settimeout(1.0)
    ss.append(s)
ids = []
for s in ss:
    s.sendto(b'who', dst)
    ids.append(s.recv(100).decode().split(':')[1])
    time.sleep(0.1)
a, b, c = ss
end = time.time() + 36
while time.time() < end:
    b.sendto(b'k', dst); c.sendto(b'k', dst); time.sleep(0.5)
# A newcomer takes the slot the move vacated, so a stale index would reach it.
d = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); d.bind(('127.0.0.1', 0)); d.settimeout(1.0)
d.sendto(b'who', dst); d.recv(100)
b.sendto(('ask ' + ids[2]).encode(), dst); time.sleep(0.3)
b.sendto(('ask ' + ids[0]).encode(), dst); time.sleep(0.3)
def drain(s):
    s.settimeout(0.3); got = []
    while True:
        try: got.append(s.recv(100).decode())
        except Exception: return got
print('IDS ' + ' '.join(ids))
print('C ' + ' '.join(drain(c)))
print('B ' + ' '.join(drain(b)))
" 2>/dev/null)
read -r _ IA IB IC <<<"$(printf '%s\n' "$FOUT" | grep '^IDS')"
FC=$(printf '%s\n' "$FOUT" | sed -n 's/^C //p')
FB=$(printf '%s\n' "$FOUT" | sed -n 's/^B //p')
FD=$(printf '%s\n' "$FOUT" | sed -n 's/^D //p')
if [ -n "${IC:-}" ] && [ "$FC" = "for:$IC" ] && [ -z "$FB" ] && [ -z "$FD" ]; then
    ok "a peer moved in the table by a forgotten one is still reached by its id ($IC)"
else
    bad "an id names its peer after the table moved it" \
        "the third peer (id ${IC:-?}) received '${FC:-<nothing>}', the asker '${FB:-<nothing>}'," \
        "the newcomer '${FD:-<nothing>}';" \
        "wanted 'for:${IC:-?}' at the third peer only (ids: ${IA:-?} ${IB:-?} ${IC:-?})"
fi
GONE=$(grep -o "ULF ask ${IA:-x} ok=[a-z]*" "$SOCKETLEY_DLOG" | tail -1) || true
if [ "$GONE" = "ULF ask ${IA:-x} ok=false" ]; then
    ok "and the forgotten peer's id answers false"
else
    bad "a forgotten peer's id is refused" "the script was told '${GONE:-<no line>}'"
fi

for r in ulp ulf; do "$BIN" stop $r >/dev/null 2>&1; "$BIN" remove $r >/dev/null 2>&1; done
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
