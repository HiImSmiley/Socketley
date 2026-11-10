#!/usr/bin/env bash
# Integration test: what a client script's self.send copies into the stage arrives whole and in order
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# While a callback for one connection runs, self.send(msg) without an id copies
# the line into bytes the runtime holds for that connection, through FFI and
# with no C call, and the runtime moves them into the connection's queue when
# the callback ends or before anything else touches the queue.  Lost bytes, a
# line sent with an id overtaking the staged ones before it, or self.pending()
# blind to what is staged would each be silent: the producer goes on, and only
# the peer could tell.
#
# So two connections each pump 200,000 numbered lines from on_connect and
# on_writable, every 1,000th through self.send(msg, id), which is C's, and every
# 777th with its own newline, and a peer checks that each connection's numbers
# arrive once each and in order.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * staged bytes dropped or doubled on the way into the queue
#   * a send with an id queued ahead of the staged lines sent before it
#   * self.pending() not counting the bytes still staged
#   * a newline added to a line that brought its own, or one left off
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate clientstage

P=$((SL_PORT_BASE+1961))
NAMES="stg_cli"
LUA="$SOCKETLEY_TMPD/stg.lua"
N=200000

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

LPID=""
cleanup() {
    if [ -n "$LPID" ]; then
        { kill -9 "$LPID" && wait "$LPID"; } 2>/dev/null || true
    fi
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a client script's staged sends arrive whole and in order ==="

# Two connections read to the end, each line "c<id> <n>" checked against the one before.
cat > "$SOCKETLEY_TMPD/peer.py" <<'PYEOF'
import socket, sys, threading
port, n = int(sys.argv[1]), int(sys.argv[2])
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(8)
out = {}
def read(c):
    c.settimeout(20)
    buf, last, who, bad = b"", 0, None, None
    try:
        while last < n and bad is None:
            b = c.recv(1 << 18)
            if not b:
                break
            buf += b
            *lines, buf = buf.split(b"\n")
            for line in lines:
                name, num = line.decode().split(" ")
                who = who or name
                if name != who or int(num) != last + 1:
                    bad = "%s after %s %d" % (line.decode(), who, last)
                    break
                last += 1
    except socket.timeout:
        pass
    out[who] = bad or ("whole %d" % last)
threads = []
for _ in range(2):
    c, _a = srv.accept()
    t = threading.Thread(target=read, args=(c,)); t.start(); threads.append(t)
for t in threads:
    t.join()
for k in sorted(out, key=str):
    print("PEER %s %s" % (k, out[k]), flush=True)
PYEOF
python3 "$SOCKETLEY_TMPD/peer.py" "$P" "$N" > "$SOCKETLEY_TMPD/peer.out" 2>&1 &
LPID=$!
for _ in $(seq 1 200); do
    ss -ltn 2>/dev/null | grep -q ":$P " && break
    sleep 0.05
done

cat > "$LUA" <<LUAEOF
local N = $N
local sent, done, delta = {}, {}, nil

local function pump(id)
    local wm = self.watermark()
    local i = sent[id] or 0
    while i < N and self.pending() < wm do
        i = i + 1
        local line = "c" .. id .. " " .. i
        if i % 1000 == 0 then
            self.send(line, id)
        elseif i % 777 == 0 then
            self.send(line .. "\n")
        elseif not delta and i > 5000 then
            local before = self.pending()
            self.send(line)
            delta = self.pending() - before - (#line + 1)
            socketley.log("STG delta=" .. delta)
        else
            self.send(line)
        end
    end
    sent[id] = i
    if i >= N and not done[id] then
        done[id] = true
        socketley.log("STG done " .. id)
    end
end

function on_connect(_, id) pump(id) end
function on_writable(id) pump(id) end
LUAEOF

daemon_start "$BIN"
create_ok "a scripted client with two connections" "$BIN" create client stg_cli -t "127.0.0.1:$P" --connections 2 --lua "$LUA" -s

for _ in $(seq 1 400); do
    [ "$(grep -c '^PEER ' "$SOCKETLEY_TMPD/peer.out" 2>/dev/null)" -ge 2 ] && break
    sleep 0.1
done

check "both connections' lines arrived whole and in order" \
    "PEER c1 whole $N|PEER c2 whole $N" "$(grep '^PEER ' "$SOCKETLEY_TMPD/peer.out" | sort | paste -sd'|')"
check "self.pending() counts the bytes still staged" "STG delta=0" \
    "$(grep -o 'STG delta=[-0-9]*' "$SOCKETLEY_DLOG" | head -1)"
check "both producers ran to the end" "2" "$(grep -c 'STG done' "$SOCKETLEY_DLOG")"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
