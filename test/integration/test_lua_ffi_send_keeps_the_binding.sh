#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: self.send, self.pending and self.watermark through LuaJIT's
# FFI answer exactly what the sol bindings behind them answer.
#
# ─── WHAT CHANGED ───────────────────────────────────────────────────────────
#
# A pacing loop -- `while self.pending() < wm do self.send(line) end` -- is
# compiled by LuaJIT, and every call of a sol binding from compiled code left
# the trace for the interpreter and stitched back.  The three calls are now Lua
# wrappers over FFI calls that stay inside the trace.  The C side takes only
# the case where the message joins the queue behind a write already in flight
# and answers "not mine" for everything else, which then goes to the old
# binding: LuaJIT forbids a function called through the FFI to enter the VM,
# so nothing that can run on_send, on_disconnect or build a refusal's sentence
# may happen there.
#
# ─── WHAT EACH PART WOULD CATCH ─────────────────────────────────────────────
#
#   1. a fast path that loses, reorders or duplicates a line, on the client and
#      on the server: the peer checks every sequence number of a paced stream
#      well past the watermark, so the drain and on_writable are crossed too
#   2. a fast path that skips on_send: the second client defines it and counts
#      every call against every send that answered true
#   3. a wrapper that answers anything but the one value `true`, or a pending
#      that comes back as cdata rather than a number
#   4. an id the C side reads differently from sol: sends from a timer, outside
#      every callback, with and without ids, keep their three refusals, and a
#      burst with an id is delivered whole on the connection it names
#   5. a disconnect in the middle of a burst reported other than once, or a send
#      after it answered other than "not connected"
#   6. a fast path that ignores the server's hard bound: the flood against a
#      reader that reads nothing must still be refused with its sentence
#   7. the ffi module left reachable: no global, no package.loaded entry, and
#      require("ffi") still fails, as it did before
#   8. the wrappers going in over a self.send the script replaced at its top
#      level: they are put in after the top level, once the compiler is open
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate luaffisend

P_ORDER=$((SL_PORT_BASE+1915))
P_CUT=$((SL_PORT_BASE+1916))
P_PACE=$((SL_PORT_BASE+1917))
P_FLOOD=$((SL_PORT_BASE+1918))
NAMES="ff_fast ff_slow ff_wrapped ff_ids ff_cut ff_pace ff_flood"
T="$SOCKETLEY_TMPD"
N=300000

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

PEERS=""
cleanup() {
    touch "$T/stop"
    for p in $PEERS; do { kill -9 "$p" && wait "$p"; } 2>/dev/null || true; done
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

# ─── The peers ──────────────────────────────────────────────────────────────
# Every line is "<tag> <seq> <pad>", and a tag's sequence has to run 1, 2, 3
# with nothing missing, so the oracle is the bytes that arrived.
cat > "$T/peer.py" <<'PYEOF'
import os, socket, sys, threading, time
mode, port, stop, out = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
# A tag is also pinned to the connection it first arrived on, so a line sent
# with an id and delivered on another connection is a failure too.
last, where, bad, lock = {}, {}, [], threading.Lock()
def read_lines(c):
    me = c.fileno()
    for line in c.makefile("rb"):
        parts = line.split(b" ", 2)
        tag, seq = parts[0].decode(), int(parts[1])
        with lock:
            if seq != last.get(tag, 0) + 1 and not bad:
                bad.append("%s:%d->%d" % (tag, last.get(tag, 0), seq))
            if where.setdefault(tag, me) != me and not bad:
                bad.append("%s:split" % tag)
            last[tag] = seq
def report():
    with lock:
        body = " ".join("%s=%d" % kv for kv in sorted(last.items()))
        mn = "none" if "M" not in where or "N" not in where else "same" if where["M"] == where["N"] else "apart"
        open(out + ".tmp", "w").write("%s MN=%s bad=%s\n" % (body, mn, bad[0] if bad else "none"))
    os.rename(out + ".tmp", out)
def listener():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(16)
    return s
if mode == "order":
    s = listener()
    def accept():
        while True:
            c, _ = s.accept()
            threading.Thread(target=read_lines, args=(c,), daemon=True).start()
    threading.Thread(target=accept, daemon=True).start()
    while not os.path.exists(stop): report(); time.sleep(0.2)
    report()
elif mode == "connect":
    c = socket.create_connection(("127.0.0.1", port))
    threading.Thread(target=read_lines, args=(c,), daemon=True).start()
    while not os.path.exists(stop): report(); time.sleep(0.2)
    report()
elif mode == "cut":
    # Reads a little, then resets the connection under a client still pumping.
    s = listener()
    c, _ = s.accept(); s.close()
    got = 0
    while got < 256 * 1024:
        b = c.recv(65536)
        if not b: break
        got += len(b)
    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
    c.close()
    open(out, "w").write("cut after %d\n" % got)
    while not os.path.exists(stop): time.sleep(0.05)
elif mode == "stall":
    # Connects and reads nothing at all.
    c = socket.socket(); c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    c.connect(("127.0.0.1", port))
    while not os.path.exists(stop): time.sleep(0.05)
PYEOF
peer() { python3 "$T/peer.py" "$@" > /dev/null 2>&1 & PEERS="$PEERS $!"; }
listening() {
    for _ in $(seq 1 200); do
        ss -ltn 2>/dev/null | grep -q ":$1 " && return 0
        sleep 0.05
    done
    return 1
}

# ─── The scripts ────────────────────────────────────────────────────────────
# One pacing producer, written twice: with on_send (every send takes the sol
# binding) and without (every send behind a write in flight takes the FFI).
pacer() {
    cat <<LUAEOF
local TAG, N = "$1", $N
local PAD = string.rep("p", 40)
local i, odd, seen, refused = 0, 0, 0, nil
local function count(...) return select("#", ...), ... end
local function pump()
  local wm = self.watermark()
  while i < N and self.pending() < wm do
    local n, okay, why = count(self.send(TAG .. " " .. (i + 1) .. " " .. PAD))
    if not okay then refused = tostring(why) return end
    if n ~= 1 or okay ~= true then odd = odd + 1 end
    i = i + 1
  end
  if i == N then
    i = i + 1
    socketley.log("FT " .. TAG .. " done sent=" .. N .. " odd=" .. odd .. " seen=" .. seen
      .. " ptype=" .. type(self.pending()) .. " wtype=" .. type(self.watermark()))
  end
end
function on_connect() pump() end
function on_writable() pump() end
function on_disconnect() socketley.log("FT " .. TAG .. " lost refused=" .. tostring(refused)) end
LUAEOF
}
pacer F > "$T/fast.lua"
{ pacer S; echo 'function on_send(msg) seen = seen + 1 end'; } > "$T/slow.lua"
{ pacer W; echo 'local orig = self.send'
  echo 'self.send = function(m, id) seen = seen + 1 return orig(m, id) end'; } > "$T/wrapped.lua"

cat > "$T/ids.lua" <<'LUAEOF'
local up = 0
local function say(tag, ...)
  local o = {}
  for k = 1, select("#", ...) do o[#o + 1] = tostring((select(k, ...))) end
  socketley.log("FT ids " .. tag .. " " .. table.concat(o, " | "))
end
local function burst(tag, id)
  local okay = 0
  for k = 1, 2000 do
    if self.send(tag .. " " .. k .. " " .. string.rep("q", 30), id) == true then okay = okay + 1 end
  end
  return okay
end
function on_connect()
  up = up + 1
  if up < 2 then return end
  socketley.set_timeout(200, function()
    say("noid", self.send("x"))
    say("id7", self.send("x", 7))
    say("pend7", self.pending(7))
    say("ffi", type(ffi), type(package.loaded.ffi), (pcall(require, "ffi")))
    say("burst", burst("M", 1), burst("N", 2))
    say("pend", type(self.pending()), type(self.pending(1)))
  end)
end
LUAEOF

cat > "$T/cut.lua" <<'LUAEOF'
local lost = 0
local line = "C 0 " .. string.rep("c", 60)
local function pump()
  local wm = self.watermark()
  while self.pending() < wm do
    if not self.send(line) then return end
  end
end
function on_connect() pump() end
function on_writable() pump() end
function on_disconnect(fd, id)
  lost = lost + 1
  socketley.log("FT cut lost=" .. lost .. " id=" .. tostring(id))
  if lost == 1 then
    socketley.set_timeout(300, function()
      local okay, why = self.send("after")
      socketley.log("FT cut after=" .. tostring(okay) .. " why=[" .. tostring(why) .. "] lost=" .. lost)
    end)
  end
end
LUAEOF

cat > "$T/pace.lua" <<LUAEOF
local N, PAD = $N, string.rep("p", 40)
local i = 0
local function pump(id)
  local wm = self.watermark()
  while i < N do
    local p = self.pending(id)
    if not p or p >= wm then return end
    if self.send(id, "V " .. (i + 1) .. " " .. PAD) ~= true then return end
    i = i + 1
  end
  if i == N then i = i + 1 socketley.log("FT pace done ptype=" .. type(self.pending(id))) end
end
function on_connect(id) pump(id) end
function on_writable(id) pump(id) end
LUAEOF

cat > "$T/flood.lua" <<'LUAEOF'
local CHUNK = string.rep("z", 65536)
function on_connect(id)
  local sent, refused, why = 0, 0, nil
  for _ = 1, 300 do
    local okay, w = self.send(id, CHUNK)
    if okay then sent = sent + 1 else refused = refused + 1 why = why or w end
  end
  local after_ok, after_why = self.send(id, "x")
  socketley.log("FT flood sent=" .. sent .. " refused=" .. refused .. " why=[" .. tostring(why)
    .. "] after=" .. tostring(after_ok) .. " none=" .. tostring(self.pending(99999)))
end
LUAEOF

echo "=== Integration: self.send through the FFI keeps the binding's answers ==="
daemon_start "$BIN"
waitlog() {
    for _ in $(seq 1 "${2:-600}"); do
        grep -q "$1" "$SOCKETLEY_DLOG" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}
g() { printf '%s\n' "$2" | sed -n "s/.* $1=\([^ ]*\).*/\1/p"; }

# ─── 1-3. Paced streams, with and without on_send ───────────────────────────
peer order "$P_ORDER" "$T/stop" "$T/order.out"
listening "$P_ORDER" || bad "the order peer listens" "nothing on $P_ORDER"
create_ok "the FFI client" "$BIN" create client ff_fast -t "127.0.0.1:$P_ORDER" --lua "$T/fast.lua" -s
create_ok "the on_send client" "$BIN" create client ff_slow -t "127.0.0.1:$P_ORDER" --lua "$T/slow.lua" -s
create_ok "the client that wraps self.send" "$BIN" create client ff_wrapped -t "127.0.0.1:$P_ORDER" --lua "$T/wrapped.lua" -s
create_ok "the client with two connections" "$BIN" create client ff_ids -t "127.0.0.1:$P_ORDER" \
    --connections 2 --lua "$T/ids.lua" -s

waitlog "FT F done" || bad "the FFI client finished its stream" "no 'FT F done' line"
waitlog "FT S done" || bad "the on_send client finished its stream" "no 'FT S done' line"
waitlog "FT W done" || bad "the wrapping client finished its stream" "no 'FT W done' line"
waitlog "FT ids pend " || bad "the timer sends ran" "no 'FT ids pend' line"

LF=$(grep -o 'FT F done.*' "$SOCKETLEY_DLOG" | tail -1) || true
LS=$(grep -o 'FT S done.*' "$SOCKETLEY_DLOG" | tail -1) || true
check "every FFI send answered the single value true" "0" "$(g odd "$LF")"
check "every bound send answered the single value true" "0" "$(g odd "$LS")"
check "on_send is not called without one" "0" "$(g seen "$LF")"
# The assertion a fast path that skips on_send fails: every send went through it.
check "on_send ran once for every send" "$N" "$(g seen "$LS")"
check "self.pending is a number" "number" "$(g ptype "$LF")"
LW=$(grep -o 'FT W done.*' "$SOCKETLEY_DLOG" | tail -1) || true
check "a self.send replaced at the top level stays the script's" "$N" "$(g seen "$LW")"
check "self.watermark is a number" "number" "$(g wtype "$LF")"

idl() { grep -o "FT ids $1 .*" "$SOCKETLEY_DLOG" | tail -1 | sed "s/^FT ids $1 //"; }
check "a send outside every callback names the choice" \
    'false | "ff_ids" holds 2 connections and this send is outside the callbacks of all of them -- name one: self.send(msg, id)' \
    "$(idl noid)"
check "a send to an id it does not have names the range" \
    'false | "ff_ids" has no connection 7; its ids are 1 to 2' "$(idl id7)"
check "the pending of an id it does not have is nil" "nil" "$(idl pend7)"
check "the ffi module is reachable nowhere" "nil | nil | false" "$(idl ffi)"
check "a burst with an id is taken whole on each connection" "2000 | 2000" "$(idl burst)"
check "and pending answers numbers from a timer" "number | number" "$(idl pend)"

# Waited for rather than slept for: what was answered true is still on its way.
arrived() {
    for _ in $(seq 1 300); do
        O=$(cat "$1" 2>/dev/null || true)
        case " $O" in *"$2"*) return 0 ;; esac
        sleep 0.1
    done
}
O=""
arrived "$T/order.out" "F=$N M=2000 N=2000 S=$N W=$N" || true
touch "$T/stop"
check "the peer saw every line in order" "none" "$(g bad " $O")"
check "the FFI client's stream arrived whole" "$N" "$(g F " $O")"
check "the on_send client's stream arrived whole" "$N" "$(g S " $O")"
check "the wrapping client's stream arrived whole" "$N" "$(g W " $O")"
check "connection 1's burst arrived whole" "2000" "$(g M " $O")"
check "connection 2's burst arrived whole" "2000" "$(g N " $O")"
check "and each on the connection its id names" "apart" "$(g MN " $O")"
rm -f "$T/stop"

# ─── 5. A disconnect in the middle of a burst ───────────────────────────────
peer cut "$P_CUT" "$T/stop" "$T/cut.out"
listening "$P_CUT" || bad "the cutting peer listens" "nothing on $P_CUT"
create_ok "the client that is cut off" "$BIN" create client ff_cut -t "127.0.0.1:$P_CUT" --lua "$T/cut.lua" -s
waitlog "FT cut after=" || bad "the send after the cut ran" "no 'FT cut after' line"
check "the disconnect is reported once, for connection 1" "FT cut lost=1 id=1" \
    "$(grep -o 'FT cut lost=.*' "$SOCKETLEY_DLOG" | sort -u | tr '\n' ';' | sed 's/;$//')"
LC=$(grep -o 'FT cut after=.*' "$SOCKETLEY_DLOG" | tail -1) || true
check "a send after it is refused as not connected" \
    'FT cut after=false why=["ff_cut" is not connected to its server, or was created --mode in and does not send] lost=1' "$LC"

# ─── 6. The server, paced and flooded ───────────────────────────────────────
create_ok "the pacing server" "$BIN" create server ff_pace -p "$P_PACE" --bind 127.0.0.1 --lua "$T/pace.lua" -s
create_ok "the flooding server" "$BIN" create server ff_flood -p "$P_FLOOD" --bind 127.0.0.1 --lua "$T/flood.lua" -s
listening "$P_PACE" || bad "the pacing server listens" "nothing on $P_PACE"
listening "$P_FLOOD" || bad "the flooding server listens" "nothing on $P_FLOOD"
peer connect "$P_PACE" "$T/stop" "$T/pace.out"
peer stall "$P_FLOOD" "$T/stop" "$T/stall.out"
waitlog "FT pace done" || bad "the server finished its stream" "no 'FT pace done' line"
waitlog "FT flood " || bad "the flood ran" "no 'FT flood' line"
check "the server's pending is a number" "FT pace done ptype=number" \
    "$(grep -o 'FT pace done.*' "$SOCKETLEY_DLOG" | tail -1)"
LFL=$(grep -o 'FT flood .*' "$SOCKETLEY_DLOG" | tail -1) || true
SENT=$(g sent " $LFL"); REF=$(g refused " $LFL")
if [ "${SENT:-0}" -gt 0 ] && [ "${REF:-0}" -gt 0 ] && [ $((SENT + REF)) -eq 300 ]; then ok; else
    bad "the flood is taken up to the bound and refused past it" "sent=$SENT refused=$REF of 300"; fi
case "$LFL" in
    *'was closed because more was queued for it than it could take'*'after=false none=nil') ok ;;
    *) bad "the refusal past the bound keeps its sentence" "[$LFL]" ;;
esac
O=""
arrived "$T/pace.out" "V=$N" || true
touch "$T/stop"
check "the server's stream arrived in order" "none" "$(g bad " $O")"
check "and whole" "$N" "$(g V " $O")"

echo "  measured: fast=[$LF]"
echo "            slow=[$LS]"
echo "            flood=[$LFL]"
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
