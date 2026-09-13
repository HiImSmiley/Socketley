#!/usr/bin/env bash
# Integration test: the third fan-out door reports what the other two do.
#
# ─── A FIX THAT SAT AT TWO DOORS OF THREE ───────────────────────────────────
#
# queue_send() and queue_broadcast() were taught to answer whether the bytes were
# taken. queue_upstream_send() was not, and its own comment had said all along
# that it is the same thing:
#
#     // The same decision queue_send() makes one function up, because
#     // upstream_broadcast() is the same shape pointed outwards
#
#     if (uc->write_queue.bytes() >= write_buffer_bytes())
#     {
#         uc->closing = true;
#         return;                       <- nothing counted, nobody told
#     }
#
# And the caller above it was worse than the client-facing one had been:
#
#     bool upstream_send(int conn_id, std::string_view msg)
#     {
#         if (!it->second->connected) return false;   // only `connected`
#         queue_upstream_send(...);                   // sets `closing`
#         return true;                                // always
#     }
#
# `closing` is set and `connected` is left alone, so every later send answered
# true FOR EVER while nothing left the process. On the client-facing side the
# same defect lost exactly one message under a success; here it loses all of
# them, silently, until the connection is torn down for another reason.
#
# Measured, 400 sends of 64 KB at an upstream that accepted the connection and
# then read nothing:
#
#     before   sent=400  failed=0     every one of them a lie
#     after    sent=129  failed=271   the same 129/271 the client-facing side
#                                     reports, because it is the same bound
#
# ─── AND WHY THE REPORT CAME WITH A NUMBER ──────────────────────────────────
#
# self.pending() resolves a CLIENT id, and an upstream lives in another map, so
# a script told "false, backlog" with no way to ask how deep the queue is can
# only retry blindly. self.upstream_pending(id) is that number -- nil for an id
# that is not one of this runtime's upstreams, so "unknown" cannot be read as
# "empty".
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate upstreamback

P_SRV=$((SL_PORT_BASE+1984))
P_UP=$((SL_PORT_BASE+1986))
P_SRV2=$((SL_PORT_BASE+1988))
P_UP2=$((SL_PORT_BASE+1990))
NAMES="ub_srv ub_paced"
LUA="$SOCKETLEY_TMPD/ub.lua"
GO="$SOCKETLEY_TMPD/drain_now"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

UPID=""; UPID2=""
cleanup() {
    for p in $UPID $UPID2; do { kill -9 "$p" && wait "$p"; } 2>/dev/null || true; done
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

# An upstream that accepts and then reads nothing until told.  The receive
# buffer is left alone deliberately: setting it small produced a TCP window in
# which nothing moved at all, which reads as a runtime stall and is the harness.
cat > "$SOCKETLEY_TMPD/peer.py" <<'PYEOF'
import os, socket, sys, time
port, go = int(sys.argv[1]), sys.argv[2]
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(8)
c, _ = srv.accept()
print("accepted", flush=True)
while not os.path.exists(go):
    time.sleep(0.05)
c.settimeout(5)
total = 0
end = time.time() + 30
while time.time() < end:
    try:
        b = c.recv(1 << 18)
        if not b: break
        total += len(b)
    except socket.timeout:
        break
print("DRAINED=%d" % total, flush=True)
PYEOF
python3 "$SOCKETLEY_TMPD/peer.py" "$P_UP" "$GO" > "$SOCKETLEY_TMPD/peer.out" 2>&1 &
UPID=$!

# The second peer reads from the start -- its GO already exists -- because the
# paced case is about a queue that DOES drain, and the flood's peer cannot also
# be that: it must not read, and the flood then closes the upstream for good.
touch "$SOCKETLEY_TMPD/go2"
python3 "$SOCKETLEY_TMPD/peer.py" "$P_UP2" "$SOCKETLEY_TMPD/go2" > "$SOCKETLEY_TMPD/peer2.out" 2>&1 &
UPID2=$!

cat > "$LUA" <<'LUAEOF'
local CHUNK = string.rep("u", 65536)
local paced = nil

-- The slope, not just the cliff.  A producer that checks upstream_pending()
-- against the watermark and waits to be called back gets NO refusals at all --
-- which is the difference between "129 of 400 went" and "all of it went".
function on_upstream_writable(uid)
    local p = paced
    if not p then return end
    p.resumed = p.resumed + 1
    while p.left > 0 do
        if (self.upstream_pending(uid) or 0) >= self.watermark() then return end
        local okay = self.upstream_send(uid, CHUNK)
        if not okay then p.refused = p.refused + 1; paced = nil; return end
        p.left = p.left - 1
        p.sent = p.sent + 1
    end
    socketley.log("UB paced sent=" .. p.sent .. " refused=" .. p.refused
        .. " resumed=" .. p.resumed)
    paced = nil
end

function on_client_message(id, msg)
    local uid = (self.upstreams() or {})[1]
    if not uid then socketley.log("UB no-upstream"); return end

    if msg == "quiet" then
        -- The half that must not change: an ordinary send is still true, and
        -- the queue is empty before anything is pushed at it.
        local okay = self.upstream_send(uid, "hello")
        socketley.log("UB quiet ok=" .. tostring(okay)
            .. " pending=" .. tostring(self.upstream_pending(uid))
            .. " nosuch=" .. tostring(self.upstream_pending(999999)))

    elseif msg == "bcast" then
        local taken, behind = self.upstream_broadcast("hello")
        socketley.log("UB bcast taken=" .. tostring(taken)
            .. " behind=" .. tostring(behind))

    elseif msg == "paced" then
        paced = { left = 400, sent = 0, refused = 0, resumed = 0 }
        -- The same 400 x 64 KB as the flood below, paced.  It cannot finish
        -- inside this call: the queue fills long before 400 and the rest can
        -- only leave when on_upstream_writable brings the producer back.
        while paced.left > 0 do
            if (self.upstream_pending(uid) or 0) >= self.watermark() then break end
            local okay = self.upstream_send(uid, CHUNK)
            if not okay then paced.refused = paced.refused + 1; break end
            paced.left = paced.left - 1
            paced.sent = paced.sent + 1
        end
        socketley.log("UB paced-start sent=" .. paced.sent
            .. " left=" .. paced.left .. " refused=" .. paced.refused)

    elseif msg == "flood" then
        local sent, failed, first = 0, 0, nil
        for _ = 1, 400 do
            local okay, why = self.upstream_send(uid, CHUNK)
            if okay then sent = sent + 1
            else
                failed = failed + 1
                if not first then first = tostring(why) end
            end
        end
        socketley.log("UB flood sent=" .. sent .. " failed=" .. failed
            .. " pending=" .. tostring(self.upstream_pending(uid))
            .. " why=[" .. tostring(first) .. "]")
    end
end
LUAEOF

echo "=== Integration: an upstream send that cannot go says so ==="
daemon_start "$BIN"

create_ok "a server with an upstream" "$BIN" create server ub_srv -p "$P_SRV" \
    -u "127.0.0.1:$P_UP" --lua "$LUA" -s
create_ok "and one whose upstream reads" "$BIN" create server ub_paced -p "$P_SRV2" \
    -u "127.0.0.1:$P_UP2" --lua "$LUA" -s
ready_tcp 127.0.0.1 "$P_SRV"  >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$P_SRV2" >/dev/null 2>&1 || true
sleep 1.5

poke()  { printf '%s\n' "$1" | timeout 25 nc -q0 127.0.0.1 "$P_SRV"  >/dev/null 2>&1 || true; sleep 0.8; }
poke2() { printf '%s\n' "$1" | timeout 25 nc -q0 127.0.0.1 "$P_SRV2" >/dev/null 2>&1 || true; sleep 0.8; }
g() { printf '%s\n' "$2" | sed -n "s/.* $1=\([^ ]*\).*/\1/p"; }

# ─── 1. The upstream is there, and the ordinary send works ──────────────────
poke quiet
QL=$(grep -o 'UB quiet .*' "$SOCKETLEY_DLOG" | tail -1) || true
if [ -n "$QL" ]; then ok; else
    bad "the script found its upstream" \
        "no 'UB quiet' line -- $(grep -c 'UB no-upstream' "$SOCKETLEY_DLOG" || true) reported none," \
        "so nothing below measures anything"; fi
check "an ordinary upstream send is true"        "true" "$(g ok "$QL")"
check "and the queue is empty before it fills"   "0"    "$(g pending "$QL")"
# nil and not -1, so a caller cannot read "unknown" as "empty".
check "upstream_pending is nil for an unknown id" "nil" "$(g nosuch "$QL")"

# ─── 2. The broadcast reports two numbers ───────────────────────────────────
poke bcast
BL=$(grep -o 'UB bcast .*' "$SOCKETLEY_DLOG" | tail -1) || true
check "a healthy upstream broadcast reaches one" "1" "$(g taken "$BL")"
check "with nothing behind"                      "0" "$(g behind "$BL")"

# ─── 3. The flood, against an upstream that reads nothing ───────────────────
poke flood
FL=$(grep -o 'UB flood .*' "$SOCKETLEY_DLOG" | tail -1) || true
if [ -n "$FL" ]; then ok; else bad "the flood ran" "no 'UB flood' line"; fi

# The assertion this file exists for.  Before it, this was 0 of 400: every send
# answered true, including the ones that went nowhere.
FAILED=$(g failed "$FL")
if [ "${FAILED:-0}" -gt 0 ]; then ok; else
    bad "a send that cannot go answers false" \
        "failed=${FAILED:-0} of 400 at an upstream reading nothing -- upstream_send" \
        "tested only \`connected\`, and the bound sets \`closing\` instead"; fi

SENT=$(g sent "$FL")
if [ "${SENT:-0}" -gt 0 ] && [ "${SENT:-0}" -lt 400 ]; then ok; else
    bad "and the ones that went still answer true" \
        "sent=${SENT:-0} of 400; 400 means nothing is reported and 0 means the" \
        "guard refuses everything"; fi

# ─── 4. And which reason it was ─────────────────────────────────────────────
# "is not connected" is the sentence for an upstream that is gone, and it is
# false of this one twice over: the connection is up, and what happened is that
# this runtime closed it because the producer outran the socket.
case "$FL" in
    *"more was queued for it than it could take"*) ok ;;
    *"is not connected"*)
        bad "the refusal names the backlog and not the connection" \
            "it said 'is not connected', which is false of a connected upstream" \
            "whose queue this runtime filled" ;;
    *) bad "the refusal names the backlog" "why=[$(g why "$FL")]" ;;
esac

# ─── 5. And the number a producer would pace on ─────────────────────────────
PEND=$(g pending "$FL")
if [ "${PEND:-0}" -gt 1000000 ]; then ok; else
    bad "upstream_pending reports what is owed" \
        "pending=${PEND:-0} after 400 x 64 KB at an upstream that read nothing;" \
        "without it a script told 'false' can only retry blindly"; fi

# ─── 6. And the slope, which is the answer to the ratio above ──────────────
# 129 of 400 is what a producer that does not look gets.  One that checks
# upstream_pending() against the watermark and waits to be called back gets all
# 400 and no refusals -- and that is only possible if on_upstream_writable
# fires, which is the flag this file was written after finding set and unread.
poke2 paced
PS=$(grep -o 'UB paced-start .*' "$SOCKETLEY_DLOG" | tail -1) || true
S1=$(g sent "$PS")
if [ "${S1:-0}" -gt 0 ]; then ok; else
    bad "a paced producer starts sending" "paced-start=[$PS]"; fi

PD=""
for _ in $(seq 1 60); do
    PD=$(grep -o 'UB paced sent=[0-9]* refused=[0-9]* resumed=[0-9]*' "$SOCKETLEY_DLOG" | tail -1) || true
    [ -n "$PD" ] && break
    sleep 0.5
done
if [ -n "$PD" ]; then ok; else
    bad "and on_upstream_writable brings it back" \
        "no 'UB paced' completion after 30s -- the producer stopped at the" \
        "watermark and was never called again, which is the flag being set and" \
        "nothing reading it"; fi
check "the whole 400 went"   "400" "$(g sent "$PD")"
check "with no refusals"     "0"   "$(g refused "$PD")"
R2=$(g resumed "$PD")
if [ "${R2:-0}" -gt 0 ]; then ok; else
    bad "and it was resumed at least once" \
        "resumed=${R2:-0}; 400 x 64 KB cannot fit under the watermark in one go"; fi

# ─── 7. The runtime is still there ──────────────────────────────────────────
check "the runtime survived it" "Up" \
      "$("$BIN" ps -a 2>/dev/null | awk '$2=="ub_srv" { print $7 }')"

echo "  measured: quiet=[$QL]"
echo "            flood=[$FL]"
echo "            paced=[$PD]"
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { cat "$SOCKETLEY_TMPD/peer.out" 2>/dev/null | sed 's/^/    peer: /'; echo "  FAILED"; }
[ "$FAIL" -eq 0 ]
