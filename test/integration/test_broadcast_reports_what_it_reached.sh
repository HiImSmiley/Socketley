#!/usr/bin/env bash
# Integration test: a broadcast says how many it reached and how many it dropped.
#
# ─── THE SAME DOOR, THE OTHER ENTRANCE ──────────────────────────────────────
#
# self.send() was fixed to report a connection dropped for backlog. The
# broadcast door was not, and it has the identical five lines:
#
#     if (conn->write_queue.bytes() >= write_queue_max_bytes)
#     {
#         conn->closing = true;
#         continue;               // <- nothing counted, nobody told
#     }
#
# So a broadcast to 3000 clients that dropped a third of them for backlog was
# indistinguishable from one that reached every single one. queue_broadcast()
# returned void; self.broadcast() returned nothing.
#
# Worse, it left the send door inconsistent with itself: a client dropped HERE
# had no closed_for_backlog set, so the script's next self.send() to it
# answered "there is no open connection ... it may have closed" -- the peer's
# sentence for this runtime's decision. One flag, two entrances; only one of
# them set it.
#
# ─── WHY THE COUNTS ARE THIS SHARD'S AND SAID SO ────────────────────────────
#
# broadcast_all() also fans out to sibling shards, whose queues this process
# cannot see. Returning a total would repeat the exact mistake the binding's
# own comment warns about -- "under --shards reaches a quarter of the clients
# while reporting success".
#
# So the numbers are this shard's, deliberately. That is the right scope here
# and the wrong one for shard_connection_count(): a script asking "how many
# clients does my runtime have" needs the global answer, and a script asking
# "which of my connections are falling behind" can only act on its own.
#
# ─── A HELD MESSAGE IS TAKEN, NOT LOST ──────────────────────────────────────
#
# A connection whose protocol is not yet classified cannot be written to -- the
# bytes would land in front of the response to a request it has already sent --
# so the broadcast goes into that connection's hold instead. That is a DEFERRED
# TAKE: the bytes are delivered as soon as the protocol is known.
#
# Counting it as neither taken nor backlogged is what the first draft of this
# did, and the first run said so: a broadcast to three connected clients
# reported taken=1, the only one that had spoken yet. Which reads as two
# clients missed, and none were.
#
# ─── AND THE COUNT IS A TRANSITION, NOT A POPULATION ────────────────────────
#
# A dropped client is marked closing, and the top of the loop skips a closing
# connection. So it is counted backlogged exactly ONCE, on the broadcast that
# dropped it -- after that it is neither taken nor backlogged. The fifth case
# asserts that, because a count that kept reporting it every round would read
# as an ongoing problem rather than one client lost once.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate bcastcount

P=$((SL_PORT_BASE+1954))
NAMES="bc_srv"
LUA="$SOCKETLEY_TMPD/bc.lua"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi; }

cleanup() {
    for n in $NAMES; do "$BIN" stop "$n"   >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

cat > "$LUA" <<'LUAEOF'
local CHUNK = string.rep("y", 65536)
local ids = {}

function on_connect(id)
    ids[#ids + 1] = id
end

function on_client_message(id, msg)
    if msg == "one" then
        -- The healthy case first: a broadcast that reaches everybody reports
        -- everybody, and nothing is backlogged.
        local taken, behind = self.broadcast("HELLO-ALL")
        socketley.log("BC one taken=" .. tostring(taken)
            .. " behind=" .. tostring(behind))

    elseif msg == "fill" then
        -- Broadcast until somebody falls behind, then one more round so the
        -- count after the drop can be compared with the count at the drop.
        local at_drop, after, rounds, why = nil, nil, 0, ""
        for _ = 1, 400 do
            local taken, behind = self.broadcast(CHUNK)
            rounds = rounds + 1
            if behind and behind > 0 and not at_drop then
                at_drop = taken .. "/" .. behind
                -- The cross-door assertion, made in the same turn as the drop
                -- rather than from a later message: closed_for_backlog is read
                -- off the connection, and the connection is reaped.
                for _, cid in ipairs(ids) do
                    local okay, reason = self.send(cid, "probe")
                    if not okay then
                        why = why .. "[" .. tostring(reason) .. "]"
                    end
                end
            elseif at_drop and not after then
                after = taken .. "/" .. behind
                break
            end
        end
        socketley.log("BC fill rounds=" .. rounds
            .. " at_drop=" .. tostring(at_drop)
            .. " after=" .. tostring(after))
        socketley.log("BC why reasons=" .. why)
    end
end
LUAEOF

echo "=== Integration: a broadcast reports what it reached ==="
daemon_start "$BIN"

create_ok "a scripted server" "$BIN" create server bc_srv -p "$P" --lua "$LUA" -s
ready_tcp 127.0.0.1 "$P" >/dev/null 2>&1 || true

OUT=$(timeout 90 python3 - "$P" <<'PYEOF' 2>&1 || true
import socket, sys, time
port = int(sys.argv[1])

def conn(rcvbuf=None):
    s = socket.create_connection(("127.0.0.1", port), 5)
    if rcvbuf:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    s.settimeout(6)
    return s

# Two readers that do read, and one that never will.
a, b = conn(), conn()
stuck = conn(2048)
time.sleep(0.8)

# ─── the healthy round ──────────────────────────────────────────────────────
a.sendall(b"one\n")
time.sleep(0.8)
try:
    got = b""
    while b"HELLO-ALL" not in got:
        got += b.recv(4096)
    print("QUIET_REACHED=1")
except Exception:
    print("QUIET_REACHED=0")

# ─── now flood, with `stuck` never reading ──────────────────────────────────
# a and b keep reading so they stay healthy and stay in `taken`.
a.sendall(b"fill\n")
deadline = time.time() + 20
drained = 0
while time.time() < deadline:
    for s in (a, b):
        try:
            c = s.recv(1 << 18)
            if c: drained += len(c)
        except socket.timeout:
            pass
        except Exception:
            pass
    if drained > 40 << 20:
        break
print("DRAINED=%d" % drained)
a.close(); b.close(); stuck.close()
PYEOF
)

L1=$(grep -o 'BC one .*' "$SOCKETLEY_DLOG" | tail -1) || true
L2=$(grep -o 'BC fill .*' "$SOCKETLEY_DLOG" | tail -1) || true
g() { printf '%s\n' "$2" | sed -n "s/.* $1=\([^ ]*\).*/\1/p"; }

# ─── 1. The healthy case: everybody, nobody behind ──────────────────────────
# Asserted first and as numbers, because a binding that returned nil would make
# every comparison below vacuously true.
check "a broadcast that reaches all three says three" "3" "$(g taken "$L1")"
check "and nothing is behind"                         "0" "$(g behind "$L1")"
case "$OUT" in *QUIET_REACHED=1*) ok ;;
    *) bad "and the message really arrived" "a reader never saw HELLO-ALL" ;; esac

# ─── 2. The drop is counted ─────────────────────────────────────────────────
AT=$(g at_drop "$L2")
if [ "$AT" != "nil" ] && [ -n "$AT" ]; then ok; else
    bad "a client that falls behind is counted" \
        "at_drop=$AT -- 400 rounds of 64 KB with one client not reading and" \
        "nothing was ever reported behind"; fi
# How MANY fall behind depends on how fast the harness drains, so the assertion
# is the property and not the number: at least one is reported behind, which is
# the thing that used to be reported as nothing at all.
if [ "${AT##*/}" -ge 1 ] 2>/dev/null; then ok; else
    bad "at least one is reported behind" "at_drop=$AT"; fi

# ─── 3. And counted once, not every round after ─────────────────────────────
# A transition and not a population: the dropped connection is marked closing
# and skipped from then on, so it must not keep being reported every round.
AFTER=$(g after "$L2")
check "the round after reports nobody behind" "0" "${AFTER##*/}"

# ─── 4. The refusal at the other door names the backlog ─────────────────────
# A build that counted correctly but did not set closed_for_backlog would pass
# everything above and still tell the script the peer hung up.
# The empty answer used to be counted a pass here, under a comment saying the
# branch was not always reached -- and nothing in this file ever sent "why",
# so it was never reached at all and this assertion was unconditional.
R=$(grep -o 'BC why .*' "$SOCKETLEY_DLOG" | tail -1) || true
case "$R" in
    *"more was queued"*) ok ;;
    *) bad "a client dropped by broadcast gets the backlog sentence" \
           "got [${R:-<no BC why line>}] -- the probe runs in the same turn as" \
           "the drop, so a peer-worded reason here is closed_for_backlog being" \
           "set at the send door and not at the broadcast one" ;;
esac

# ─── 5. The runtime is still serving both readers ───────────────────────────
check "the runtime survived it" "Up" \
      "$("$BIN" ps -a 2>/dev/null | awk '$2=="bc_srv" { print $7 }')"

echo "  measured: healthy=[$L1] flood=[$L2]"
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else
    printf '%s\n' "$OUT" | sed 's/^/    driver: /'
    echo "  FAILED"
fi
[ "$FAIL" -eq 0 ]
