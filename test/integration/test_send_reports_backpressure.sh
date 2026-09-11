#!/usr/bin/env bash
# Integration test: a script is told when it is sending faster than the socket.
#
# ─── WHAT IT WAS TOLD BEFORE ────────────────────────────────────────────────
#
# queue_send() answered nothing, and the comment at its caller said the rest:
#
#     "Queued, which is what 'sent' means on an async write path here, with a
#      connection closed for exceeding the write-queue bound reported by the
#      connection going away."
#
# Which is to say not reported. The order made it exact -- the `closing` check
# runs BEFORE the queue check, so:
#
#     call N    queue under the bound   -> queued,  true
#     call N+1  queue over the bound    -> DROPPED, and still true; the
#                                          connection is marked closing
#     call N+2  closing                 -> false, "there is no open connection
#                                          ... it may have closed"
#
# One message dropped under a success, and then a refusal that reads as the
# peer's doing when the runtime closed it because the producer outran it.
#
# Measured on a client that connects and never reads, with a script sending 400
# chunks of 64 KB:
#
#     before   sent=130  failed=270   first refusal: "there is no open connection"
#     after    sent=129  failed=271   first refusal: names the backlog
#
# The difference is one message, and it is the whole defect: 130 was the one
# that filled the queue, went in the bin, and was called a success.
#
# ─── WHICH ASSERTION BELOW IS THE ONE ───────────────────────────────────────
#
# Worth saying plainly, because the counter-proof says it: with the fix reverted
# and self.pending() left in place, this file scores 9/10 and the single failure
# is the refusal's wording. `failed` is 270 on the BROKEN build too -- the calls
# after the drop are refused by the `closing` check, just for the wrong reason
# -- so counting refusals does not discriminate and is only a guard here.
#
# The discriminator is what the script is TOLD. "there is no open connection ...
# it may have closed" is the sentence a peer hanging up gets; this connection
# was closed by the runtime because the producer outran it, and those two want
# opposite responses -- give up, or slow down.
#
# The 130-vs-129 message itself cannot be asserted from outside: the connection
# ends either way, so the peer receives the same bytes. It is only visible in
# what the script counted, and the absolute number moves with the machine.
#
# ─── AND THE QUESTION NOBODY COULD ASK ──────────────────────────────────────
#
# Nothing in the Lua surface reported queue depth or writability, so a producer
# could not pace -- it could only discover afterwards that its connection had
# been taken away. self.pending(id) is that number. Without it, being told
# "false" is still only a post-mortem.
#
# This is the precondition for any streaming API: a stream whose producer cannot
# see backpressure is a slower way to run out of memory.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate backpressure

P=$((SL_PORT_BASE+1948))
NAMES="bp_srv"
LUA="$SOCKETLEY_TMPD/bp.lua"

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
function on_client_message(id, msg)
    if msg == "flood" then
        -- 400 x 64 KB against a peer that does not read: far past the 8 MiB
        -- bound, so the queue is certain to fill however fast the machine is.
        local chunk = string.rep("x", 65536)
        local sent, failed, first = 0, 0, nil
        local at_start = self.pending(id)
        for _ = 1, 400 do
            local o, why = self.send(id, chunk)
            if o then sent = sent + 1
            else
                failed = failed + 1
                if not first then first = tostring(why) end
            end
        end
        socketley.log("BP flood sent=" .. sent .. " failed=" .. failed
            .. " at_start=" .. tostring(at_start)
            .. " at_end=" .. tostring(self.pending(id))
            .. " why=[" .. tostring(first) .. "]")

    elseif msg == "quiet" then
        -- The half that must not change: an ordinary send is still true, and
        -- the peer still gets it.
        local o = self.send(id, "QUIET-REPLY")
        socketley.log("BP quiet ok=" .. tostring(o)
            .. " pending=" .. tostring(self.pending(id))
            .. " nosuch=" .. tostring(self.pending(999999)))
    end
end
LUAEOF

echo "=== Integration: a send that cannot go says so ==="
daemon_start "$BIN"

create_ok "a scripted server" "$BIN" create server bp_srv -p "$P" --lua "$LUA" -s
ready_tcp 127.0.0.1 "$P" >/dev/null 2>&1 || true

# ─── 1. The ordinary case, first, so the flood is not the only measurement ──
QUIET=$(timeout 12 python3 - "$P" <<'PYEOF' 2>/dev/null || true
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); s.settimeout(4)
s.sendall(b"quiet\n")
time.sleep(1.0)
try:    print(s.recv(256).decode().strip())
except Exception: print("")
s.close()
PYEOF
)
check "an ordinary send still reaches the client" "QUIET-REPLY" "$QUIET"

QL=$(grep -o 'BP quiet .*' "$SOCKETLEY_DLOG" | tail -1)
qf() { printf '%s\n' "$QL" | sed -n "s/.* $1=\([^ ]*\).*/\1/p"; }
check "and still answers true"                    "true" "$(qf ok)"
check "self.pending answers nil for a non-connection" "nil" "$(qf nosuch)"

# ─── 2. The flood ───────────────────────────────────────────────────────────
# A peer that connects, asks, and never reads. Its receive buffer is set small
# so the kernel stops absorbing early and the runtime's own queue is what fills.
timeout 25 python3 - "$P" <<'PYEOF' 2>/dev/null || true
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
s.sendall(b"flood\n")
time.sleep(6)
s.close()
PYEOF
sleep 1

FL=$(grep -o 'BP flood .*' "$SOCKETLEY_DLOG" | tail -1)
ff() { printf '%s\n' "$FL" | sed -n "s/.* $1=\([^ ]*\).*/\1/p"; }

if [ -n "$FL" ]; then ok; else
    bad "the flood ran at all" "no 'BP flood' line -- everything below measures nothing"; fi

# A guard and not the discriminator -- see the header. The broken build also
# refuses these, by way of the `closing` check; what it gets wrong is the
# reason, which is asserted further down.
FAILED=$(ff failed)
if [ "${FAILED:-0}" -gt 0 ]; then ok; else
    bad "a send that cannot go answers false" \
        "failed=$FAILED of 400 against a peer that never read -- every one of" \
        "them was called a success"; fi

SENT=$(ff sent)
if [ "${SENT:-0}" -gt 0 ] && [ "${SENT:-0}" -lt 400 ]; then ok; else
    bad "and the ones that did go still answer true" \
        "sent=$SENT of 400; 400 would mean nothing was reported and 0 would" \
        "mean the guard refuses everything"; fi

# ─── The assertion this file exists for ─────────────────────────────────────
# Which of the five reasons it was. "there is no open connection" is the
# sentence a peer hanging up gets, and it is the wrong one here: the runtime
# closed this connection because the producer outran it, and the answer to that
# is to pace rather than to give up. This is the one that goes red with the fix
# reverted.
case "$FL" in
    *"more was queued for it than it could take"*) ok ;;
    *"there is no open connection"*)
        bad "the refusal names the backlog and not the peer" \
            "it said 'there is no open connection', which reads as the peer's" \
            "doing -- this connection was closed by the runtime" ;;
    *) bad "the refusal names the backlog" "why=[$(ff why)]" ;;
esac

# ─── 3. And the number that lets a producer avoid all of it ─────────────────
check "self.pending starts at zero" "0" "$(ff at_start)"
AT_END=$(ff at_end)
if [ "${AT_END:-0}" -gt 1000000 ]; then ok; else
    bad "self.pending reports what is still owed" \
        "at_end=$AT_END after 400 x 64 KB against a peer that never read;" \
        "a producer watching this can pace before the bound rather than after"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "    flood: $FL"; echo "    quiet: $QL"; echo "  FAILED"; }
[ "$FAIL" -eq 0 ]
