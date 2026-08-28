#!/usr/bin/env bash
# suite: quiet -- times a 400ms block against a 1500ms budget.
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
# A callback that never returns is stopped by a wall-clock deadline enforced
# through a LUA_MASKCOUNT hook, and the four claims are chosen so a build that
# answered by killing the whole runtime would fail: the daemon answers for
# another runtime during the stall, the runaway names itself and its bound in
# the log, the offending runtime still serves afterwards, and a merely slow
# callback is untouched -- with the daemon run at SOCKETLEY_LUA_TIMEOUT_MS=1500
# because the operator's knob is itself a claim under test.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luadeadline

PORT=$((SL_PORT_BASE+1100))
SPIN_PORT=$((PORT + 1))
BYST_PORT=$((PORT + 2))
OWN_PORT=$((PORT + 3))
SLOW_PORT=$((PORT + 4))
TOP_PORT=$((PORT + 5))
SINK_PORT=$((PORT + 6))
BE_PORT=$((PORT + 7))
PX_PORT=$((PORT + 8))
BE2_PORT=$((PORT + 9))
PX2_PORT=$((PORT + 10))

NAMES="dl_spin dl_byst dl_own dl_slow dl_px dl_px2"
BE_PID=""; BE2_PID=""; SINK_PID=""

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    [ -n "$BE_PID" ]   && kill "$BE_PID"   2>/dev/null
    [ -n "$BE2_PID" ]  && kill "$BE2_PID"  2>/dev/null
    [ -n "$SINK_PID" ] && kill "$SINK_PID" 2>/dev/null
    # shellcheck disable=SC2086
    "$BIN" stop $NAMES 2>/dev/null || true
    sleep 0.3
    # shellcheck disable=SC2086
    "$BIN" remove $NAMES 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a Lua callback that does not return is stopped ==="

# ── The scripts ─────────────────────────────────────────────────────────────
# Every runtime echoes and the runaway is behind a keyword, so "is this runtime
# still serving" has an answer on the wire both before and after the callback
# that hangs.
mk_echo_spinner() {
    # $1 = path, $2 = extra top-level line (may be empty)
    cat > "$1" <<LUAEOF
${2}
function on_message(msg)
    if msg == "spin" then
        local n = 0
        while true do n = n + 1 end
    end
    self.broadcast("echo:" .. msg)
end
LUAEOF
}

SPIN="$SOCKETLEY_TMPD/spin.lua"
BYST="$SOCKETLEY_TMPD/byst.lua"
OWN="$SOCKETLEY_TMPD/own.lua"
SLOW="$SOCKETLEY_TMPD/slow.lua"
TOP="$SOCKETLEY_TMPD/toplevel.lua"

mk_echo_spinner "$SPIN" ""
mk_echo_spinner "$BYST" ""
mk_echo_spinner "$OWN"  "callback_timeout_ms = 300"

# The control is a callback that blocks 400ms in socketley.http against a
# listener that accepts and then says nothing -- which cannot be a socketley
# runtime, because every one of them answers or closes -- and it is wall time
# rather than an os.clock busy loop, whose result depended on how busy the
# machine was.
cat > "$SLOW" <<LUAEOF
function on_message(msg)
    if msg == "slow" then
        socketley.http({ url = "http://127.0.0.1:$SINK_PORT/wait", timeout_ms = 400 })
    end
    self.broadcast("echo:" .. msg)
end
LUAEOF

# A top level that never returns runs synchronously inside `create`, so it gets
# its own assertion: the create is refused with a reason rather than blocking
# the operator's terminal forever.
printf 'local n = 0\nwhile true do n = n + 1 end\n' > "$TOP"

# Exported before the daemon is started, because this is the daemon's
# environment and not the CLI's.
export SOCKETLEY_LUA_TIMEOUT_MS=1500

daemon_start "$BIN"

create_ok "spinner created"    "$BIN" create server dl_spin -p "$SPIN_PORT" --mode inout --lua "$SPIN" -s
create_ok "bystander created"  "$BIN" create server dl_byst -p "$BYST_PORT" --mode inout --lua "$BYST" -s
create_ok "own-budget created" "$BIN" create server dl_own  -p "$OWN_PORT"  --mode inout --lua "$OWN" -s
create_ok "slow one created"   "$BIN" create server dl_slow -p "$SLOW_PORT" --mode inout --lua "$SLOW" -s
# The sink accepts and then says nothing, keeping its sockets in a list on
# purpose because dropping the last reference lets the collector close them and
# a close is the one thing this must never send.
cat > "$SOCKETLEY_TMPD/sink.py" <<'SINKEOF'
import socket, sys
port = int(sys.argv[1])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(16)
print("ready", flush=True)
held = []
while True:
    try:
        c, _ = s.accept()
        held.append(c)
    except Exception:
        break
SINKEOF
python3 "$SOCKETLEY_TMPD/sink.py" "$SINK_PORT" >"$SOCKETLEY_TMPD/sink.log" 2>&1 &
SINK_PID=$!
SINK_READY=""
for _ in $(seq 1 50); do
    grep -q ready "$SOCKETLEY_TMPD/sink.log" 2>/dev/null && { SINK_READY=1; break; }
    sleep 0.1
done
# Counted as an assertion because the control below is worthless without it: a
# sink that never bound gives socketley.http an instant ECONNREFUSED, which
# looks exactly like the fast return that control exists to rule out.
if [ -n "$SINK_READY" ]; then pass; else
    fail "the silent sink is listening" \
         "nothing bound 127.0.0.1:$SINK_PORT within 5s" \
         "$(head -3 "$SOCKETLEY_TMPD/sink.log" 2>/dev/null)"
fi

ready_tcp 127.0.0.1 "$SPIN_PORT" 8 || echo "  NOTE: dl_spin never accepted a connection"
ready_tcp 127.0.0.1 "$BYST_PORT" 8 || echo "  NOTE: dl_byst never accepted a connection"

# say NAME PORT MESSAGE — one connection, one message, whatever came back.
say() {
    printf '%s\n' "$3" | timeout 8 nc -q 2 127.0.0.1 "$2" 2>/dev/null || true
}

# ── Control: everything works before the runaway ────────────────────────────
#
# Without this the four assertions after the spin are all satisfied by a build
# where nothing ever worked in the first place.
BEFORE=$(say dl_spin "$SPIN_PORT" hello-before)
case "$BEFORE" in
    *echo:hello-before*) pass ;;
    *) fail "control: the spinner serves before anything hangs" \
            "sent 'hello-before' to 127.0.0.1:$SPIN_PORT, got: ${BEFORE:-<nothing>}" \
            "nothing below means anything if this runtime never answered" ;;
esac

BEFORE_STATS_RC=0
"$BIN" stats dl_byst >/dev/null 2>&1 || BEFORE_STATS_RC=$?
if [ "$BEFORE_STATS_RC" = "0" ]; then pass; else
    fail "control: stats answers before anything hangs" \
         "stats dl_byst exited $BEFORE_STATS_RC"
fi

# ── The runaway ─────────────────────────────────────────────────────────────
#
# -q 0 so nc gives up on the reply immediately: there is not going to be one,
# on_message never reaches the broadcast, and a client waiting for it would just
# be a slower way to get here.
printf 'spin\n' | timeout 10 nc -q 0 127.0.0.1 "$SPIN_PORT" >/dev/null 2>&1 &
SPIN_CLIENT=$!
sleep 0.4

# ── 1. The operator is not locked out ───────────────────────────────────────
#
# Issued while the callback is still inside its budget.
T0=$(date +%s.%N)
STATS_RC=0
STATS_OUT=$("$BIN" stats dl_byst 2>&1) || STATS_RC=$?
T1=$(date +%s.%N)
ELAPSED=$(echo "$T1 - $T0" | bc)

if [ "$STATS_RC" = "0" ]; then pass; else
    fail "the daemon still answers stats for another runtime" \
         "stats dl_byst exited $STATS_RC after ${ELAPSED}s" \
         "the CLI gives up after 5s, so this is the daemon not answering at all" \
         "stats said: ${STATS_OUT:-<nothing>}"
fi

# One clock pointed at two runtimes for opposite answers -- a client of the
# stalled one waits while the bystander answers throughout -- because with
# every runtime in its own process the daemon is no longer blocked, and the
# elapsed time rather than the presence of a reply is the measurement since a
# client waiting past the deadline does get its reply.
S0=$(date +%s.%N)
SPIN_DURING=$(printf 'hello-during\n' | timeout 8 nc -q 2 127.0.0.1 "$SPIN_PORT" 2>/dev/null || true)
S1=$(date +%s.%N)
SPIN_ELAPSED=$(echo "$S1 - $S0" | bc)

if [ "$(echo "$SPIN_ELAPSED > 0.3" | bc)" = "1" ]; then pass; else
    fail "control: the spinner's own clients wait behind its runaway callback" \
         "dl_spin answered in ${SPIN_ELAPSED}s, which is too fast for a callback" \
         "to have been holding its loop — so nothing was stalled anywhere, and" \
         "the stats call above returning fast says nothing about the split" \
         "dl_spin said: ${SPIN_DURING:-<nothing>}"
fi

wait "$SPIN_CLIENT" 2>/dev/null || true

# ── 2. The runaway reported itself ──────────────────────────────────────────
# Read out of the daemon's log rather than the CLI, and asserted on the hook's
# own line, because sol2's raise is caught and printed in Release but comes
# back as an unread result under Sanitize.
wait_log() {
    local pattern=$1 timeout=${2:-12}
    local deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        grep -qE "$pattern" "$SOCKETLEY_DLOG" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}

# The runtime's name is part of the claim, because a deadline is the diagnostic
# somebody reads in a hurry and "[lua] on_message ..." does not say which of
# forty servers stopped.
if wait_log '\[lua dl_spin\] on_message hit its 1500ms deadline and was stopped'; then pass; else
    fail "the callback that outran its budget said so, naming the runtime" \
         "no '[lua dl_spin] on_message hit its 1500ms deadline and was stopped' in" \
         "$SOCKETLEY_DLOG" \
         "a bound nobody is told about is a support ticket"
fi

# A second claim: the deadline also arrived at the call site as a failure with
# script and line attached, so this going red while the one above stays green
# means the deadline is reported by the mechanism that raises it and by nothing
# that observes it.
if wait_log '\[lua dl_spin\] on_message error: .*exceeded the 1500ms deadline'; then pass; else
    fail "the deadline reaches the call site's !valid() branch too" \
         "no '[lua dl_spin] on_message error: ... exceeded the 1500ms deadline' line" \
         "the hook raises a Lua error; invoke_on_message checks valid() and" \
         "reports — if only the hook's line is here, that branch never saw it"
fi

# ── 3. The runtime is still serving ─────────────────────────────────────────
#
# The assertion that separates this from a build that answered by killing the
# runtime — which would satisfy "the daemon survived" and lose every connection
# the runtime was holding.
AFTER=$(say dl_spin "$SPIN_PORT" hello-after)
case "$AFTER" in
    *echo:hello-after*) pass ;;
    *) fail "the offending runtime is still serving once the callback returns" \
            "sent 'hello-after' to 127.0.0.1:$SPIN_PORT, got: ${AFTER:-<nothing>}" \
            "one callback failed; the runtime it belongs to was not the thing" \
            "that was supposed to end" ;;
esac

BYST_AFTER=$(say dl_byst "$BYST_PORT" hello-bystander)
case "$BYST_AFTER" in
    *echo:hello-bystander*) pass ;;
    *) fail "the runtime that did nothing wrong is still serving" \
            "sent 'hello-bystander' to 127.0.0.1:$BYST_PORT, got: ${BYST_AFTER:-<nothing>}" ;;
esac

# Asserted by the number in the message rather than by timing the stall, so it
# says which budget was applied and not merely that something eventually
# stopped.
printf 'spin\n' | timeout 10 nc -q 0 127.0.0.1 "$OWN_PORT" >/dev/null 2>&1 || true

if wait_log '\[lua dl_own\] on_message hit its 300ms deadline and was stopped'; then pass; else
    fail "a script's own callback_timeout_ms is what bounds its callbacks" \
         "dl_own declared callback_timeout_ms = 300 and no line in the log names it" \
         "the daemon's own default here is 1500 — if that is what fired, the" \
         "script's declaration was read and then ignored"
fi

OWN_AFTER=$(say dl_own "$OWN_PORT" hello-own)
case "$OWN_AFTER" in
    *echo:hello-own*) pass ;;
    *) fail "the runtime with its own budget is still serving" \
            "sent 'hello-own' to 127.0.0.1:$OWN_PORT, got: ${OWN_AFTER:-<nothing>}" ;;
esac

# 400ms of blocking socketley.http inside a 1500ms budget, because a deadline
# that fires on the documented use of the one blocking primitive this tree
# ships is worse than no deadline.
SLOW_T0=$(date +%s.%N)
SLOW_OUT=$(say dl_slow "$SLOW_PORT" slow)
SLOW_T1=$(date +%s.%N)
SLOW_ELAPSED=$(echo "$SLOW_T1 - $SLOW_T0" | bc)
case "$SLOW_OUT" in
    *echo:slow*) pass ;;
    *) fail "a callback that blocks for 400ms finishes and answers" \
            "sent 'slow' to 127.0.0.1:$SLOW_PORT, got: ${SLOW_OUT:-<nothing>}" \
            "it blocks 400ms against a 1500ms budget and must not be stopped —" \
            "a bound that fires on working code is not a fix" ;;
esac

# ...and it really did block rather than the http call failing instantly, with
# the floor being `say`'s 2s linger plus the block.
if [ "$(echo "$SLOW_ELAPSED > 2.3" | bc)" = "1" ]; then pass; else
    fail "the slow callback really did hold the loop for its 400ms" \
         "the round trip took ${SLOW_ELAPSED}s, and 2s of that is nc's linger" \
         "if socketley.http came back at once there was no slow callback here" \
         "and the control above proved nothing"
fi

# A count rather than a presence check, because a build that also stopped the
# slow callback would satisfy every assertion above and fail only here.
STOPS=$(grep -c "on_message hit its .*ms deadline and was stopped" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "${STOPS:-0}" = "2" ]; then pass; else
    fail "exactly the two runaway on_message callbacks were stopped" \
         "the log has ${STOPS:-0} on_message stop lines, wanted 2" \
         "$(grep 'deadline and was stopped' "$SOCKETLEY_DLOG" 2>/dev/null || true)"
fi

# A deadline inside on_proxy_request has to be the refusal case and not the
# returns-nothing case, because forwarding the bytes of a request whose policy
# hook was stopped mid-decision admits exactly what the hook exists to refuse.
PX_SEEN="$SOCKETLEY_TMPD/px.seen"
PX_SEEN2="$SOCKETLEY_TMPD/px2.seen"
: > "$PX_SEEN"; : > "$PX_SEEN2"

cat > "$SOCKETLEY_TMPD/be.py" <<'PY'
import socket, sys, threading
port, path = int(sys.argv[1]), sys.argv[2]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(8)
print("ready", flush=True)
def serve(c):
    try:
        d = c.recv(65536)
        if d:
            with open(path, "ab") as f: f.write(d)
            c.sendall(b"BACKEND-REPLY\n")
    except Exception: pass
    finally:
        try: c.close()
        except Exception: pass
while True:
    try: threading.Thread(target=serve, args=(s.accept()[0],), daemon=True).start()
    except Exception: break
PY

python3 "$SOCKETLEY_TMPD/be.py" "$BE_PORT"  "$PX_SEEN"  >"$SOCKETLEY_TMPD/be.log"  2>&1 &
BE_PID=$!
python3 "$SOCKETLEY_TMPD/be.py" "$BE2_PORT" "$PX_SEEN2" >"$SOCKETLEY_TMPD/be2.log" 2>&1 &
BE2_PID=$!
for i in $(seq 1 50); do
    grep -q ready "$SOCKETLEY_TMPD/be.log" 2>/dev/null && \
    grep -q ready "$SOCKETLEY_TMPD/be2.log" 2>/dev/null && break
    sleep 0.1
done

printf 'function on_proxy_request(id, data)\n  local n = 0\n  while true do n = n + 1 end\nend\n' \
    > "$SOCKETLEY_TMPD/pxspin.lua"
# The fourth case, deliberately: an observer that returns nothing.
printf 'function on_proxy_request(id, data)\n  socketley.log("PXWATCH saw " .. #data .. " bytes")\nend\n' \
    > "$SOCKETLEY_TMPD/pxwatch.lua"

create_ok "spinning proxy hook created" "$BIN" create proxy dl_px -p "$PX_PORT" \
    --backend "127.0.0.1:$BE_PORT" --protocol tcp --lua "$SOCKETLEY_TMPD/pxspin.lua" -s
create_ok "watching proxy hook created" "$BIN" create proxy dl_px2 -p "$PX2_PORT" \
    --backend "127.0.0.1:$BE2_PORT" --protocol tcp --lua "$SOCKETLEY_TMPD/pxwatch.lua" -s
ready_tcp 127.0.0.1 "$PX_PORT"  8 || echo "  NOTE: dl_px never accepted a connection"
ready_tcp 127.0.0.1 "$PX2_PORT" 8 || echo "  NOTE: dl_px2 never accepted a connection"

printf 'PAYLOAD-THROUGH-SPIN\n' | timeout 20 nc -q 1 127.0.0.1 "$PX_PORT"  >/dev/null 2>&1 || true
printf 'PAYLOAD-THROUGH-WATCH\n' | timeout 20 nc -q 1 127.0.0.1 "$PX2_PORT" >/dev/null 2>&1 || true
sleep 0.8

if wait_log '\[lua dl_px\] on_proxy_request hit its 1500ms deadline and was stopped'; then pass; else
    fail "a byte hook that never returns is stopped too" \
         "no on_proxy_request stop line in $SOCKETLEY_DLOG" \
         "the deadline reaches this hook through the same guarded accessor as" \
         "every other callback; if it does not, a proxy is still freezable"
fi

if grep -q "PAYLOAD-THROUGH-SPIN" "$PX_SEEN" 2>/dev/null; then
    fail "a stopped byte hook refuses rather than forwarding unchanged" \
         "the backend received the payload anyway" \
         "a stopped hook must land in the !r.valid() refusal, NOT in the" \
         "'returned nothing, forward unchanged' case bccfbea documents —" \
         "forwarding a request whose policy hook never finished deciding is" \
         "the admission the hook was written to prevent"
else pass; fi

# Control: the fourth case still works with the deadline installed, without
# which the assertion above passes against a build where nothing reaches a
# backend through a Lua-hooked proxy.
if grep -q "PAYLOAD-THROUGH-WATCH" "$PX_SEEN2" 2>/dev/null; then pass; else
    fail "control: a hook that returns nothing still forwards unchanged" \
         "the backend behind dl_px2 saw: $(cat "$PX_SEEN2" 2>/dev/null | tr -d '\0' | head -c 80)" \
         "an observer hook ends without a return and its bytes must go through" \
         "— that is the contract bccfbea wrote down, and arming a deadline" \
         "around the call must not have disturbed it"
fi

# Exit 1 specifically, because 2 is the fatal code and would also be what a
# daemon that had stopped answering produced.
TOP_RC=0
TOP_OUT=$(timeout 30 "$BIN" create server dl_top -p "$TOP_PORT" --mode inout \
              --lua "$TOP" -s 2>&1) || TOP_RC=$?
"$BIN" remove dl_top >/dev/null 2>&1 || true

if [ "$TOP_RC" = "1" ]; then pass; else
    fail "a top level that never returns refuses the create" \
         "create exited $TOP_RC, wanted 1" \
         "create said: ${TOP_OUT:-<nothing>}" \
         "this chunk runs synchronously inside the command — without a bound" \
         "the operator's terminal blocks on a create that never answers"
fi
case "$TOP_OUT" in
    *"top level"*deadline*|*deadline*"top level"*) pass ;;
    *) fail "the refusal says the top level outran the deadline" \
            "create said: ${TOP_OUT:-<nothing>}" \
            "a refusal with no reason in it sends whoever reads it to the log" ;;
esac

# A callback_timeout_ms that cannot be a millisecond count refuses the create
# and says so on the terminal that asked, in every build.
BADCTO="$SOCKETLEY_TMPD/badcto.lua"
printf 'callback_timeout_ms = "soon"\nfunction on_message(m) end\n' > "$BADCTO"
BC_RC=0
BC_OUT=$(timeout 30 "$BIN" create server dl_bad -p "$((PORT + 11))" --mode inout \
             --lua "$BADCTO" -s 2>&1) || BC_RC=$?
"$BIN" remove dl_bad >/dev/null 2>&1 || true
if [ "$BC_RC" = "1" ]; then pass; else
    fail "a callback_timeout_ms that is not a number refuses the create" \
         "create exited $BC_RC, wanted 1" \
         "create said: ${BC_OUT:-<nothing>}"
fi
case "$BC_OUT" in
    *callback_timeout_ms*) pass ;;
    *) fail "that refusal names the global that was wrong" \
            "create said: ${BC_OUT:-<nothing>}" ;;
esac

# ── The daemon that did all of that is still the same process ───────────────
if kill -0 "$SOCKETLEY_DPID" 2>/dev/null; then pass; else
    fail "the daemon survived every one of those" "pid $SOCKETLEY_DPID is gone"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
