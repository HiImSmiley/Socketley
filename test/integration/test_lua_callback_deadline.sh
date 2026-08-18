#!/usr/bin/env bash
# Integration test: a Lua callback that never returns is stopped, and only it.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# Nothing used to bound a script's execution.  `while true do end` in any
# callback froze the single event-loop thread that serves every runtime in the
# daemon — all traffic, the metrics endpoint, the IPC socket — and the only way
# out was SIGKILL.  Measured on the parent commit, one server spinning inside
# on_message and a second server that had done nothing at all:
#
#     stats <the other runtime>      no answer, exit 2 after 5s
#     traffic to the other runtime   not served
#     the daemon                     80% of a core, until killed -9
#     the daemon's log               nothing
#
# One script, and the whole process is gone.  What replaces it is a wall-clock
# deadline per callback invocation, enforced through a LUA_MASKCOUNT hook: the
# hook fires every few thousand VM instructions, reads a clock, and raises a Lua
# error when the invocation has outrun its budget.  The callback fails the way
# any other failing callback does; the runtime keeps serving.
#
# ─── WHY THE ASSERTIONS ARE THE ONES BELOW ──────────────────────────────────
#
# "The daemon did not die" is not enough, and is the assertion this file most
# had to avoid: it passes just as well against a build that reacted by killing
# the runtime, which would be a much heavier answer than the one intended and
# would lose every connection the runtime was holding.  So there are four
# claims, and the last two are what separate this from that build:
#
#   * the daemon answers `stats` for a DIFFERENT runtime while the runaway is
#     still inside its budget — the operator is not locked out either
#   * the runaway said so, in the daemon's log, naming itself and the bound
#   * the offending runtime is still serving afterwards — send it a message and
#     it answers
#   * a callback that is merely slow, and finishes inside its budget, is not
#     touched.  A deadline that fires on working code is worse than none
#
# ─── THE KNOBS, EXERCISED RATHER THAN DESCRIBED ─────────────────────────────
#
# The daemon here runs with SOCKETLEY_LUA_TIMEOUT_MS=1500 rather than the
# built-in 10000.  Two reasons, and neither is only speed: the operator's knob
# is a claim this file has to test, and 1500ms is under the CLI's own five
# second receive timeout — so `stats` issued in the middle of the stall waits it
# out and answers, which is the thing an operator most wants back and which the
# 10000ms default deliberately does not promise.
#
# The script's own `callback_timeout_ms` is tested against the same daemon: one
# runtime declares 300, and the log has to name 300 for that one and 1500 for
# the one that declared nothing.  Counting the lines is what makes the
# no-false-positive control real — a build that stopped the merely-slow callback
# too would produce a third line and fail here rather than passing quietly.
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
#
# Every one of them echoes, so "is this runtime still serving" is a question
# with an answer on the wire rather than an inference from the absence of a
# crash.  The runaway is behind a keyword, so the runtime can be proved working
# before and after the callback that hangs.
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

# The control: a callback that takes real time and finishes.
#
# The delay is a socketley.http call at a listener that accepts the connection
# and then does nothing at all — never answers, never closes — so the block is
# socketley.http waiting out its own 400ms timeout.  WALL time, spent asleep in
# the kernel.
#
# ─── THE SINK CANNOT BE A SOCKETLEY RUNTIME, AND USED TO BE ─────────────────
#
# It was `create server dl_sink --mode in`, described here as a runtime that
# "accepts and answers nothing".  That was never true.  A --mode in server
# answers 404 to any HTTP request, immediately — probed at 109 bytes back
# inside a millisecond.  The 400ms was never poll() waiting for an answer that
# did not come; the answer came at once, and socketley.http then sat waiting
# for EOF because it ignores the response framing.  The delay was the server
# NOT closing the connection.
#
# So this control was measuring a defect.  When --http learned to honour the
# `Connection: close` that socketley.http sends, the server began closing at
# once, the EOF arrived immediately, and the 400ms evaporated: the round trip
# fell from >2.3s to 2.006s, which is nc's 2s linger with the block gone.  The
# fixture has to be a listener that really does stay silent, and nothing built
# out of this daemon can be one.
#
# This was a `while os.clock() - t < 0.4` busy loop and that is a trap worth
# recording.  os.clock() is CPU time and the deadline is wall-clock, so on a
# machine under load the loop waits for 0.4s of CPU that takes two seconds to
# arrive, blows a 1500ms budget, and the control fails against a build with
# nothing wrong with it.  Watched: green on an idle machine, red under the
# sanitizer build while three other jobs were running.  A control whose result
# depends on how busy the machine is cannot distinguish the two things it exists
# to distinguish.
#
# 400ms against the 1500ms budget also says something the busy loop could not:
# socketley.http's timeout is clamped to what is left of the callback's, and
# 400 out of 1500 must come back untouched.
cat > "$SLOW" <<LUAEOF
function on_message(msg)
    if msg == "slow" then
        socketley.http({ url = "http://127.0.0.1:$SINK_PORT/wait", timeout_ms = 400 })
    end
    self.broadcast("echo:" .. msg)
end
LUAEOF

# A top level that never returns.  This one runs synchronously inside `create`,
# which is why it gets its own assertion: the create has to be refused with a
# reason rather than blocking the operator's terminal on a command that will
# never answer.
printf 'local n = 0\nwhile true do n = n + 1 end\n' > "$TOP"

# 1500ms rather than the built-in 10000 — see the header.  Exported before the
# daemon is started, because this is the daemon's environment, not the CLI's.
export SOCKETLEY_LUA_TIMEOUT_MS=1500

daemon_start "$BIN"

create_ok "spinner created"    "$BIN" create server dl_spin -p "$SPIN_PORT" --mode inout --lua "$SPIN" --daemon-process -s
create_ok "bystander created"  "$BIN" create server dl_byst -p "$BYST_PORT" --mode inout --lua "$BYST" --daemon-process -s
create_ok "own-budget created" "$BIN" create server dl_own  -p "$OWN_PORT"  --mode inout --lua "$OWN"  --daemon-process -s
create_ok "slow one created"   "$BIN" create server dl_slow -p "$SLOW_PORT" --mode inout --lua "$SLOW" --daemon-process -s
# The sink: accepts, and from there on says and does nothing.  Not a socketley
# runtime — see the block above $SLOW for why one cannot serve here.  The
# accepted sockets are kept in a list on purpose: dropping the last reference
# lets the garbage collector close them, and a close is an EOF, which is the
# one thing this must never send.
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
# Issued while the callback is still inside its budget, so this command really
# does have to wait behind the stall — and the elapsed time below is what proves
# it waited rather than being answered by a daemon that was never blocked.  On
# the parent commit this is the exit 2 the header records.
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

# The stall was real.  Without this, a build that never ran the callback at all
# — a broken dispatch, a script that failed to load — passes the assertion above
# instantly and is reported as the fix working.
if [ "$(echo "$ELAPSED > 0.3" | bc)" = "1" ]; then pass; else
    fail "that stats call really did wait behind the stalled callback" \
         "it came back in ${ELAPSED}s, which is too fast for a callback to have" \
         "been holding the event loop — so nothing was being bounded here"
fi

wait "$SPIN_CLIENT" 2>/dev/null || true

# ── 2. The runaway reported itself ──────────────────────────────────────────
#
# Read out of the daemon's log and not out of the CLI, because a callback error
# happens on traffic with no command in flight to carry it anywhere.
#
# This is the hook's own line, written before it raises, and that is deliberate:
# `sol::function` is sol2's unsafe function in Release and its protected one in
# any build without NDEBUG, so the raise is caught and printed in Release and
# comes back as an unread result value — silently — under Sanitize.  Asserting
# the "[lua] on_message error: ..." line instead would make this file pass in
# Release and fail in the sanitizer build for a mechanism that worked in both.
wait_log() {
    local pattern=$1 timeout=${2:-12}
    local deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        grep -qE "$pattern" "$SOCKETLEY_DLOG" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}

# The runtime's name is part of the claim now.  The hook's line used to say
# "[lua] on_message ...", which does not tell an operator with forty servers
# which one stopped — and a deadline is exactly the diagnostic somebody reads
# in a hurry.
if wait_log '\[lua dl_spin\] on_message hit its 1500ms deadline and was stopped'; then pass; else
    fail "the callback that outran its budget said so, naming the runtime" \
         "no '[lua dl_spin] on_message hit its 1500ms deadline and was stopped' in" \
         "$SOCKETLEY_DLOG" \
         "a bound nobody is told about is a support ticket"
fi

# ...and it arrived at the call site as a failure, not only at the hook.
#
# Two different claims, and the second is the one that has to be re-checked
# every time the invocation sites move.  07baee7..b868bb5 replaced every
# `catch (const sol::error&)` in this tree with a protected call whose
# `!valid()` branch reports — a deadline is raised as an ordinary Lua error, so
# it has to travel that same route and be diagnosed there, with the script and
# line attached, which the hook's own line cannot know.  If this goes red while
# the one above stays green, the deadline is being reported by the mechanism
# that raises it and by nothing that observes it, which is the arrangement the
# sweep exists to have ended.
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

# ── 4. The script's own budget is the one used ──────────────────────────────
#
# dl_own declares callback_timeout_ms = 300 at its top level.  Asserted by the
# number in the message rather than by timing the stall, so it says which budget
# was applied and not merely that something eventually stopped.
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

# ── 5. Control: a slow callback that finishes is not touched ────────────────
#
# 400ms of blocking socketley.http inside a 1500ms budget.  A deadline that
# fires on this is worse than no deadline, because it breaks code that works —
# and this particular shape is the documented use of the one blocking primitive
# this tree ships.
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

# ...and it really did block, rather than the http call failing instantly and
# leaving nothing for the deadline to have fired on.  `say` lingers 2s after
# EOF, so the floor is that plus the block.
if [ "$(echo "$SLOW_ELAPSED > 2.3" | bc)" = "1" ]; then pass; else
    fail "the slow callback really did hold the loop for its 400ms" \
         "the round trip took ${SLOW_ELAPSED}s, and 2s of that is nc's linger" \
         "if socketley.http came back at once there was no slow callback here" \
         "and the control above proved nothing"
fi

# ...and exactly two on_message callbacks were stopped in this whole run:
# dl_spin at 1500 and dl_own at 300.  A count, not a presence check: a build
# that also stopped the slow one would satisfy every assertion above and fail
# only here.
STOPS=$(grep -c "on_message hit its .*ms deadline and was stopped" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "${STOPS:-0}" = "2" ]; then pass; else
    fail "exactly the two runaway on_message callbacks were stopped" \
         "the log has ${STOPS:-0} on_message stop lines, wanted 2" \
         "$(grep 'deadline and was stopped' "$SOCKETLEY_DLOG" 2>/dev/null || true)"
fi

# ── 5b. The proxy byte hooks, whose contract has four cases ─────────────────
#
# on_proxy_request tells four outcomes apart, and 6710699/dcf2791 settled the
# newest of them: an error refuses the request and closes, an explicit nil
# drops, a string replaces, and RETURNING NOTHING AT ALL forwards the bytes
# unchanged — because a hook that only watches traffic ends without a return
# and used to have that read as "drop".
#
# A deadline landing in that function has to be the first of those and not the
# fourth.  Both are, in a sense, "the hook did not produce a value": the
# difference is that one of them is a hook that finished with no opinion and the
# other is a hook that never finished at all, and forwarding the bytes of a
# request whose policy hook was stopped mid-decision would admit exactly what
# the hook exists to be able to refuse.  It comes back as `!r.valid()`, which
# is the refusal branch — asserted here rather than reasoned about, because the
# two cases are one enum value apart in code that was rewritten under me.
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
    --backend "127.0.0.1:$BE_PORT" --protocol tcp --lua "$SOCKETLEY_TMPD/pxspin.lua" --daemon-process -s
create_ok "watching proxy hook created" "$BIN" create proxy dl_px2 -p "$PX2_PORT" \
    --backend "127.0.0.1:$BE2_PORT" --protocol tcp --lua "$SOCKETLEY_TMPD/pxwatch.lua" --daemon-process -s
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
         "'returned nothing, forward unchanged' case dcf2791 documents —" \
         "forwarding a request whose policy hook never finished deciding is" \
         "the admission the hook was written to prevent"
else pass; fi

# Control: the fourth case still works with the deadline installed.  Without
# this, the assertion above passes against a build where NOTHING reaches a
# backend through a Lua-hooked proxy.
if grep -q "PAYLOAD-THROUGH-WATCH" "$PX_SEEN2" 2>/dev/null; then pass; else
    fail "control: a hook that returns nothing still forwards unchanged" \
         "the backend behind dl_px2 saw: $(cat "$PX_SEEN2" 2>/dev/null | tr -d '\0' | head -c 80)" \
         "an observer hook ends without a return and its bytes must go through" \
         "— that is the contract dcf2791 wrote down, and arming a deadline" \
         "around the call must not have disturbed it"
fi

# ── 6. A top level that never returns refuses the create ────────────────────
#
# It runs inside the `create` command, so its failure has to come back as a
# refusal with a reason.  Exit 1 specifically: 2 is the fatal code and would
# also be what a daemon that had stopped answering produced.
TOP_RC=0
TOP_OUT=$(timeout 30 "$BIN" create server dl_top -p "$TOP_PORT" --mode inout \
              --lua "$TOP" --daemon-process -s 2>&1) || TOP_RC=$?
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

# ── 7. A callback_timeout_ms that is not a number ───────────────────────────
#
# The global is read out of a table the script controls, and 091e6d9 is the
# commit that made every such read in this tree the checked form after an
# unchecked one took the daemon down with std::terminate.  This one is checked,
# and the assertion is on the behaviour rather than the spelling: a value that
# cannot be a millisecond count refuses the create and says so, on the terminal
# that asked, in every build.
BADCTO="$SOCKETLEY_TMPD/badcto.lua"
printf 'callback_timeout_ms = "soon"\nfunction on_message(m) end\n' > "$BADCTO"
BC_RC=0
BC_OUT=$(timeout 30 "$BIN" create server dl_bad -p "$((PORT + 11))" --mode inout \
             --lua "$BADCTO" --daemon-process -s 2>&1) || BC_RC=$?
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
