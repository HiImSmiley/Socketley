#!/usr/bin/env bash
# Integration test: a worker refuses, by name, the calls it cannot serve.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# A runtime created without --daemon-process runs in its own process, and that
# process cannot serve every call the API offers.  Each refusal used to
# be a false, a nil or an empty table — which is precisely what a *successful*
# call returns on a daemon with nothing in it.  A script could not tell "there
# is nothing there" from "I cannot see anything from here", so it carried on
# against nothing, and neither the script nor the operator was told.
#
# They are refused instead, by name, with the reason and the way out, and the
# refusal is a Lua error rather than a return value: `if socketley.create(...)`
# is how these are written and a false is what that already handles.
#
# ─── WHY THIS FILE PROBES socketley.pipe, AND WHAT IT PROBED BEFORE ─────────
#
# It has now been re-pointed twice, and the reason is the same both times: it
# was written on a call that later stopped being refused.
#
#   .list   the worker was handed the runtime map, so list() answers out
#           there.  Five assertions went red that were never about listing.
#   .stop   the four map calls travel to the daemon now.  Six went red, and
#           this file's own header had called them "permanently refused".
#           Watched, not assumed — 12/18 before the re-point.
#
# That header was wrong on its own terms, and the correction is worth keeping
# rather than quietly replacing: it argued that being handed a COPY of the map
# is not permission to alter it, which is true and is not the question.  The
# calls do not alter the copy; they ask the process that holds the original.
#
# So the split is not "reads come back, writes never do".  It is:
#
#   needs the map        .list, .get, .send, .create, .start, .stop, .remove
#                        and socketley.cluster.*.  All of these are answered
#                        in a worker now — the first three from the replica,
#                        the four map calls over the control plane at
#                        child_map_fd.  A file written on one of these has an
#                        expiry date, and this one has expired twice.
#   needs a CONNECTION   .pipe and self.route().  A connection does not travel
#                        in a snapshot of anything: the descriptor has to be
#                        passed with SCM_RIGHTS or its bytes relayed under a
#                        reference.  shared/conn_transfer.h has both and
#                        nothing is wired to it.
#
# The probe is from the second group, which is the only one whose refusal is
# about the mechanism rather than about the transport.  It will expire too, on
# the day conn_transfer is wired up, and that is the honest position for a file
# like this to be in — what it must not do is claim a refusal is permanent.
#
# socketley.pipe on two names nothing in this file ever creates, specifically:
# the CONTROL arm of every assertion here really executes the call in the
# daemon, so the probe has to be one that changes nothing when it succeeds.
# pipe() on absent names answers `false` plus "there is no runtime called ..."
# in the daemon, raises in a worker, and touches nothing on either side.
#
# ─── THE TWO PLACES A REFUSAL LANDS ─────────────────────────────────────────
#
#   * In a callback.  The chain that ran it reports the error and refuses the
#     request — a filter that raised has not said "carry on" — so the client
#     gets a 500 and the log gets the message.
#   * At the script's top level.  The script does not load, and a worker whose
#     script did not load does not serve: it exits, saying it is a configuration
#     it will never accept, and the supervisor leaves the runtime `failed`
#     instead of forking five more copies of the same refusal.  Before, the
#     proxy came up and relayed with none of the filters, routes or callbacks
#     the operator wrote, behind one WARN.
#
# ─── THE CONTROLS ───────────────────────────────────────────────────────────
#
# Three, and they are what stop this from being a file that passes against a
# build where Lua does not work at all:
#
#   * The same script on an in-process proxy must ANSWER the management call.
#     The refusal has to be about the boundary, not about the call.
#   * The same script on an in-process proxy must stay `running`.  Without it,
#     "the out-of-process one is failed" also passes on a build that fails
#     every proxy with a script.
#   * The worker's own script must be alive and serving: a route that touches
#     nothing cross-runtime must answer normally from inside the worker.  A
#     build that refused the entire Lua API, or that never loaded the script,
#     would satisfy every other assertion here.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate workerrefusal

BE_PORT=$((SL_PORT_BASE+450))
CB_IN_PORT=$((SL_PORT_BASE+451))
CB_OOP_PORT=$((SL_PORT_BASE+452))
TOP_IN_PORT=$((SL_PORT_BASE+453))
TOP_OOP_PORT=$((SL_PORT_BASE+454))
RT_TARGET_PORT=$((SL_PORT_BASE+455))
RT_IN_PORT=$((SL_PORT_BASE+456))
RT_OOP_PORT=$((SL_PORT_BASE+457))

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop  cb_oop cb_in top_oop top_in backend rt_target rt_in rt_oop 2>/dev/null || true
    sleep 0.3
    "$BIN" remove cb_oop cb_in top_oop top_in backend rt_target rt_in rt_oop 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a worker refuses what it cannot serve, by name ==="

daemon_start "$BIN"

# ── The callback script ─────────────────────────────────────────────────────
#
# /mgmt makes a management call that a worker cannot serve; /ok touches nothing
# cross-runtime and is the proof that this interpreter is loaded and serving.
CB_LUA="$SOCKETLEY_TMPD/cb.lua"
cat > "$CB_LUA" <<'LUAEOF'
filters = {
    function(req)
        if string.find(req.path, "/mgmt", 1, true) then
            -- Two names nothing in this file ever creates.  In the daemon this
            -- answers false plus a reason and changes nothing; in a worker it
            -- raises.  The reason is carried into the body because the control
            -- below checks for it: a bare `false` is also what a build with a
            -- broken pipe() returns, and the sentence is what tells them apart.
            local ok, why = socketley.pipe("mgmt_no_such_src", 1, "mgmt_no_such_dst")
            return { status = 200,
                     body = "pipe=" .. tostring(ok) .. " why=" .. tostring(why) .. "\n" }
        end
        if string.find(req.path, "/ok", 1, true) then
            return { status = 200, body = "alive\n" }
        end
    end,
}
LUAEOF

# ── The top-level script ────────────────────────────────────────────────────
TOP_LUA="$SOCKETLEY_TMPD/top.lua"
cat > "$TOP_LUA" <<'LUAEOF'
local ok, why = socketley.pipe("top_no_such_src", 1, "top_no_such_dst")
socketley.log("TOPLEVEL-SAW " .. tostring(ok) .. " " .. tostring(why))
filters = {
    function(req)
        if string.find(req.path, "/ok", 1, true) then
            return { status = 200, body = "alive\n" }
        end
    end,
}
LUAEOF

# body NAME PORT PATH -> the response body, or the empty string.
body() {
    curl -s --max-time 3 "http://127.0.0.1:$2/$1$3" 2>/dev/null || printf ''
}
# code NAME PORT PATH -> the HTTP status, or 000.
code() {
    curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
         "http://127.0.0.1:$2/$1$3" 2>/dev/null || printf '000'
}
# state NAME -> the daemon's word for it, lowercased, or the empty string.
#
# `ls` and not `ps`: ps lists only what is running, which is the one state this
# file is asserting a runtime is NOT in.  Asked of ps, a failed runtime and a
# runtime that never existed are the same empty output.
state() {
    "$BIN" ls 2>/dev/null | awk -v n="$1" '$2 == n { print tolower($7) }' | head -1
}

create_ok "backend created" "$BIN" create server backend -p "$BE_PORT" -s
create_ok "in-process callback proxy created" "$BIN" create proxy cb_in \
    -p "$CB_IN_PORT" --backend "127.0.0.1:$BE_PORT" --protocol http --lua "$CB_LUA" \
    --daemon-process -s
create_ok "out-of-process callback proxy created" "$BIN" create proxy cb_oop \
    -p "$CB_OOP_PORT" --backend "127.0.0.1:$BE_PORT" --protocol http --lua "$CB_LUA" \
    -s

for _ in $(seq 1 60); do
    [ "$(body cb_oop "$CB_OOP_PORT" /ok)" = "alive" ] && break
    sleep 0.1
done

# ── Control 1: the worker's script is loaded and serving ────────────────────
OK_OOP=$(body cb_oop "$CB_OOP_PORT" /ok)
if [ "$OK_OOP" = "alive" ]; then pass; else
    fail "control: the worker's script is running" \
         "/ok answered '$OK_OOP', wanted 'alive'" \
         "the filter chain is not running inside the worker, so every refusal" \
         "asserted below would also hold for a proxy with no script at all"
fi

# ── Control 2: the same call answers in process ─────────────────────────────
MGMT_IN=$(body cb_in "$CB_IN_PORT" /mgmt)
# Both halves, and the second is what makes this a control rather than a
# formality.  `pipe=false` alone is also what a build whose pipe() is broken
# returns; the reason naming the runtime is the evidence that the call ran, went
# looking and answered about what it found.
case "$MGMT_IN" in
    *"pipe=false"*"there is no runtime called"*) pass ;;
    *)
        fail "control: socketley.pipe answers in the daemon" \
             "/mgmt on the in-process proxy answered '$MGMT_IN'," \
             "wanted 'pipe=false why=there is no runtime called ...'" \
             "the refusal below cannot be attributed to the process boundary if" \
             "the call does not work on either side of it" ;;
esac

# ── Assertion 1: the call is refused in the worker ──────────────────────────
MGMT_OOP_CODE=$(code cb_oop "$CB_OOP_PORT" /mgmt)
MGMT_OOP_BODY=$(body cb_oop "$CB_OOP_PORT" /mgmt)
if [ "$MGMT_OOP_CODE" = "500" ]; then pass; else
    fail "a management call in a worker is refused, not answered" \
         "/mgmt on the out-of-process proxy answered $MGMT_OOP_CODE '$MGMT_OOP_BODY'," \
         "wanted 500 — a 200 means socketley.pipe() answered in a worker, and" \
         "there is no channel out there for it to have moved a connection over:" \
         "the answer would be about descriptors this process alone can see"
fi

# ── Assertion 2: and the refusal says what and why ──────────────────────────
if grep -q 'socketley\.pipe() is refused in a worker process' \
        "$SOCKETLEY_DLOG" 2>/dev/null; then
    pass
else
    fail "the refusal names the call and the reason" \
         "no such line in the daemon log" \
         "wanted: socketley.pipe() is refused in a worker process: ..." \
         "last lines: $(tail -3 "$SOCKETLEY_DLOG" 2>/dev/null | tr '\n' '|')"
fi
if grep -q 'refused in a worker process.*--daemon-process' \
        "$SOCKETLEY_DLOG" 2>/dev/null; then
    pass
else
    fail "the refusal names the way out" \
         "the message does not mention --daemon-process, so an operator" \
         "reading it is not told how to get the call back"
fi

# ── Assertion 3: a top-level refusal fails the runtime ──────────────────────
create_ok "in-process top-level proxy created" "$BIN" create proxy top_in \
    -p "$TOP_IN_PORT" --backend "127.0.0.1:$BE_PORT" --protocol http --lua "$TOP_LUA" \
    --daemon-process -s
# Deliberately not create_ok.  This create is expected to be refused, and that
# is now an assertion in its own right: `create` waits for the worker's verdict
# before answering, so a script the worker will not load is refused by the
# command that asked for it instead of being reported as success and corrected
# in the log a moment later.  It used to exit 0 here, which is the defect that
# wait exists to close.
#
# Exit 1 specifically, not merely non-zero: "unknown flag" and "unknown runtime"
# are refusals too, and 2 is the timeout — an oracle that accepted any failure
# would pass against a build that simply never answered.
TOP_OOP_RC=0
TOP_OOP_OUT=$("$BIN" create proxy top_oop \
    -p "$TOP_OOP_PORT" --backend "127.0.0.1:$BE_PORT" --protocol http --lua "$TOP_LUA" \
    -s 2>&1) || TOP_OOP_RC=$?
if [ "$TOP_OOP_RC" = "1" ]; then pass; else
    fail "create refuses a script the worker will not load" \
         "create exited $TOP_OOP_RC, wanted 1" \
         "the script's top-level socketley.pipe() cannot work in a worker, so the" \
         "worker refuses the configuration — and create is what has to say so," \
         "because by the time the log says it the operator has been told 0" \
         "create said: ${TOP_OOP_OUT:-<nothing>}"
fi

# Already true by the time create returned, since create waited for it.  The
# poll is kept because it costs nothing when the answer is already there and
# still covers the runtime being failed by the health tick instead.
for _ in $(seq 1 100); do
    [ "$(state top_oop)" = "failed" ] && break
    sleep 0.2
done

TOP_OOP_STATE=$(state top_oop)
TOP_IN_STATE=$(state top_in)

if [ "$TOP_OOP_STATE" = "failed" ]; then pass; else
    fail "a worker whose script will not load does not serve" \
         "top_oop is '$TOP_OOP_STATE', wanted 'failed'" \
         "the script's top-level socketley.pipe() cannot work in a worker, so the" \
         "script did not load — and a proxy relaying with none of the filters," \
         "routes or callbacks the operator wrote is not the proxy they configured"
fi

# ── Control 3: the same script is fine in the daemon ────────────────────────
if [ "$TOP_IN_STATE" = "up" ] || [ "$TOP_IN_STATE" = "running" ]; then pass; else
    fail "control: the same script runs in process" \
         "top_in is '$TOP_IN_STATE', wanted to still be up" \
         "if this is failed too, the assertion above is about scripts, not about" \
         "the boundary, and proves nothing"
fi

# ── Assertion 4: it is not restarted in a loop ──────────────────────────────
#
# A refused configuration is not a crash: forking it again produces the same
# refusal.  The supervisor is told so by the exit status, and one refusal in the
# log is the evidence that it listened -- five would be the evidence that it did
# not.
REFUSALS=$(grep -c 'refusing to serve without it' "$SOCKETLEY_DLOG" 2>/dev/null) || REFUSALS=0
if [ "$REFUSALS" -eq 1 ]; then pass; else
    fail "a refused configuration is not retried" \
         "the worker refused $REFUSALS times, wanted exactly 1" \
         "restarting a child that cannot accept its configuration produces one" \
         "more copy of the same refusal per attempt, up to the burst limit"
fi

# ── Assertion 5: self.route() is refused too, and says so ───────────────────
#
# It reaches for the same runtime map as the calls above and is refused for the
# same reason; it is only spelled self. rather than socketley., which is the
# whole reason it was missed.  It answered a bare false — which is also what it
# answers for a target that does not exist — so a script could not tell a
# runtime that is absent from one that is merely in another process.
#
# A server rather than a proxy, because self.route() is a server's call.
ROUTE_LUA="$SOCKETLEY_TMPD/route.lua"
# "route" and not something shorter: a client message under three bytes is not
# delivered to on_client_message at all on this build — protocol detection wants
# that many before it will decide — so a two-letter word would make this file
# fail for a reason that has nothing to do with what it is asserting.
cat > "$ROUTE_LUA" <<'LUAEOF'
function on_connect(client_id) self.send(client_id, "ready") end
function on_client_message(client_id, msg)
    if msg == "route" then
        local ok, err = pcall(function() return self.route(client_id, "rt_target") end)
        socketley.log("ROUTE ok=" .. tostring(ok) .. " res=" .. tostring(err))
    end
end
LUAEOF
TARGET_LUA="$SOCKETLEY_TMPD/target.lua"
cat > "$TARGET_LUA" <<'LUAEOF'
function on_connect(client_id) socketley.log("RT_TARGET_GOT_ONE") end
LUAEOF

create_ok "route target created" "$BIN" create server rt_target -p "$RT_TARGET_PORT" \
          --lua "$TARGET_LUA" --daemon-process -s
create_ok "routing server in the daemon created" "$BIN" create server rt_in -p "$RT_IN_PORT" \
          --lua "$ROUTE_LUA" --daemon-process -s
create_ok "routing server in a worker created" "$BIN" create server rt_oop -p "$RT_OOP_PORT" \
          --lua "$ROUTE_LUA" -s

# poke PORT — open a connection, read the greeting so the server has finished
# with it, ask to be routed, and hold the connection open long enough for the
# route to be acted on.
poke() { python3 -c "
import socket,time,sys
s=socket.create_connection(('127.0.0.1',int(sys.argv[1])));s.settimeout(2)
try: s.recv(4096)
except Exception: pass
s.sendall(b'route\n');time.sleep(1.0);s.close()" "$1" 2>/dev/null || true; }

poke "$RT_IN_PORT"      # the control: in the daemon, this must actually route
poke "$RT_OOP_PORT"      # the worker: this must be refused by name
sleep 0.8

if grep -q 'self\.route() is refused in a worker process' "$SOCKETLEY_DLOG" 2>/dev/null
then pass; else
    fail "self.route() is refused in a worker, by name" \
         "the log carries no such refusal" \
         "a bare false here is indistinguishable from 'no such target', which is" \
         "the accepted-but-not-applied shape this whole file is about:" \
         "$(grep -a -o 'ROUTE ok=[a-z]* res=[^ ]*' "$SOCKETLEY_DLOG" 2>/dev/null | tail -1)"
fi

# ── Control 4: the same call, in the daemon, still routes ───────────────────
#
# Without this, "the worker refused" also passes on a build where self.route()
# refuses everywhere — which would be a broken feature, not a boundary.
if grep -q 'RT_TARGET_GOT_ONE' "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "control: the same self.route() works in the daemon" \
         "the target never reported a routed connection" \
         "if this fails the assertion above is about routing being broken," \
         "not about the process boundary, and proves nothing"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
