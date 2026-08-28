#!/usr/bin/env bash
# Integration test: how a worker's refusal reaches the operator.
#
# ─── THIS FILE HAS NOW EXPIRED THREE TIMES, AND THE THIRD ONE ENDED IT ──────
#
# It was written on the premise that a runtime in its own process cannot serve
# every call the API offers, and that each such call must be refused BY NAME
# rather than answered with the false, nil or empty table a successful call
# also returns.  The premise about refusals was right.  The premise about which
# calls need one has been wrong three times:
#
#   .list   the worker was handed the runtime map, so list() answers out there.
#           Five assertions went red that were never about listing.
#   .stop   the four map calls travel to the daemon now.  Six went red, and
#           this header had called them "permanently refused".
#   .pipe   the last one, and the one this header called "about the mechanism
#           rather than about the transport" -- correctly, and then predicted
#           the wrong mechanism.  It said the call was waiting on SCM_RIGHTS.
#           It was not: across two runtimes socketley.pipe is route_client(),
#           which keeps the socket where it is and relays.  What it wanted was
#           a way to name another runtime's connection, which is
#           shared/route_relay.h.  Watched, not assumed -- 11/18 before this
#           rewrite, and self.route went red with it.
#
# There is no fourth call to re-point at.  Every refusal this file was written
# about is now installed only when the worker was forked WITHOUT the control
# plane at fd 6 -- an older daemon, or one that could not make the socketpair --
# which no test in this tree can produce.
#
# ─── SO WHAT IS LEFT, AND WHY IT IS THE HALF WORTH KEEPING ──────────────────
#
# The durable half was never the list of calls.  It is the DELIVERY: where a
# refusal lands, who is told, and what the command that asked for it exits
# with.  That machinery is unchanged and is still the only cover for it:
#
#   * a script that raises at its top level is refused by `create`, which
#     waits for the worker's verdict rather than reporting success and
#     correcting itself in the log a moment later;
#   * the runtime is left `failed` and does not serve;
#   * and it is not restarted in a loop, because a refused configuration is
#     not a crash.
#
# Those four assertions kept their shape and changed their trigger, from a
# refused API call to a plain error() -- which raises for a reason that cannot
# expire.
#
# What replaced the rest is the inverse claim, kept here rather than moved
# because this is the file that would notice: the calls listed above are
# answered in a worker now, and no refusal for any of them appears in the log
# at all.  A build that reinstalls one goes red here.
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

echo "=== Integration: how a worker's refusal reaches the operator ==="

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
            -- Two names nothing in this file ever creates.  It answers false
            -- plus a reason on BOTH sides now and changes nothing on either.
            -- The reason is carried into the body because the assertions below
            -- check it: a bare `false` is also what a build with a broken
            -- pipe() returns, and the sentence is what tells them apart.
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
-- A plain raise, and deliberately not an API call.  Every call this file used
-- to raise with has since been served, taking these assertions red with it
-- three times; error() cannot stop being an error.  It also raises on the
-- FIRST line, so nothing is half-built when it does -- which is what makes
-- "the runtime does not serve" a statement about the refusal rather than about
-- whatever the script managed to set up before it died.
error("toplevel: a deliberate raise, so only the worker can know")
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

# ── Assertion 1: the call is ANSWERED in the worker ────────────────────────
#
# The inverse of what stood here.  A 500 is what a refusal produces -- the
# filter chain reports the error and refuses the request -- so a 500 now means
# a build that has put the refusal back.
MGMT_OOP_CODE=$(code cb_oop "$CB_OOP_PORT" /mgmt)
MGMT_OOP_BODY=$(body cb_oop "$CB_OOP_PORT" /mgmt)
if [ "$MGMT_OOP_CODE" = "200" ]; then pass; else
    fail "a management call in a worker is answered, not refused" \
         "/mgmt on the out-of-process proxy answered $MGMT_OOP_CODE '$MGMT_OOP_BODY'," \
         "wanted 200 — a 500 is the refusal being reinstalled, and the call" \
         "has a channel now: see shared/route_relay.h"
fi

# ── Assertion 2: and it answers the SAME THING on both sides ───────────────
#
# Not merely "answered".  A script must not be able to tell which side of the
# boundary it is running on from the text it gets back, and the refusal wording
# is served by two different code paths -- the in-daemon one from route_client
# and the worker one from the daemon, over the map socket -- so this is the one
# assertion that would catch them drifting apart.
if [ "$MGMT_OOP_BODY" = "$MGMT_IN" ]; then pass; else
    fail "the worker and the daemon answer the same call the same way" \
         "worker: '$MGMT_OOP_BODY'" \
         "daemon: '$MGMT_IN'" \
         "the two paths that produce this sentence are different code, and this" \
         "is what stops them saying different things"
fi

# ── Assertion 2b: no refusal for these calls in the log at all ─────────────
#
# The negative oracle, and it is not redundant with the two above: a build
# could answer /mgmt correctly while still refusing self.route, or refuse in a
# path this file never exercises.  Nothing in this suite should now produce
# this sentence.
if ! grep -q 'refused in a worker process' "$SOCKETLEY_DLOG" 2>/dev/null; then
    pass
else
    fail "no call is refused in a worker for being out of process" \
         "the daemon log carries a refusal that should no longer exist:" \
         "$(grep -a -m1 -o 'refused in a worker process[^"]*' "$SOCKETLEY_DLOG" | cut -c1-160)"
fi

# ── Assertion 3: a script that raises at load fails the runtime ────────────
#
# The in-daemon arm that used to stand here is gone, and its removal is the
# point rather than a tidy-up.  It was a CONTROL: the same script loaded in the
# daemon and was refused in a worker, so the failure could be attributed to the
# boundary.  With the trigger changed from a refused API call to error(), there
# is no boundary left in it -- the script raises on both sides, so an in-daemon
# arm would assert that a raise is a raise.
#
# What still needs a control is "the worker loads scripts at all", and cb_oop
# above is it: same process kind, same load path, a script that works.
#
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
         "the script raises on its first line, so the worker refuses the" \
         "configuration — and create is what has to say so, because by the" \
         "time the log says it the operator has been told 0" \
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

if [ "$TOP_OOP_STATE" = "failed" ]; then pass; else
    fail "a worker whose script will not load does not serve" \
         "top_oop is '$TOP_OOP_STATE', wanted 'failed'" \
         "the script raises before it defines anything, so it did not load — and" \
         "a proxy relaying with none of the filters, routes or callbacks the" \
         "operator wrote is not the proxy they configured"
fi

# ── Control 3: a worker DOES load a script that works ──────────────────────
#
# Replaces the in-daemon arm described above.  Without it, "top_oop is failed"
# also passes on a build where no worker ever loads a script, which would make
# every assertion in this section true for the wrong reason.
if [ "$(body cb_oop "$CB_OOP_PORT" /ok)" = "alive" ]; then pass; else
    fail "control: a worker loads a script that does not raise" \
         "cb_oop's /ok did not answer 'alive'" \
         "if no worker can load any script, top_oop being failed says nothing" \
         "about this one"
fi

# ── Assertion 4: it is not restarted in a loop ──────────────────────────────
#
# A refused configuration is not a crash: forking it again produces the same
# refusal.  The supervisor is told so by the exit status, and one refusal in the
# log is the evidence that it listened -- five would be the evidence that it did
# not.
# Counted on the raise text, which the worker prints once per attempt to load.
# The previous oracle grepped 'refusing to serve without it', which belonged to
# the configuration-refusal path the old trigger took; error() takes the
# script-load path and prints its own message.  Changing the oracle with the
# trigger is not weakening it -- what is being counted is still "how many times
# did the supervisor fork this child", and one is still the only right answer.
REFUSALS=$(grep -c 'toplevel: a deliberate raise' "$SOCKETLEY_DLOG" 2>/dev/null) || REFUSALS=0
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

ROUTED=$(grep -c 'RT_TARGET_GOT_ONE' "$SOCKETLEY_DLOG" 2>/dev/null) || ROUTED=0
if [ "$ROUTED" -ge 2 ]; then pass; else
    fail "self.route() in a worker reaches the target" \
         "the target reported $ROUTED routed connection(s), wanted 2" \
         "one for the in-daemon arm and one for the worker arm; 1 means the" \
         "boundary is still not crossed and only the control routed:" \
         "$(grep -a -o 'ROUTE ok=[a-z]* res=[^ ]*' "$SOCKETLEY_DLOG" 2>/dev/null | tail -2 | tr '\n' '|')"
fi

# ── Assertion 5b: and it answers true, not merely "did not raise" ──────────
#
# pcall's first value is true for a call that merely RETURNED false, so ok=true
# alone says only that nothing was thrown -- which is what the refusal this
# file used to assert would not produce, and is not what a working route looks
# like either.  res is self.route's own return value.
if [ "$(grep -a -c 'ROUTE ok=true res=true' "$SOCKETLEY_DLOG" 2>/dev/null)" -ge 2 ]; then
    pass
else
    fail "self.route() answers true on both sides" \
         "wanted two 'ROUTE ok=true res=true' lines, got:" \
         "$(grep -a -o 'ROUTE ok=[a-z]* res=[^ ]*' "$SOCKETLEY_DLOG" 2>/dev/null | tr '\n' '|')"
fi

# ── Control 4: the in-daemon arm routed at all ─────────────────────────────
#
# Kept, and it is now the floor under a count rather than a separate claim: if
# neither arm routed, "wanted 2" is unreachable for a reason that has nothing
# to do with the boundary, and this is what says which.
if [ "$ROUTED" -ge 1 ]; then pass; else
    fail "control: self.route() works in the daemon at all" \
         "neither arm reported a routed connection" \
         "the assertion above is then about routing being broken outright," \
         "not about the process boundary, and proves nothing"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
