#!/usr/bin/env bash
# Integration test: a worker refuses the management API it cannot serve, by name.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# A proxy created with runs in its own process.  That process
# holds one runtime and no map of runtimes, so socketley.create, .start, .stop,
# .remove, .send, .list, .get, .pipe and the whole socketley.cluster table have
# nothing to act on.  They used to return a false, a nil or an empty table —
# which is precisely what a *successful* call returns on a daemon with nothing
# in it.  A script could not tell "there is nothing there" from "I cannot see
# anything from here", so it carried on against nothing, and neither the script
# nor the operator was told.
#
# They are refused now, by name, with the reason and the way out, and the
# refusal is a Lua error rather than a return value: `if socketley.create(...)`
# is how these are written and a false is what that already handles.
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

daemon_isolate workerrefusal

BE_PORT=19450
CB_IN_PORT=19451
CB_OOP_PORT=19452
TOP_IN_PORT=19453
TOP_OOP_PORT=19454

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop  cb_oop cb_in top_oop top_in backend 2>/dev/null || true
    sleep 0.3
    "$BIN" remove cb_oop cb_in top_oop top_in backend 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a worker refuses the management API by name ==="

daemon_start "$BIN"

# ── The callback script ─────────────────────────────────────────────────────
#
# /mgmt reaches for the runtime map; /ok touches nothing cross-runtime and is
# the proof that this interpreter is loaded and serving.
CB_LUA="$SOCKETLEY_TMPD/cb.lua"
cat > "$CB_LUA" <<'LUAEOF'
filters = {
    function(req)
        if string.find(req.path, "/mgmt", 1, true) then
            local l = socketley.list()
            return { status = 200, body = "list=" .. tostring(#l) .. "\n" }
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
local peers = socketley.list()
socketley.log("TOPLEVEL-SAW " .. tostring(#peers))
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
if [ "${MGMT_IN#list=}" != "$MGMT_IN" ] && [ "${MGMT_IN#list=0}" = "$MGMT_IN" ]; then
    pass
else
    fail "control: socketley.list answers in the daemon" \
         "/mgmt on the in-process proxy answered '$MGMT_IN', wanted 'list=<n>' with n > 0" \
         "the refusal below cannot be attributed to the process boundary if the" \
         "call does not work on either side of it"
fi

# ── Assertion 1: the call is refused in the worker ──────────────────────────
MGMT_OOP_CODE=$(code cb_oop "$CB_OOP_PORT" /mgmt)
MGMT_OOP_BODY=$(body cb_oop "$CB_OOP_PORT" /mgmt)
if [ "$MGMT_OOP_CODE" = "500" ]; then pass; else
    fail "a management call in a worker is refused, not answered" \
         "/mgmt on the out-of-process proxy answered $MGMT_OOP_CODE '$MGMT_OOP_BODY'," \
         "wanted 500 — a 200 means socketley.list() returned an empty table, which" \
         "is the same thing it returns on a daemon with nothing in it"
fi

# ── Assertion 2: and the refusal says what and why ──────────────────────────
if grep -q 'socketley\.list() is refused in a worker process' \
        "$SOCKETLEY_DLOG" 2>/dev/null; then
    pass
else
    fail "the refusal names the call and the reason" \
         "no such line in the daemon log" \
         "wanted: socketley.list() is refused in a worker process: ..." \
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
create_ok "out-of-process top-level proxy created" "$BIN" create proxy top_oop \
    -p "$TOP_OOP_PORT" --backend "127.0.0.1:$BE_PORT" --protocol http --lua "$TOP_LUA" \
    -s

# The supervisor reaps the child on the health timer, so this takes a few
# seconds; poll for the verdict rather than sleeping a guess at it.
for _ in $(seq 1 100); do
    [ "$(state top_oop)" = "failed" ] && break
    sleep 0.2
done

TOP_OOP_STATE=$(state top_oop)
TOP_IN_STATE=$(state top_in)

if [ "$TOP_OOP_STATE" = "failed" ]; then pass; else
    fail "a worker whose script will not load does not serve" \
         "top_oop is '$TOP_OOP_STATE', wanted 'failed'" \
         "the script's top-level socketley.list() cannot work in a worker, so the" \
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

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
