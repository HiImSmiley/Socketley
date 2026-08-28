#!/usr/bin/env bash
# Integration test: an HTTP handler that raises is reported, and answers 500.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
#
# 2a1e135..df02e6f made every Lua callback in this tree a sol::protected_function
# whose caller checks valid() before reading anything, because the
# `catch (const sol::error&)` those calls used to sit inside only fires when
# sol2's panic handler throws AND that throw unwinds out of the interpreter —
# and it does not in this repository's own Sanitize configuration.  Measured
# there on the parent commit, one script raising from on_http_request:
#
#     Release   the catch runs, the request falls through to 404, log: nothing
#     Sanitize  the catch never runs
#
# on_http_request was the one callback the sweep did not reach.  It was still
# declared sol::function, its accessor was still `guarded` rather than
# `guarded_protected`, and its call site in server_instance.cpp checked nothing
# at all: `sol::object result = lua()->on_http_request()(lua_req)` reads index 0
# of the result unconditionally.  On a failed protected call index 0 is the
# ERROR OBJECT, which is the read df02e6f records the cost of on the cache path
# — on_miss stored a Lua error message as the fetched value and served it as a
# hit for ever.
#
# ─── WHY 500 AND NOT 404 ────────────────────────────────────────────────────
#
# The falling-through was not neutral.  `return nil` from on_http_request is
# documented as "I have no answer, serve the static file or 404", so a build
# that answers a RAISE the same way makes a broken handler indistinguishable
# from a handler that declined — at the client and, without the log line, at the
# operator too.  The tree settled this question the same way for the proxy hook
# one file over: "a hook that raises has not said carry on".
#
# ─── THE CONTROLS ───────────────────────────────────────────────────────────
#
# Three, and they are what stop this file from passing against a build that
# simply answers 500 to everything:
#
#   * a handler that returns a table is still served, before and after the raise
#   * a handler that returns nothing still falls through to 404 — the documented
#     meaning of nil is not collateral damage
#   * the interpreter survives: the same runtime serves /ok again afterwards
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luahttperr

PORT=$((SL_PORT_BASE+1010))

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop   http_err >/dev/null 2>&1 || true
    sleep 0.2
    "$BIN" remove http_err >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: an HTTP handler that raises ==="

daemon_start "$BIN"

LUA="$SOCKETLEY_TMPD/httperr.lua"
cat > "$LUA" <<'LUAEOF'
function on_http_request(req)
    if req.path == "/boom" then
        error("the handler exploded")
    end
    if req.path == "/ok" then
        return { status = 200, body = "served by lua" }
    end
    -- /fall: no return at all.  Documented as "fall through to static/404".
end
LUAEOF

create_ok "server with an HTTP handler created" "$BIN" create server http_err \
    -p "$PORT" --lua "$LUA" -s
ready_tcp 127.0.0.1 "$PORT" 10 || echo "  NOTE: the runtime never accepted"

# status PATH -> the HTTP status code, or 000 when nothing answered
status() {
    curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
        "http://127.0.0.1:$PORT$1" 2>/dev/null || printf '000'
}
body() {
    curl -s --max-time 3 "http://127.0.0.1:$PORT$1" 2>/dev/null || true
}

# ── Control 1: the handler works ────────────────────────────────────────────
OK_BEFORE=$(body /ok)
case "$OK_BEFORE" in
    *"served by lua"*) pass ;;
    *) fail "control: a handler that returns a table is served" \
            "GET /ok said '${OK_BEFORE:-<nothing>}'" \
            "every assertion below is about a handler that is otherwise working" ;;
esac

# ── Control 2: returning nothing still falls through ────────────────────────
FALL=$(status /fall)
if [ "$FALL" = "404" ]; then pass; else
    fail "control: a handler that returns nothing falls through" \
         "GET /fall answered $FALL, wanted 404" \
         "nil is documented as 'no answer' and must keep meaning that — a build" \
         "that answers 500 to everything must not pass this file"
fi

# ── The raise is answered, not admitted ─────────────────────────────────────
BOOM=$(status /boom)
if [ "$BOOM" = "500" ]; then pass; else
    fail "a handler that raises answers 500" \
         "GET /boom answered $BOOM, wanted 500" \
         "the call site read index 0 of an unchecked result and fell through to" \
         "the static/404 path, so a broken handler was indistinguishable at the" \
         "client from one that declined to answer"
fi

# ── The raise is reported, in both builds ───────────────────────────────────
#
# The needle is the callback's own name plus the message the script raised, so
# this cannot be satisfied by an unrelated line that happens to say [lua].
if grep -qa "on_http_request error" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "the raise is named in the daemon's log" \
         "no 'on_http_request error' line in $SOCKETLEY_DLOG" \
         "the call site checked nothing, so the only report was a catch that" \
         "does not fire under the sanitizer — the build the nightly job uses"
fi
if grep -qa "the handler exploded" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "the report carries the script's own message" \
         "no 'the handler exploded' in $SOCKETLEY_DLOG" \
         "the error object is what a protected call returns; a report that" \
         "names the callback but not the reason sends nobody to the right line"
fi

# ── Control 3: the interpreter survived it ──────────────────────────────────
OK_AFTER=$(body /ok)
case "$OK_AFTER" in
    *"served by lua"*) pass ;;
    *) fail "control: the same runtime serves again after the raise" \
            "GET /ok said '${OK_AFTER:-<nothing>}'" \
            "one raising request must not take the handler down with it" ;;
esac

TOTAL=$((TOTAL+1))
if kill -0 "$SOCKETLEY_DPID" 2>/dev/null && daemon_alive "$SOCKETLEY_SOCKET"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: the daemon did not survive a raising HTTP handler"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
