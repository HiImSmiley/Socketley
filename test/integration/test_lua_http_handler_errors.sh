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
#
# ─── AND THE OTHER WAY A HANDLER CAN BE UNREADABLE ──────────────────────────
#
# A raise is the loud failure.  The quiet one is a handler that returns a table
# whose fields are the wrong type, which `get_or` cannot distinguish from a
# field the script never set — so it substituted the documented default for
# both and said nothing.  Measured on a private daemon before the fix:
#
#     body   = 12345          200, empty body       no log line
#     body   = {1,2}          200, empty body       no log line
#     status = "404"          200, carrying the     no log line
#                             body meant for a 404
#     headers = {X-Count=7}   header simply absent  no log line
#
# The first row is the one that reads as a broken server: a 200 with nothing in
# it, from a handler that plainly meant to answer something.  A status or a body
# this end cannot read now answers 500 and names the type it got; a header pair
# that is not two strings is dropped and named, because one bad header costs the
# client that header while a bad body costs the whole answer.
#
# `nil` and no-return-at-all stay completely silent.  That is the DECLINE, it is
# documented, and Control 2 above is what stops this section from turning it
# into a diagnostic.
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
    -- The four shapes this end cannot build a response from.  Each is a field
    -- the script DID set, which is the whole distinction: an absent field takes
    -- its documented default and must stay silent.
    if req.path == "/badbody" then
        return { status = 200, body = 12345 }
    end
    if req.path == "/tablebody" then
        return { status = 200, body = { 1, 2 } }
    end
    if req.path == "/badstatus" then
        return { status = "404", body = "meant for a 404" }
    end
    if req.path == "/badheader" then
        return { status = 200, body = "hdr",
                 headers = { ["X-Good"] = "yes", ["X-Count"] = 7 } }
    end
    -- Not a table at all: documented as falling through, so the CLIENT's answer
    -- is unchanged and only the log gains a line.
    if req.path == "/string" then
        return "not a table"
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

# ── A table this end cannot build a response from ───────────────────────────
#
# Each row asserts the STATUS, because that is what the client sees and what
# was wrong: a 200 with an empty body is what a handler returning body = 12345
# used to produce, and it is indistinguishable from a working server answering
# nothing.
# path:status:what-was-wrong, so the failure line names the field rather than
# the URL -- `${path#bad}` read "tablebody" for the second row.
for probe in "badbody:500:body is a number" \
             "tablebody:500:body is a table" \
             "badstatus:500:status is a string"; do
    path=${probe%%:*}; rest=${probe#*:}; want=${rest%%:*}; what=${rest#*:}
    got=$(status "/$path")
    if [ "$got" = "$want" ]; then pass; else
        fail "a table whose $what answers $want" \
             "GET /$path answered $got, wanted $want" \
             "get_or() substitutes the default for a field of the wrong type as" \
             "readily as for one that is absent, so this used to be a 200 with" \
             "the unreadable part dropped and nothing in the log"
    fi
done

# The body really is empty on the old path, so assert the new one carries the
# 500's own body rather than the handler's.
BB=$(body /badbody)
case "$BB" in
    *"500"*) pass ;;
    *) fail "the 500 carries a body of its own" \
            "GET /badbody said '${BB:-<nothing>}'" \
            "an empty 200 was the defect; an empty 500 would be half a fix" ;;
esac

# A header pair that is not two strings costs that header and nothing else:
# the good one on the same table must still arrive.
HDRS=$(curl -s -D - -o /dev/null --max-time 3 "http://127.0.0.1:$PORT/badheader" 2>/dev/null || true)
if grep -qi "^X-Good: yes" <<<"$HDRS" && ! grep -qi "^X-Count" <<<"$HDRS"; then pass; else
    fail "a bad header pair is dropped and the rest are kept" \
         "the response headers were: $(tr -d '\r' <<<"$HDRS" | tr '\n' '|')" \
         "one unreadable header must not cost the client the whole answer," \
         "which is why this one is dropped rather than answered 500"
fi

# And each is named in the log with the type it actually got, so the operator
# is sent to the field rather than to the callback.
for needle in "\`status\` is a string" "\`body\` is a number" "\`body\` is a table"; do
    if grep -qa "$needle" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
        fail "the log names the type that arrived" \
             "no '$needle' in $SOCKETLEY_DLOG" \
             "naming only the field leaves the operator guessing what it was"
    fi
done

# ── A non-table return: the client's answer is unchanged, the log gains a line ─
STR=$(status /string)
if [ "$STR" = "404" ]; then pass; else
    fail "a non-table return still falls through" \
         "GET /string answered $STR, wanted 404" \
         "man/socketley.1 promises that anything which is not a table means the" \
         "same as nil; the diagnostic was added without changing that"
fi
if grep -qa "expected a table or nil" "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "but it is said out loud" \
         "no 'expected a table or nil' in $SOCKETLEY_DLOG" \
         "only nil declines — a script that returned a string meant to answer"
fi

# ── Control 4: the decline stays silent ─────────────────────────────────────
#
# The whole point of the distinction.  /fall returned nothing at all and must
# not have produced any on_http_request diagnostic; the ones above were all
# from paths that DID return something.
if grep -qa "expected a table or nil" "$SOCKETLEY_DLOG" && \
   [ "$(grep -ca "expected a table or nil" "$SOCKETLEY_DLOG")" = "1" ]; then pass; else
    fail "control: returning nothing produces no diagnostic" \
         "'expected a table or nil' appears $(grep -ca 'expected a table or nil' "$SOCKETLEY_DLOG" 2>/dev/null || echo 0) times, wanted exactly 1" \
         "/fall and /string both reach the fall-through, and only /string" \
         "returned something — a decline that logs is the defect inverted"
fi

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
