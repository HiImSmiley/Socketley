#!/usr/bin/env bash
# Integration test: what a Lua call tells you when it did not do the thing.
#
# ─── A BARE `false` IS A VERDICT WITH THE EVIDENCE REMOVED ──────────────────
#
# 7b951e3 fixed the calls that took a value, altered it and reported success.
# This file is about the step after that: the call answers, and the answer
# carries nothing.
#
#     socketley.start("web") -> false
#
# for a runtime that does not exist, for one that is already running, for one
# whose port another process holds, and for one whose --cpus this daemon's ring
# cannot meet.  Four situations, four different things to do about them, one
# answer.  A script that wants to be idempotent has to guess which it was; a
# script that wants to report has nothing to report.
#
# And the self.* mutators were worse than that: they returned NOTHING.
# self.send(id, msg) to a closed connection, self.set_data on an id that is not
# a connection, self.join_group on the same — each did nothing at all and said
# nothing at all.  Checking a `port` in socketley.create's config table while
# leaving these open is the arrangement that teaches a script author the check
# exists.
#
# ─── WHY THE ASSERTIONS COME IN PAIRS ───────────────────────────────────────
#
# "it returned false" is also what a build with the call deleted returns, and
# "there is a second return value" is satisfied by a constant.  So every refusal
# below is asserted together with the TEXT of its reason, and every reason is
# asserted alongside the same call made correctly, which must still answer
# `true` with no second value.  A build that refused everything passes half of
# this file and fails the other half; so does a build that refused nothing.
#
# The three multiple-return contexts Lua does NOT truncate are asserted
# directly, because they are the whole compatibility claim: `local ok = f()`
# still binds one value, `if not f() then` still branches on the first, and a
# call in a non-final argument position still passes one argument.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luaret

PB=$((SL_PORT_BASE + 1150))
RPC_PORT=$((PB + 0))    # the script under test, in the daemon
SUBJ_PORT=$((PB + 1))   # the runtime it starts and stops
PX_PORT=$((PB + 2))     # the HTTP proxy, --strategy lua
BE1_PORT=$((PB + 3))    # its two backends
BE2_PORT=$((PB + 4))

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
assert_eq() {
    local label=$1 want=$2 got=$3; shift 3
    if [ "$got" = "$want" ]; then pass; else
        fail "$label" "got '$got', wanted '$want'" "$@"
    fi
}
assert_has() {
    local label=$1 needle=$2 hay=$3; shift 3
    if [ "${hay#*"$needle"}" != "$hay" ]; then pass; else
        fail "$label" "'$needle' is not in '$hay'" "$@"
    fi
}

cleanup() {
    touch "${BE_STOP:-/dev/null}" 2>/dev/null || true
    for p in "${BE1_PID:-}" "${BE2_PID:-}"; do
        [ -n "$p" ] && wait "$p" 2>/dev/null
    done
    for r in retpx retsubj ret; do "$BIN" stop "$r" 2>/dev/null || true; done
    sleep 0.3
    for r in retpx retsubj ret; do "$BIN" remove "$r" 2>/dev/null || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: what a Lua call says when it did not do it ==="

daemon_start "$BIN"

cat > "$SOCKETLEY_TMPD/ask.py" <<'PYEOF'
import select, socket, sys, time
port, text, budget = int(sys.argv[1]), sys.argv[2], float(sys.argv[3])
s = socket.create_connection(("127.0.0.1", port), 5)
s.sendall((text + "\n").encode())
out, end = b"", time.time() + budget
while time.time() < end:
    r, _, _ = select.select([s], [], [], 0.05)
    if not r:
        continue
    try:
        d = s.recv(65536)
    except Exception:
        break
    if not d:
        break
    out += d
s.close()
print(out.decode("latin-1").replace("\r", "").strip())
PYEOF
ask() { python3 "$SOCKETLEY_TMPD/ask.py" "$1" "$2" "${3:-2.5}"; }
hits() { grep -ac "$1" "$SOCKETLEY_DLOG" 2>/dev/null || true; }

RPC_LUA="$SOCKETLEY_TMPD/ret.lua"
cat > "$RPC_LUA" <<LUAEOF
local SUBJ_PORT = $SUBJ_PORT
LUAEOF
cat >> "$RPC_LUA" <<'LUAEOF'
local function reply(id, s) self.send(id, s) end
local function words(msg)
    local out = {}
    for w in msg:gmatch("%S+") do out[#out+1] = w end
    return out
end

-- "<ok>|<reason>" for every call in the family, so one helper reads them all
-- and the shell asserts on both halves of one string.
local function two(...)
    local ok, why = ...
    return tostring(ok) .. "|" .. tostring(why)
end

function on_client_message(id, msg)
    local a = words(msg)
    local cmd = a[1]

    -- ── socketley.* ────────────────────────────────────────────────────────
    if cmd == "start_missing" then
        reply(id, two(socketley.start("nosuchruntime")))

    elseif cmd == "start_twice" then
        socketley.create("server", "retsubj", { port = SUBJ_PORT })
        local first = two(socketley.start("retsubj"))
        local again = two(socketley.start("retsubj"))
        reply(id, "first=" .. first .. " again=" .. again)

    elseif cmd == "stop_missing" then
        reply(id, two(socketley.stop("nosuchruntime")))

    elseif cmd == "stop_notrunning" then
        socketley.stop("retsubj")
        reply(id, two(socketley.stop("retsubj")))

    elseif cmd == "send_missing" then
        reply(id, two(socketley.send("nosuchruntime", "hi")))

    elseif cmd == "send_notrunning" then
        reply(id, two(socketley.send("retsubj", "hi")))

    elseif cmd == "remove_missing" then
        reply(id, two(socketley.remove("nosuchruntime")))

    elseif cmd == "remove_ok" then
        reply(id, two(socketley.remove("retsubj")))

    -- ── the compatibility claim, asserted rather than asserted about ───────
    elseif cmd == "compat" then
        -- One value in an assignment, whichever way the call went.
        local ok1 = socketley.start("nosuchruntime")
        local ok2 = socketley.stop("nosuchruntime")
        -- `if not f() then` still branches on the first value.
        local branched = "no"
        if not socketley.start("nosuchruntime") then branched = "yes" end
        -- A call in a NON-final argument position passes exactly one.
        local function argc(...) return select("#", ...) end
        local n = argc(socketley.start("nosuchruntime"), "tail")
        reply(id, "ok1=" .. tostring(ok1) .. " ok2=" .. tostring(ok2) ..
                  " branched=" .. branched .. " argc=" .. tostring(n))

    -- ── self.* mutators ────────────────────────────────────────────────────
    elseif cmd == "self_send_dead" then
        -- 999999 is past MAX_FDS and has never been a connection.
        reply(id, two(self.send(999999, "x")))

    elseif cmd == "self_send_live" then
        reply(id, two(self.send(id, "SELFSEND-OK")))

    elseif cmd == "self_disconnect_dead" then
        reply(id, two(self.disconnect(999999)))

    elseif cmd == "self_setdata_dead" then
        reply(id, two(self.set_data(999999, "k", "v")))

    elseif cmd == "self_setdata_emptykey" then
        reply(id, two(self.set_data(id, "", "v")))

    elseif cmd == "self_setdata_live" then
        reply(id, two(self.set_data(id, "k", "v")))

    elseif cmd == "self_group_empty" then
        reply(id, two(self.join_group(id, "")))

    elseif cmd == "self_group_dead" then
        reply(id, two(self.join_group(999999, "g")))

    elseif cmd == "self_group_live" then
        reply(id, two(self.join_group(id, "g")))

    elseif cmd == "self_pipe_same" then
        reply(id, two(self.pipe(id, id)))

    elseif cmd == "self_pipe_dead" then
        reply(id, two(self.pipe(id, 999999)))

    elseif cmd == "self_unpipe_unpiped" then
        reply(id, two(self.unpipe(id)))

    -- ── the list with a hole in it ─────────────────────────────────────────
    elseif cmd == "multicast_hole" then
        -- The middle entry is a string, which is what a client id looks like
        -- after a round trip through json_decode.
        reply(id, two(self.multicast({ id, "2", id }, "MC-HOLE")))

    elseif cmd == "multicast_keyed" then
        reply(id, two(self.multicast({ a = id }, "MC-KEYED")))

    elseif cmd == "multicast_ok" then
        -- A well-formed list of two, one of which is this live connection and
        -- one of which is a stale id: the count separates them.
        reply(id, "n=" .. tostring(self.multicast({ id, 999999 }, "MC-OK")))

    -- ── group_send answers with a number, not a bool ───────────────────────
    elseif cmd == "group_count" then
        self.join_group(id, "gc")
        local n = self.group_send("gc", "GC-PAYLOAD")
        local m = self.group_send("nosuchgroup", "GC-NOBODY")
        reply(id, "n=" .. tostring(n) .. " m=" .. tostring(m))
    end
end
LUAEOF

create_ok "the script under test is created in the daemon" "$BIN" create server ret \
    -p "$RPC_PORT" --mode in --lua "$RPC_LUA" --daemon-process -s
ready_tcp 127.0.0.1 "$RPC_PORT" 10 || echo "  NOTE: the RPC server never accepted"

# ── 1. socketley.start ─────────────────────────────────────────────────────
R=$(ask "$RPC_PORT" start_missing)
assert_has "start of a runtime that does not exist is false" "false|" "$R" "got: $R"
assert_has "...and says which runtime it could not find" \
           'there is no runtime called "nosuchruntime"' "$R" \
    "a bare false is the same answer this call gives for a runtime that is" \
    "already running, and the two need different things done about them" \
    "got: $R"

R=$(ask "$RPC_PORT" start_twice 4.0)
assert_has "a start that works answers true" "first=true|nil" "$R" "got: $R"
assert_has "...and starting it again is refused, saying so" \
           'again=false|"retsubj" is already running' "$R" \
    "the control and the case in one string: a build that refused everything" \
    "fails the first half, one that refused nothing fails the second" \
    "got: $R"

# ── 2. socketley.stop ──────────────────────────────────────────────────────
R=$(ask "$RPC_PORT" stop_missing)
assert_has "stop of a runtime that does not exist names it" \
           'there is no runtime called "nosuchruntime"' "$R" "got: $R"

R=$(ask "$RPC_PORT" stop_notrunning 4.0)
assert_has "stopping something already stopped names its state" \
           '"retsubj" is stopped, not running' "$R" \
    "an idempotent teardown is written by calling stop twice; the second call" \
    "must be able to say it was already done rather than looking like a failure" \
    "got: $R"

# ── 3. socketley.send ──────────────────────────────────────────────────────
R=$(ask "$RPC_PORT" send_missing)
assert_has "send to a runtime that does not exist names it" \
           'there is no runtime called "nosuchruntime"' "$R" "got: $R"

R=$(ask "$RPC_PORT" send_notrunning)
assert_has "send to a runtime that is not running says so" \
           '"retsubj" is stopped, not running' "$R" \
    "the message went nowhere either way; the difference is whether the" \
    "script can tell that from a typo in the name" "got: $R"

# ── 4. socketley.remove ────────────────────────────────────────────────────
R=$(ask "$RPC_PORT" remove_missing)
assert_has "remove of a runtime that does not exist names it" \
           'there is no runtime called "nosuchruntime"' "$R" "got: $R"
R=$(ask "$RPC_PORT" remove_ok 4.0)
assert_eq "...and a remove that works answers a bare true" "true|nil" "$R" \
    "one value on success, not 'true, nil' — which is what makes this" \
    "sol::variadic_results rather than a tuple"

# ── 5. the compatibility claim ─────────────────────────────────────────────
assert_eq "a second return value breaks none of the three contexts that matter" \
          "ok1=false ok2=false branched=yes argc=2" "$(ask "$RPC_PORT" compat)" \
    "assignment takes one value, 'if not f()' branches on the first, and a" \
    "call in a non-final argument position passes exactly one — so argc is 2," \
    "the call plus the literal, and not 3"

# ── 6. the self.* mutators ─────────────────────────────────────────────────
R=$(ask "$RPC_PORT" self_send_dead)
assert_has "self.send to an id that is not a connection is false" "false|" "$R" "got: $R"
assert_has "...and says so, naming the runtime" "there is no open connection 999999" "$R" \
    "it returned nothing at all before: the message vanished and the script" \
    "had no way to learn that it had" "got: $R"

assert_eq "self.send to a live connection answers a bare true" \
          "true|nil" "$(grep -o 'true|nil' <<<"$(ask "$RPC_PORT" self_send_live)" | head -1)" \
    "the control for every self.* refusal below"

R=$(ask "$RPC_PORT" self_disconnect_dead)
assert_has "self.disconnect of a non-connection says so" \
           "there is no open connection 999999" "$R" "got: $R"

R=$(ask "$RPC_PORT" self_setdata_dead)
assert_has "self.set_data on a non-connection says so" \
           "there is no open connection 999999" "$R" "got: $R"
R=$(ask "$RPC_PORT" self_setdata_emptykey)
assert_has "self.set_data with an empty key is refused" "the metadata key is empty" "$R" \
    "get_data(\"\") answers nil whether it was set or not, so a write under" \
    "that key cannot be observed by anything" "got: $R"
assert_eq "self.set_data on a live connection answers true" \
          "true|nil" "$(ask "$RPC_PORT" self_setdata_live)"

R=$(ask "$RPC_PORT" self_group_empty)
assert_has "join_group with an empty group name is refused" "the group name is empty" "$R" \
    "an empty name is what a missing table field looks like after '..', and" \
    "it names a group no client can ever be reached by" "got: $R"
R=$(ask "$RPC_PORT" self_group_dead)
assert_has "join_group of a non-connection says so" \
           "there is no open connection 999999" "$R" "got: $R"
assert_eq "join_group of a live connection answers true" \
          "true|nil" "$(ask "$RPC_PORT" self_group_live)"

R=$(ask "$RPC_PORT" self_pipe_same)
assert_has "self.pipe of one connection to itself is refused" \
           "a pipe joins two connections, and those are one" "$R" "got: $R"
R=$(ask "$RPC_PORT" self_pipe_dead)
assert_has "self.pipe to a non-connection says which two it was given" \
           "is not an open connection on" "$R" "got: $R"
R=$(ask "$RPC_PORT" self_unpipe_unpiped)
assert_has "self.unpipe of a connection that is not piped says so" \
           "is not piped" "$R" "got: $R"

# ── 7. a list with a hole in it is not a shorter list ──────────────────────
R=$(ask "$RPC_PORT" multicast_hole)
assert_has "a multicast list with a non-id entry is refused" \
           "multicast list entry 2 is not a client id" "$R" \
    "it used to drop that entry and send to the rest, reporting nothing —" \
    "and the entry it drops is the one whose id came back from json_decode" \
    "as a string, which is how this happens in practice" "got: $R"
assert_eq "...and nothing was sent" "0" "$(hits 'MC-HOLE')" \
    "the refusal is a refusal: a build that reported the error and delivered" \
    "to the other two satisfies the line above and fails this one"

R=$(ask "$RPC_PORT" multicast_keyed)
assert_has "a keyed table is named rather than read as an empty list" \
           "no entry at index 1" "$R" \
    "the same trap filters and routes are validated against: it reads like a" \
    "registration and reaches nobody" "got: $R"

# The payload is delivered to the very connection that is reading the reply, so
# it arrives ahead of it on the same socket; the answer is picked out rather
# than matched whole.
assert_eq "a well-formed multicast answers how many it reached" \
          "n=1" "$(grep -o 'n=[0-9]*' <<<"$(ask "$RPC_PORT" multicast_ok)" | head -1)" \
    "two ids, one live and one stale: a bool cannot tell that from two live" \
    "ones, and the stale id is the ordinary case after a disconnect"

# ── 8. group_send answers with a count ─────────────────────────────────────
assert_eq "group_send reports how many it reached, and zero for an empty group" \
          "n=1 m=0" "$(grep -o 'n=[0-9]* m=[0-9]*' <<<"$(ask "$RPC_PORT" group_count)" | head -1)" \
    "zero is what a misspelled group name looks like once its last real" \
    "member has left, and a bool cannot say it"

# ── 9. on_route is handed the stripped path as a third argument ────────────
#
# The proxy's own /<name>/ prefix is stripped on the way to the backend, and
# on_route deliberately sees the client's path — filters see the same one, and
# that consistency is worth keeping.  What it cost is that a script routing on
# /api/users had to cut '"/" .. self.name .. "/"' off the front itself and get
# the bare /gw case right, which is the one nobody gets right: the prefix is 5
# characters and the path is 3.
cat > "$SOCKETLEY_TMPD/be.py" <<'PYEOF'
import os, socket, sys, threading
port, tag, stop_path = int(sys.argv[1]), sys.argv[2], sys.argv[3]
ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", port)); ls.listen(16); ls.settimeout(0.2)
def serve(c):
    try:
        c.settimeout(2); c.recv(65536)
        body = tag.encode()
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass
while not os.path.exists(stop_path):
    try:
        c, _ = ls.accept()
    except socket.timeout:
        continue
    except Exception:
        break
    threading.Thread(target=serve, args=(c,), daemon=True).start()
ls.close()
PYEOF
BE_STOP="$SOCKETLEY_TMPD/be.stop"
python3 "$SOCKETLEY_TMPD/be.py" "$BE1_PORT" BE1 "$BE_STOP" & BE1_PID=$!
python3 "$SOCKETLEY_TMPD/be.py" "$BE2_PORT" BE2 "$BE_STOP" & BE2_PID=$!

cat > "$SOCKETLEY_TMPD/px.lua" <<'EOF'
function on_route(method, path, backend_path)
    socketley.log("ROUTE m=" .. tostring(method) ..
                  " client=" .. tostring(path) ..
                  " backend=" .. tostring(backend_path))
    return 0
end
EOF
create_ok "the lua-routed HTTP proxy is created" "$BIN" create proxy retpx \
    -p "$PX_PORT" --protocol http --strategy lua \
    --backend "127.0.0.1:$BE1_PORT" --backend "127.0.0.1:$BE2_PORT" \
    --lua "$SOCKETLEY_TMPD/px.lua" -s
ready_http 127.0.0.1 "$PX_PORT" "/retpx/ping" 20 || echo "  NOTE: the proxy never answered"

curl -s -m 5 "http://127.0.0.1:$PX_PORT/retpx/api/users" >/dev/null 2>&1 || true
curl -s -m 5 "http://127.0.0.1:$PX_PORT/retpx" >/dev/null 2>&1 || true
sleep 0.6

assert_eq "on_route still gets the client's path, prefix included" \
          "1" "$(hits 'ROUTE m=GET client=/retpx/api/users')" \
    "unchanged on purpose: the filter chain is handed the same path, and a" \
    "script that already strips it by hand must keep working"
assert_eq "...and now also the path the backend will see" \
          "1" "$(hits 'client=/retpx/api/users backend=/api/users')" \
    "a third argument; Lua drops arguments a handler does not declare, so no" \
    "existing on_route sees any difference"
assert_eq "...and the bare gateway path becomes /, not the empty string" \
          "1" "$(hits 'client=/retpx backend=/$')" \
    "this is the case a hand-written strip gets wrong: the prefix is longer" \
    "than the path, so sub() past the end yields '' and matches nothing"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
