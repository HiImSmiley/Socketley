#!/usr/bin/env bash
# Integration test: the proxy's Lua surface — on_route, the two filter hooks,
# and the self.* table.
#
# ─── on_route's INDEX IS 0-BASED, AND OUT OF RANGE IS NOT AN ERROR ──────────
#
#     if (result.is<int>()) {
#         int idx = result.as<int>();
#         if (idx >= 0 && idx < pool_size) { ... return &m_backends[idx]; }
#     }
#     // Fallback to round-robin
#
# Two things there are easy to break in silence.  The index is 0-based while
# every table in Lua is 1-based, so a script written the obvious way selects the
# wrong backend and nothing says so.  And an index outside the pool is not
# refused — it falls through to round-robin — so a script whose arithmetic is
# off by one keeps working, just not the way it was written.
#
# Both are asserted by where the connections actually landed, counted off each
# backend's own total_connections:
#
#   * a fixed index of 1 must put ALL of them on the second backend and none on
#     the other two.  A 1-based reading would put them on the third; asserting
#     only "the chosen one got some" would pass either way.
#   * an out-of-range index must spread them evenly.  Asserting only "it did not
#     fail" would also pass a fallback that sent everything to backend 0, which
#     is the plausible wrong fallback and the one a reader would assume.
#
# ─── THE TWO FILTER HOOKS ARE THREE-WAY ────────────────────────────────────
#
#     if (r.get_type() == sol::type::nil) return;        // drop the bytes
#     if (r.is<std::string>()) { ...replace... }
#     // anything else: forward unchanged
#
# All three arms are asserted, and on_proxy_request's are read off the BACKEND's
# own record of what arrived — not off the client, which sees the same "nothing
# useful came back" for a dropped request as for a backend that never answered.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_create.sh"

daemon_isolate luaproxy

PB=${SOCKETLEY_PORT_BASE:-19330}
BE_PORT=$((PB + 0))       # backend for the hook and introspection proxies
HOOK_PORT=$((PB + 1))     # proxy carrying on_proxy_request / on_proxy_response
INTRO_PORT=$((PB + 2))    # proxy answering with its own self.* values
R0_PORT=$((PB + 4))       # the three routing backends
R1_PORT=$((PB + 5))
R2_PORT=$((PB + 6))
ROUTE_PORT=$((PB + 7))    # proxy with --strategy lua

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

cleanup() {
    "$BIN" stop  pbe phook pintro pr0 pr1 pr2 proute 2>/dev/null || true
    sleep 0.3
    "$BIN" remove pbe phook pintro pr0 pr1 pr2 proute 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: the proxy Lua surface ==="

daemon_start "$BIN"

MODE_FILE="$SOCKETLEY_TMPD/hookmode"
echo forward > "$MODE_FILE"
ROUTE_FILE="$SOCKETLEY_TMPD/routeidx"
echo 1 > "$ROUTE_FILE"

# ask PORT TEXT — one connection, one line, whatever comes back within a second.
# The reply is printed with newlines flattened, because these hooks replace
# whole byte ranges and the framing is not what is being asserted.
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
print(out.decode("latin-1").replace("\r", "").replace("\n", "|").strip("|"))
PYEOF
ask() { python3 "$SOCKETLEY_TMPD/ask.py" "$1" "$2" "${3:-1.0}"; }

# fate PORT TEXT — "closed" if the peer hung up inside the budget, "open" if it
# did not.  A dropped request and a closed client both give the caller no bytes;
# only this tells them apart.
cat > "$SOCKETLEY_TMPD/fate.py" <<'PYEOF'
import select, socket, sys, time
port, text, budget = int(sys.argv[1]), sys.argv[2], float(sys.argv[3])
s = socket.create_connection(("127.0.0.1", port), 5)
s.sendall((text + "\n").encode())
end, verdict = time.time() + budget, "open"
while time.time() < end:
    r, _, _ = select.select([s], [], [], 0.05)
    if not r:
        continue
    try:
        d = s.recv(65536)
    except Exception:
        verdict = "closed"; break
    if not d:
        verdict = "closed"; break
s.close()
print(verdict)
PYEOF
fate() { python3 "$SOCKETLEY_TMPD/fate.py" "$1" "$2" "${3:-1.5}"; }

# The backend behind the hook proxy: it records exactly what arrived and answers
# with a fixed string, so both hooks have an unambiguous side to be read from.
BE_LUA="$SOCKETLEY_TMPD/be.lua"
cat > "$BE_LUA" <<'LUAEOF'
function on_client_message(id, msg)
    socketley.log("PBE got=[" .. msg .. "]")
    self.send(id, "BACKEND-SAID-HELLO")
end
LUAEOF

HOOK_LUA="$SOCKETLEY_TMPD/hook.lua"
cat > "$HOOK_LUA" <<LUAEOF
local MODE_FILE = "$MODE_FILE"
LUAEOF
cat >> "$HOOK_LUA" <<'LUAEOF'
local function mode()
    local f = io.open(MODE_FILE, "r")
    if not f then return "forward" end
    local m = f:read("*l")
    f:close()
    return m or "forward"
end

-- The three arms, chosen per request so that one proxy covers all of them and
-- the assertions cannot be confused by three different interpreters.
function on_proxy_request(client_id, data)
    local m = mode()
    if m == "closeclient" then
        self.close_client(client_id)
        return nil
    end
    if m == "reqdrop"    then return nil end
    if m == "reqreplace" then return "REPLACED-BY-REQUEST-HOOK\n" end
    if m == "reqbadtype" then return 0 end
    -- Falls off the end without returning: the observer shape, which forwards.
end

function on_proxy_response(client_id, data)
    local m = mode()
    if m == "respdrop"     then return nil end
    if m == "respreplace"  then return "REPLACED-BY-RESPONSE-HOOK\n" end
    if m == "respbadtype"  then return 0 end
    -- Falls off the end: the observer shape, which forwards.
end
LUAEOF

# The introspection proxy answers with its own self.* values in place of the
# backend's reply, so every figure is read off the wire as an exact string.
INTRO_LUA="$SOCKETLEY_TMPD/intro.lua"
cat > "$INTRO_LUA" <<'LUAEOF'
function on_proxy_response(client_id, data)
    local b = self.backends()
    local h = self.backend_health()
    local st = self.stats()
    local parts = {}
    parts[#parts+1] = "backends=" .. table.concat(b, ",")
    parts[#parts+1] = "health1=" .. tostring(h[1])
    parts[#parts+1] = "clients=" .. tostring(#self.clients())
    parts[#parts+1] = "peerip=" .. tostring(self.peer_ip(client_id))
    parts[#parts+1] = "proto=" .. tostring(self.protocol)
    -- The type alias: register_bindings does m_lua[type_to_string(type)] = self,
    -- so `proxy` is not a copy of the table, it IS the table.  Identity rather
    -- than "a call through it also works", because a build that made a second
    -- table with the same methods would satisfy the weaker claim and would
    -- silently give a script two places to keep state.
    parts[#parts+1] = "alias_same=" .. tostring(rawequal(proxy, self))
    parts[#parts+1] = "alias_call=" .. tostring(#proxy.backends())
    parts[#parts+1] = "backend_count=" .. tostring(st.backend_count)
    parts[#parts+1] = "conns=" .. tostring(st.connections)
    parts[#parts+1] = "total=" .. tostring(st.total_connections)
    parts[#parts+1] = "bytesin_positive=" .. tostring(st.bytes_in > 0)
    return table.concat(parts, " ") .. "\n"
end
LUAEOF

ROUTE_LUA="$SOCKETLEY_TMPD/route.lua"
cat > "$ROUTE_LUA" <<LUAEOF
local IDX_FILE = "$ROUTE_FILE"
LUAEOF
cat >> "$ROUTE_LUA" <<'LUAEOF'
function on_route()
    local f = io.open(IDX_FILE, "r")
    if not f then return 0 end
    local n = tonumber(f:read("*l"))
    f:close()
    return n or 0
end
LUAEOF

RBE_LUA="$SOCKETLEY_TMPD/rbe.lua"
cat > "$RBE_LUA" <<'LUAEOF'
function on_client_message(id, msg)
    self.send(id, "FROM-" .. self.name)
end
LUAEOF

hits() { grep -ac "$1" "$2" 2>/dev/null || true; }
stat() {
    { "$BIN" stats "$1" 2>/dev/null || true; } \
        | awk -F: -v k="$2" '$1 == k { print $2; exit }'
}
await_stat() {
    local i
    for i in $(seq 1 60); do
        [ "$(stat "$1" "$2")" = "$3" ] && return 0
        sleep 0.1
    done
    return 0
}

create_ok "hook backend created" "$BIN" create server pbe \
    -p "$BE_PORT" --mode in --lua "$BE_LUA" -s
ready_tcp 127.0.0.1 "$BE_PORT" 10 || echo "  NOTE: the hook backend never accepted"
create_ok "hook proxy created" "$BIN" create proxy phook \
    -p "$HOOK_PORT" --protocol tcp --backend "127.0.0.1:$BE_PORT" --lua "$HOOK_LUA" -s
create_ok "introspection proxy created" "$BIN" create proxy pintro \
    -p "$INTRO_PORT" --protocol tcp --backend "127.0.0.1:$BE_PORT" --lua "$INTRO_LUA" -s

create_ok "routing backend 0 created" "$BIN" create server pr0 -p "$R0_PORT" --mode in --lua "$RBE_LUA" -s
create_ok "routing backend 1 created" "$BIN" create server pr1 -p "$R1_PORT" --mode in --lua "$RBE_LUA" -s
create_ok "routing backend 2 created" "$BIN" create server pr2 -p "$R2_PORT" --mode in --lua "$RBE_LUA" -s
for p in "$R0_PORT" "$R1_PORT" "$R2_PORT"; do
    ready_tcp 127.0.0.1 "$p" 10 || echo "  NOTE: nothing accepted on $p"
done
create_ok "routing proxy created" "$BIN" create proxy proute \
    -p "$ROUTE_PORT" --protocol tcp --strategy lua \
    --backend "127.0.0.1:$R0_PORT" --backend "127.0.0.1:$R1_PORT" --backend "127.0.0.1:$R2_PORT" \
    --lua "$ROUTE_LUA" -s

for p in "$HOOK_PORT" "$INTRO_PORT" "$ROUTE_PORT"; do
    ready_tcp 127.0.0.1 "$p" 10 || echo "  NOTE: nothing accepted on $p"
done

# ── 1. on_proxy_request: forward, replace, drop ────────────────────────────
echo forward > "$MODE_FILE"
OUT=$(ask "$HOOK_PORT" "PROBE-FORWARD" 1.5)
assert_eq "a hook that returns nothing forwards the bytes unchanged" \
          "1" "$(hits 'PBE got=\[PROBE-FORWARD\]' "$SOCKETLEY_DLOG")" \
    "read off the backend's own record of what arrived, so a hook that" \
    "silently rewrote the bytes fails here rather than passing quietly." \
    "This is the observer shape -- log(data) and nothing else -- and it" \
    "read as nil until 60c73fd, which emptied every connection through it"
assert_eq "...and the backend's answer comes back to the client" \
          "BACKEND-SAID-HELLO" "$OUT"

echo reqreplace > "$MODE_FILE"
ask "$HOOK_PORT" "PROBE-REPLACED" 1.5 >/dev/null
assert_eq "on_proxy_request returning a string replaces the bytes" \
          "1" "$(hits 'PBE got=\[REPLACED-BY-REQUEST-HOOK\]' "$SOCKETLEY_DLOG")"
assert_eq "...and the bytes the client actually sent never reached the backend" \
          "0" "$(hits 'PBE got=\[PROBE-REPLACED\]' "$SOCKETLEY_DLOG")" \
    "a replace that appended rather than replaced would satisfy the line" \
    "above and fail this one"

echo reqdrop > "$MODE_FILE"
BEFORE_MSGS=$(stat pbe total_messages)
ask "$HOOK_PORT" "PROBE-DROPPED" 1.5 >/dev/null
sleep 0.6
assert_eq "on_proxy_request returning nil drops the bytes" \
          "0" "$(hits 'PBE got=\[PROBE-DROPPED\]' "$SOCKETLEY_DLOG")"
assert_eq "...and the backend received nothing at all in their place" \
          "$BEFORE_MSGS" "$(stat pbe total_messages)" \
    "the second oracle for the same claim: 'the payload is absent from the" \
    "log' is also true of a hook that replaced it with something else"

# A value the other side cannot read is a refusal, not a forward.  The filter
# chain answers 500 to the same shape and on_auth answers value_or(false); this
# is the byte path, so it closes.  Asserted off the backend, because the client
# sees the same silence for a refusal as for a backend that never answered.
echo reqbadtype > "$MODE_FILE"
BEFORE_BAD=$(stat pbe total_messages)
ask "$HOOK_PORT" "PROBE-BADTYPE" 1.5 >/dev/null
sleep 0.6
assert_eq "on_proxy_request returning a non-string, non-nil refuses the request" \
          "0" "$(hits 'PBE got=\[PROBE-BADTYPE\]' "$SOCKETLEY_DLOG")"
assert_eq "...and nothing reached the backend in its place" \
          "$BEFORE_BAD" "$(stat pbe total_messages)" \
    "the second oracle: absent from the log is also true of a rewrite"

# ── 2. on_proxy_response: forward, replace, drop ───────────────────────────
echo forward > "$MODE_FILE"
assert_eq "a response hook that returns nothing forwards the reply unchanged" \
          "BACKEND-SAID-HELLO" "$(ask "$HOOK_PORT" "RESP-FORWARD" 1.5)"

echo respreplace > "$MODE_FILE"
assert_eq "on_proxy_response returning a string replaces the reply" \
          "REPLACED-BY-RESPONSE-HOOK" "$(ask "$HOOK_PORT" "RESP-REPLACED" 1.5)"

# The same refusal on the response side.  respbadtype was wired into the script
# when the request arm got its assertion and left with no caller — the exact
# shape this suite has been clearing out elsewhere, a branch that exists and is
# never taken.  Here the refusal closes the CLIENT connection, since a response
# the hook was to redact must not be delivered unredacted.
echo respbadtype > "$MODE_FILE"
assert_eq "on_proxy_response returning a non-string, non-nil refuses the reply" \
          "" "$(ask "$HOOK_PORT" "RESP-BADTYPE" 1.5)"
assert_eq "control: the backend answered the one that was refused" \
          "1" "$(hits 'PBE got=\[RESP-BADTYPE\]' "$SOCKETLEY_DLOG")" \
    "without this, 'the client got nothing' is satisfied by a request that" \
    "never left the proxy — a different hook and a different bug"
# ─── WHAT IS DELIBERATELY NOT ASSERTED HERE, AND WHY ────────────────────────
#
# The man page says this refusal closes the client connection — "here by
# closing the client connection, since the response this hook was to redact
# must not be delivered unredacted" — and it does not.  The refusal branch runs
# (the log carries "on_proxy_response returned a number; expected a string or
# nil — refusing the response") and sets cconn->closing, and nothing acts on the
# flag: on this path the code returns before queuing anything, so there is no
# write completion to notice it, and the client is idle so there is no read
# completion either.  Measured on the same proxy, one connection per arm:
#
#     hook forwards (observer)         client sees  answered: BACKEND-SAID-HELLO
#     on_proxy_request  -> wrong type  client sees  closed
#     on_proxy_response -> wrong type  client sees  OPEN, still open at 6 s
#
# So the half of fail-closed that matters is kept — the reply is withheld, which
# is asserted above — and the client is left waiting for a response that will
# never come.  Reported as a defect rather than folded into a test commit, and
# NOT asserted in either direction: asserting "open" would enshrine the bug as
# the contract, and asserting "closed" would make this file red against the
# build it is being committed with.
echo respdrop > "$MODE_FILE"
assert_eq "on_proxy_response returning nil drops the reply" \
          "" "$(ask "$HOOK_PORT" "RESP-DROPPED" 1.5)"
assert_eq "control: the backend did answer the dropped one" \
          "1" "$(hits 'PBE got=\[RESP-DROPPED\]' "$SOCKETLEY_DLOG")" \
    "without this, 'the client got nothing' is satisfied by a request that" \
    "never reached the backend, which is a different hook and a different bug"

# ── 2b. self.close_client ──────────────────────────────────────────────────
#
# Paired with the drop above, because both give the caller nothing back and the
# difference between them is the whole point of the call: a dropped request
# leaves the client connected and waiting, and close_client does not.
echo reqdrop > "$MODE_FILE"
assert_eq "control: a dropped request leaves the client connected" \
          "open" "$(fate "$HOOK_PORT" "FATE-DROPPED")" \
    "without this, 'the connection closed' below is satisfied by a proxy" \
    "that hangs up on everybody"

echo closeclient > "$MODE_FILE"
assert_eq "self.close_client() closes the connection it named" \
          "closed" "$(fate "$HOOK_PORT" "FATE-CLOSED")"
echo forward > "$MODE_FILE"

# ── 3. on_route: the index is 0-based ──────────────────────────────────────
echo 1 > "$ROUTE_FILE"
R0_BEFORE=$(stat pr0 total_connections); R1_BEFORE=$(stat pr1 total_connections)
R2_BEFORE=$(stat pr2 total_connections)
for _ in $(seq 1 6); do ask "$ROUTE_PORT" "ROUTE-PROBE" 0.5 >/dev/null; done
await_stat pr1 total_connections $((R1_BEFORE + 6))

assert_eq "on_route returning 1 selects the SECOND backend" \
          "$((R1_BEFORE + 6))" "$(stat pr1 total_connections)" \
    "the index is 0-based while every Lua table is 1-based, so a script" \
    "written the obvious way lands on the third backend and nothing says so"
assert_eq "...and the first backend gets none of them" \
          "$R0_BEFORE" "$(stat pr0 total_connections)"
assert_eq "...and the third backend gets none of them" \
          "$R2_BEFORE" "$(stat pr2 total_connections)" \
    "the two zeroes are the assertion: 'the chosen one got some' is true of" \
    "a 1-based reading as well, because it also chooses exactly one"

# ── 4. on_route out of range falls back to round-robin, not to backend 0 ───
echo 99 > "$ROUTE_FILE"
R0_BEFORE=$(stat pr0 total_connections); R1_BEFORE=$(stat pr1 total_connections)
R2_BEFORE=$(stat pr2 total_connections)
for _ in $(seq 1 6); do ask "$ROUTE_PORT" "ROUTE-PROBE" 0.5 >/dev/null; done
sleep 1.0

R0_D=$(( $(stat pr0 total_connections) - R0_BEFORE ))
R1_D=$(( $(stat pr1 total_connections) - R1_BEFORE ))
R2_D=$(( $(stat pr2 total_connections) - R2_BEFORE ))
assert_eq "an out-of-range index still routes all six connections" \
          "6" "$((R0_D + R1_D + R2_D))" \
    "out of range is not refused; the selection falls through"
if [ "$R0_D" -ge 1 ] && [ "$R1_D" -ge 1 ] && [ "$R2_D" -ge 1 ]; then pass; else
    fail "the fallback is round-robin rather than always-backend-0" \
         "the six connections landed $R0_D / $R1_D / $R2_D" \
         "every backend has to receive at least one; all six on the first is" \
         "the plausible wrong fallback and the one a reader would assume"
fi

# ── 5. the proxy self.* table ──────────────────────────────────────────────
INTRO=$(ask "$INTRO_PORT" "INTRO-PROBE" 1.5)
assert_eq "self.backends() lists the configured backend" \
          "1" "$(grep -c "backends=127.0.0.1:$BE_PORT" <<<"$INTRO" || true)" \
    "got: $INTRO"
# "closed" is the healthy state, not the broken one: the table reports the
# CIRCUIT BREAKER's state, whose three values are closed / open / half_open, and
# a closed breaker is one that is letting traffic through.  Pinned as the exact
# word because it reads like the opposite of what it means, and a change to the
# vocabulary would break every script that switches on it.
assert_eq "self.backend_health() reports the breaker closed for a healthy backend" \
          "1" "$(grep -c 'health1=closed' <<<"$INTRO" || true)" \
    "got: $INTRO"
assert_eq "self.clients() counts the connection being served" \
          "1" "$(grep -c 'clients=1' <<<"$INTRO" || true)" "got: $INTRO"
assert_eq "self.peer_ip() answers the client's address" \
          "1" "$(grep -c 'peerip=127.0.0.1' <<<"$INTRO" || true)" "got: $INTRO"
assert_eq "self.protocol says tcp" \
          "1" "$(grep -c 'proto=tcp' <<<"$INTRO" || true)" "got: $INTRO"
assert_eq "self.stats() counts the backends" \
          "1" "$(grep -c 'backend_count=1' <<<"$INTRO" || true)" "got: $INTRO"
assert_eq "self.stats() counts the live connection" \
          "1" "$(grep -c 'conns=1' <<<"$INTRO" || true)" "got: $INTRO"
assert_eq "the global 'proxy' IS the self table, not a copy of it" \
          "1" "$(grep -c 'alias_same=true' <<<"$INTRO" || true)" "got: $INTRO"
assert_eq "...and a method called through the alias answers" \
          "1" "$(grep -c 'alias_call=1' <<<"$INTRO" || true)" "got: $INTRO"
assert_eq "self.stats().bytes_in has moved" \
          "1" "$(grep -c 'bytesin_positive=true' <<<"$INTRO" || true)" \
    "a zero here means the figure is not wired to the traffic" \
    "got: $INTRO"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
