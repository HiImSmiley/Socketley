#!/usr/bin/env bash
# Integration test: the server's self.* table, and the two callbacks that change
# what the runtime does with traffic rather than merely observing it.
#
# ─── WHAT IS COVERED, AND WHY EACH ASSERTION IS THE SHAPE IT IS ─────────────
#
# The script under test answers RPCs on the connection that asked, so most of
# the surface is asserted as an exact reply on the wire.  The rest needs more
# than one client at once — a broadcast is only interesting beside a client that
# should NOT have received it — and those are driven by a small transcript
# runner that opens several connections and records what arrived on each.
#
#   self.clients()          the count, and that the asking client is in it
#   self.peer_ip(id)        127.0.0.1, from the connection's own end
#   self.set_data/get_data  per-connection, isolated between two clients that
#                           are connected AT THE SAME TIME, and set_data(id, k,
#                           nil) DELETES rather than storing a nil
#   self.broadcast(msg)     reaches every client
#   self.multicast(ids,msg) reaches the named client and NOT the other one
#   self.disconnect(id)     closes that client and leaves the other alone
#   join/leave/group_send   reaches the member, not the non-member, and stops
#                           reaching the member after it leaves
#   self.pipe/unpipe        bytes from one client come out of the other, and
#                           stop when the pipe is taken down
#   the upstream family     upstreams(), upstream_send(), upstream_broadcast(),
#                           on_upstream, on_upstream_connect
#   on_send                 fires for what the runtime sends, with the payload
#
# ─── on_message SUPPRESSES THE DEFAULT RELAY ────────────────────────────────
#
# A --mode inout server relays every message to the other clients unless the
# script defines on_message, in which case the script owns the traffic:
#
#     invoke_on_message(msg);
#     if (lua() && lua()->has_on_message())
#         break;                      <- the relay does not happen
#
# That is a large, silent behavioural switch keyed on the mere existence of a
# function.  It is asserted with two servers, the SAME configuration and two
# clients each: one script defines on_message and one does not, and the claim is
# that the second client receives the message in one case and not in the other.
# Either half alone proves nothing — "it was not relayed" is also true of a
# server that is not relaying anything at all.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luasrvapi

PB=$((SL_PORT_BASE+170))
API_PORT=$((PB + 0))     # the RPC server, --mode in
RELAY_ON_PORT=$((PB + 1))  # --mode inout WITH on_message
RELAY_OFF_PORT=$((PB + 2)) # --mode inout WITHOUT on_message
UP_TARGET_PORT=$((PB + 3)) # what the upstream leg dials
UP_PORT=$((PB + 4))        # the server holding the upstream

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
    "$BIN" stop  api relay_on relay_off up_target up_srv 2>/dev/null || true
    sleep 0.3
    "$BIN" remove api relay_on relay_off up_target up_srv 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: the server self.* table ==="

daemon_start "$BIN"

# ── The transcript runner ───────────────────────────────────────────────────
#
# Actions, in order, each on its own argument:
#
#   c<i>            open connection i
#   s<i>:<text>     send one line on connection i
#   r<i>            drain connection i and print one `R<i>:<line>` per line
#   x<i>            close connection i
#   w:<seconds>     wait
#
# A drain rather than a read: what a client did NOT receive is half of what this
# file asserts, and a blocking read cannot say "nothing arrived" without
# stopping.  Each drain reports everything queued and moves on, so an assertion
# about an absent line is a grep that finds nothing rather than a timeout.
cat > "$SOCKETLEY_TMPD/tx.py" <<'PYEOF'
import select, socket, sys, time

port = int(sys.argv[1])
conns, bufs = {}, {}

def drain(i, budget=0.6):
    s = conns[i]
    end = time.time() + budget
    while time.time() < end:
        r, _, _ = select.select([s], [], [], 0.05)
        if not r:
            continue
        try:
            data = s.recv(65536)
        except Exception:
            break
        if not data:
            print("R%d:<closed>" % i, flush=True)
            return
        bufs[i] += data.decode("latin-1")
    while "\n" in bufs[i]:
        line, bufs[i] = bufs[i].split("\n", 1)
        if line.strip():
            print("R%d:%s" % (i, line.strip()), flush=True)
    # Whatever is left without a newline is reported too, and that is not
    # tidiness: self.multicast() and self.pipe() forward the bytes exactly as
    # given, where self.broadcast() and self.group_send() append a newline.  A
    # reader that only ever splits on newlines therefore sees nothing at all
    # from half the API, and would report those two as not delivering.
    if bufs[i].strip():
        print("R%d:%s" % (i, bufs[i].strip()), flush=True)
        bufs[i] = ""

for act in sys.argv[2:]:
    kind = act[0]
    if kind == "c":
        i = int(act[1:])
        conns[i] = socket.create_connection(("127.0.0.1", port), 5)
        bufs[i] = ""
        print("C%d:open" % i, flush=True)
    elif kind == "s":
        i, text = act[1:].split(":", 1)
        conns[int(i)].sendall((text + "\n").encode())
    elif kind == "r":
        drain(int(act[1:]))
    elif kind == "x":
        i = int(act[1:])
        conns[i].close()
        print("X%d:closed" % i, flush=True)
    elif kind == "w":
        time.sleep(float(act.split(":", 1)[1]))
PYEOF

# tx PORT ACTIONS... — run a transcript, print it.
tx() { local p=$1; shift; python3 "$SOCKETLEY_TMPD/tx.py" "$p" "$@"; }

# ── The script under test ───────────────────────────────────────────────────
API_LUA="$SOCKETLEY_TMPD/api.lua"
cat > "$API_LUA" <<'LUAEOF'
-- Every reply goes back on the connection that asked, so the assertion is an
-- exact string on the wire rather than a log line about one.
local function reply(id, s) self.send(id, s) end

-- Every connected client except the one that asked.
--
-- The alternative is for the shell to learn a descriptor number from one
-- transcript and use it in the next — which only works while the kernel happens
-- to hand out the same numbers twice, and is a coin toss the moment it does
-- not.  Resolving it inside the runtime keeps every scenario to one process and
-- one set of connections.
local function others(me)
    local out = {}
    for _, c in ipairs(self.clients()) do
        if c ~= me then out[#out+1] = c end
    end
    return out
end

local function words(msg)
    local out = {}
    for w in msg:gmatch("%S+") do out[#out+1] = w end
    return out
end

function on_client_message(id, msg)
    local a = words(msg)
    local cmd = a[1]

    if cmd == "whoami" then
        reply(id, "id=" .. tostring(id))

    elseif cmd == "clients" then
        local ids = self.clients()
        local mine = false
        for _, c in ipairs(ids) do if c == id then mine = true end end
        reply(id, "clients=" .. tostring(#ids) .. " mine=" .. tostring(mine))

    elseif cmd == "ident" then
        -- self.connections() and self.protocol on a SERVER.  Both names are
        -- bound on four different tables and only the other three were ever
        -- asked; a binding wired to the wrong instance answers plausibly here
        -- and is never noticed.
        reply(id, "conns=" .. tostring(self.connections()) ..
                  " proto=" .. tostring(self.protocol) ..
                  " alias_same=" .. tostring(rawequal(server, self)) ..
                  " alias_conns=" .. tostring(server.connections()))

    elseif cmd == "sendone" then
        -- self.send() to one client.  Named separately from every other reply
        -- in this script so the on_send assertion below can be about THIS
        -- payload and not about the RPC traffic.
        self.send(id, "DIRECT-SEND-PAYLOAD")

    elseif cmd == "peerip" then
        reply(id, "peerip=" .. tostring(self.peer_ip(id)))

    elseif cmd == "setdata" then
        self.set_data(id, a[2], a[3])
        reply(id, "ok")

    elseif cmd == "getdata" then
        reply(id, "getdata=[" .. tostring(self.get_data(id, a[2])) .. "]")

    elseif cmd == "getdataof" then
        -- The isolation assertion: one client asking for ANOTHER client's key.
        local o = others(id)[1]
        reply(id, "getdataof=[" .. tostring(o and self.get_data(o, a[2]) or "noother") .. "]")

    elseif cmd == "deldata" then
        -- The third argument is nil, which is a delete and not a store.
        self.set_data(id, a[2], nil)
        reply(id, "ok")

    elseif cmd == "bcast" then
        self.broadcast(a[2])

    elseif cmd == "mcast" then
        -- Deliberately without a newline.  multicast forwards the bytes as
        -- given, where broadcast and group_send append one; the transcript
        -- runner reports unterminated bytes for exactly this reason, so the
        -- assertion is about the API as it is rather than about a framing this
        -- file added to make itself easier to read.
        self.multicast(others(id), a[2])

    elseif cmd == "kick" then
        for _, c in ipairs(others(id)) do self.disconnect(c) end

    elseif cmd == "join" then
        self.join_group(id, a[2])
        reply(id, "ok")

    elseif cmd == "leave" then
        self.leave_group(id, a[2])
        reply(id, "ok")

    elseif cmd == "gsend" then
        self.group_send(a[2], a[3])

    elseif cmd == "pipe" then
        local o = others(id)[1]
        if o then self.pipe(id, o) end
        reply(id, "ok")

    elseif cmd == "unpipe" then
        self.unpipe(id)

    -- Driven from a client that is NOT in the pipe, because process_message()
    -- forwards a piped client's bytes and RETURNS before on_client_message --
    -- "bypassing Lua callbacks", as its own comment says.  A piped client
    -- therefore cannot ask for anything at all, including its own unpipe, and
    -- the two commands below are the only shape in which unpipe can be tested.
    elseif cmd == "pipe2" then
        local o = others(id)
        if #o >= 2 then self.pipe(o[1], o[2]) end
        reply(id, "ok")

    elseif cmd == "unpipe2" then
        local o = others(id)
        if #o >= 1 then self.unpipe(o[1]) end
        reply(id, "ok")

    elseif cmd == "upstreams" then
        reply(id, "upstreams=" .. tostring(#self.upstreams()))
    end
end

function on_send(msg)
    socketley.log("API on_send=[" .. msg .. "]")
end
LUAEOF

# Two --mode inout servers, identical but for the presence of on_message.
RELAY_ON_LUA="$SOCKETLEY_TMPD/relay_on.lua"
cat > "$RELAY_ON_LUA" <<'LUAEOF'
function on_message(msg)
    socketley.log("RELAYON saw=[" .. msg .. "]")
end
LUAEOF
RELAY_OFF_LUA="$SOCKETLEY_TMPD/relay_off.lua"
cat > "$RELAY_OFF_LUA" <<'LUAEOF'
function on_start()
    socketley.log("RELAYOFF started")
end
LUAEOF

UP_LUA="$SOCKETLEY_TMPD/up.lua"
cat > "$UP_LUA" <<'LUAEOF'
function on_upstream_connect(conn_id)
    socketley.log("UP connect=" .. tostring(conn_id) ..
                  " count=" .. tostring(#self.upstreams()))
    self.upstream_send(conn_id, "HELLO-FROM-UPSTREAM-SEND")
end
function on_upstream(conn_id, data)
    socketley.log("UP data=" .. tostring(conn_id) .. " [" .. data .. "]")
end
function on_upstream_disconnect(conn_id)
    socketley.log("UP disconnect=" .. tostring(conn_id))
end
function on_client_message(id, msg)
    if msg == "ubcast" then self.upstream_broadcast("HELLO-FROM-UPSTREAM-BCAST") end
end
LUAEOF

UP_TARGET_LUA="$SOCKETLEY_TMPD/uptarget.lua"
cat > "$UP_TARGET_LUA" <<'LUAEOF'
function on_client_message(id, msg)
    socketley.log("UPTARGET got=[" .. msg .. "]")
    self.send(id, "PONG-" .. msg)
end
LUAEOF

said() {
    local pattern=$1 deadline=$(( $(date +%s) + ${2:-8} ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        grep -qaE "$pattern" "$SOCKETLEY_DLOG" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}
hits() { grep -ac "$1" "$2" 2>/dev/null || true; }
# got TRANSCRIPT PATTERN — how many lines of a transcript match.
got() { grep -c "$2" <<<"$1" 2>/dev/null || true; }

create_ok "RPC server created" "$BIN" create server api \
    -p "$API_PORT" --mode in --lua "$API_LUA" -s
create_ok "relaying server WITH on_message created" "$BIN" create server relay_on \
    -p "$RELAY_ON_PORT" --mode inout --lua "$RELAY_ON_LUA" -s
create_ok "relaying server WITHOUT on_message created" "$BIN" create server relay_off \
    -p "$RELAY_OFF_PORT" --mode inout --lua "$RELAY_OFF_LUA" -s
create_ok "upstream target created" "$BIN" create server up_target \
    -p "$UP_TARGET_PORT" --mode in --lua "$UP_TARGET_LUA" -s
ready_tcp 127.0.0.1 "$UP_TARGET_PORT" 10 || echo "  NOTE: the upstream target never accepted"
create_ok "server with an upstream created" "$BIN" create server up_srv \
    -p "$UP_PORT" --mode in --upstream "127.0.0.1:$UP_TARGET_PORT" --lua "$UP_LUA" -s

for p in "$API_PORT" "$RELAY_ON_PORT" "$RELAY_OFF_PORT" "$UP_PORT"; do
    ready_tcp 127.0.0.1 "$p" 10 || echo "  NOTE: nothing accepted on $p"
done

# ── 1. clients(), peer_ip() ─────────────────────────────────────────────────
#
# Client 2 says whoami and is answered BEFORE client 1 is asked to count: the
# reply is proof that the server has accepted it, where a sleep is a guess that
# is wrong under load and produces "clients=1" for a build with nothing wrong
# with it.
T=$(tx "$API_PORT" c1 c2 s1:whoami r1 s2:whoami r2 s1:clients r1 s1:peerip r1 x1 x2)
ID1=$(sed -n 's/^R1:id=//p' <<<"$T" | head -1)
if [ -n "$ID1" ]; then pass; else
    fail "the RPC channel answers at all" "no id came back" \
         "every assertion in this file is a reply on this channel" \
         "transcript: $(tr '\n' '|' <<<"$T")"
fi
assert_eq "self.clients() counts both connections and includes the asker" \
          "R1:clients=2 mine=true" "$(grep -o 'R1:clients=[0-9]* mine=[a-z]*' <<<"$T" | head -1)" \
    "two clients are connected when this is asked; a count of 1 means the" \
    "second is not in the table, and mine=false means the caller is not"
assert_eq "self.peer_ip() answers the connection's own address" \
          "R1:peerip=127.0.0.1" "$(grep -o 'R1:peerip=[0-9.]*' <<<"$T" | head -1)"

# ── 2. set_data / get_data: per connection, and nil deletes ─────────────────
#
# Both clients are connected throughout.  A store that is per-runtime rather
# than per-connection returns client 2's value to client 1 and passes any test
# that only ever has one client on the wire.
T=$(tx "$API_PORT" c1 c2 \
        s1:whoami r1 s2:whoami r2 \
        "s1:setdata colour red" r1 \
        "s2:setdata colour blue" r2 \
        "s1:getdata colour" r1 \
        "s2:getdata colour" r2 \
        "s1:getdataof colour" r1 \
        "s1:deldata colour" r1 \
        "s1:getdata colour" r1 \
        "s2:getdata colour" r2 \
        x1 x2)
assert_eq "get_data returns what this connection set" \
          "R1:getdata=[red]" "$(grep -o 'R1:getdata=\[[a-z]*\]' <<<"$T" | head -1)"
assert_eq "...and the other connection has its own value under the same key" \
          "R2:getdata=[blue]" "$(grep -o 'R2:getdata=\[[a-z]*\]' <<<"$T" | head -1)" \
    "both clients are connected at once, so a per-runtime store answers 'red'" \
    "or 'blue' to both and this is the assertion that sees it"
assert_eq "get_data(other_id, key) reaches the OTHER connection's value" \
          "R1:getdataof=[blue]" "$(grep -o 'R1:getdataof=\[[a-z]*\]' <<<"$T" | head -1)" \
    "the id argument selects the connection; if it were ignored this would" \
    "answer red, which is what the caller stored under the same key"
assert_eq "set_data(id, key, nil) deletes rather than storing" \
          "R1:getdata=[nil]" "$(grep -o 'R1:getdata=\[[a-z]*\]' <<<"$T" | sed -n 2p)" \
    "get_data returns nil for an absent key, so a delete that stored an empty" \
    "string would answer [] here"
assert_eq "...and deleting one connection's key leaves the other's alone" \
          "R2:getdata=[blue]" "$(grep -o 'R2:getdata=\[[a-z]*\]' <<<"$T" | sed -n 2p)"

# ── 3. broadcast, multicast, disconnect ────────────────────────────────────
#
# Both clients speak first, and not for tidiness.  Relay traffic for a client
# that has never sent a byte is held until the connection is classified, and on
# this build the FIRST message so held is never released at all — measured, and
# reported separately; it is not what any assertion here is about.  A whoami
# from each client settles both connections so that these scenarios measure the
# call under test rather than that.
T=$(tx "$API_PORT" c1 c2 s1:whoami r1 s2:whoami r2 \
        "s1:bcast BROADCAST-PAYLOAD" w:0.4 r1 r2 x1 x2)
assert_eq "self.broadcast() reaches the client that asked for it" \
          "1" "$(got "$T" 'R1:BROADCAST-PAYLOAD')"
assert_eq "self.broadcast() reaches the other client too" \
          "1" "$(got "$T" 'R2:BROADCAST-PAYLOAD')"
assert_eq "on_send fired with the payload the runtime sent" \
          "1" "$(hits 'API on_send=\[BROADCAST-PAYLOAD\]' "$SOCKETLEY_DLOG")"

T=$(tx "$API_PORT" c1 c2 s1:whoami r1 s2:whoami r2 \
        "s1:mcast MULTICAST-PAYLOAD" w:0.4 r1 r2 x1 x2)
assert_eq "self.multicast() reaches the client it named" \
          "1" "$(got "$T" 'R2:MULTICAST-PAYLOAD')"
assert_eq "self.multicast() does NOT reach the client it did not name" \
          "0" "$(got "$T" 'R1:MULTICAST-PAYLOAD')" \
    "without this half, multicast is indistinguishable from broadcast"

T=$(tx "$API_PORT" c1 c2 s1:whoami r1 s2:whoami r2 \
        "s1:kick" w:0.5 r2 "s1:clients" r1 x1 x2)
assert_eq "self.disconnect() closes the client it named" \
          "1" "$(got "$T" 'R2:<closed>')"
assert_eq "...and the runtime no longer counts it" \
          "R1:clients=1 mine=true" "$(grep -o 'R1:clients=[0-9]* mine=[a-z]*' <<<"$T" | head -1)" \
    "the caller is still there, so this also says disconnect took the client" \
    "it was told to and not simply everything"

# ── 3b. self.connections, self.protocol, and the `server` alias ────────────
T=$(tx "$API_PORT" c1 c2 s1:whoami r1 s2:whoami r2 s1:ident r1 x1 x2)
assert_eq "self.connections() on a server counts both connections" \
          "R1:conns=2 proto=tcp alias_same=true alias_conns=2" \
          "$(grep -o 'R1:conns=.*' <<<"$T" | head -1)" \
    "four tables bind a method called connections and only the other three" \
    "were ever asked.  alias_same is rawequal: register_bindings does" \
    "m_lua[type_to_string(type)] = self, so the global 'server' is not a copy" \
    "of the table, it IS the table — a build that made a second table with the" \
    "same methods would satisfy 'a call through it works' and would silently" \
    "give a script two places to keep state" \
    "transcript: $(tr '\n' '|' <<<"$T")"

# ── 3c. on_send fires for what the runtime broadcasts, and not for a reply ──
#
# invoke_on_send has two call sites — server broadcast and the client's
# send — and self.send(id, msg) is not one of them.  That asymmetry is not
# written down anywhere, and a script that logs outbound traffic in on_send
# sees broadcasts and silently misses every targeted reply.  Pinned as it is so
# that changing it is a decision; the assertion is a count of ZERO for a payload
# that was definitely sent, which is the only shape that can catch it.
BEFORE_SEND=$(hits 'API on_send=' "$SOCKETLEY_DLOG")
T=$(tx "$API_PORT" c1 s1:whoami r1 s1:sendone w:0.4 r1 x1)
assert_eq "control: the targeted send did arrive at the client" \
          "1" "$(got "$T" 'R1:DIRECT-SEND-PAYLOAD')" \
    "if it never arrived, the zero below is about a send that did not happen"
assert_eq "on_send does NOT fire for self.send(id, msg)" \
          "0" "$(hits 'API on_send=\[DIRECT-SEND-PAYLOAD\]' "$SOCKETLEY_DLOG")" \
    "current behaviour: invoke_on_send is reached from broadcast and from" \
    "the client's send, and from nowhere else"
assert_eq "...and no on_send line was produced at all by that reply" \
          "$BEFORE_SEND" "$(hits 'API on_send=' "$SOCKETLEY_DLOG")" \
    "the stronger form of the same claim: not merely 'not with that payload'"

# ── 4. groups ──────────────────────────────────────────────────────────────
T=$(tx "$API_PORT" c1 c2 s1:whoami r1 s2:whoami r2 \
        "s1:join team" r1 w:0.3 \
        "s2:gsend team GROUP-PAYLOAD" w:0.4 r1 r2 \
        "s1:leave team" r1 w:0.3 \
        "s2:gsend team GROUP-AFTER-LEAVE" w:0.4 r1 r2 x1 x2)
assert_eq "group_send reaches the client that joined" \
          "1" "$(got "$T" 'R1:GROUP-PAYLOAD')"
assert_eq "group_send does not reach a client that never joined" \
          "0" "$(got "$T" 'R2:GROUP-PAYLOAD')"
assert_eq "leave_group stops the delivery" \
          "0" "$(got "$T" 'R1:GROUP-AFTER-LEAVE')" \
    "paired with the join above: 'it did not arrive' on its own is also true" \
    "of a group_send that never sends anything to anybody"

# ── 5. pipe / unpipe ───────────────────────────────────────────────────────
#
# THREE clients, and the one that gives the orders is not in the pipe.  The old
# shape had two, with the piped client asking for its own unpipe -- which
# process_message() can never deliver, because the pipe forwards and returns
# before on_client_message runs.  That assertion passed anyway, and only
# because pipe() forwarded the parsed line WITHOUT its newline: `unpipe` and
# `AFTER-THE-PIPE` arrived merged as one unsplittable token, so the string the
# assertion looked for was not there.  Framing the pipe made the vacuum
# visible.
T=$(tx "$API_PORT" c1 c2 c3 s1:whoami r1 s2:whoami r2 s3:whoami r3 \
        "s1:pipe2" r1 w:0.3 \
        "s2:THROUGH-THE-PIPE" w:0.4 r3 \
        "s1:unpipe2" r1 w:0.4 \
        "s2:AFTER-THE-PIPE" w:0.4 r3 x1 x2 x3)
assert_eq "self.pipe() carries one client's bytes to the other" \
          "1" "$(got "$T" 'R3:THROUGH-THE-PIPE')"
assert_eq "self.unpipe() stops it" \
          "0" "$(got "$T" 'R3:AFTER-THE-PIPE')" \
    "the pair is the assertion: a pipe that never carried anything satisfies" \
    "the second line on its own"

# And the framing, which is the reason the pair above could be vacuous for so
# long.  parse_partial() hands the line without its newline and pipe() used to
# forward exactly that, so two lines arrived as one token the reader could
# never split again -- while broadcast(), send() and group_send() all put the
# separator back.
T=$(tx "$API_PORT" c1 c2 c3 s1:whoami r1 s2:whoami r2 s3:whoami r3 \
        "s1:pipe2" r1 w:0.3 \
        "s2:LINE-ONE" "s2:LINE-TWO" w:0.5 r3 x1 x2 x3)
assert_eq "two lines through a pipe arrive as two lines (first)" \
          "1" "$(got "$T" 'R3:LINE-ONE')" \
    "0 for both means they arrived merged as LINE-ONELINE-TWO, which is what" \
    "forwarding the parsed line without its separator produces"
assert_eq "two lines through a pipe arrive as two lines (second)" \
          "1" "$(got "$T" 'R3:LINE-TWO')"

# ── 6. on_message suppresses the default relay of --mode inout ─────────────
#
# The two servers differ in one thing and one thing only: whether the script
# defines on_message.  Same mode, same two clients, same payload, and in both
# cases both clients speak once first for the reason given in section 3.
RELAY_TX=(c1 c2 s1:hello s2:hello w:0.5 r1 r2 "s1:RELAY-PROBE" w:0.6 r2 x1 x2)
T=$(tx "$RELAY_OFF_PORT" "${RELAY_TX[@]}")
assert_eq "control: --mode inout relays to the other client with no on_message" \
          "1" "$(got "$T" 'R2:RELAY-PROBE')" \
    "if this fails the suppression assertion below is about a server that" \
    "does not relay at all, and says nothing about on_message"

T=$(tx "$RELAY_ON_PORT" "${RELAY_TX[@]}")
assert_eq "defining on_message suppresses that relay" \
          "0" "$(got "$T" 'R2:RELAY-PROBE')" \
    "same mode, same two clients, same payload — the only difference is that" \
    "the script defines on_message, and that alone hands the traffic to it"
assert_eq "...and the script saw the message it took over" \
          "1" "$(hits 'RELAYON saw=\[RELAY-PROBE\]' "$SOCKETLEY_DLOG")" \
    "otherwise 'nothing arrived' is satisfied by a server that dropped it"

# ── 7. the upstream family ─────────────────────────────────────────────────
said 'UP connect=' 12 || true
assert_eq "on_upstream_connect fired, and self.upstreams() counts the leg" \
          "1" "$(hits 'UP connect=1 count=1' "$SOCKETLEY_DLOG")" \
    "the conn_id is documented as 1-based and stable"
said 'UPTARGET got=' 12 || true
assert_eq "self.upstream_send() reached the far end, with the payload" \
          "1" "$(hits 'UPTARGET got=\[HELLO-FROM-UPSTREAM-SEND\]' "$SOCKETLEY_DLOG")"
said 'UP data=' 12 || true
assert_eq "on_upstream carried the reply back, with the conn_id" \
          "1" "$(hits 'UP data=1 \[PONG-HELLO-FROM-UPSTREAM-SEND\]' "$SOCKETLEY_DLOG")"

tx "$UP_PORT" c1 w:0.3 s1:ubcast w:0.6 x1 >/dev/null
said 'UPTARGET got=\[HELLO-FROM-UPSTREAM-BCAST\]' 10 || true
assert_eq "self.upstream_broadcast() reached the far end too" \
          "1" "$(hits 'UPTARGET got=\[HELLO-FROM-UPSTREAM-BCAST\]' "$SOCKETLEY_DLOG")"

"$BIN" stop up_target >/dev/null 2>&1 || true
said 'UP disconnect=' 12 || true
assert_eq "on_upstream_disconnect fired when the far end went away" \
          "1" "$(hits 'UP disconnect=1' "$SOCKETLEY_DLOG")"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
