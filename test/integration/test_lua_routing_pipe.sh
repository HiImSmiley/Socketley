#!/usr/bin/env bash
# Integration test: self.get_route, self.owner_broadcast, and socketley.pipe.
#
# ─── WHAT WAS LEFT ──────────────────────────────────────────────────────────
#
# test_route_identity.sh holds down self.route, self.unroute and
# self.owner_send with real assertions.  Three neighbours of theirs were called
# by nothing at all:
#
#   self.get_route(id)      the only way a script can ask where a connection
#                           went, and the only one of the routing calls that
#                           returns an answer rather than performing an action
#   self.owner_broadcast()  a sub-server reaching every client of its owner
#   socketley.pipe(...)     the four-argument cross-runtime form
#
# ─── THE PAIR THAT MAKES get_route AN ASSERTION ────────────────────────────
#
# "It returned rt_sub" on its own is satisfied by a build that returns the only
# sub-server it knows about regardless of who is asking.  So it is asked three
# times: about a routed connection (the target's name), about a connection that
# was never routed (nil), and about the same routed connection after unroute
# (nil again).  The third is the one that cannot pass on a no-op — a build that
# answered from a table it never cleared would still say rt_sub.
#
# ─── socketley.pipe IS TWO CALLS, AND THE ARGUMENT COUNT SAYS WHICH ────────
#
# The four-argument form used to read as though it joined two descriptors
# across two runtimes.  It never did: for src ~= dst it calls
# route_client(src_fd, dst_name) and the fourth argument was discarded
# entirely, so a script that went to the trouble of obtaining a descriptor from
# the destination was told it had been used.
#
# The arity is the request now.  Four is the pipe — two connections of ONE
# server, paired through pipe_peer_fd, which is an index into that server's own
# table and cannot name anything outside it.  Three is the route — the
# connection is handed to the destination RUNTIME, which decides what answers
# it.  Asking for four across two runtimes is asking for the thing that does
# not exist, and is refused by name rather than served as the other one.
#
# Both sides are asserted below: the refusal, and the three-argument form
# delivering the destination traffic that was addressed to no descriptor.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luaroute

PB=$((SL_PORT_BASE+180))
PAR_PORT=$((PB + 0))
SUB_PORT=$((PB + 1))
A_PORT=$((PB + 2))
B_PORT=$((PB + 3))

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
    "$BIN" stop  rt_par rt_sub pipe_a pipe_b 2>/dev/null || true
    sleep 0.3
    "$BIN" remove rt_par rt_sub pipe_a pipe_b 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: get_route, owner_broadcast, socketley.pipe ==="

daemon_start "$BIN"

# The transcript runner from test_lua_server_api.sh, for the same reason: what a
# client did NOT receive is half of what is asserted, so every read is a bounded
# drain rather than a blocking read.  Unterminated bytes are reported too —
# self.pipe and the routed path forward exactly what was sent.
cat > "$SOCKETLEY_TMPD/tx.py" <<'PYEOF'
import select, socket, sys, time
port = int(sys.argv[1])
conns, bufs = {}, {}

def drain(i, budget=0.7):
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
    if bufs[i].strip():
        print("R%d:%s" % (i, bufs[i].strip()), flush=True)
        bufs[i] = ""

for act in sys.argv[2:]:
    kind = act[0]
    if kind == "c":
        i = int(act[1:])
        conns[i] = socket.create_connection(("127.0.0.1", port), 5)
        bufs[i] = ""
    elif kind == "s":
        i, text = act[1:].split(":", 1)
        conns[int(i)].sendall((text + "\n").encode())
    elif kind == "r":
        drain(int(act[1:]))
    elif kind == "x":
        conns[int(act[1:])].close()
    elif kind == "w":
        time.sleep(float(act.split(":", 1)[1]))
PYEOF
tx() { local p=$1; shift; python3 "$SOCKETLEY_TMPD/tx.py" "$p" "$@"; }

SUB_LUA="$SOCKETLEY_TMPD/sub.lua"
cat > "$SUB_LUA" <<'LUAEOF'
function on_client_message(id, msg)
    socketley.log("SUB got=[" .. msg .. "]")
    if msg == "ob" then
        socketley.log("SUB ob=" .. tostring(self.owner_broadcast("OWNER-BCAST")))
    end
end
LUAEOF

PAR_LUA="$SOCKETLEY_TMPD/par.lua"
cat > "$PAR_LUA" <<LUAEOF
local SUB_PORT = $SUB_PORT
local SUB_LUA  = "$SUB_LUA"
LUAEOF
cat >> "$PAR_LUA" <<'LUAEOF'
local routed = nil

-- The sub-server is spawned from a message and NOT from on_start.
--
-- Starting a runtime from inside on_start WEDGES THE DAEMON — permanently, and
-- in the worst shape a failure can take: the IPC socket goes on accepting
-- connections and never answers one, so it looks like a hang rather than a
-- crash and every other runtime that daemon serves is lost with it.  Isolated
-- to the start, not to the create, and not to either spelling of it:
--
--     on_start,           socketley.create{ start = true }   WEDGED
--     on_start,           create then socketley.start()      WEDGED
--     on_client_message,  socketley.create{ start = true }   answers
--
-- Reported as a defect.  test_route_identity.sh spawns from a message too, and
-- says only that a routed client's messages go elsewhere — so the reason this
-- shape is the one that works has not been written down anywhere until now.
-- Cost of learning it the other way: one run whose every assertion was red for
-- a reason none of them named.
function on_client_message(id, msg)
    if msg == "spawn" then
        socketley.create("server", "rt_sub", { port = SUB_PORT, config = SUB_LUA })
        socketley.start("rt_sub")
        self.send(id, "spawn=ok")

    elseif msg == "route" then
        routed = id
        self.send(id, "route=" .. tostring(self.route(id, "rt_sub")))

    elseif msg == "getroute" then
        -- Asked from the admin connection ABOUT the routed one: a routed
        -- client's own messages no longer reach this runtime.
        self.send(id, "getroute=" .. tostring(self.get_route(routed)))

    elseif msg == "getroute_self" then
        self.send(id, "getroute_self=" .. tostring(self.get_route(id)))

    elseif msg == "unroute" then
        local left = self.unroute(routed)
        self.send(id, "unroute=" .. tostring(left) ..
                      " after=" .. tostring(self.get_route(routed)))
    end
end
LUAEOF

A_LUA="$SOCKETLEY_TMPD/a.lua"
cat > "$A_LUA" <<'LUAEOF'
local first = nil

function on_client_message(id, msg)
    if msg == "cross" then
        -- Three arguments: route this connection to the runtime named.
        self.send(id, "cross=" .. tostring(socketley.pipe("pipe_a", id, "pipe_b")))

    elseif msg == "cross4" then
        -- Four, across two runtimes: the combination that does not exist.
        self.send(id, "cross4=" .. tostring(socketley.pipe("pipe_a", id, "pipe_b", 0)))

    elseif msg == "crossmissing" then
        self.send(id, "crossmissing=" ..
                  tostring(socketley.pipe("pipe_a", id, "nosuchruntime")))

    elseif msg == "hold" then
        first = id
        self.send(id, "held")

    elseif msg == "joinme" then
        -- The same-runtime form: src and dst are this runtime, so it pairs the
        -- two descriptors instead of routing.
        self.send(id, "join=" .. tostring(socketley.pipe("pipe_a", first, "pipe_a", id)))

    else
        socketley.log("PIPEA got=[" .. msg .. "]")
    end
end
LUAEOF

B_LUA="$SOCKETLEY_TMPD/b.lua"
cat > "$B_LUA" <<'LUAEOF'
function on_client_message(id, msg)
    socketley.log("PIPEB got=[" .. msg .. "]")
end
LUAEOF

hits() { grep -ac "$1" "$2" 2>/dev/null || true; }
got()  { grep -c "$2" <<<"$1" 2>/dev/null || true; }
said() {
    local pattern=$1 deadline=$(( $(date +%s) + ${2:-8} ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        grep -qaE "$pattern" "$SOCKETLEY_DLOG" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}

# In the daemon, all of them: self.route and socketley.pipe both reach for the
# runtime map, which a worker does not have — test_worker_lua_refusal.sh covers
# the refusal, and this file covers what the calls do where they are allowed.
create_ok "parent server created in the daemon" "$BIN" create server rt_par \
    -p "$PAR_PORT" --mode in --lua "$PAR_LUA" --daemon-process -s
create_ok "pipe source created in the daemon" "$BIN" create server pipe_a \
    -p "$A_PORT" --mode in --lua "$A_LUA" --daemon-process -s
create_ok "pipe destination created in the daemon" "$BIN" create server pipe_b \
    -p "$B_PORT" --mode in --lua "$B_LUA" --daemon-process -s
for p in "$PAR_PORT" "$A_PORT" "$B_PORT"; do
    ready_tcp 127.0.0.1 "$p" 10 || echo "  NOTE: nothing accepted on $p"
done
# Bring the sub-server up through the parent's own script, then wait for it.
tx "$PAR_PORT" c1 s1:spawn r1 x1 >/dev/null
ready_tcp 127.0.0.1 "$SUB_PORT" 10 || echo "  NOTE: the sub-server never accepted"

# ── 1. get_route, three ways ───────────────────────────────────────────────
#
# One transcript: client 1 is routed, client 2 is the admin.  A routed client's
# messages go to the sub-server, so the questions have to come from the other
# connection.
T=$(tx "$PAR_PORT" c1 c2 \
        s1:route r1 w:0.4 \
        s2:getroute r2 \
        s2:getroute_self r2 \
        s2:unroute r2 x1 x2)
assert_eq "control: the client was routed" \
          "R1:route=true" "$(grep -o 'R1:route=[a-z]*' <<<"$T" | head -1)" \
    "everything below is about where a connection went; if it went nowhere," \
    "nil is the right answer to all three questions and none of them mean" \
    "anything.  transcript: $(tr '\n' '|' <<<"$T")"
assert_eq "self.get_route() names the runtime the connection was routed to" \
          "R2:getroute=rt_sub" "$(grep -o 'R2:getroute=[a-z_]*' <<<"$T" | head -1)"
assert_eq "self.get_route() is nil for a connection that was never routed" \
          "R2:getroute_self=nil" "$(grep -o 'R2:getroute_self=[a-z_]*' <<<"$T" | head -1)" \
    "the same call, the same runtime, a different connection — without this," \
    "'it said rt_sub' is satisfied by a build that names the only sub-server" \
    "it knows about whoever is asking"
assert_eq "self.unroute() clears it, and get_route says so afterwards" \
          "R2:unroute=true after=nil" \
          "$(grep -o 'R2:unroute=[a-z]* after=[a-z_]*' <<<"$T" | head -1)" \
    "the change that must survive: a build answering from a table it never" \
    "cleared still says rt_sub here, and passes both assertions above"

# ── 2. owner_broadcast reaches the owner's clients ─────────────────────────
#
# Client 1 is routed to the sub-server and then speaks; the sub-server calls
# owner_broadcast; the parent's OTHER client — which is not routed and never
# talked to the sub — is where the message has to land.
T=$(tx "$PAR_PORT" c1 c2 s2:whoami r2 \
        s1:route r1 w:0.4 \
        s1:ob w:0.6 r2 r1 x1 x2)
said 'SUB ob=' 8 || true
assert_eq "control: the routed client's message reached the sub-server" \
          "1" "$(hits 'SUB got=\[ob\]' "$SOCKETLEY_DLOG")" \
    "owner_broadcast is called from there; if the message never arrived the" \
    "call never happened"
assert_eq "self.owner_broadcast() reports that it found its owner" \
          "1" "$(hits 'SUB ob=true' "$SOCKETLEY_DLOG")" \
    "false is what it returns when the owner is unset, gone, or not a server"
assert_eq "...and the payload reaches a client of the owner" \
          "1" "$(got "$T" 'R2:OWNER-BCAST')" \
    "that client is connected to the parent and has never spoken to the" \
    "sub-server; reaching it is the whole point of the call"

# ── 3. socketley.pipe, three-argument cross-runtime form ───────────────────
T=$(tx "$A_PORT" c1 s1:cross r1 w:0.4 "s1:CROSSED-PAYLOAD" w:0.6 x1)
assert_eq "socketley.pipe() across two runtimes reports success" \
          "R1:cross=true" "$(grep -o 'R1:cross=[a-z]*' <<<"$T" | head -1)"
said 'PIPEB got=' 8 || true
assert_eq "...and the source's traffic arrives at the destination runtime" \
          "1" "$(hits 'PIPEB got=\[CROSSED-PAYLOAD\]' "$SOCKETLEY_DLOG")" \
    "the connection is routed by NAME and the destination decides what" \
    "answers it; there is no destination descriptor in this, which is why" \
    "the form that offers one is refused below"
assert_eq "...and the traffic no longer reaches the source runtime" \
          "0" "$(hits 'PIPEA got=\[CROSSED-PAYLOAD\]' "$SOCKETLEY_DLOG")" \
    "a build that copied rather than moved the connection satisfies the line" \
    "above and fails this one"

T=$(tx "$A_PORT" c1 s1:crossmissing r1 x1)
assert_eq "socketley.pipe() to a runtime that does not exist returns false" \
          "R1:crossmissing=false" \
          "$(grep -o 'R1:crossmissing=[a-z]*' <<<"$T" | head -1)"

# The fourth argument across two runtimes is the request that does not exist.
# It used to be accepted, discarded, and reported as success — and this file
# asserted that, because it was the behaviour.
T=$(tx "$A_PORT" c1 s1:cross4 r1 x1)
assert_eq "...and a destination descriptor across two runtimes is refused" \
          "R1:cross4=false" "$(grep -o 'R1:cross4=[a-z]*' <<<"$T" | head -1)" \
    "pipe_peer_fd is an index into ONE server's connection table, so there is" \
    "no cross-runtime pairing to make; the call routed by name and threw the" \
    "descriptor away while answering true"

# ── 4. socketley.pipe, same-runtime form ───────────────────────────────────
#
# src and dst name this runtime, so it pairs the two descriptors instead of
# routing — the same thing self.pipe does, reached through the other spelling.
T=$(tx "$A_PORT" c1 c2 s1:hold r1 s2:joinme r2 w:0.4 \
        "s1:SAME-RUNTIME-PAYLOAD" w:0.6 r2 x1 x2)
assert_eq "socketley.pipe() with one runtime named twice reports success" \
          "R2:join=true" "$(grep -o 'R2:join=[a-z]*' <<<"$T" | head -1)"
assert_eq "...and one client's bytes come out of the other" \
          "1" "$(got "$T" 'R2:SAME-RUNTIME-PAYLOAD')" \
    "the fast path, which is lua_pipe under another name"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
