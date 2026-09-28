#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Integration test: what a routed connection is called, and what a stale name does.
#
# Almost every assertion here is about a message that must NOT arrive, so the
# first three are controls.  A file of silences passes against a build where
# routing does not work at all, and that is exactly the shape this feature
# fails in — the sub-server's script is handed an id, and whether that id means
# anything is invisible from outside until it means the wrong thing.
#
# The defect the last four are about: a sub-server was handed the *parent's*
# descriptor number for a routed client, and owner_send wrote that number
# straight into the parent's connection table with no check that it still named
# the same connection.  A routed client leaves, the kernel reissues its
# descriptor to the next accept, and the sub-server's next owner_send on the id
# it was given lands in an unrelated client's stream.
#
# Runs its own daemon on its own socket and state directory, and kills it by
# the pid it started, never by name: other suites and other people's daemons
# are on this machine.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_ports.sh"

WORK=$(mktemp -d /tmp/socketley-routeid-XXXXXX)
export SOCKETLEY_SOCKET="$WORK/s.sock"
. "$(dirname "$0")/lib_daemon.sh"
daemon_watch "$WORK"   # its processes go with it if it is killed
export HOME="$WORK/home"
mkdir -p "$HOME"

PARENT_PORT=$((SL_PORT_BASE+771))
SUB_PORT=$((SL_PORT_BASE+772))
LONE_PORT=$((SL_PORT_BASE+773))
PAR2_PORT=$((SL_PORT_BASE+774))
DPID=""

cleanup() {
    [ -n "$DPID" ] && kill -9 "$DPID" 2>/dev/null
    sleep 0.3
    rm -rf "$WORK"
}
trap cleanup EXIT

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

echo "=== Integration: routed-connection identity ==="

# ─── The two scripts ────────────────────────────────────────────────────────
#
# The sub-server is created from the parent's Lua rather than from the command
# line, because that is what sets the ownership owner_send needs — and it is
# created on the first message rather than in on_start, which wedges the daemon
# on every build tested (see the report; it predates this change).

cat > "$WORK/sub.lua" <<'EOLUA'
victim = nil

function on_connect(client_id)
    -- Reported so the test can see which namespace the id came out of.
    socketley.log("sub_connect " .. client_id)
end

function on_disconnect(client_id)
    socketley.log("sub_disconnect " .. client_id)
end

function on_client_message(client_id, msg)
    if msg == "remember" then
        victim = client_id
        self.send(client_id, "remembered=" .. tostring(client_id))
        return
    end
    if msg == "ping" then
        self.send(client_id, "pong-from-sub")
        return
    end
    if msg == "owner_ping" then
        local sent = self.owner_send(client_id, "owner-pong")
        socketley.log("owner_ping sent=" .. tostring(sent))
        return
    end
    if msg == "leak" then
        -- Aimed at a client that has gone.  On a build that names connections
        -- by descriptor this reaches whoever inherited the number.
        local sent = false
        if victim then sent = self.owner_send(victim, "SECRET") end
        self.send(client_id, "leak_sent=" .. tostring(sent) ..
                             " victim=" .. tostring(victim))
        return
    end
end
EOLUA

cat > "$WORK/parent.lua" <<EOLUA
last_routed = nil

function on_connect(client_id)
    self.send(client_id, "id=" .. client_id)
end

function on_client_message(client_id, msg)
    if msg == "spawn" then
        socketley.create("server", "rid_sub", { port = $SUB_PORT, config = "$WORK/sub.lua" })
        socketley.start("rid_sub")
        return
    end
    if msg == "join" then
        if self.route(client_id, "rid_sub") then last_routed = client_id end
        return
    end
    -- Asked by a *different* client, because a routed client's messages do not
    -- come here any more — that is what being routed means.
    if msg == "unroute_last" then
        local left = false
        if last_routed then left = self.unroute(last_routed) end
        self.send(client_id, "unrouted=" .. tostring(left))
        return
    end
    self.send(client_id, "parent-echo:" .. msg)
end
EOLUA

# ─── Daemon ─────────────────────────────────────────────────────────────────

"$BIN" daemon >"$WORK/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 60); do
    [ -S "$SOCKETLEY_SOCKET" ] && "$BIN" ls >/dev/null 2>&1 && break
    sleep 0.1
done
if ! "$BIN" ls >/dev/null 2>&1; then
    echo "  FAIL: daemon did not come up"
    exit 1
fi

# --daemon-process WAS load-bearing here, and is not any more.
#
# The paragraph this replaces was correct when it was written and is worth
# recording rather than deleting.  It said: this parent's script calls
# socketley.create() and socketley.start(), which reach for the runtime map;
# a worker was refused them by name; so a parent left out of process never
# created rid_sub, nothing listened on SUB_PORT, and the harness died on its
# first connect there with every assertion below unrun.
#
# Two changes since have removed both halves.  The four map calls travel to the
# daemon now, and self.route reaches a runtime in another process through
# shared/route_relay.h.  Measured on this file rather than assumed: with the
# flag removed it went 9/14, then 13/14, then 14/14 as the two landed, and the
# fourteenth was a real leak the second one closed.
#
# The flag is gone rather than kept, and that is the stronger arrangement: with
# it, "the id is not a descriptor" was a statement about naming inside one
# address space, which is the easy case. Without it the parent and its
# sub-server are in different processes and the id has to survive the crossing
# -- which is what conn_identity.h is for and what these fourteen assertions
# are now actually testing.
"$BIN" create server rid_par -p "$PARENT_PORT" --lua "$WORK/parent.lua" \
       -s >/dev/null 2>&1
sleep 0.5

OUT=$(python3 - "$PARENT_PORT" "$SUB_PORT" <<'PY'
import socket, sys, time

PARENT = int(sys.argv[1])
SUB    = int(sys.argv[2])

def conn(port):
    s = socket.create_connection(("127.0.0.1", port))
    s.settimeout(1.2)
    return s

def rd(s):
    try:
        return s.recv(8192).decode(errors="replace")
    except Exception:
        return ""

def drain(s, seconds=0.5):
    """Everything that arrives within the window, not just the first packet."""
    out = ""
    end = time.time() + seconds
    while time.time() < end:
        try:
            chunk = s.recv(8192)
        except Exception:
            break
        if not chunk:
            break
        out += chunk.decode(errors="replace")
    return out

results = []
def check(name, cond, detail=""):
    results.append("%s|%s|%s" % ("ok" if cond else "bad", name, detail))

# Bring the sub-server up.
b = conn(PARENT); rd(b); b.sendall(b"spawn\n"); time.sleep(0.9); b.close(); time.sleep(0.3)

# ── Controls: routing works at all ──────────────────────────────────────────
c1 = conn(PARENT)
own_id = rd(c1).strip()                       # "id=<parent fd>"
c1.sendall(b"join\n"); time.sleep(0.3)

c1.sendall(b"ping\n")
answer = drain(c1, 0.6)
check("a routed client reaches the sub-server", "pong-from-sub" in answer,
      "sent ping after join, got %r" % answer)

c1.sendall(b"owner_ping\n")
answer = drain(c1, 0.6)
check("owner_send reaches a live routed client", "owner-pong" in answer,
      "got %r" % answer)

c1.sendall(b"remember\n")
answer = drain(c1, 0.6)
remembered = ""
for line in answer.splitlines():
    if line.startswith("remembered="):
        remembered = line.split("=", 1)[1]
check("the sub-server was told which client this is", remembered != "",
      "no id came back: %r" % answer)

# ── The namespace ───────────────────────────────────────────────────────────
# The id the sub-server sees must not be a descriptor.  On a build that passes
# the parent's fd through, this is a small number — and a small number is one
# the sub-server's own descriptor table can also hold, which is the ambiguity.
parent_fd = own_id.split("=", 1)[1] if "=" in own_id else "?"
try:
    handle = int(remembered)
except ValueError:
    handle = -1
check("a routed client is not named by a descriptor", handle >= (1 << 24),
      "the sub-server was handed %s, and the parent calls that connection fd %s"
      % (remembered or "nothing", parent_fd))

# ── The defect ──────────────────────────────────────────────────────────────
c1.close()
time.sleep(0.8)

# Fresh, unrelated clients.  One of them takes the descriptor number the routed
# client had; none of them ever asked to join anything.
fresh = []
for _ in range(6):
    v = conn(PARENT)
    fresh.append((v, rd(v).strip()))
    time.sleep(0.05)

took_the_number = any(ident == own_id for _, ident in fresh)

time.sleep(0.3)
d = conn(SUB); d.sendall(b"leak\n")
answer = drain(d, 0.8)

sent_flag = ""
for line in answer.splitlines():
    if line.startswith("leak_sent="):
        sent_flag = line.split("=", 1)[1].split(" ")[0]

check("owner_send refuses a connection that has gone", sent_flag == "false",
      "it answered %r — a write to a departed connection reported as delivered"
      % (sent_flag or answer))

leaked_to = None
for v, ident in fresh:
    got = drain(v, 0.4)
    if "SECRET" in got:
        leaked_to = ident
check("nothing was written into the stranger that inherited the descriptor",
      leaked_to is None,
      "client %s — which never routed anywhere — received a message addressed "
      "to a connection that closed before it arrived" % leaked_to)

# The check above is only worth anything if the reissue actually happened.
check("the descriptor was in fact reissued", took_the_number,
      "no fresh client took %s, so the leak had nowhere to land and the check "
      "above proved nothing this run" % own_id)

for v, _ in fresh:
    v.close()
d.close()

# ── unroute puts the client back ────────────────────────────────────────────
#
# The control first: a client that has joined is answered by the sub-server and
# not by the parent.  Without it, "the parent answers after unroute" is also
# what a build that never routed anything would say.
c2 = conn(PARENT); rd(c2)
c2.sendall(b"join\n"); time.sleep(0.3)
c2.sendall(b"ping\n")
answer = drain(c2, 0.6)
check("a joined client is answered by the sub-server, not the parent",
      "pong-from-sub" in answer and "parent-echo" not in answer,
      "got %r" % answer)

admin = conn(PARENT); rd(admin)
admin.sendall(b"unroute_last\n")
answer = drain(admin, 0.6)
check("unroute reports that it did something", "unrouted=true" in answer,
      "got %r" % answer)

c2.sendall(b"hello\n")
answer = drain(c2, 0.6)
check("unroute returns the client to its own server",
      "parent-echo:hello" in answer, "got %r" % answer)
c2.close()
admin.close()

print("\n".join(results))
PY
)
RC=$?

if [ $RC -ne 0 ] || [ -z "$OUT" ]; then
    bad "harness did not run (rc=$RC)"
else
    while IFS='|' read -r verdict name detail; do
        [ -z "$verdict" ] && continue
        if [ "$verdict" = "ok" ]; then ok; else bad "$name: $detail"; fi
    done <<< "$OUT"
fi

# The sub-server's own view, from its log lines.  Both callbacks have always
# fired; what is checked is the id they fired with — a handle out of the
# reserved range, not a number that this runtime's own descriptor table could
# also produce.
if grep -q "sub_connect 1[6-9][0-9]\{6\}" "$WORK/daemon.log"; then ok; else
    bad "on_connect fired with $(grep -o 'sub_connect [0-9]*' "$WORK/daemon.log" | tail -1 | cut -d' ' -f2), which is inside this runtime's own descriptor range"
fi
if grep -q "sub_disconnect 1[6-9][0-9]\{6\}" "$WORK/daemon.log"; then ok; else
    bad "on_disconnect fired with $(grep -o 'sub_disconnect [0-9]*' "$WORK/daemon.log" | tail -1 | cut -d' ' -f2), which is inside this runtime's own descriptor range"
fi

# ─── A stopped origin takes its routes with it ──────────────────────────────
#
# A stop does not go through the per-connection close path — it walks the client
# table and clears it — so nothing told the target that the connections routed
# to it had gone.  The entries stayed, naming a runtime that was no longer
# running, and the target counted them as live connections for the rest of its
# life.
#
# The target here is created from the command line and is nobody's child.  That
# matters: a target the parent created is stopped by the same cascade that
# stops the parent, so its own teardown clears the entries and the leak cannot
# be seen.  An independent one is left running, which is the configuration the
# fix is about — and the one an operator gets by pointing self.route() at a
# server that already existed.

cat > "$WORK/lone.lua" <<'EOLUA'
function on_connect(client_id)  socketley.log("lone_connect " .. client_id) end
function on_disconnect(client_id) socketley.log("lone_disconnect " .. client_id) end
EOLUA

cat > "$WORK/parent2.lua" <<EOLUA
function on_client_message(client_id, msg)
    if msg == "join_lone" then self.route(client_id, "rid_lone") end
end
EOLUA

# Both out of process, like everything else here, and the paragraph that used
# to justify keeping them in the daemon is the one worth recording.
#
# It said: self.route() looks its target up in the runtime map, a worker holds
# no such map, so routing from a worker to a runtime in another process does
# not happen -- measured, with `false` returned, rid_lone counting 0 and its
# on_connect never firing.  Right about the symptom and wrong about the cause.
# route_client() never needed the map; it needed the target's OBJECT, and what
# it has now is shared/route_relay.h, which addresses the connection by
# conn_ref instead of reaching for the object.
#
# These two checks are about a stopped origin leaving stale entries in its
# target's books, and running them across processes is what makes them worth
# having: in one address space the origin's own teardown does the cleanup
# synchronously, which is the case that always worked.  Across processes it
# cannot -- the teardown's frames are written after the daemon has already
# retired the supervisor, and a KILLED worker never runs teardown at all -- so
# the daemon tells every other runtime instead.  That is route_op::forget, and
# the second of these two assertions is its only cover.
"$BIN" create server rid_lone -p "$LONE_PORT" --lua "$WORK/lone.lua" \
       -s >/dev/null 2>&1
"$BIN" create server rid_par2 -p "$PAR2_PORT" --lua "$WORK/parent2.lua" \
       -s >/dev/null 2>&1
sleep 0.6

lone_conns() { "$BIN" stats rid_lone 2>/dev/null | grep -E "^connections:" | head -1 | cut -d: -f2; }

python3 - "$PAR2_PORT" <<'PY' >/dev/null 2>&1 &
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
s.settimeout(2)
s.sendall(b"join_lone\n")
time.sleep(8)
PY
HOLDER=$!
sleep 1.2

BEFORE=$(lone_conns)
"$BIN" stop rid_par2 >/dev/null 2>&1
sleep 1.2
AFTER=$(lone_conns)

# The control.  Without it, "0 afterwards" is also what a build that never
# routed anything says, and the check below would pass for the wrong reason.
if [ "${BEFORE:-0}" -ge 1 ]; then ok; else
    bad "the target did not count the routed connection before the stop (got '${BEFORE:-}'), so the check below proves nothing"
fi
if [ "${AFTER:-1}" -eq 0 ]; then ok; else
    bad "the target still counts ${AFTER} connection(s) after the runtime that owned them stopped, and nothing will ever remove them"
fi
kill "$HOLDER" 2>/dev/null

echo "--- $PASS/$TOTAL passed ---"
[ "$FAIL" -eq 0 ]
