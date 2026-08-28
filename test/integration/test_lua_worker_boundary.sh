#!/usr/bin/env bash
# Integration test: the Lua management API across the daemon/worker boundary.
#
# ─── WHAT THIS PINS ─────────────────────────────────────────────────────────
#
# Since 8399bee a runtime lives in a process of its own unless it was created
# with --daemon-process.  The daemon keeps a *placeholder* for it: an object
# with the name, the port and the state, and not one connection, not one client
# fd.  Three of the Lua management calls read that placeholder as though it were
# the runtime, and each of them was wrong in a way a script could not see.
#
#   socketley.send(name, msg)     broadcast into the placeholder's empty client
#                                 table, then returned true.  Delivered nothing
#                                 and said it had.
#   socketley.get(name)           .connections read the placeholder's tables:
#   socketley.cluster.runtimes()  0 for a runtime with connections, which is the
#   socketley.cluster.group(g)    same shape as an idle one.  group() is what a
#                                 least-connections choice is written against,
#                                 so every such choice picked the local member
#                                 however busy it was.
#   socketley.remove(name)        freed the placeholder under a supervisor still
#                                 holding a pointer to it: `free(): double free
#                                 detected in tcache 2`, on the FIRST call, every
#                                 time — taking the daemon and every other
#                                 runtime with it.
#
# 9695a8b, e3b7cbf and 14ef983 fixed those.  This file is what would have caught
# them, and every assertion in it has been watched to fail against f2a2ea4, the
# commit immediately before: see the commit message for the runs.
#
# ─── WHY THE ORACLES ARE WHAT THEY ARE ──────────────────────────────────────
#
# The connection figures are compared against `stats`, not against a number
# written into this file.  `stats` reads reported_connection_count() — the
# figure the worker pushes — and was already correct before the fix (2296eac),
# so it is an oracle that moves with the traffic and cannot be satisfied by a
# binding that returns a constant.  A count asserted as a literal 3 would pass
# against a build that answers 3 to everything; a count asserted as "whatever
# stats says, and stats says more than zero" cannot.
#
# The zero case is asserted too, BEFORE any client connects.  On its own
# "afterwards it says 3" would also hold for a binding that reports the peak, or
# the total, or the number of runtimes; paired with "beforehand it said 0" it
# only holds for a binding that reports the live count.
#
# ─── THE CONTROLS ───────────────────────────────────────────────────────────
#
# Two, and without them this file passes against builds it should fail:
#
#   * The same socketley.send() to an IN-DAEMON target must deliver.  Otherwise
#     "the worker-backed target received it" is also satisfied by a build where
#     send is broken everywhere and this file measures nothing.
#   * cluster.runtimes() and cluster.group() must be non-empty at all.  Both
#     return an empty table when the daemon has no cluster discovery configured,
#     which is indistinguishable from "the runtime is not there" — so the daemon
#     is put in a cluster of one first, and the emptiness is an assertion.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luaworker

# One base, so the whole file can be driven on a private block while it is being
# written without editing sixteen literals.  The default is the range the suite
# runs it on; nothing but a developer's shell ever sets the variable.
PB=$((SL_PORT_BASE+100))
CTL_PORT=$((PB + 0))       # controller, in the daemon: the script under test
PEER_PORT=$((PB + 1))      # the worker-backed target
INPROC_PORT=$((PB + 2))    # the in-daemon target — control for send
STOPPED_PORT=$((PB + 3))   # created, then stopped
VICTIM_PORT=$((PB + 10))   # ..+14, the five removed from Lua

VICTIMS=5

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
    touch "${STOPFILE:-/dev/null}" 2>/dev/null || true
    "$BIN" stop ctl peer inproc stoppedpeer 2>/dev/null || true
    sleep 0.3
    "$BIN" remove ctl peer inproc stoppedpeer 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: the Lua management API across the worker boundary ==="

daemon_start "$BIN"

STOPFILE="$SOCKETLEY_TMPD/hold.stop"
HOLD_OUT="$SOCKETLEY_TMPD/hold.out"

# hold_open PORT N — open N connections, record everything that arrives on any
# of them, and keep them open until $STOPFILE appears.
#
# The connections have to outlive several CLI commands, which is why this is a
# process and not a `nc` per assertion: the whole point of the count assertions
# is that they are read while the connections are up, and a client that has
# already gone is the zero case wearing the answer's clothes.
cat > "$SOCKETLEY_TMPD/hold.py" <<'PYEOF'
import os, select, socket, sys
port, n, out_path, stop_path = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
socks = []
for _ in range(n):
    s = socket.create_connection(("127.0.0.1", port), 3)
    s.setblocking(False)
    socks.append(s)
out = open(out_path, "a", buffering=1)
out.write("READY\n")
while not os.path.exists(stop_path):
    r, _, _ = select.select(socks, [], [], 0.1)
    for s in r:
        try:
            data = s.recv(65536)
        except Exception:
            continue
        if not data:
            socks.remove(s)
            continue
        for line in data.decode("latin-1").splitlines():
            if line:
                out.write("RECV:" + line + "\n")
for s in socks:
    s.close()
out.write("DONE\n")
PYEOF

# ── The script under test ───────────────────────────────────────────────────
#
# It runs in the daemon (--daemon-process): the calls it makes are the
# cross-runtime ones, which a worker refuses outright, so the only place they
# can be measured is where they are allowed.  Its targets are the ones in
# workers, which is the boundary this file is about.
CTL_LUA="$SOCKETLEY_TMPD/ctl.lua"
cat > "$CTL_LUA" <<'LUAEOF'
local function say(s) socketley.log("CTL " .. s) end

-- The three figures, formatted so a single grep can read the one it wants and
-- an absent line is distinguishable from a zero.
local function report(tag, name, group)
    local info = socketley.get(name)
    say(tag .. " get=" .. tostring(info and info.connections or "nil"))

    local n = -1
    for _, r in ipairs(socketley.cluster.runtimes()) do
        if r.name == name then n = r.connections end
    end
    say(tag .. " runtimes=" .. tostring(n))

    local g = -1
    local members = 0
    for _, m in ipairs(socketley.cluster.group(group)) do
        members = members + 1
        if m.port == info.port then g = m.connections end
    end
    -- One figure per line.  Two on one line and the reader has to know which
    -- came first, which is a thing to get wrong in the shell for no gain.
    say(tag .. " group=" .. tostring(g))
    say(tag .. " members=" .. tostring(members))
end

function on_client_message(id, msg)
    if msg == "idle" then
        report("idle", "peer", "gr")
    elseif msg == "busy" then
        report("busy", "peer", "gr")
    elseif msg == "send-peer" then
        say("send-peer=" .. tostring(socketley.send("peer", "LUA-SEND-OOP")))
    elseif msg == "send-inproc" then
        say("send-inproc=" .. tostring(socketley.send("inproc", "LUA-SEND-INPROC")))
    elseif msg == "send-missing" then
        say("send-missing=" .. tostring(socketley.send("nosuchruntime", "x")))
    elseif msg == "send-stopped" then
        say("send-stopped=" .. tostring(socketley.send("stoppedpeer", "x")))
    elseif msg:sub(1, 3) == "rm:" then
        local name = msg:sub(4)
        say("rm " .. name .. "=" .. tostring(socketley.remove(name)))
    end
end
LUAEOF

# poke WORD — one line into the controller, connection closed afterwards.
poke() {
    printf '%s\n' "$1" | timeout 5 nc -q 1 127.0.0.1 "$CTL_PORT" >/dev/null 2>&1 || true
}
# said PATTERN — did the controller's script log it?  Waits, because the daemon
# writes its [lua] lines when the loop gets to them.
said() {
    local pattern=$1 deadline=$(( $(date +%s) + ${2:-6} ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        grep -qaE "$pattern" "$SOCKETLEY_DLOG" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}
# field TAG KEY — the last value the script logged for one figure, or empty.
#
# The `|| true` is inside the pipeline and load-bearing under `set -o pipefail`:
# grep exits 1 when it matches nothing, which is exactly the case an assertion
# below has something to say about, and without it the capture takes grep's
# status and ends the run at the assignment with no result line.
field() {
    { grep -aoE "CTL $1 $2=[-0-9]+" "$SOCKETLEY_DLOG" 2>/dev/null || true; } \
        | tail -1 | sed 's/.*=//'
}
# word TAG — the last true/false the script logged for one call, or empty.
word() {
    { grep -aoE "CTL $1=[a-z]+" "$SOCKETLEY_DLOG" 2>/dev/null || true; } \
        | tail -1 | sed 's/.*=//'
}
# hits PATTERN FILE — how many lines match.  Never `grep -c … || echo 0`: grep -c
# already PRINTS 0 when it matches nothing and then exits 1, so the fallback
# appends a second zero and every numeric test on the result errors out.
hits() { grep -ac "$1" "$2" 2>/dev/null || true; }
# stat_conns NAME — the oracle: what `stats` says, which is the worker's own
# pushed figure and was already right before any of this was fixed.
stat_conns() {
    "$BIN" stats "$1" 2>/dev/null | awk -F: '$1 == "connections" { print $2 }' | head -1
}
# workers — how many worker processes this daemon is running.  Children of the
# daemon pid, so it cannot see another test's, another checkout's, or another
# agent's.
workers() { pgrep -P "$SOCKETLEY_DPID" 2>/dev/null | wc -l | tr -d ' '; }

# The cluster calls answer an empty table when discovery is not configured, and
# an empty table is what "the runtime is not there" looks like too.  A cluster of
# one is enough to tell those apart and needs no second daemon.
mkdir -p "$SOCKETLEY_TMPD/cluster"
"$BIN" daemon --name luaworker --cluster "$SOCKETLEY_TMPD/cluster" >/dev/null 2>&1 || true

create_ok "controller created in the daemon" "$BIN" create server ctl \
    -p "$CTL_PORT" --mode in --lua "$CTL_LUA" -s
create_ok "worker-backed target created" "$BIN" create server peer \
    -p "$PEER_PORT" --mode out -g gr -s
create_ok "in-daemon target created" "$BIN" create server inproc \
    -p "$INPROC_PORT" --mode out -s
create_ok "target to be stopped created" "$BIN" create server stoppedpeer \
    -p "$STOPPED_PORT" -s
"$BIN" stop stoppedpeer >/dev/null 2>&1 || true

ready_tcp 127.0.0.1 "$CTL_PORT" 8  || echo "  NOTE: controller never accepted"
ready_tcp 127.0.0.1 "$PEER_PORT" 8 || echo "  NOTE: peer never accepted"

# ── 1. The figures with nothing connected ───────────────────────────────────
#
# The probe on the line above is a connection.  `nc -z` opens one and drops it,
# and the worker goes on counting it until the ring reports the hangup after it
# reported the accept.  Its own sample of its own counters comes round every
# 250 ms, so when the two coincide the daemon is handed a 1 for a connection
# that is already gone and holds it until the next sample.  Read inside that
# window, all three of the assertions below say 1 about a runtime nothing is
# connected to — which is exactly the failure this file produced in a nightly,
# down to the reported value.
#
# Measured here, by reading the figure straight after the probe: 7 stale reads
# in 164 on an idle machine.  The `stats` oracle on the line below escapes it
# only by being read later — after `said` has waited for the log line and a
# fresh sample has landed — not by being any more accurate.
#
# It is not a figure that settles by being asked again, so polling until it
# reads 0 would not fix it: the first read can be answered from the sample taken
# BEFORE the probe connected, and the loop would exit on a stale zero having
# proved nothing.  What is waited for is a sample taken after the probe was
# gone.  See ready_conns in lib_ready.sh for the arithmetic.
ready_conns "$BIN" peer 0 15 \
    || echo "  NOTE: peer never published an idle connection count"

poke idle
said 'CTL idle group=' 8 || true

IDLE_STAT=$(stat_conns peer)
assert_eq "control: stats says the idle worker-backed runtime has no connections" \
          "0" "$IDLE_STAT" \
          "without this the 'busy' assertions below cannot be read as a change"
assert_eq "socketley.get() reports 0 while nothing is connected" \
          "0" "$(field idle get)"
assert_eq "cluster.runtimes() reports 0 while nothing is connected" \
          "0" "$(field idle runtimes)"
assert_eq "cluster.group() reports 0 while nothing is connected" \
          "0" "$(field idle group)"

# The control for the two cluster calls: an empty view answers 0 for everything
# and would satisfy all three assertions above.  A member had to be found for
# the figure to have come from anywhere.
IDLE_MEMBERS=$(field idle 'members')
assert_eq "control: cluster.group() found the group at all" "1" "$IDLE_MEMBERS" \
    "an empty cluster view answers every question with nothing, and 'nothing'" \
    "reads as 0 — so the counts above would hold on a daemon that cannot see" \
    "its own runtimes"

# ── 2. The same three figures with three connections open ───────────────────
: > "$HOLD_OUT"
python3 "$SOCKETLEY_TMPD/hold.py" "$PEER_PORT" 3 "$HOLD_OUT" "$STOPFILE" &
HOLD_PID=$!
for _ in $(seq 1 100); do grep -q READY "$HOLD_OUT" 2>/dev/null && break; sleep 0.05; done

# Wait for the worker's pushed figure to catch up before reading any of them, so
# that a slow push is not reported as a wrong answer.
for _ in $(seq 1 100); do [ "$(stat_conns peer)" = "3" ] && break; sleep 0.1; done
BUSY_STAT=$(stat_conns peer)

poke busy
said 'CTL busy group=' 8 || true

assert_eq "control: stats sees the three connections" "3" "$BUSY_STAT" \
    "the oracle every assertion below compares against; if this is not 3 the" \
    "connections were never made and nothing below means anything"
assert_eq "socketley.get() reports what stats reports for a runtime in a worker" \
          "$BUSY_STAT" "$(field busy get)" \
          "the placeholder's own tables are empty, so this answered 0 —" \
          "indistinguishable, to a script, from an idle runtime"
assert_eq "cluster.runtimes() reports what stats reports" \
          "$BUSY_STAT" "$(field busy runtimes)"
assert_eq "cluster.group() reports what stats reports" \
          "$BUSY_STAT" "$(field busy group)" \
          "a least-connections choice is written against this figure: a local" \
          "member answering 0 beside a remote member's true count wins every" \
          "such choice however busy it is"

# ── 3. socketley.send() to a runtime in a worker ────────────────────────────
poke send-peer
said 'CTL send-peer=' 8 || true
assert_eq "socketley.send() to a worker-backed runtime returns true" \
          "true" "$(word send-peer)"

# The return value was ALWAYS true; that is the defect, not the fix.  What has
# to be asserted is arrival.
DELIVERED=0
for _ in $(seq 1 100); do
    DELIVERED=$(hits 'RECV:LUA-SEND-OOP' "$HOLD_OUT")
    [ "$DELIVERED" -ge 3 ] && break
    sleep 0.1
done
assert_eq "the message reaches every client of the worker-backed runtime" \
          "3" "$DELIVERED" \
          "socketley.send() broadcast into the daemon placeholder's empty" \
          "client table and returned true; nothing was delivered and nothing" \
          "said so"

touch "$STOPFILE"
wait "$HOLD_PID" 2>/dev/null || true

# ── 4. The control: the same call, in the daemon, still delivers ────────────
: > "$HOLD_OUT"
rm -f "$STOPFILE"
python3 "$SOCKETLEY_TMPD/hold.py" "$INPROC_PORT" 1 "$HOLD_OUT" "$STOPFILE" &
HOLD_PID=$!
for _ in $(seq 1 100); do grep -q READY "$HOLD_OUT" 2>/dev/null && break; sleep 0.05; done
# READY means the CLIENT's connect() returned, which is a kernel handshake and
# says nothing about the server having accepted yet.  A broadcast issued in that
# window walks an empty client table and writes nowhere — a race that cost an
# hour here, diagnosed as a product defect twice before the wait went in.  The
# runtime's own count is the thing that has to have caught up.
for _ in $(seq 1 100); do [ "$(stat_conns inproc)" = "1" ] && break; sleep 0.1; done

poke send-inproc
IN_DELIVERED=0
for _ in $(seq 1 100); do
    IN_DELIVERED=$(hits 'RECV:LUA-SEND-INPROC' "$HOLD_OUT")
    [ "$IN_DELIVERED" -ge 1 ] && break
    sleep 0.1
done
assert_eq "control: socketley.send() to an in-daemon runtime delivers" \
          "1" "$IN_DELIVERED" \
          "if this fails, 'the worker-backed target received it' above is not" \
          "about the boundary — send is simply broken, and this file proves" \
          "nothing either way"
touch "$STOPFILE"
wait "$HOLD_PID" 2>/dev/null || true

# ── 5. A send with nowhere to go says so ────────────────────────────────────
poke send-missing
said 'CTL send-missing=' 6 || true
assert_eq "socketley.send() to a name that does not exist returns false" \
          "false" "$(word send-missing)"

poke send-stopped
said 'CTL send-stopped=' 6 || true
assert_eq "socketley.send() to a stopped runtime returns false" \
          "false" "$(word send-stopped)" \
          "a stopped runtime has no worker behind it, so there is nowhere for" \
          "the message to go — answering true would be the old lie in a" \
          "quieter voice"

# ── 6. socketley.remove() of runtimes in workers ────────────────────────────
#
# Five, not one.  The double free happened on the FIRST call, so one would be
# enough to catch this defect — but "the daemon survived N and ran all N" is the
# claim worth keeping, and it is the one that fails if a future change makes the
# first removal safe and the second not.
WORKERS_BEFORE=$(workers)
for i in $(seq 1 "$VICTIMS"); do
    create_ok "victim $i created in a worker" "$BIN" create server "victim$i" \
        -p $((VICTIM_PORT + i)) -s
done
for _ in $(seq 1 100); do
    [ "$(workers)" -ge $((WORKERS_BEFORE + VICTIMS)) ] && break
    sleep 0.1
done
WORKERS_UP=$(workers)
assert_eq "control: the five victims are each in a process of their own" \
          "$((WORKERS_BEFORE + VICTIMS))" "$WORKERS_UP" \
          "if they are not out of process the removals below take the path" \
          "that was never broken, and this section measures nothing"

for i in $(seq 1 "$VICTIMS"); do
    poke "rm:victim$i"
    sleep 0.2
done
said "CTL rm victim$VICTIMS=" 8 || true

RM_RAN=$({ grep -acE "CTL rm victim[0-9]+=true" "$SOCKETLEY_DLOG" 2>/dev/null || true; })
assert_eq "every socketley.remove() ran" "$VICTIMS" "$RM_RAN" \
    "the first one used to free the placeholder under a supervisor still" \
    "holding a pointer to it, so the daemon died on #1 and the other four" \
    "never happened"

# The daemon, not merely this script's next line.  A daemon that died and was
# auto-started again by the CLI is a different daemon and answers just as well,
# which is why the pid is checked rather than the socket.
if kill -0 "$SOCKETLEY_DPID" 2>/dev/null && daemon_alive "$SOCKETLEY_SOCKET"; then
    pass
else
    # No backticks in this text.  It is inside double quotes, so a backtick pair
    # is a command substitution the shell runs while reporting the failure — and
    # what it tried to run here was the heap diagnostic itself, which turned a
    # red assertion into a shell syntax error printed over the top of it.
    fail "the daemon survives a Lua remove of a worker-backed runtime" \
         "the daemon that ran the removes is gone" \
         "free(): double free detected in tcache 2 — and with it every other" \
         "runtime this daemon was serving"
fi
if grep -qa "double free\|corruption\|Aborted" "$SOCKETLEY_DLOG" 2>/dev/null; then
    fail "the daemon log is clean across the removes" \
         "the log carries a heap diagnostic" \
         "$(grep -a 'double free\|corruption\|Aborted' "$SOCKETLEY_DLOG" | head -2 | tr '\n' '|')"
else
    pass
fi

LEFT=$("$BIN" ls 2>/dev/null | grep -c ' victim' || true)
assert_eq "no removed runtime is still in the inventory" "0" "$LEFT"

for _ in $(seq 1 100); do
    [ "$(workers)" -le "$WORKERS_BEFORE" ] && break
    sleep 0.1
done
assert_eq "no worker process outlives the runtime it was serving" \
          "$WORKERS_BEFORE" "$(workers)" \
          "a removal that leaves the child running leaves the port bound," \
          "which is the next run's collision rather than this one's failure"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
