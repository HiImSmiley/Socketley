#!/usr/bin/env bash
# Integration test: the cross-runtime Lua API answers the same in a worker as
# it does in the daemon.
#
# ─── WHAT THIS IS FOR ───────────────────────────────────────────────────────
# Eleven of the twelve management calls a worker used to refuse are closed --
# seven answered from a pushed replica and four asked of the daemon -- and each
# is asserted twice, as a control against a hard-coded value and as parity
# against the in-daemon arm, because parity alone passes when both arms are
# equally broken.
# ─── HOW EACH ARM IS MEASURED ───────────────────────────────────────────────
# The probe is a server whose client sends one of three words in order --
# probe, make, unmake -- each running its group under pcall so a raise reports
# rather than ending the callback, with the four world-changing calls graded by
# external oracles rather than by their own return value.
# ─── WHY THE HOLDER SENDS A BYTE FIRST ──────────────────────────────────────
# The holder speaks before it reads, because an unclassified connection
# receives no relay traffic and CONN stays 0 -- and the one polled assertion is
# get.connections, whose daemon arm is exact and worker arm replicated, so it
# converges rather than agreeing in an instant; it was a single sample that
# passed only because the suite put 180 ms between the connection and the read,
# and pipe and route are parity assertions now rather than the permanent
# refusals this header once called them.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate workerparity

PEER_PORT=$((SL_PORT_BASE+460))
IDLE_PORT=$((SL_PORT_BASE+461))
IN_PORT=$((SL_PORT_BASE+465))
OOP_PORT=$((SL_PORT_BASE+466))
# The script asks for self.port + 10, so these are derived, not chosen.
IN_KID_PORT=$((IN_PORT+10))
OOP_KID_PORT=$((OOP_PORT+10))

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

# The in-daemon arm against a value written here, so the day one goes red the
# parity assertion below it has stopped meaning anything and says so.
ctl() {
    local label=$1 got=$2 want=$3; shift 3
    if [ "$got" = "$want" ]; then pass; return; fi
    fail "control: $label answers in the daemon" \
         "the in-daemon arm said '$got', wanted '$want'" \
         "the parity assertion for this call cannot be attributed to the" \
         "process boundary while the call does not work on either side of it" \
         "$@"
}

# The worker arm against the in-daemon arm, with an honest refusal and an
# un-refused call that answers an empty table named differently -- because the
# second is worse than doing nothing and a file reporting the same score for
# both cannot catch it.
par() {
    local call=$1 oop=$2 in=$3
    if [ "$oop" = "$in" ]; then pass; return; fi
    case "$oop" in
        REFUSED:*)
            fail "parity: socketley.$call" \
                 "worker arm: $oop" \
                 "daemon arm: $in" \
                 "still refused — this is the expected red until the map lands" ;;
        *)
            fail "REGRESSION: socketley.$call answers nothing instead of refusing" \
                 "worker arm: $oop" \
                 "daemon arm: $in" \
                 "the refusal has been removed and the call did NOT start" \
                 "working — it now returns what a successful call returns on a" \
                 "daemon with nothing in it, which no script can tell apart" \
                 "from the truth. This is worse than the refusal it replaced." \
                 "Either finish the transport or put the refusal back." ;;
    esac
}

# For the calls refused for good, asserting that the refusal names the right
# missing thing rather than parity, which is unreachable by design -- with the
# create family gone from this list within a release of being called permanent,
# because they ask the process holding the map rather than altering a copy.
refused() {
    local call=$1 oop=$2 needle=$3; shift 3
    case "$oop" in
        REFUSED:*"$needle"*) pass; return ;;
    esac
    fail "refused by name: $call" \
         "worker arm: $oop" \
         "wanted a refusal saying: $needle" \
         "$@"
}

CLUSTER_DIR="$SOCKETLEY_TMPD/cluster"
PEER_OUT="$SOCKETLEY_TMPD/peer.out"
HOLDER_PID=""

cleanup() {
    [ -n "$HOLDER_PID" ] && kill "$HOLDER_PID" 2>/dev/null
    "$BIN" stop  par_in par_oop par_peer par_idle par_in_kid par_oop_kid 2>/dev/null || true
    sleep 0.3
    "$BIN" remove par_in par_oop par_peer par_idle par_in_kid par_oop_kid 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: the cross-runtime Lua API, in a worker and in the daemon ==="

mkdir -p "$CLUSTER_DIR"
daemon_start "$BIN"
# --cluster, because the four cluster calls answer an empty table on either
# side without a discovery object, and sent to a daemon that is already up
# rather than on its command line, which is configuration mode.
if "$BIN" daemon --name parnode --cluster "$CLUSTER_DIR" >/dev/null 2>&1; then
    pass
else
    fail "setup: cluster discovery is on" \
         "the daemon refused --name/--cluster" \
         "the four socketley.cluster.* calls answer an empty table with no" \
         "discovery object, in the daemon as well as in a worker, so their" \
         "controls below would be measuring nothing"
fi

# ─── The probe script ───────────────────────────────────────────────────────
# Identical for both arms and derived from self.*, which makes self.name and
# self.port part of what is measured rather than silently absorbed.
PROBE_LUA="$SOCKETLEY_TMPD/probe.lua"
cat > "$PROBE_LUA" <<'LUAEOF'
local PEER   = "par_peer"
local ABSENT = "par_nosuch"
-- The four runtimes that exist while `probe` runs on either arm.  Counted
-- rather than listed, so the answer does not depend on which arm is asking.
local WANTED = { par_peer = 1, par_idle = 1, par_in = 1, par_oop = 1 }

local function kid() return self.name .. "_kid" end

-- one(f) -> the observation, or "REFUSED:<the raise, on one line>"
local function one(f)
  local ok, a = pcall(f)
  if not ok then return "REFUSED:" .. tostring(a):gsub("%s+", " ") end
  return a
end

-- socketley.get(PEER), formatted.  Its own function because `getpeer` below
-- re-asks it while `probe` asks it once, and two copies of this expression
-- would be two things to keep in step for no reason.
local function get_peer()
  local g = socketley.get(PEER)
  if g == nil then return "nil" end
  return g.type .. "/" .. g.state .. "/" .. g.port .. "/" .. g.connections
         .. "/" .. tostring(g.owner)
end

local function report(what)
  local out = {}
  local function add(k, v) out[#out+1] = k .. " " .. tostring(v) end

  if what == "probe" then
    add("list", one(function()
      local l = socketley.list(); local k = 0
      for _, n in ipairs(l) do if WANTED[n] then k = k + 1 end end
      return k .. "/" .. #l
    end))
    add("get", one(get_peer))
    -- The same call, asked about a name that is not there.  Without it, a
    -- build that answered every get() with an invented row would pass the line
    -- above.
    add("getabsent", one(function()
      return socketley.get(ABSENT) == nil and "nil" or "nonnil"
    end))
    add("send", one(function()
      local ok, why = socketley.send(PEER, "PARITY-" .. self.name .. "\n")
      return ok and "true" or ("false:" .. tostring(why))
    end))
    -- The CROSS-RUNTIME branch, three arguments, which is the one that has to
    -- cross a process boundary.  Not the four-argument same-runtime branch:
    -- that pairs two of this server's own connections and crosses nothing.
    --
    -- The SOURCE is this runtime and not par_peer, and that changed with the
    -- assertion below.  While this was expected to be refused outright it did
    -- not matter which names it used; now that it answers, naming a THIRD
    -- runtime as the source is a question only that runtime's own process can
    -- answer -- socketley.pipe needs the source's connection table, which lives
    -- where the source lives.  So the two arms would legitimately differ, and
    -- the difference would be about where par_peer is rather than about
    -- anything this file is measuring.
    add("pipe", one(function()
      local ok, why = socketley.pipe(self.name, 4242, "par_idle")
      return ok and "true" or ("false:" .. tostring(why))
    end))
    add("cdaemons", one(function()
      local d = socketley.cluster.daemons()
      return #d .. "/" .. tostring(d[1] and d[1].runtimes)
    end))
    add("cruntimes", one(function()
      local r = socketley.cluster.runtimes(); local k = 0
      for _, e in ipairs(r) do if WANTED[e.name] then k = k + 1 end end
      return k .. "/" .. #r
    end))
    -- par_peer and par_idle are both in group "parity"; only par_peer is
    -- running, and group() promises running members with a port.  So this is
    -- 1, and a build that forgot the filter says 2.
    add("cgroup", one(function()
      return tostring(#socketley.cluster.group("parity"))
    end))
    add("cstats", one(function()
      local s = socketley.cluster.stats()
      return s.daemons .. "/" .. s.runtimes .. "/" .. s.running .. "/"
             .. tostring(s.groups and s.groups.parity)
    end))

  elseif what == "getpeer" then
    -- Just the one field, so the convergence poll can re-ask cheaply without
    -- re-running send() — which delivers to a real client — or pipe(), or the
    -- four cluster calls, on every iteration.
    add("get", one(get_peer))

  elseif what == "make" then
    add("create", one(function()
      local ok, why = socketley.create("server", kid(), { port = self.port + 10 })
      return ok and "true" or ("false:" .. tostring(why))
    end))
    add("start", one(function()
      local ok, why = socketley.start(kid())
      return ok and "true" or ("false:" .. tostring(why))
    end))

  elseif what == "unmake" then
    add("stop", one(function()
      local ok, why = socketley.stop(kid())
      return ok and "true" or ("false:" .. tostring(why))
    end))
    add("remove", one(function()
      local ok, why = socketley.remove(kid())
      return ok and "true" or ("false:" .. tostring(why))
    end))
  end

  out[#out+1] = "ENDREPORT"
  return table.concat(out, "\n") .. "\n"
end

-- ── self.route(), the thirteenth refusal ───────────────────────────────────
--
-- It gets its own word rather than a line in `probe`, because it is the one
-- call here that cannot report down the connection it is about: a route that
-- SUCCEEDS gives this client to par_peer, and there is then nobody on this end
-- to answer with.  So the verdict goes to the log, under a marker carrying
-- this runtime's own name — that tells the two arms apart without depending on
-- how the log happens to tag a line.  socketley.log is in no refusal group and
-- works in a worker.
local function do_route(client_id)
  local ok, a = pcall(function()
    return self.route(client_id, PEER) and "true" or "false"
  end)
  if ok then
    socketley.log("ROUTE-" .. self.name .. " " .. tostring(a))
  else
    socketley.log("ROUTE-" .. self.name .. " REFUSED:" ..
                  tostring(a):gsub("%s+", " "))
  end
end

function on_client_message(client_id, msg)
  local what = msg:match("^%a+") or "?"
  if what == "route" then return do_route(client_id) end
  self.send(client_id, report(what))
end
LUAEOF

# par_peer's own script exists for one assertion -- that a route in the daemon
# arm really moved a connection -- logging the id rather than a bare marker so
# the lines can be counted.
PEER_LUA="$SOCKETLEY_TMPD/peer.lua"
cat > "$PEER_LUA" <<'LUAEOF'
function on_connect(client_id)
  socketley.log("PEER_CONN " .. tostring(client_id))
end
LUAEOF

# ─── The two clients ────────────────────────────────────────────────────────
ASK_PY="$SOCKETLEY_TMPD/ask.py"
cat > "$ASK_PY" <<'PYEOF'
import socket, sys
port = int(sys.argv[1]); what = sys.argv[2]
s = socket.create_connection(('127.0.0.1', port), timeout=5); s.settimeout(8)
s.sendall((what + "\n").encode())
buf = b''
try:
    while b'ENDREPORT' not in buf:
        d = s.recv(65536)
        if not d: break
        buf += d
except Exception as e:
    buf += b'\nNOANSWER ' + str(e).encode() + b'\n'
s.close()
sys.stdout.write(buf.decode('utf-8', 'replace'))
PYEOF

# The connection socketley.send() has to reach and `get.connections` counts,
# which sends first and then reads for the rest of the test.
HOLD_PY="$SOCKETLEY_TMPD/hold.py"
cat > "$HOLD_PY" <<'PYEOF'
import socket, sys, time
port = int(sys.argv[1]); out = sys.argv[2]; secs = float(sys.argv[3])
s = socket.create_connection(('127.0.0.1', port), timeout=5); s.settimeout(0.5)
s.sendall(b'hi\n')
end = time.time() + secs
with open(out, 'ab', buffering=0) as f:
    while time.time() < end:
        try:
            d = s.recv(65536)
            if not d: break
            f.write(d)
        except socket.timeout:
            pass
        except Exception:
            break
s.close()
PYEOF

# ask PORT WORD -> the whole report, or the empty string.
ask() { python3 "$ASK_PY" "$1" "$2" 2>/dev/null || printf ''; }
# field REPORT KEY -> the value the report gave for that call, or <missing>.
field() {
    local v
    v=$(printf '%s\n' "$1" | awk -v k="$2" '$1 == k { $1=""; sub(/^ /,""); print; exit }')
    printf '%s' "${v:-<missing>}"
}
# row NAME -> that runtime's `ls` line, collapsed, or the empty string.
row() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2 == n { print tolower($4"/"$7) }'; }
conn() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2 == n { print $5 }'; }

# ─── The world both arms look at ────────────────────────────────────────────
# par_peer and par_idle are --daemon-process on purpose, because an in-daemon
# subject's connection count comes from live tables and gives both arms one
# unambiguous right answer.
create_ok "target server created" "$BIN" create server par_peer \
    -p "$PEER_PORT" --group parity --lua "$PEER_LUA" -s
create_ok "unstarted group member created" "$BIN" create server par_idle \
    -p "$IDLE_PORT" --group parity
create_ok "in-daemon probe created" "$BIN" create server par_in \
    -p "$IN_PORT" --lua "$PROBE_LUA" -s
create_ok "worker probe created" "$BIN" create server par_oop \
    -p "$OOP_PORT" --lua "$PROBE_LUA" -s

python3 "$HOLD_PY" "$PEER_PORT" "$PEER_OUT" 60 >/dev/null 2>&1 &
HOLDER_PID=$!
for _ in $(seq 1 60); do [ "$(conn par_peer)" = "1" ] && break; sleep 0.1; done

if [ "$(conn par_peer)" = "1" ]; then pass; else
    fail "setup: the target holds exactly one connection" \
         "par_peer reports $(conn par_peer) connections, wanted 1" \
         "get.connections and the send oracle both rest on this, so every" \
         "assertion below about either would be measuring the fixture"
fi

# ─── probe: the read-only surface, both arms, before either mutates ─────────
IN_REPORT=$(ask "$IN_PORT" probe)
OOP_REPORT=$(ask "$OOP_PORT" probe)

# The one control that has to come first: a worker whose script never loaded,
# or whose interpreter refuses everything, answers nothing — and every parity
# assertion below would then be comparing two absences.
if printf '%s' "$OOP_REPORT" | grep -q ENDREPORT; then pass; else
    fail "control: the worker's script is loaded and answering" \
         "the worker arm sent no report at all" \
         "got: ${OOP_REPORT:-<nothing>}" \
         "nothing below this line would be measuring the process boundary"
fi
if printf '%s' "$IN_REPORT" | grep -q ENDREPORT; then pass; else
    fail "control: the in-daemon script is loaded and answering" \
         "the in-daemon arm sent no report at all" \
         "got: ${IN_REPORT:-<nothing>}"
fi

IN_list=$(field "$IN_REPORT" list);           OOP_list=$(field "$OOP_REPORT" list)
IN_get=$(field "$IN_REPORT" get);             OOP_get=$(field "$OOP_REPORT" get)
IN_gabs=$(field "$IN_REPORT" getabsent);      OOP_gabs=$(field "$OOP_REPORT" getabsent)
IN_send=$(field "$IN_REPORT" send);           OOP_send=$(field "$OOP_REPORT" send)
IN_pipe=$(field "$IN_REPORT" pipe);           OOP_pipe=$(field "$OOP_REPORT" pipe)
IN_cd=$(field "$IN_REPORT" cdaemons);         OOP_cd=$(field "$OOP_REPORT" cdaemons)
IN_cr=$(field "$IN_REPORT" cruntimes);        OOP_cr=$(field "$OOP_REPORT" cruntimes)
IN_cg=$(field "$IN_REPORT" cgroup);           OOP_cg=$(field "$OOP_REPORT" cgroup)
IN_cs=$(field "$IN_REPORT" cstats);           OOP_cs=$(field "$OOP_REPORT" cstats)

# ── list ────────────────────────────────────────────────────────────────────
# Four of four and four in the map, because a worker map omitting its own
# runtime says 3/3 and an empty one says 0/0, which is the lie the refusal
# existed to prevent.
ctl "socketley.list()" "$IN_list" "4/4" \
    "a build that answered an empty table would say 0/0"
par list "$OOP_list" "$IN_list"

# ── get ─────────────────────────────────────────────────────────────────────
# Every field of the placeholder shape at once, with the control moved below
# the convergence loop because both arms are workers now and both read a pushed
# figure.
WANT_GET="server/running/$PEER_PORT/1/nil"

# The one converging figure is asserted by polling to a deadline read out of
# the source at 4x the push interval, which sits between the 2x the design
# promises and the 8x health tick the behaviour replaced -- a single sample
# passed only inside the suite and failed five runs of five standalone.
STATS_MS=$(grep -oE 'stats_interval_ms *= *[0-9]+' \
           "$(dirname "$0")/../../socketley/shared/ipc/worker_protocol.h" 2>/dev/null \
           | grep -oE '[0-9]+$' | head -1)
case "$STATS_MS" in
    ''|*[!0-9]*)
        # Not fatal, but not silent either: the bound below is then a guess, and
        # a guess that has stopped tracking the code is how a deadline ends up
        # meaningless.
        STATS_MS=250
        STATS_SRC="ASSUMED — could not read stats_interval_ms from worker_protocol.h" ;;
    *)
        STATS_SRC="read from worker_protocol.h" ;;
esac
CONVERGE_MS=$((STATS_MS * 4))

# Both arms are re-read, because both are workers now and a reference sampled
# once can be stale -- measured under Sanitize as two arms that agreed within
# one interval being reported as never converging.
now_ms() { mono_ms; }
GET_T0=$(now_ms)
GET_WAITED=0
while [ "$OOP_get" != "$IN_get" ] || [ "$IN_get" != "$WANT_GET" ]; do
    GET_WAITED=$(( $(now_ms) - GET_T0 ))
    [ "$GET_WAITED" -ge "$CONVERGE_MS" ] && break
    sleep 0.05
    OOP_get=$(field "$(ask "$OOP_PORT" getpeer)" get)
    IN_get=$(field "$(ask "$IN_PORT" getpeer)" get)
done

# The control, now that both arms have had the window the design promises them.
ctl "socketley.get()" "$IN_get" "$WANT_GET" \
    "a build with no connection figure in the map would say .../0/nil;" \
    "waited ${GET_WAITED}ms of ${CONVERGE_MS}ms"
GET_WAITED=$(( $(now_ms) - GET_T0 ))

if [ "$OOP_get" = "$IN_get" ]; then
    pass
else
    case "$OOP_get" in
        REFUSED:*)
            fail "parity: socketley.get" \
                 "worker arm: $OOP_get" \
                 "daemon arm: $IN_get" \
                 "still refused — this is the expected red until the map lands" ;;
        *)
            fail "parity: socketley.get — connections never converged" \
                 "worker arm: $OOP_get" \
                 "daemon arm: $IN_get" \
                 "polled for ${GET_WAITED}ms, deadline ${CONVERGE_MS}ms" \
                 "(4 x stats_interval_ms=${STATS_MS}, $STATS_SRC)" \
                 "THIS FIELD IS A CONVERGING FIGURE, NOT AN INSTANTANEOUS ONE." \
                 "par_peer lives in the daemon, so the daemon's count is exact" \
                 "and the worker's is a replica arriving on a push — they are" \
                 "not supposed to agree in the same instant, only before this" \
                 "deadline. Waiting longer is NOT the fix: the deadline is twice" \
                 "the worst case the push design documents, and already only" \
                 "half the two-second health tick this replaced. Exceeding it" \
                 "means the coalescing floor in on_worker_stats() has broken or" \
                 "the counts are back on the health tick." ;;
    esac
fi

ctl "socketley.get() on a name that is not there" "$IN_gabs" "nil" \
    "a build that invented a row for any name would say nonnil"

# Written as a mode check so it is never vacuously green: a worker either
# answers both questions or refuses both, and answering only the lookup that
# succeeds is the shape a map that cannot express absence would produce.
oop_mode() { case "$1" in REFUSED:*) printf refused ;; *) printf answered ;; esac; }
if [ "$(oop_mode "$OOP_get")" != "$(oop_mode "$OOP_gabs")" ]; then
    fail "socketley.get() answers both questions or neither" \
         "get is $(oop_mode "$OOP_get") in the worker and get-on-an-absent-name is $(oop_mode "$OOP_gabs")" \
         "worker get:       $OOP_get" \
         "worker getabsent: $OOP_gabs" \
         "a map that can name a runtime but cannot say a name is unknown turns" \
         "every typo in a script into a row that looks real"
elif [ "$(oop_mode "$OOP_gabs")" = "answered" ] && [ "$OOP_gabs" != "$IN_gabs" ]; then
    fail "socketley.get() on a name that is not there, in a worker" \
         "worker arm: $OOP_gabs, daemon arm: $IN_gabs"
else
    pass
fi

# ── send ────────────────────────────────────────────────────────────────────
ctl "socketley.send()" "$IN_send" "true" \
    "a target that is running and holds a connection is a send that succeeds"
par send "$OOP_send" "$IN_send"

# ── pipe: at parity now ─────────────────────────────────────────────────────
# This was called refused for good and the header was wrong about the mechanism
# rather than the refusal, because the three-argument form is route_client()
# and needed route_relay.h -- with 4242 deliberately not an open connection of
# either arm.
ctl "socketley.pipe()" "$IN_pipe" \
    "false:connection 4242 could not be routed to \"par_idle\": that is not an open connection of this server" \
    "in the daemon this resolves the source locally and answers about the" \
    "descriptor; 4242 is deliberately not an open connection of it"
par pipe "$OOP_pipe" "$IN_pipe"

# ── cluster.* ───────────────────────────────────────────────────────────────
# One daemon, so one entry, and its runtimes count is the size of the map.
ctl "socketley.cluster.daemons()" "$IN_cd" "1/4" \
    "an empty table says 0/nil"
par cluster.daemons "$OOP_cd" "$IN_cd"

ctl "socketley.cluster.runtimes()" "$IN_cr" "4/4" \
    "this needs a group and a daemon name per row, which list()'s names alone" \
    "cannot supply — a map carrying only names would fail here and not above"
par cluster.runtimes "$OOP_cr" "$IN_cr"

ctl "socketley.cluster.group()" "$IN_cg" "1" \
    "2 means the running-and-bound filter was dropped; 0 means no group tag" \
    "reached the caller at all"
par cluster.group "$OOP_cg" "$IN_cg"

# par_idle is counted in the group histogram although it is not running, which
# is what stats() does and what a reimplementation would most easily get wrong.
ctl "socketley.cluster.stats()" "$IN_cs" "1/4/3/2" \
    "3 running of 4, and both group members counted"
par cluster.stats "$OOP_cs" "$IN_cs"

# ─── make: create + start, and an oracle that is not the script ─────────────
IN_MAKE=$(ask "$IN_PORT" make)
OOP_MAKE=$(ask "$OOP_PORT" make)
IN_create=$(field "$IN_MAKE" create); OOP_create=$(field "$OOP_MAKE" create)
IN_start=$(field "$IN_MAKE" start);   OOP_start=$(field "$OOP_MAKE" start)

ctl "socketley.create()" "$IN_create" "true" \
    "a name that is free and a port that is free is a create that succeeds"
par create "$OOP_create" "$IN_create"

ctl "socketley.start()" "$IN_start" "true" \
    "a runtime that exists and is not running is a start that succeeds"
par start "$OOP_start" "$IN_start"

for _ in $(seq 1 30); do [ -n "$(row par_in_kid)" ] && break; sleep 0.1; done
IN_ROW=$(row par_in_kid)

ctl "the child the in-daemon arm made is really there" \
    "$IN_ROW" "$IN_KID_PORT/up" \
    "the script's own 'true' is not evidence that anything was built; this is"

# Both halves are asked for opposite reasons -- `ls` listing it proves the
# create reached the daemon's map, and the port answering proves the runtime is
# really serving -- because a create answered locally and a refused one look
# identical in the CLI.
listening() { ss -ltnH 2>/dev/null | awk -v p=":$1\$" '$4 ~ p { f=1 } END { print f?"yes":"no" }'; }

if [ "$(listening "$IN_KID_PORT")" = "yes" ]; then pass; else
    fail "control: the in-daemon arm's child is actually listening" \
         "nothing is bound on $IN_KID_PORT" \
         "the port probe below is what tells a runtime that is SERVING from one" \
         "whose placeholder merely says so, and if it cannot see this one it" \
         "can see nothing"
fi

for _ in $(seq 1 30); do [ -n "$(row par_oop_kid)" ] && break; sleep 0.1; done
OOP_ROW=$(row par_oop_kid)

if [ -n "$OOP_ROW" ] && [ "$(listening "$OOP_KID_PORT")" = "yes" ]; then
    pass
else
    fail "the child the worker arm made is in the DAEMON's map and serving" \
         "ls says '${OOP_ROW:-<nothing>}', and $OOP_KID_PORT is $(listening "$OOP_KID_PORT") bound" \
         "the script's own 'true' is not evidence: a create answered inside the" \
         "worker would return true having built a runtime in that process —" \
         "serving, unpersisted, absent from ls, gone at the next restart — and" \
         "a create that flipped a placeholder would show Up and bind nothing." \
         "Both halves are needed to rule out both"
fi

# ─── unmake: stop + remove, same treatment ──────────────────────────────────
IN_UNMAKE=$(ask "$IN_PORT" unmake)
OOP_UNMAKE=$(ask "$OOP_PORT" unmake)
IN_stop=$(field "$IN_UNMAKE" stop);     OOP_stop=$(field "$OOP_UNMAKE" stop)
IN_remove=$(field "$IN_UNMAKE" remove); OOP_remove=$(field "$OOP_UNMAKE" remove)

ctl "socketley.stop()" "$IN_stop" "true" \
    "a runtime that is running is a stop that succeeds"
par stop "$OOP_stop" "$IN_stop"

ctl "socketley.remove()" "$IN_remove" "true" \
    "a runtime that exists is a remove that succeeds"
par remove "$OOP_remove" "$IN_remove"

for _ in $(seq 1 30); do [ -z "$(row par_in_kid)" ] && break; sleep 0.1; done

# Was there and is now gone, because "is now gone" alone is green when the
# child was never created.
gone_after() {
    local label=$1 before=$2 after=$3
    if [ -z "$before" ]; then
        fail "$label" "there was no child to remove — nothing was measured here" \
             "the create/start oracle above is the finding; this one has no" \
             "subject, and passing it would report the absence as a success"
        return
    fi
    if [ -n "$after" ]; then
        fail "$label" "ls still says '$after' for a runtime remove() answered true for" \
             "remove answering true for a runtime still in the map is the same" \
             "shape of lie as send answering true for a message that went nowhere"
        return
    fi
    pass
}
gone_after "the child the in-daemon arm removed is really gone" \
           "$IN_ROW" "$(row par_in_kid)"

# And the worker counterpart, with the BEFORE guard stopping it passing on a
# build where the create never worked.
for _ in $(seq 1 30); do [ -z "$(row par_oop_kid)" ] && break; sleep 0.1; done
gone_after "the child the worker arm removed is really gone" \
           "$OOP_ROW" "$(row par_oop_kid)"

# The port too, for the reason the create oracle gives: a remove that took the
# row out of the map and left the child running is a listener nothing in the
# CLI can find, which is the worse half of the same failure.
if [ "$(listening "$OOP_KID_PORT")" = "no" ]; then pass; else
    fail "the worker arm's removed child stopped serving" \
         "$OOP_KID_PORT is still bound after remove() answered true" \
         "the row is gone from ls, so nothing in the CLI names this process any" \
         "more — a remove that leaves the listener up is a leak with no handle"
fi

# The send oracle, last because the holder has had the whole test to receive:
# this is the assertion a return value cannot make, since the placeholder path
# returned true into an object with no connections.
sleep 0.5
if grep -q "PARITY-par_in" "$PEER_OUT" 2>/dev/null; then pass; else
    fail "control: the in-daemon arm's send actually arrived" \
         "the client holding a connection to par_peer never received it" \
         "got: $(tr -d '\0' < "$PEER_OUT" 2>/dev/null | tr '\n' '|')" \
         "without this, 'the worker's send did not arrive' is about send," \
         "not about the boundary"
fi
if grep -q "PARITY-par_oop" "$PEER_OUT" 2>/dev/null; then pass; else
    fail "the worker arm's send actually arrived" \
         "the client holding a connection to par_peer never received it" \
         "got: $(tr -d '\0' < "$PEER_OUT" 2>/dev/null | tr '\n' '|')"
fi

# ─── self.route(): the thirteenth refusal ───────────────────────────────────
# Last, because a route that works changes the CONN column the probe asserted
# was exactly 1 -- and it belongs with pipe rather than the eleven, since
# route_client() writes into the target's private maps and runs its on_connect
# on this stack.
PEER_CONN_BEFORE=$(grep -ac "PEER_CONN " "$SOCKETLEY_DLOG" 2>/dev/null) || PEER_CONN_BEFORE=0

# poke PORT — connect, ask to be routed, and hold the connection open long
# enough for accept_routed() to run the target's on_connect.
poke() { python3 -c "
import socket,time,sys
s=socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=5);s.settimeout(3)
s.sendall(b'route\n');time.sleep(1.0);s.close()" "$1" 2>/dev/null || true; }

poke "$IN_PORT"
poke "$OOP_PORT"
sleep 1.0

IN_ROUTE=$(grep -ao "ROUTE-par_in [^ ]*" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1)
OOP_ROUTE=$(grep -ao "ROUTE-par_oop [^ ]*" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1)
PEER_CONN_AFTER=$(grep -ac "PEER_CONN " "$SOCKETLEY_DLOG" 2>/dev/null) || PEER_CONN_AFTER=0

ctl "self.route()" "$IN_ROUTE" "ROUTE-par_in true" \
    "an open connection and a server to give it to is a route that succeeds"

# par_peer logs every connection it accepts, so a route that really happened is
# one more line and both arms routing is two -- without which "both arms
# answered true" passes on a build that moves nothing.
if [ "$PEER_CONN_AFTER" -ge $((PEER_CONN_BEFORE + 2)) ]; then pass; else
    fail "control: both routes really moved a connection" \
         "par_peer logged $PEER_CONN_BEFORE connections before and $PEER_CONN_AFTER after" \
         "wanted at least two more — one per arm; one more means only the" \
         "in-daemon arm arrived, and self.route() answering true out there is" \
         "not evidence the target got anything"
fi

# The parity claim itself, through the same helper, so a worker arm that still
# refuses is reported as refused rather than as a mismatch.
par route "${OOP_ROUTE:-<no ROUTE line at all>}" "${IN_ROUTE/par_in/par_oop}"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
