#!/usr/bin/env bash
# Integration test: the cross-runtime Lua API answers the same in a worker as
# it does in the daemon.
#
# ─── WHAT THIS IS FOR ───────────────────────────────────────────────────────
#
# Since 2313c26 a runtime created without --daemon-process lives in a worker
# process, and that is the DEFAULT.  A worker holds one runtime and no map of
# runtimes, so twelve calls of the management API have nothing to answer from:
#
#     socketley.create  .start  .stop  .remove  .send  .list  .get  .pipe
#     socketley.cluster.daemons  .runtimes  .group  .stats
#
# They are refused rather than answered, which is the right interim choice —
# an empty list() from a worker is indistinguishable from a daemon with nothing
# in it — and the wrong end state, because a third of the scripting API is then
# missing from the default mode and a script only finds out at runtime.
#
# This file is the definition of done for closing that.  One script, two
# runtimes, one assertion per call asserted twice:
#
#   * a CONTROL, comparing the in-daemon arm against a hard-coded expected
#     value, and
#   * a PARITY assertion, comparing the worker arm against the in-daemon arm.
#
# Both, and not just the second.  `assert_eq "$OOP_list" "$IN_list"` passes
# when both arms are equally broken — both refused, both empty, both nil — and
# that is precisely the state this file exists to detect.  The control is what
# makes the parity assertion mean something: it says the daemon arm really did
# see four runtimes, one connection, one group member, so a worker arm that
# matches it has really answered rather than really failed.
#
# ─── HOW EACH ARM IS MEASURED ───────────────────────────────────────────────
#
# The probe script is a server.  A client connects, sends one word, and the
# script runs that word's group of calls under pcall and sends back one line
# per call: either the canonical observation, or `REFUSED:<the raise>`.  pcall
# rather than letting the error escape, because a raise in on_client_message
# would end the callback and the arm would report nothing at all — which is a
# failure this file could not tell from a worker that never came up.
#
# Three words, in this order, and the order matters:
#
#   probe   the read-only surface.  Run on BOTH arms before either mutates
#           anything, so both see the same four runtimes.
#   make    create + start a child of this arm's own.
#   unmake  stop + remove it again.
#
# ─── THE ORACLES THAT ARE NOT THE SCRIPT'S OWN WORD ─────────────────────────
#
# Four of the twelve change the world, and a script grading its own return
# value proves nothing about whether anything happened.  So:
#
#   * create/start   `ls` must show the child, running, on the port the script
#                    asked for — from outside the daemon, over the CLI.
#   * stop/remove    `ls` must no longer show it.
#   * send           a real client holding a real connection to the target must
#                    RECEIVE the bytes.  socketley.send() on a placeholder used
#                    to return true and deliver to an empty table; a return
#                    value cannot tell that apart from delivery, and a reader
#                    on the far end can.
#
# ─── WHY THE HOLDER SENDS A BYTE FIRST ──────────────────────────────────────
#
# A connection that has sent nothing has no identified protocol yet and is
# deliberately excluded from relay traffic, so a client that never speaks never
# receives a broadcast, and the CONN column stays 0 until it does.  Verified on
# this build.  The holder therefore sends "hi\n" before it starts reading, and
# the test waits for CONN to reach 1 before probing — otherwise `get.connections`
# would read 0 for a reason that has nothing to do with the process boundary.
#
# ─── PIPE IS THE ONE THAT STAYS REFUSED ─────────────────────────────────────
#
# socketley.pipe() hands a file descriptor from one runtime to another.  Across
# processes that is fd passing, which is a separate project, so its worker arm
# is expected to stay a refusal for good.  Its assertion is therefore not
# parity but specificity: the refusal must say THAT, rather than share the
# generic "reaches for the runtime map" text with the other eleven.  An
# operator told the generic message would go looking for a map that, for this
# one call, is not what is missing.
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

# ctl LABEL GOT WANT WHAT-A-BREAK-WOULD-LOOK-LIKE...
#
# The in-daemon arm against a value written here.  Every one of these is green
# today; the day one goes red the parity assertion below it has stopped meaning
# anything, and this says so before it is misread as progress.
ctl() {
    local label=$1 got=$2 want=$3; shift 3
    if [ "$got" = "$want" ]; then pass; return; fi
    fail "control: $label answers in the daemon" \
         "the in-daemon arm said '$got', wanted '$want'" \
         "the parity assertion for this call cannot be attributed to the" \
         "process boundary while the call does not work on either side of it" \
         "$@"
}

# par CALL OOP IN
#
# The worker arm against the in-daemon arm.  These are the twelve.
par() {
    local call=$1 oop=$2 in=$3
    if [ "$oop" = "$in" ]; then pass; return; fi
    fail "parity: socketley.$call" \
         "worker arm: $oop" \
         "daemon arm: $in"
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
# --cluster, because socketley.cluster.* returns an empty table when the daemon
# has no discovery object at all — on either side of the boundary.  Four of the
# twelve would then be green in a worker for the wrong reason.
#
# Sent to a daemon that is already up, not passed on its command line: `daemon
# --name/--cluster` is CONFIGURATION mode in cli.cpp, which starts a detached
# daemon and talks to it over IPC.  Given to daemon_start it produces a daemon
# nothing holds the pid of and a "never came up" that is about the flag rather
# than the build.
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
#
# Identical for both arms, and everything in it is derived from self.* so that
# nothing has to be substituted per arm: the child's name is self.name .. "_kid"
# and its port is self.port + 10.  That makes self.name and self.port part of
# what is measured — they are read inside the worker too — and a build that got
# either wrong out there shows up in the external `ls` oracle rather than being
# silently absorbed.
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

local function report(what)
  local out = {}
  local function add(k, v) out[#out+1] = k .. " " .. tostring(v) end

  if what == "probe" then
    add("list", one(function()
      local l = socketley.list(); local k = 0
      for _, n in ipairs(l) do if WANTED[n] then k = k + 1 end end
      return k .. "/" .. #l
    end))
    add("get", one(function()
      local g = socketley.get(PEER)
      if g == nil then return "nil" end
      return g.type .. "/" .. g.state .. "/" .. g.port .. "/" .. g.connections
             .. "/" .. tostring(g.owner)
    end))
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
    -- The CROSS-RUNTIME branch, which is the one that would have to hand a
    -- descriptor to another process.  Not the same-runtime branch — that one
    -- pairs two of this server's own connections, needs neither a map nor a
    -- descriptor crossing anything, and would make the refusal asserted below
    -- read as being about something it is not.
    add("pipe", one(function()
      local ok, why = socketley.pipe("par_peer", 4242, "par_idle")
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

function on_client_message(client_id, msg)
  self.send(client_id, report(msg:match("^%a+") or "?"))
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

# The connection socketley.send() has to reach, and the one `get.connections`
# counts.  Sends first, then reads for the rest of the test — see the header.
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
#
# par_peer and par_idle are --daemon-process on purpose.  They are the SUBJECT
# of the reads, not the thing being tested, and an in-daemon subject has a
# connection count read from live tables rather than from a pushed frame — so
# `get.connections` has one unambiguous right answer for both arms to be
# compared against.
create_ok "target server created" "$BIN" create server par_peer \
    -p "$PEER_PORT" --group parity --daemon-process -s
create_ok "unstarted group member created" "$BIN" create server par_idle \
    -p "$IDLE_PORT" --group parity --daemon-process
create_ok "in-daemon probe created" "$BIN" create server par_in \
    -p "$IN_PORT" --lua "$PROBE_LUA" --daemon-process -s
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
# Four of four, and four in the map.  A worker map that omits the worker's OWN
# runtime says 3/3 and is caught here; an empty one says 0/0, which is the lie
# the refusal exists to prevent.
ctl "socketley.list()" "$IN_list" "4/4" \
    "a build that answered an empty table would say 0/0"
par list "$OOP_list" "$IN_list"

# ── get ─────────────────────────────────────────────────────────────────────
# Every field of the placeholder shape at once.  connections is the one that
# cannot be answered from a name alone: a map carrying a stale or absent count
# says .../0 here beside a CONN column that says 1.
ctl "socketley.get()" "$IN_get" "server/running/$PEER_PORT/1/nil" \
    "a build with no connection figure in the map would say .../0/nil"
par get "$OOP_get" "$IN_get"

ctl "socketley.get() on a name that is not there" "$IN_gabs" "nil" \
    "a build that invented a row for any name would say nonnil"

# Not one of the twelve — it is the same call — but it is what stops `get`
# passing by answering every name.  Written as a mode check so that it is never
# vacuously green: a worker either answers BOTH questions, in which case both
# must match the daemon, or refuses both.  Answering the lookup that succeeds
# while refusing the one that would say "no such name" is a third state, and it
# is the shape a map that cannot express absence would produce.
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

# ── pipe: refused for good, and it must say why ─────────────────────────────
ctl "socketley.pipe()" "$IN_pipe" \
    "false:connection 4242 could not be routed to \"par_idle\" — it is not an open connection of \"par_peer\", or it was itself routed in from another runtime, or \"par_idle\" refused it" \
    "in the daemon this reaches both runtimes and answers about the descriptor;" \
    "4242 is deliberately not an open connection of either"
# The one asymmetry that is not a defect.  fd passing across processes is a
# separate project, so this stays a refusal — but sharing the other eleven's
# text sends the reader after a runtime map, and a runtime map is not what is
# missing here.
case "$OOP_pipe" in
    REFUSED:*descriptor*|REFUSED:*file\ descriptor*) pass ;;
    *) fail "socketley.pipe() in a worker is refused as fd passing, by name" \
            "worker arm: $OOP_pipe" \
            "wanted a refusal whose reason is passing a descriptor between" \
            "processes — not the generic 'reaches for the runtime map' text," \
            "which for this one call names the wrong missing thing" ;;
esac

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

# daemons/runtimes/running/groups.parity.  par_idle is counted in the group
# histogram although it is not running, which is what stats() does and what a
# reimplementation somewhere else would most easily get wrong.
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
OOP_ROW=$(row par_oop_kid)

ctl "the child the in-daemon arm made is really there" \
    "$IN_ROW" "$IN_KID_PORT/up" \
    "the script's own 'true' is not evidence that anything was built; this is"
if [ "$OOP_ROW" = "$IN_KID_PORT/up" ] || [ "$OOP_ROW" = "$OOP_KID_PORT/up" ]; then
    pass
else
    fail "the child the worker arm made is really there" \
         "ls says '${OOP_ROW:-<no such runtime>}', wanted '$OOP_KID_PORT/up'" \
         "the port is self.port + 10 read inside the worker, so a wrong port" \
         "here is self.port being wrong out there rather than create being wrong"
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

# WAS there, and is now gone.  Not "is now gone" on its own: that is green when
# the child was never created, which is exactly the state the worker arm is in
# today — an assertion that passes because nothing happened is not coverage of
# the thing that was supposed to happen.  BEFORE is the row captured after
# `make`, above.
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
gone_after "the child the worker arm removed is really gone" \
           "$OOP_ROW" "$(row par_oop_kid)"

# ─── the send oracle: bytes on a real connection ────────────────────────────
#
# Last, because the holder has had the whole test to receive them.  This is the
# assertion socketley.send()'s return value cannot make: the placeholder path
# returned true and broadcast into an object with no connections in it.
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

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
