#!/usr/bin/env bash
# Integration test: socketley.create/.start/.stop/.remove from a script in a
# worker reach the daemon's map and do what they say.
#
# ─── WHAT THIS IS ABOUT ─────────────────────────────────────────────────────
# These four raised in a worker and worked in the daemon, so once the worker
# became the default they were a third of the management API that did not exist
# in the ordinary case -- they travel now over child_map_fd, and the answer
# comes back before the Lua call returns.
# ─── WHAT EACH ASSERTION HERE WOULD CATCH ───────────────────────────────────
# `true` is never the evidence, because a worker answering out of its own
# replica map returns it having built a runtime the daemon never hears about --
# so what is asked every time is what the daemon says afterwards: the runtime
# in `ls`, the port actually accepting a connection, the port ceasing to
# accept, the runtime gone -- and the refusals, checked against the same script
# run in the daemon rather than a literal, because the property is that a
# script cannot tell which side of the boundary it is on.
# ─── THE CONTROL ────────────────────────────────────────────────────────────
# The same script byte for byte on an in-daemon runtime, without which every
# assertion below also passes on a build that quietly moved the whole runtime
# into the daemon.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate workermapmut

OOP_PORT=$((SL_PORT_BASE+470))
IN_PORT=$((SL_PORT_BASE+471))
KID_OOP_PORT=$((SL_PORT_BASE+472))
KID_IN_PORT=$((SL_PORT_BASE+473))

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop  parent_oop parent_in kid_oop kid_in 2>/dev/null || true
    sleep 0.3
    "$BIN" remove parent_oop parent_in kid_oop kid_in 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a worker's script changes the daemon's map ==="

daemon_start "$BIN"

# One file parameterised by the runtime's own name and port so the two arms
# cannot drift, logging everything with a tag this file greps for -- and in
# on_start deliberately, because that is where these calls are written and the
# hardest place to serve them: a daemon that only served them from its event
# loop would be waiting for a worker that is waiting for it.
LUA="$SOCKETLEY_TMPD/mapmut.lua"
cat > "$LUA" <<'LUAEOF'
local me  = self.name
local kid = me == "parent_oop" and "kid_oop" or "kid_in"

-- Two above this runtime's own port.  Not an environment variable: the worker
-- inherits the DAEMON's environment, and the daemon was started long before
-- this test picked its ports -- so a variable exported beside the `create`
-- reaches the CLI process and nothing else.  Watched: `port` arrived nil and
-- on_start raised on the first arithmetic that touched it.
local port = self.port + 2

local function say(tag, ok, why)
    socketley.log("MAPMUT " .. me .. " " .. tag .. "=" .. tostring(ok)
                  .. " why=" .. tostring(why))
end

function on_start()
    -- Absent name first, while nothing has been created: this is the one
    -- refusal whose wording cannot be produced by a build that never asks the
    -- daemon at all, because the worker's replica is empty of this name too.
    -- It is here for the message, not for the false.
    say("start_absent", socketley.start("mapmut_no_such_runtime"))

    say("create", socketley.create("server", kid, { port = port, start = true }))

    -- The duplicate and the already-running, both against a name that exists
    -- ONLY in the daemon's map at this moment: the worker's replica is pushed
    -- on a coalescing timer, so a build that answered either of these locally
    -- would say "there is no runtime called ..." instead.  That is not a
    -- hypothetical -- it is what the first draft of this feature did.
    say("create_dup", socketley.create("server", kid, { port = port + 100 }))
    say("start_again", socketley.start(kid))
end

function on_message() end
LUAEOF

# state NAME -> the daemon's word for it, lowercased, or the empty string.
state() {
    "$BIN" ls 2>/dev/null | awk -v n="$1" '$2 == n { print tolower($7) }' | head -1
}
# listed NAME -> "yes" when the daemon's map has a row for it.
listed() {
    "$BIN" ls 2>/dev/null | awk -v n="$1" '$2 == n { f=1 } END { print f ? "yes" : "no" }'
}
# A connection rather than `ss`, because a listening socket the runtime never
# accepted from is what a half-started runtime leaves behind.
accepts() {
    if timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null; then
        printf 'yes'
    else
        printf 'no'
    fi
}
# saw TAG NAME -> the value the script logged for TAG, or the empty string.
saw() {
    grep -o "MAPMUT $2 $1=[^ ]* why=.*" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1
}

# ── The worker arm ──────────────────────────────────────────────────────────
#
# create_ok, not a bare create: a `create -s` that exits non-zero here is the
# deadlock described above, and it must fail this file loudly rather than
# leaving every assertion below to report a missing runtime.
create_ok "worker-backed parent created and started" \
    "$BIN" create server parent_oop -p "$OOP_PORT" --lua "$LUA" -s

# ── Assertion 1: create reached the daemon's map ────────────────────────────
if [ "$(listed kid_oop)" = "yes" ]; then pass; else
    fail "a worker's socketley.create builds a runtime in the DAEMON" \
         "kid_oop is not in \`ls\`" \
         "the call may still have returned true: a worker answering out of its" \
         "own replica map builds a runtime this process never hears about, and" \
         "that is exactly what the refusal this change removes was protecting" \
         "against — so \`ls\` is the oracle and the return value is not" \
         "the script logged: $(saw create parent_oop)"
fi

# ── Assertion 2: start = true actually bound and is serving ─────────────────
KID_OOP_ACCEPTS=$(accepts "$KID_OOP_PORT")
if [ "$KID_OOP_ACCEPTS" = "yes" ]; then pass; else
    fail "a worker's socketley.create with start = true is SERVING" \
         "nothing accepted a connection on $KID_OOP_PORT" \
         "\`ls\` says '$(state kid_oop)', which is not evidence on its own:" \
         "runtime_instance::start stores \`running\` and returns true for an" \
         "out-of-process placeholder with no child forked, so a build that" \
         "flipped a state and bound nothing looks identical in \`ls\`"
fi

# ── Assertion 3: the refusals carry the daemon's own wording ────────────────
#
# Three of them, and each names a state only the daemon can know about.
DUP=$(saw create_dup parent_oop)
case "$DUP" in
    *"create_dup=false"*"already exists"*) pass ;;
    *)
        fail "a duplicate name is refused with the daemon's reason" \
             "the script logged '${DUP:-<nothing>}'" \
             "wanted create_dup=false why=... already exists" \
             "the name exists only in the daemon's map at that moment — the" \
             "worker's replica is pushed on a timer — so a build that answered" \
             "locally would say 'there is no runtime called ...' instead" ;;
esac

AGAIN=$(saw start_again parent_oop)
case "$AGAIN" in
    *"start_again=false"*"already running"*) pass ;;
    *)
        fail "starting an already-running runtime is refused, with the reason" \
             "the script logged '${AGAIN:-<nothing>}'" \
             "wanted start_again=false why=... is already running" ;;
esac

ABSENT=$(saw start_absent parent_oop)
case "$ABSENT" in
    *"start_absent=false"*"there is no runtime called"*) pass ;;
    *)
        fail "starting a runtime that does not exist is refused, with the reason" \
             "the script logged '${ABSENT:-<nothing>}'" \
             "wanted start_absent=false why=there is no runtime called ..." ;;
esac

# Typed at the CLI rather than from the script, because what is under test is
# the daemon's half -- a `stop` served for a worker has to take the child down
# before it answers.
"$BIN" stop kid_oop >/dev/null 2>&1 || true
sleep 0.5
if [ "$(accepts "$KID_OOP_PORT")" = "no" ]; then pass; else
    fail "a stopped child stops accepting" \
         "$KID_OOP_PORT still accepted a connection after \`stop kid_oop\`" \
         "this is the control for assertion 2: if the port answers whether or" \
         "not the runtime is running, assertion 2 proves nothing"
fi

# reload-lua re-runs the script's top level in the worker, which is the second
# place the daemon is blocked waiting for the child, so a build that fixed only
# the startup wait passes everything above and fails here.
RELOAD_LUA="$SOCKETLEY_TMPD/mapmut_reload.lua"
cat > "$RELOAD_LUA" <<'LUAEOF'
local ok, why = socketley.remove("kid_oop")
socketley.log("MAPMUT parent_oop remove=" .. tostring(ok)
              .. " why=" .. tostring(why))
function on_message() end
LUAEOF
cp "$RELOAD_LUA" "$LUA"
"$BIN" reload-lua parent_oop >/dev/null 2>&1 || true

for _ in $(seq 1 50); do
    [ "$(listed kid_oop)" = "no" ] && break
    sleep 0.2
done

REMOVED=$(saw remove parent_oop)
if [ "$(listed kid_oop)" = "no" ]; then pass; else
    fail "a worker's socketley.remove takes the runtime out of the daemon's map" \
         "kid_oop is still in \`ls\` as '$(state kid_oop)'" \
         "the script logged '${REMOVED:-<nothing>}'" \
         "this one runs at reload time, where the daemon is blocked in" \
         "await_routes rather than await_startup — a build that drained the map" \
         "socket in only one of the two waits passes every assertion above"
fi

# Byte for byte the same file on an in-daemon runtime, without which every
# assertion so far also passes on a build that silently ran the worker inside
# the daemon.
cat > "$LUA" <<'LUAEOF'
local me  = self.name
local kid = me == "parent_oop" and "kid_oop" or "kid_in"

-- Two above this runtime's own port.  Not an environment variable: the worker
-- inherits the DAEMON's environment, and the daemon was started long before
-- this test picked its ports -- so a variable exported beside the `create`
-- reaches the CLI process and nothing else.  Watched: `port` arrived nil and
-- on_start raised on the first arithmetic that touched it.
local port = self.port + 2

local function say(tag, ok, why)
    socketley.log("MAPMUT " .. me .. " " .. tag .. "=" .. tostring(ok)
                  .. " why=" .. tostring(why))
end

function on_start()
    say("start_absent", socketley.start("mapmut_no_such_runtime"))
    say("create", socketley.create("server", kid, { port = port, start = true }))
    say("create_dup", socketley.create("server", kid, { port = port + 100 }))
    say("start_again", socketley.start(kid))
end

function on_message() end
LUAEOF

create_ok "in-daemon parent created and started" \
    "$BIN" create server parent_in -p "$IN_PORT" --lua "$LUA" -s

if [ "$(listed kid_in)" = "yes" ] && [ "$(accepts "$KID_IN_PORT")" = "yes" ]; then
    pass
else
    fail "control: the same script works in the daemon" \
         "kid_in is '$(listed kid_in)' in ls and accepts=$(accepts "$KID_IN_PORT")" \
         "if this fails too, the assertions above are about the script and not" \
         "about the process boundary, and prove nothing about either"
fi

# The point of the whole change stated as an assertion, compared against the
# other arm rather than against a literal, so a build that is wrong in the same
# way on both sides cannot pass by matching a string this file chose.
for tag in start_absent create_dup start_again; do
    A=$(saw "$tag" parent_oop | sed 's/^MAPMUT parent_oop //; s/kid_oop/KID/g')
    B=$(saw "$tag" parent_in  | sed 's/^MAPMUT parent_in //;  s/kid_in/KID/g')
    if [ -n "$A" ] && [ "$A" = "$B" ]; then pass; else
        fail "$tag reads the same on both sides of the boundary" \
             "worker:   ${A:-<nothing>}" \
             "in-daemon: ${B:-<nothing>}" \
             "a script branches on these strings; two wordings for one outcome" \
             "is the defect this whole change exists to remove"
    fi
done

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && { echo "  OK"; exit 0; } || { echo "  FAILED"; exit 1; }
