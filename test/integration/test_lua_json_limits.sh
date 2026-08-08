#!/usr/bin/env bash
# Integration test: socketley.json_encode / json_decode refuse rather than crash.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# Both are recursive in C++ over a structure the script hands them, and neither
# had a depth limit or a cycle check.  Measured on the parent commit:
#
#   encode, on a table containing itself:
#       [INFO] [lua jc] about to encode a cyclic table
#       Segmentation fault (core dumped)
#
#   decode, on string.rep("[", n) .. string.rep("]", n):
#       n =  20000  ( 40 KB)   survived
#       n = 100000  (200 KB)   Segmentation fault (core dumped)
#
# The decode case is the one that matters: json_decode exists to be pointed at a
# request body, so the nesting is chosen by whoever sent the request, and 200 KB
# is an ordinary body.  That made every script calling it on network input a way
# for an unauthenticated client to take the daemon down.
#
# The callback deadline does not cover either: it hooks Lua instructions and a
# wall clock, and this is C++ frames on the C stack.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
# "The daemon survived" is not enough on its own — a build where json_encode
# returned false for everything would pass it.  So each refusal is paired with a
# control that must still WORK, and one of those controls is specific:
#
#   A table reachable twice by different paths but NOT containing itself must
#   still encode.  {a = shared, b = shared} is an ordinary document.  A fix
#   written with a "visited" set instead of an ancestor chain refuses it, and
#   that regression is invisible to every other assertion here.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate lua_json
PASS=0; FAIL=0; TOTAL=0

cleanup() { daemon_stop; }
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

SCRIPTS="$SOCKETLEY_TMPD/scripts"
mkdir -p "$SCRIPTS"

# run_script NAME PORT FILE
#
# Load a script as a runtime's on_start and let it run.  --daemon-process on
# purpose: out of process the crash would kill only the worker, which the
# supervisor then restarts, and the assertion would be measuring the restart
# policy rather than the interpreter.  In the daemon, a crash is unambiguous.
run_script() {
    local name=$1 port=$2 file=$3
    # Every case starts against a daemon of our own that is answering, so a
    # crash in one case cannot be reported again by the next.  Markers are per
    # case, so the log truncation inside daemon_recover costs nothing.
    daemon_recover
    "$BIN" create server "$name" -p "$port" --daemon-process --lua "$file" -s \
        >/dev/null 2>&1 || true
    sleep 0.4
}

# said MARKER — did the script reach this point?
said() { grep -q "$1" "$SOCKETLEY_DLOG" 2>/dev/null; }

# daemon_recover — a live, answering daemon of our own before the next case.
#
# Each case has to measure its own script.  Without this, every case after a
# crash reports "the daemon is gone" about the PREVIOUS case's crash: measured
# against the unfixed build, three failures where there were two findings, and
# the third one — "a document within the limit still decodes" — read as a
# tightness problem in the limit rather than as an echo.
#
# The condition is "OUR daemon is serving", not "a daemon answers": every CLI
# command auto-starts one when the socket is silent, so `ping || restart` forks
# a replacement while asking the question and leaves $SOCKETLEY_DPID stale.
daemon_recover() {
    local serving; serving=$(daemon_pids "$SOCKETLEY_SOCKET")
    if [ -n "$serving" ] && [ "$serving" = "${SOCKETLEY_DPID:-}" ] \
       && timeout 5 "$BIN" ping >/dev/null 2>&1; then
        return 0
    fi
    daemon_sweep "$SOCKETLEY_SOCKET"
    if [ -n "${SOCKETLEY_DPID:-}" ]; then wait "$SOCKETLEY_DPID" 2>/dev/null || true; fi
    # kill -9 returns when the signal is queued, not when the process is gone,
    # and a starting daemon asks is_running() — a real connect() — before it
    # binds.  Starting inside that window makes it decide one is already there
    # and exit 0, which lib_daemon reports as FATAL.
    local i
    for i in $(seq 1 50); do
        [ -z "$(daemon_pids "$SOCKETLEY_SOCKET")" ] && break
        sleep 0.1
    done
    : > "$SOCKETLEY_DLOG"
    daemon_start "$BIN"
}

echo "=== Integration: Lua JSON depth and cycle limits ==="

daemon_start "$BIN"
P=$((SL_PORT_BASE + 810))

# ─── Control: the ordinary round trip still works ───────────────────────────
#
# First, because every refusal below is only meaningful against a build where
# the happy path is intact.
cat > "$SCRIPTS/ok.lua" <<'LUA'
function on_start()
  local s = socketley.json_encode({ name = "x", n = 3, list = {1,2,3} })
  local back = socketley.json_decode(s)
  if back and back.name == "x" and back.n == 3 and back.list[2] == 2 then
    socketley.log("JSON_ROUNDTRIP_OK")
  else
    socketley.log("JSON_ROUNDTRIP_BROKEN " .. tostring(s))
  end
end
LUA
run_script jsonok $((P + 0)) "$SCRIPTS/ok.lua"

if said "JSON_ROUNDTRIP_OK"; then pass
else fail "encode/decode round trip still works" \
          "the script did not report a successful round trip" \
          "every refusal below is meaningless if the happy path is broken."; fi

# ─── Control: a shared subtable is not a cycle ──────────────────────────────
#
# The assertion that separates an ancestor chain from a visited set.  Reached
# twice by different paths, contains itself nowhere; it has to encode.
cat > "$SCRIPTS/shared.lua" <<'LUA'
function on_start()
  local shared = { v = 1 }
  local s, why = socketley.json_encode({ a = shared, b = shared })
  if s then socketley.log("JSON_SHARED_OK " .. s)
  else socketley.log("JSON_SHARED_REFUSED " .. tostring(why)) end
end
LUA
run_script jsonshared $((P + 1)) "$SCRIPTS/shared.lua"

if said "JSON_SHARED_OK"; then pass
elif said "JSON_SHARED_REFUSED"; then
    fail "a shared (non-cyclic) subtable still encodes" \
         "it was refused as if it were a cycle" \
         "{a = shared, b = shared} is an ordinary document; refusing it means" \
         "the cycle check is a visited set rather than an ancestor chain."
else
    fail "a shared (non-cyclic) subtable still encodes" \
         "the script reported neither outcome"
fi

# ─── The cycle ──────────────────────────────────────────────────────────────
cat > "$SCRIPTS/cycle.lua" <<'LUA'
function on_start()
  local t = {}
  t.self = t
  socketley.log("CYCLE_BEFORE")
  local s, why = socketley.json_encode(t)
  if s then socketley.log("CYCLE_ENCODED " .. tostring(s))
  else socketley.log("CYCLE_REFUSED " .. tostring(why)) end
end
LUA
run_script jsoncycle $((P + 2)) "$SCRIPTS/cycle.lua"

if ! daemon_alive "$SOCKETLEY_SOCKET"; then
    fail "a cyclic table does not crash the daemon" \
         "the daemon is gone" \
         "json_encode followed t.self = t until the stack ran out."
elif said "CYCLE_REFUSED"; then pass
elif said "CYCLE_ENCODED"; then
    fail "a cyclic table is refused" "it reported success, which cannot be right"
else
    fail "a cyclic table is refused" \
         "the script reached json_encode and never came back" \
         "marker CYCLE_BEFORE present: $(said CYCLE_BEFORE && echo yes || echo no)"
fi

# ─── The depth, on the side that takes outside input ────────────────────────
cat > "$SCRIPTS/deep.lua" <<'LUA'
function on_start()
  local n = 100000
  local s = string.rep("[", n) .. string.rep("]", n)
  socketley.log("DEEP_BEFORE")
  local v, why = socketley.json_decode(s)
  if v then socketley.log("DEEP_DECODED")
  else socketley.log("DEEP_REFUSED " .. tostring(why)) end
end
LUA
run_script jsondeep $((P + 3)) "$SCRIPTS/deep.lua"

if ! daemon_alive "$SOCKETLEY_SOCKET"; then
    fail "a deeply nested document does not crash the daemon" \
         "the daemon is gone" \
         "200 KB of nesting is an ordinary request body, and json_decode is" \
         "written to be pointed at one."
elif said "DEEP_REFUSED"; then pass
elif said "DEEP_DECODED"; then
    fail "a deeply nested document is refused" \
         "it decoded 100000 levels, which the limit exists to prevent"
else
    fail "a deeply nested document is refused" \
         "the script reached json_decode and never came back"
fi

# ─── And a document just inside the limit still decodes ─────────────────────
#
# Pairs with the assertion above for the same reason the shared-table control
# pairs with the cycle one: a limit of zero would pass everything so far.
cat > "$SCRIPTS/shallow.lua" <<'LUA'
function on_start()
  local n = 64
  local s = string.rep("[", n) .. "42" .. string.rep("]", n)
  local v, why = socketley.json_decode(s)
  if v then socketley.log("SHALLOW_OK")
  else socketley.log("SHALLOW_REFUSED " .. tostring(why)) end
end
LUA
run_script jsonshallow $((P + 4)) "$SCRIPTS/shallow.lua"

if said "SHALLOW_OK"; then pass
else fail "a document within the limit still decodes" \
          "64 levels of nesting was refused, so the limit is too tight" \
          "or the refusal fires regardless of depth."; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
