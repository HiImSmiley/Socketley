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
# Load a script as a runtime's on_start and let it run.
#
# This used to pass --daemon-process on purpose, so that a crash took the daemon
# and was unambiguous: out of process it kills only the worker, the supervisor
# restarts it, and an assertion on "did it crash" would be measuring the restart
# policy.  There is no in-daemon runtime now, so the assertions below are the
# ones that survive the difference -- they read what the interpreter REFUSED,
# out of the log, rather than inferring it from something dying.
run_script() {
    local name=$1 port=$2 file=$3
    # Every case starts against a daemon of our own that is answering, so a
    # crash in one case cannot be reported again by the next.  Markers are per
    # case, so the log truncation inside daemon_recover costs nothing.
    daemon_recover
    "$BIN" create server "$name" -p "$port" --lua "$file" -s \
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

# ─── Malformed input is refused rather than half-decoded ────────────────────
#
# The decoder reported nothing but the depth limit.  Everything else came back
# as whatever it had understood by the time it gave up, so a script could not
# tell a complete document from a fragment:
#
#     [1,2       -> a two-element table, indistinguishable from [1,2]
#     {"a":}     -> an empty table, the field silently gone
#     "x         -> the string x
#     nul        -> nil, which is also the answer for a real null
#     {a:1}      -> a table with an "" field
#
# `[1,2` is the case worth naming: that is a request body cut off by a dropped
# connection, and the handler proceeded on it believing it was whole.
#
# Each is checked for a REFUSAL, not merely for "not equal to the whole
# document" — a build that returned nil for all of them would pass the weaker
# form while being just as unable to say what went wrong.
cat > "$SCRIPTS/malformed.lua" <<'LUA'
function on_start()
  local cases = { "[1,2", '{"a":}', '"x', "nul", "{a:1}", "", "-", "{" }
  local refused, accepted = 0, {}
  for _, doc in ipairs(cases) do
    local v, why = socketley.json_decode(doc)
    if v == false and why then refused = refused + 1
    else accepted[#accepted + 1] = doc end
  end
  socketley.log("MALFORMED_REFUSED " .. refused .. "/" .. #cases)
  if #accepted > 0 then
    socketley.log("MALFORMED_ACCEPTED " .. table.concat(accepted, " | "))
  end
  -- The control: a real null must still decode, and must NOT be reported as
  -- an error.  It is the one document whose value is nil, and the refusal
  -- contract exists precisely so the two are different answers.
  local v, why = socketley.json_decode("null")
  if v == false then socketley.log("NULL_REFUSED " .. tostring(why))
  else socketley.log("NULL_OK") end
end
LUA
run_script jsonmal $((P + 5)) "$SCRIPTS/malformed.lua"

if said "MALFORMED_REFUSED 8/8"; then pass
else fail "every malformed document is refused" \
          "$(grep -o 'MALFORMED_REFUSED [0-9/]*' "$SOCKETLEY_DLOG" 2>/dev/null | tail -1)" \
          "$(grep -o 'MALFORMED_ACCEPTED.*' "$SOCKETLEY_DLOG" 2>/dev/null | tail -1)" \
          "a fragment decoded to a value the script cannot tell from a whole one."; fi

if said "NULL_OK"; then pass
else fail "a real null still decodes" \
          "the document 'null' was reported as an error" \
          "null is a value, not a failure; conflating them is the bug this" \
          "whole contract exists to remove, only in the other direction."; fi

# ─── Trailing data ──────────────────────────────────────────────────────────
#
# json_decode_value stops at the end of the first complete value and says
# nothing about what follows, so the binding is where this is caught.  A body
# with something appended to it is exactly the case worth noticing.
cat > "$SCRIPTS/trailing.lua" <<'LUA'
function on_start()
  local v = socketley.json_decode('{"a":1} and then some')
  if v == false then socketley.log("TRAILING_REFUSED")
  else socketley.log("TRAILING_ACCEPTED") end
  -- Control: trailing WHITESPACE is not trailing data.  A body that ends in a
  -- newline is the normal case, and refusing it would break every caller.
  local w = socketley.json_decode('  {"a":1}  \n\t')
  if w and w.a == 1 then socketley.log("WS_OK")
  else socketley.log("WS_REFUSED") end
end
LUA
run_script jsontrail $((P + 6)) "$SCRIPTS/trailing.lua"

if said "TRAILING_REFUSED"; then pass
else fail "trailing data after the document is refused" \
          "'{\"a\":1} and then some' decoded to {a=1} and the rest went unmentioned"; fi

if said "WS_OK"; then pass
else fail "trailing whitespace is still accepted" \
          "a document ending in a newline was refused — that is the normal case"; fi

# ─── encode is a function of its argument ───────────────────────────────────
#
# A Lua table has no order of its own, and lua_next does not produce the same
# arbitrary order for two tables holding equal data.  So json_encode returned
# different strings for the same content, which breaks every use that compares
# its output: an ETag, a cache key, a signature, a dedup hash.
#
# Found by the fuzz target as encode(decode(encode(x))) != encode(x):
#
#     once : {"b":[1,2,{"c":"x"}],"e":3}
#     twice: {"e":3,"b":[1,2,{"c":"x"}]}
#
# ─── Why this asserts SORTED and not merely EQUAL ───────────────────────────
#
# The first version of this case built two tables with five keys in opposite
# insertion orders and asserted their encodings matched.  It passed against the
# unfixed build: with five short keys LuaJIT happened to produce the same
# arbitrary order for both, so the assertion reported "stable" about code that
# was not.  Green on both sides is worth nothing, and it is the failure mode
# this suite has been bitten by before.
#
# Sorted order is the contract itself rather than a proxy for it, and twenty
# keys make an accidental pass effectively impossible — the unfixed build would
# have to hash them into alphabetical order by chance.  Measured against it:
#
#   {"m":1,"c":2,"x":3,"a":4,"q":5,"b":6,"z":7,"d":8,"p":9,"e":10,
#    "y":11,"f":12,"g":14,"w":15,"h":16,"r":17,"i":18,"v":19,"j":20,"n":13}
#
# so this assertion is red there.
#
# The equality of two differently-built tables is kept below because it is the
# property a caller actually depends on — but it is the weaker check and it is
# NOT red on the unfixed build: measured, both twenty-key tables still encoded
# identically there.  It states the intent; the sorted check is what catches a
# regression.
cat > "$SCRIPTS/stable.lua" <<'LUA'
function on_start()
  local names = {"m","c","x","a","q","b","z","d","p","e",
                 "y","f","n","g","w","h","r","i","v","j"}
  local a = {}
  for i, k in ipairs(names) do a[k] = i end
  local b = {}
  for i = #names, 1, -1 do b[names[i]] = i end

  local sa, sb = socketley.json_encode(a), socketley.json_encode(b)

  -- The contract: object keys come out in sorted order.  Values are numbers,
  -- so every quoted run followed by a colon is a key.
  local keys = {}
  for k in string.gmatch(sa, '"([^"]*)":') do keys[#keys + 1] = k end
  local sorted = (#keys == #names)
  for i = 2, #keys do
    if keys[i] <= keys[i - 1] then sorted = false end
  end
  if sorted then socketley.log("SORTED_OK")
  else socketley.log("SORTED_BROKEN " .. tostring(sa)) end

  if sa == sb then socketley.log("STABLE_OK")
  else socketley.log("STABLE_DIFFERS " .. tostring(sa) .. " vs " .. tostring(sb)) end

  -- And the round trip is a fixpoint: encode, decode, encode again.
  local once = socketley.json_encode({ e = 3, b = {1,2,{ c = "x" }} })
  local twice = socketley.json_encode(socketley.json_decode(once))
  if once == twice then socketley.log("FIXPOINT_OK")
  else socketley.log("FIXPOINT_DIFFERS " .. once .. " vs " .. twice) end

  -- The control: sorting keys must not disturb ARRAY order, which is part of
  -- the value.  [10,20,30] sorted as text would be "10","20","30" and look
  -- fine; [3,20,100] would not.
  local arr = socketley.json_encode({3, 20, 100})
  if arr == "[3,20,100]" then socketley.log("ARRAY_ORDER_OK")
  else socketley.log("ARRAY_ORDER_BROKEN " .. tostring(arr)) end
end
LUA
run_script jsonstable $((P + 7)) "$SCRIPTS/stable.lua"

if said "SORTED_OK"; then pass
else fail "object keys are written in sorted order" \
          "$(grep -o 'SORTED_BROKEN.*' "$SOCKETLEY_DLOG" 2>/dev/null | tail -1)" \
          "without a defined order the output is whatever lua_next happened to" \
          "produce, which is not the same twice for equal data."; fi

if said "STABLE_OK"; then pass
else fail "equal data encodes to equal strings" \
          "$(grep -o 'STABLE_DIFFERS.*' "$SOCKETLEY_DLOG" 2>/dev/null | tail -1)" \
          "json_encode was not a function of its argument, so an ETag or a" \
          "cache key computed from it changed without the data changing."; fi

if said "FIXPOINT_OK"; then pass
else fail "encode(decode(encode(x))) == encode(x)" \
          "$(grep -o 'FIXPOINT_DIFFERS.*' "$SOCKETLEY_DLOG" 2>/dev/null | tail -1)"; fi

if said "ARRAY_ORDER_OK"; then pass
else fail "array order survives the key sort" \
          "$(grep -o 'ARRAY_ORDER_BROKEN.*' "$SOCKETLEY_DLOG" 2>/dev/null | tail -1)" \
          "an array's order is part of the value; only object keys may be sorted."; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
