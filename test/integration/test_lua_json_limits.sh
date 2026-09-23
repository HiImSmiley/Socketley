#!/usr/bin/env bash
# Integration test: socketley.json_encode / json_decode refuse rather than crash.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
# Both are recursive in C++ over a structure the script hands them and neither
# had a depth limit or a cycle check, so a self-referencing table segfaulted
# the encoder and 200 KB of nesting -- an ordinary request body -- segfaulted
# the decoder, which made every script calling it on network input a way for an
# unauthenticated client to take the daemon down; the callback deadline covers
# neither, since it hooks Lua instructions and this is C++ frames on the C
# stack.
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
# Each refusal is paired with a control that must still work, one of them
# specific: a table reachable twice by different paths but not containing
# itself must still encode, because a fix written with a visited set instead of
# an ancestor chain refuses it invisibly.

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

# Load a script as a runtime's on_start and let it run, with the assertions
# reading what the interpreter refused out of the log rather than inferring it
# from something dying -- since out of process a crash kills only the worker
# and would be measuring the restart policy.
run_script() {
    local name=$1 port=$2 file=$3
    # Every case starts against a daemon of our own that is answering, so a
    # crash in one case cannot be reported again by the next.
    daemon_recover
    "$BIN" create server "$name" -p "$port" --lua "$file" -s \
        >/dev/null 2>&1 || true
    sleep 0.4
}

# said MARKER — did the script reach this point?
said() { grep -q "$1" "$SOCKETLEY_DLOG" 2>/dev/null; }

# Each case has to measure its own script, or every case after a crash reports
# the previous one's death and two findings read as three -- with the condition
# being that our daemon is serving, since `ping || restart` forks a replacement
# while asking the question.
daemon_recover() {
    local serving; serving=$(daemon_pids "$SOCKETLEY_SOCKET")
    if [ -n "$serving" ] && [ "$serving" = "${SOCKETLEY_DPID:-}" ] \
       && timeout 5 "$BIN" ping >/dev/null 2>&1; then
        return 0
    fi
    daemon_sweep "$SOCKETLEY_SOCKET"
    if [ -n "${SOCKETLEY_DPID:-}" ]; then wait "$SOCKETLEY_DPID" 2>/dev/null || true; fi
    # kill -9 returns when the signal is queued rather than when the process is
    # gone, so a daemon starting inside that window decides one is already
    # there and exits 0.
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

# The assertion that separates an ancestor chain from a visited set: reached
# twice by different paths, containing itself nowhere, so it has to encode.
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

# The decoder returned whatever it had understood by the time it gave up, so a
# truncated body was indistinguishable from a whole one -- and each case is
# checked for a refusal rather than merely for inequality, because a build
# returning nil for all of them would pass the weaker form.
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
# json_decode_value stops at the end of the first complete value and says
# nothing about what follows, so the binding is where trailing content is
# caught.
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
# A Lua table has no order of its own, so json_encode returned different
# strings for the same content and broke every use that compares its output --
# asserted as sorted order rather than as two encodings matching, because with
# five short keys the unfixed build happened to agree, while twenty keys make
# an accidental pass effectively impossible; the equality check is kept below
# as the property a caller depends on, but it is the weaker one and is not red
# on the unfixed build.
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

# ─── A number JSON cannot spell ─────────────────────────────────────────────
#
# %.14g writes `inf`, `-inf` and `nan`, none of which is a JSON token, so the
# encoder produced a document its own decoder refuses -- and the script was
# handed a string, so `if not s then` did not fire and the bytes went to the
# client.  The cast that decides the integer form also ran BEFORE its range
# test, which is undefined for any magnitude past int64 and is not covered by
# -fsanitize=undefined on gcc.
cat > "$SCRIPTS/nonfinite.lua" <<'LUA'
function on_start()
  local vals  = { 1/0, -1/0, 0/0 }
  local names = { "inf", "-inf", "nan" }
  local refused, emitted = 0, {}
  for i, v in ipairs(vals) do
    local s, why = socketley.json_encode({ x = v })
    if not s and why then
      refused = refused + 1
    else
      emitted[#emitted + 1] = names[i] .. "=" .. tostring(s)
      -- The policy-independent half: whatever comes back has to be a document
      -- this build's own decoder reads.
      local back = socketley.json_decode(s)
      if not back then socketley.log("NONFINITE_UNPARSEABLE " .. tostring(s)) end
    end
  end
  socketley.log("NONFINITE_REFUSED " .. refused .. "/3")
  if #emitted > 0 then
    socketley.log("NONFINITE_EMITTED " .. table.concat(emitted, " | "))
  end

  -- The control: an ordinary enormous double is finite and must still encode
  -- and still round trip.  A fix that refused everything past 1e15 would pass
  -- every assertion above and fail this one.
  local big = socketley.json_encode({ x = 1e300 })
  local back = big and socketley.json_decode(big)
  if back and back.x == 1e300 then socketley.log("BIG_OK " .. big)
  else socketley.log("BIG_BROKEN " .. tostring(big)) end
end
LUA
run_script jsonnonfinite $((P + 8)) "$SCRIPTS/nonfinite.lua"

if said "NONFINITE_REFUSED 3/3"; then pass
else fail "an infinity or a NaN is refused rather than written" \
          "$(grep -o 'NONFINITE_REFUSED [0-9/]*' "$SOCKETLEY_DLOG" 2>/dev/null | tail -1)" \
          "$(grep -o 'NONFINITE_EMITTED.*' "$SOCKETLEY_DLOG" 2>/dev/null | tail -1)" \
          "JSON has no token for either, so the script was handed a string and" \
          "sent bytes no consumer can parse."; fi

if said "NONFINITE_UNPARSEABLE"; then
    fail "json_encode never produces what json_decode refuses" \
         "$(grep -o 'NONFINITE_UNPARSEABLE.*' "$SOCKETLEY_DLOG" 2>/dev/null | tail -1)" \
         "the two halves of one pair disagreed about their own grammar."
else pass; fi

if said "BIG_OK"; then pass
else fail "a large finite double still encodes and round-trips" \
          "$(grep -o 'BIG_BROKEN.*' "$SOCKETLEY_DLOG" 2>/dev/null | tail -1)" \
          "1e300 is an ordinary number; refusing it means the guard is on" \
          "magnitude rather than on finiteness."; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
