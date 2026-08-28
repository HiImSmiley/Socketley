#!/usr/bin/env bash
# Integration test: what the Lua API does with a value it was given.
#
# ─── ONE SHAPE, SIX PLACES ──────────────────────────────────────────────────
#
# Every assertion in this file is about the same failure: a value is accepted,
# quietly altered or ignored, and success is reported.  That is worse than a
# refusal in a way that is easy to underrate — a refusal is read by the person
# who typed the thing, at the moment they typed it, and a silent alteration is
# discovered later by whoever is trying to work out why a runtime is not on the
# port they wrote down.
#
#   * socketley.create returns true for a child whose script never loaded and
#     for a `start = true` that never bound.
#   * `port = 70000` becomes 4464, `mode = "mater"` becomes an inout server,
#     `on_parent_stop = "keeep"` means the default, and `prot = 8080` means
#     nothing at all.
#   * socketley.pipe's fourth argument is read by nothing in the cross-runtime
#     branch, and the call reports success for a destination it did not use.
#   * `tick_ms = 5` became 100 in one file and 10 in the other, so the value
#     the timer used depended on which rule you read.
#   * `--lua` was executed the moment it was parsed, so self.port held whatever
#     -p had managed to set BEFORE it on the command line.
#   * No Lua diagnostic named the runtime it came from, so with more than one
#     script running the log said which callback failed and never which
#     runtime's.
#
# ─── WHY THE ASSERTIONS ARE PAIRED ──────────────────────────────────────────
#
# "create returned false" is also what a build with socketley.create removed
# would report, so each refusal is asserted together with the inventory: the
# runtime is not there afterwards.  And each refusal is paired with the same
# call made correctly, which must still succeed — a build that refused
# everything satisfies every "returns false" line in this file and fails every
# other one.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luaargs

PB=$((SL_PORT_BASE+1130))
RPC_PORT=$((PB + 0))    # the script under test, in the daemon
MADE_PORT=$((PB + 1))   # the child it is asked to build
TAKEN_PORT=$((PB + 2))  # held by python, so a bind there must fail
PIPE_B_PORT=$((PB + 3)) # the destination of the cross-runtime pipe
ORDER_PORT=$((PB + 4))  # the flag-order runtimes
TICK_PORT=$((PB + 5))

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
assert_has() {
    local label=$1 needle=$2 hay=$3; shift 3
    if [ "${hay#*"$needle"}" != "$hay" ]; then pass; else
        fail "$label" "'$needle' is not in '$hay'" "$@"
    fi
}

cleanup() {
    touch "${HOLD_STOP:-/dev/null}" 2>/dev/null || true
    [ -n "${HOLD_PID:-}" ] && wait "$HOLD_PID" 2>/dev/null
    for r in args made pipe_b ord_late ord_early tickrt; do
        "$BIN" stop "$r" 2>/dev/null || true
    done
    sleep 0.3
    for r in args made pipe_b ord_late ord_early tickrt; do
        "$BIN" remove "$r" 2>/dev/null || true
    done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: Lua argument handling and reporting ==="

daemon_start "$BIN"

# A port nothing may bind.  Held for the whole file so `start = true` against it
# is a bind failure and not a race.
cat > "$SOCKETLEY_TMPD/hold.py" <<'PYEOF'
import os, socket, sys, time
port, stop_path = int(sys.argv[1]), sys.argv[2]
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(4)
while not os.path.exists(stop_path):
    time.sleep(0.2)
s.close()
PYEOF
HOLD_STOP="$SOCKETLEY_TMPD/hold.stop"
python3 "$SOCKETLEY_TMPD/hold.py" "$TAKEN_PORT" "$HOLD_STOP" &
HOLD_PID=$!

# ask PORT TEXT [BUDGET] [FOLLOW]
#
# One line in, everything that comes back, flattened.  FOLLOW is a second line
# sent half a second later ON THE SAME CONNECTION, which is what section 3
# needs: the connection the pipe moved is the connection the payload has to
# travel on, and opening a second one would be measuring a different thing.
cat > "$SOCKETLEY_TMPD/ask.py" <<'PYEOF'
import select, socket, sys, time
port, text, budget = int(sys.argv[1]), sys.argv[2], float(sys.argv[3])
follow = sys.argv[4] if len(sys.argv) > 4 else ""
s = socket.create_connection(("127.0.0.1", port), 5)
s.sendall((text + "\n").encode())
out, end, sent = b"", time.time() + budget, not follow
while time.time() < end:
    if not sent and time.time() > end - budget + 0.5:
        try:
            s.sendall((follow + "\n").encode())
        except Exception:
            pass
        sent = True
    r, _, _ = select.select([s], [], [], 0.05)
    if not r:
        continue
    try:
        d = s.recv(65536)
    except Exception:
        break
    if not d:
        break
    out += d
s.close()
print(out.decode("latin-1").replace("\r", "").strip())
PYEOF
ask() { python3 "$SOCKETLEY_TMPD/ask.py" "$1" "$2" "${3:-2.5}" ${4:+"$4"}; }
hits() { grep -ac "$1" "$SOCKETLEY_DLOG" 2>/dev/null || true; }

# A script that does not compile, for the child create is asked to build.
cat > "$SOCKETLEY_TMPD/broken.lua" <<'EOF'
function on_start(
EOF

# The destination of the cross-runtime pipe.
cat > "$SOCKETLEY_TMPD/pipe_b.lua" <<'EOF'
function on_message(msg) socketley.log("PIPEB got=[" .. msg .. "]") end
EOF

RPC_LUA="$SOCKETLEY_TMPD/args.lua"
cat > "$RPC_LUA" <<LUAEOF
local MADE_PORT  = $MADE_PORT
local TAKEN_PORT = $TAKEN_PORT
local BROKEN     = "$SOCKETLEY_TMPD/broken.lua"
LUAEOF
cat >> "$RPC_LUA" <<'LUAEOF'
local function reply(id, s) self.send(id, s) end
local function words(msg)
    local out = {}
    for w in msg:gmatch("%S+") do out[#out+1] = w end
    return out
end

-- create=<what it returned> gone=<is the name absent afterwards>
--
-- The second half is the assertion.  A build that returns false and leaves the
-- half-built runtime in the map has not refused anything, it has just stopped
-- talking about it.
--
-- The removal first is not tidiness: on the parent commit every one of these
-- leaves `made` behind, and the NEXT case then measures a create that was
-- refused for the name being taken.  One bug reported six times, and five of
-- them for the wrong reason.
local function attempt(id, name, cfg)
    socketley.remove(name)
    local ok = socketley.create("server", name, cfg)
    reply(id, "create=" .. tostring(ok) ..
              " gone=" .. tostring(socketley.get(name) == nil))
end

function on_client_message(id, msg)
    local a = words(msg)
    local cmd = a[1]

    if cmd == "badscript" then
        attempt(id, "made", { port = MADE_PORT, config = BROKEN })

    elseif cmd == "badstart" then
        attempt(id, "made", { port = TAKEN_PORT, start = true })

    elseif cmd == "badport" then
        attempt(id, "made", { port = 70000 })

    elseif cmd == "badmode" then
        attempt(id, "made", { port = MADE_PORT, mode = "mater" })

    elseif cmd == "badpolicy" then
        attempt(id, "made", { port = MADE_PORT, on_parent_stop = "keeep" })

    elseif cmd == "badkey" then
        attempt(id, "made", { prot = 8080 })

    elseif cmd == "goodcreate" then
        socketley.remove("made")
        local ok = socketley.create("server", "made",
            { port = MADE_PORT, mode = "in", on_parent_stop = "remove" })
        local i = socketley.get("made")
        reply(id, "create=" .. tostring(ok) ..
                  " port=" .. tostring(i and i.port))

    elseif cmd == "dropmade" then
        reply(id, "removed=" .. tostring(socketley.remove("made")))

    elseif cmd == "pipe4" then
        -- The fourth argument names a descriptor of the DESTINATION runtime,
        -- and the cross-runtime branch routes by name and reads it never.
        reply(id, "pipe4=" .. tostring(socketley.pipe("args", id, "pipe_b", 0)))

    elseif cmd == "pipe3" then
        reply(id, "pipe3=" .. tostring(socketley.pipe("args", id, "pipe_b")))

    elseif cmd == "boom" then
        -- Reaches on_message-shaped reporting through a callback error: the
        -- log line has to name this runtime, not just the callback.
        local t = nil
        reply(id, "boom=" .. tostring(t.nothing))
    end
end
LUAEOF

create_ok "the script under test is created in the daemon" "$BIN" create server args \
    -p "$RPC_PORT" --mode in --lua "$RPC_LUA" -s
ready_tcp 127.0.0.1 "$RPC_PORT" 10 || echo "  NOTE: the RPC server never accepted"

create_ok "the pipe destination is created in the daemon" "$BIN" create server pipe_b \
    -p "$PIPE_B_PORT" --mode in --lua "$SOCKETLEY_TMPD/pipe_b.lua" -s
ready_tcp 127.0.0.1 "$PIPE_B_PORT" 10 || echo "  NOTE: pipe_b never accepted"

# ── 1. socketley.create reports what it actually built ─────────────────────
assert_eq "a child whose script will not load is refused, not reported as made" \
          "create=false gone=true" "$(ask "$RPC_PORT" badscript)" \
    "load_lua_script's return was discarded, so the child was created," \
    "registered and answered true with not one callback registered"

assert_eq "a child whose start cannot bind is refused, not reported as made" \
          "create=false gone=true" "$(ask "$RPC_PORT" badstart)" \
    "start = true on a port another process holds; mgr->start's return was" \
    "discarded, so the answer was true for a server that never listened"

# ── 2. the config table is validated ───────────────────────────────────────
assert_eq "a port outside 0..65535 is refused, not truncated" \
          "create=false gone=true" "$(ask "$RPC_PORT" badport)" \
    "70000 cast to uint16_t is 4464 — a runtime on a port nobody chose, and" \
    "the CLI's own -p has refused exactly this since parse_uint16 existed"

assert_eq "an unrecognised mode is refused, not defaulted to inout" \
          "create=false gone=true" "$(ask "$RPC_PORT" badmode)" \
    "the default: branch of the mode switch swallowed every misspelling, so" \
    "a server meant to be one-way was a two-way server that looked right"

assert_eq "an unrecognised on_parent_stop is refused, not read as stop" \
          "create=false gone=true" "$(ask "$RPC_PORT" badpolicy)" \
    "only 'remove' was compared for; everything else, a typo included, meant" \
    "the default — so a child meant to go with its parent outlived it"

assert_eq "a key that is not a config key is refused, not ignored" \
          "create=false gone=true" "$(ask "$RPC_PORT" badkey)" \
    "prot = 8080 produced a server on port 0 with nothing said; the same" \
    "argument filters and routes are validated under, in the same file"

GOOD=$(ask "$RPC_PORT" goodcreate)
assert_eq "...and a config that is right is still built, with the port asked for" \
          "create=true port=$MADE_PORT" "$GOOD" \
    "the control for every refusal above: a build that refused everything" \
    "would pass all four and fail this one"
assert_eq "...and it can be removed again" "removed=true" "$(ask "$RPC_PORT" dropmade)"

# ── 3. socketley.pipe's fourth argument ────────────────────────────────────
assert_eq "a cross-runtime pipe given a destination descriptor is refused" \
          "pipe4=false" "$(grep -o 'pipe4=[a-z]*' <<<"$(ask "$RPC_PORT" pipe4)" | head -1)" \
    "the cross-runtime branch routes the connection to the destination" \
    "RUNTIME and lets it decide; there is no descriptor it could honour, so" \
    "the argument was read by nothing and the call answered true"

P3=$(ask "$RPC_PORT" pipe3 2.5 PIPED-PAYLOAD)
assert_eq "...and the three-argument form, which is what it can do, still works" \
          "pipe3=true" "$(grep -o 'pipe3=[a-z]*' <<<"$P3" | head -1)" \
    "the arity is the request now: three routes by name, four pairs two" \
    "descriptors inside one runtime"
sleep 0.5
assert_eq "...and the destination runtime receives the source's traffic" \
          "1" "$(hits 'PIPEB got=\[PIPED-PAYLOAD\]')" \
    "asserted after a payload sent on the same connection that was piped"

# ── 4. tick_ms has one floor ───────────────────────────────────────────────
#
# `-s`, and it is load-bearing rather than tidiness.  `tick_ms` is a GLOBAL in
# the script, so reading it means evaluating the script's top level, and that
# happens where the script runs -- in the worker, at start.  A bare `create`
# only compiles it, which is the whole of what the placeholder does.
#
# This block used to have no `-s` and passed, because --daemon-process was not
# needed to make `create` load a script in the daemon: `create --lua x` there
# loaded AND ran it, floor check included.  With every runtime in a worker the
# floor is checked one command later.  That is the contract now -- a script runs
# when its runtime starts -- and asserting the refusal at `create -s` is
# asserting the same rule at the first command that can enforce it.
cat > "$SOCKETLEY_TMPD/tick5.lua" <<'EOF'
tick_ms = 5
function on_tick(dt) end
EOF
TICK_OUT=$("$BIN" create server tickrt -p "$TICK_PORT" \
           --lua "$SOCKETLEY_TMPD/tick5.lua" -s 2>&1) && TICK_RC=0 || TICK_RC=$?
assert_eq "tick_ms below the floor is refused rather than silently multiplied" \
          "1" "$TICK_RC" \
    "lua_context mapped anything under 10 to 100 and runtime_instance clamped" \
    "it to 10, so the same script ticked at two different rates depending on" \
    "which of the two rules you read; got: $TICK_OUT"
assert_has "...and the refusal names the floor" "10" "$TICK_OUT" "got: $TICK_OUT"
# Left `failed` rather than absent, and that is the other half of the same
# change.  A create that refuses in the daemon builds nothing; a create that is
# refused BY ITS WORKER has already put a runtime in the map, and what says so
# is the state.  Asserting it is gone would be asserting the old command's
# shape, not this one's contract.
assert_eq "...and it is left failed rather than serving" "1" \
          "$("$BIN" ls 2>/dev/null | awk '$2 == "tickrt" && tolower($7) == "failed"' | grep -c . || true)" \
    "a runtime whose script the worker would not load must not read as Up:" \
    "$("$BIN" ls 2>/dev/null | grep ' tickrt ' || echo '<not listed at all>')"

# ── 5. self.port does not depend on the order the flags were typed ─────────
cat > "$SOCKETLEY_TMPD/order.lua" <<'EOF'
function on_start() socketley.log("SELFPORT=" .. tostring(self.port)) end
EOF
create_ok "--lua before -p" "$BIN" create server ord_late \
    --lua "$SOCKETLEY_TMPD/order.lua" -p "$ORDER_PORT" -s
create_ok "-p before --lua" "$BIN" create server ord_early \
    -p "$((ORDER_PORT + 10))" --lua "$SOCKETLEY_TMPD/order.lua" -s
sleep 0.6
assert_eq "self.port is the port that was asked for, --lua written first" \
          "1" "$(hits "SELFPORT=$ORDER_PORT")" \
    "--lua was acted on the moment it was parsed, so the self table snapshotted" \
    "a port -p had not set yet and self.port stayed 0 for the runtime's life," \
    "while socketley.get(name).port answered correctly the whole time"
assert_eq "...and written second" "1" "$(hits "SELFPORT=$((ORDER_PORT + 10))")" \
    "the control: this ordering was always right, and a fix that broke it" \
    "would have moved the bug rather than removed it"

# ── 6. a Lua diagnostic names the runtime it came from ─────────────────────
ask "$RPC_PORT" boom >/dev/null 2>&1 || true
sleep 0.4
assert_eq "a callback error names the runtime whose script raised it" \
          "1" "$(hits '\[lua args\] on_client_message error')" \
    "with more than one script running, 'on_message error: h.lua:12' names a" \
    "file at best and the runtime never — and two runtimes commonly share one" \
    "script file"
assert_eq "socketley.log names the runtime that wrote the line" \
          "1" "$(hits '\[lua pipe_b\] PIPEB got=')" \
    "the same argument: one stderr, forty scripts writing to it"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
