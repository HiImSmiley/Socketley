#!/usr/bin/env bash
# Integration test: a client runtime with --lua.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# No test in this suite had ever created a client with a script.  The client
# table binds three things — self.send, self.connections and self.protocol — and
# none of them was executed by anything.
#
# ─── THE ORDER IS PART OF THE CONTRACT ──────────────────────────────────────
#
# on_connect fires BEFORE on_start on a client, which is the reverse of the
# order a reader expects and is not written down anywhere.  It falls out of
# where invoke_on_connect sits: the client dials in start(), the dial is
# non-blocking, and on_connect is called at the point the socket is armed —
# which is before the runtime has finished starting.  A script that initialises
# its state in on_start and uses it in on_connect is therefore broken today, and
# would be silently fixed or silently broken further by a change to that order.
#
# This file pins the order as it is.  Not because it is the right way round —
# that is a design question this file does not answer — but so that changing it
# is a decision somebody makes rather than a side effect somebody ships.  The
# assertion is the exact sequence the script recorded, so both a swap and a
# dropped callback fail it.
#
# ─── WHAT IS DELIBERATELY NOT PINNED ────────────────────────────────────────
#
# on_connect also fires for a dial that is later refused: connect() returns
# EINPROGRESS, the callback runs, and on_disconnect follows when the refusal
# arrives.  Measured against a port with nothing on it — on_connect id=6
# conns=1, then on_disconnect id=6.  client_instance.cpp says as much where it
# does it ("the connect may still be in flight at this point"), so it is a known
# consequence of the non-blocking dial rather than an oversight, and asserting
# it here would freeze a decision that has not been made.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_create.sh"

daemon_isolate luaclient

PB=${SOCKETLEY_PORT_BASE:-19160}
SRV_PORT=$((PB + 0))
UDP_PORT=$((PB + 1))

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
    "$BIN" stop  lc_cli lc_udpcli lc_srv lc_udpsrv 2>/dev/null || true
    sleep 0.3
    "$BIN" remove lc_cli lc_udpcli lc_srv lc_udpsrv 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a client runtime with --lua ==="

daemon_start "$BIN"

SRV_LUA="$SOCKETLEY_TMPD/srv.lua"
cat > "$SRV_LUA" <<'LUAEOF'
function on_client_message(id, msg)
    socketley.log("SRV got=[" .. msg .. "]")
    self.send(id, "REPLY-" .. msg)
end
LUAEOF

UDPSRV_LUA="$SOCKETLEY_TMPD/udpsrv.lua"
cat > "$UDPSRV_LUA" <<'LUAEOF'
function on_message(msg)
    socketley.log("UDPSRV got=[" .. msg .. "]")
end
LUAEOF

# write_client FILE TAG — the script under test.  The order table is the point:
# every callback appends its own name, and every line carries the sequence so
# far, so a swap shows up as a different string rather than as an absence.
write_client() {
    cat > "$1" <<LUAEOF
local TAG = "$2"
local order = {}

function on_connect(id)
    order[#order+1] = "on_connect"
    socketley.log(TAG .. " order=" .. table.concat(order, ",") ..
                  " id=" .. tostring(id) ..
                  " conns=" .. tostring(self.connections()))
end

function on_start()
    order[#order+1] = "on_start"
    socketley.log(TAG .. " order=" .. table.concat(order, ","))
    socketley.log(TAG .. " ident name=" .. self.name ..
                  " type=" .. self.type ..
                  " proto=" .. self.protocol ..
                  " alias=" .. tostring(rawequal(client, self)))
    self.send("$3")
end

function on_message(msg)
    socketley.log(TAG .. " msg=[" .. msg .. "]")
end

function on_disconnect(id)
    socketley.log(TAG .. " disc id=" .. tostring(id))
end
LUAEOF
}

CLI_LUA="$SOCKETLEY_TMPD/cli.lua"
write_client "$CLI_LUA" CLI "PAYLOAD-FROM-CLIENT"
UDPCLI_LUA="$SOCKETLEY_TMPD/udpcli.lua"
write_client "$UDPCLI_LUA" UDPCLI "UDP-PAYLOAD-FROM-CLIENT"

said() {
    local pattern=$1 deadline=$(( $(date +%s) + ${2:-8} ))
    while [ "$(date +%s)" -le "$deadline" ]; do
        grep -qaE "$pattern" "$SOCKETLEY_DLOG" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}
# line PATTERN — the first log line matching it, without the timestamp noise.
line() {
    { grep -aoE "$1" "$SOCKETLEY_DLOG" 2>/dev/null || true; } | head -1
}
hits() { grep -ac "$1" "$2" 2>/dev/null || true; }
stat() {
    { "$BIN" stats "$1" 2>/dev/null || true; } \
        | awk -F: -v k="$2" '$1 == k { print $2; exit }'
}
# await_stat NAME KEY WANT — wait for a figure to reach WANT, then leave it to
# the assertion to say whether it did.  A worker pushes its figures to the
# daemon, so a `stats` read taken the instant a log line appears reads a number
# that has not arrived yet; without this the two assertions using it failed
# against a build with nothing wrong with it.
await_stat() {
    local i
    for i in $(seq 1 100); do
        [ "$(stat "$1" "$2")" = "$3" ] && return 0
        sleep 0.1
    done
    return 0
}

create_ok "TCP server created" "$BIN" create server lc_srv \
    -p "$SRV_PORT" --mode in --lua "$SRV_LUA" -s
create_ok "UDP server created" "$BIN" create server lc_udpsrv \
    -p "$UDP_PORT" --udp --lua "$UDPSRV_LUA" -s
ready_tcp 127.0.0.1 "$SRV_PORT" 10 || echo "  NOTE: the TCP server never accepted"

create_ok "TCP client created with a script" "$BIN" create client lc_cli \
    -t "127.0.0.1:$SRV_PORT" --lua "$CLI_LUA" -s
create_ok "UDP client created with a script" "$BIN" create client lc_udpcli \
    --udp -t "127.0.0.1:$UDP_PORT" --lua "$UDPCLI_LUA" -s

said 'CLI order=on_connect,on_start' 10 || true
said 'SRV got=' 10 || true
said 'CLI msg=' 10 || true

# ── 1. The callback order ──────────────────────────────────────────────────
assert_eq "on_connect fires first, and reports one connection" \
          "CLI order=on_connect id=OK conns=1" \
          "$(line 'CLI order=on_connect id=[0-9]+ conns=[0-9]+' | sed -E 's/id=[0-9]+/id=OK/')" \
    "the id is normalised because it is a descriptor number and not a" \
    "contract; the sequence and the count are"
assert_eq "on_start fires second" \
          "CLI order=on_connect,on_start" "$(line 'CLI order=on_connect,on_start')" \
    "current behaviour, pinned so that a change to it is a decision rather" \
    "than a side effect: a script that sets state up in on_start and uses it" \
    "in on_connect is broken today and would be silently fixed by a swap"

# ── 2. self.name, self.type, self.protocol ─────────────────────────────────
# alias=true is rawequal: the global `client` is the same table as self, not a
# copy — register_bindings does m_lua[type_to_string(type)] = self.  A copy
# would pass a "calling through it works" check and give a script two places to
# keep state.
assert_eq "self.name, self.type, self.protocol, and the 'client' alias" \
          "CLI ident name=lc_cli type=client proto=tcp alias=true" \
          "$(line 'CLI ident name=[a-z_]+ type=[a-z]+ proto=[a-z]+ alias=[a-z]+')"
said 'UDPCLI ident' 10 || true
assert_eq "self.protocol says udp on a --udp client" \
          "UDPCLI ident name=lc_udpcli type=client proto=udp alias=true" \
          "$(line 'UDPCLI ident name=[a-z_]+ type=[a-z]+ proto=[a-z]+ alias=[a-z]+')" \
    "the tcp assertion above passes on a build that hard-codes the string;" \
    "the pair does not"

# ── 3. self.send, and the exact bytes on the far side ──────────────────────
assert_eq "self.send() delivers the payload to the server" \
          "1" "$(hits 'SRV got=\[PAYLOAD-FROM-CLIENT\]' "$SOCKETLEY_DLOG")" \
    "the server's own callback, with the exact string — not 'a message'"
await_stat lc_srv total_messages 1
assert_eq "the server's message counter agrees" "1" "$(stat lc_srv total_messages)" \
    "a second oracle for the same delivery, off the runtime rather than off" \
    "a script, so a build whose logging works and whose plumbing does not" \
    "cannot satisfy both"
assert_eq "on_message on the client carries the server's reply" \
          "1" "$(hits 'CLI msg=\[REPLY-PAYLOAD-FROM-CLIENT\]' "$SOCKETLEY_DLOG")"

said 'UDPSRV got=' 10 || true
assert_eq "self.send() on a UDP client reaches the UDP server" \
          "1" "$(hits 'UDPSRV got=\[UDP-PAYLOAD-FROM-CLIENT\]' "$SOCKETLEY_DLOG")"

# ── 4. self.connections() against the runtime's own figure ─────────────────
await_stat lc_cli connections 1
assert_eq "self.connections() agrees with stats while connected" \
          "1" "$(stat lc_cli connections)" \
    "the script reported 1 in on_connect above; this is the same claim asked" \
    "of the runtime, so the two cannot be satisfied by one wrong constant"

# ── 5. on_disconnect names the connection that connected ───────────────────
CONN_ID=$({ grep -aoE 'CLI order=on_connect id=[0-9]+' "$SOCKETLEY_DLOG" 2>/dev/null || true; } \
          | head -1 | sed 's/.*id=//')
"$BIN" stop lc_srv >/dev/null 2>&1 || true
said 'CLI disc id=' 10 || true
DISC_ID=$({ grep -aoE 'CLI disc id=[0-9]+' "$SOCKETLEY_DLOG" 2>/dev/null || true; } \
          | head -1 | sed 's/.*id=//')

# Both operands have to exist before the comparison means anything — an
# identity assertion over two empty strings is green and says nothing.
if [ -n "$CONN_ID" ] && [ -n "$DISC_ID" ]; then pass; else
    fail "there are two ids to compare" \
         "on_connect gave '${CONN_ID:-<none>}', on_disconnect '${DISC_ID:-<none>}'"
fi
assert_eq "on_disconnect names the connection that connected" "$CONN_ID" "$DISC_ID"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
