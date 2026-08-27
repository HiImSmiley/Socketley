#!/usr/bin/env bash
# Integration test: on_auth, the connection gate.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# on_auth is the only Lua callback whose return value decides whether a client
# is served at all, and until now nothing in this suite called it.  It is a
# three-way decision made in runtime_instance::invoke_on_auth, and the two
# rejecting arms are the ones that matter:
#
#     if (!m_lua || !m_lua->has_on_auth()) return true;   // absent  -> allow
#     sol::optional<bool> res = m_lua->on_auth()(client_id);
#     return res.value_or(false);                          // nil/non-bool -> REJECT
#     ... catch (const sol::error&) { return false; }      // raised  -> REJECT
#
# Fail-closed in both, which is the right way round and exactly the property
# that rots quietly: a change that made a raised error allow the connection
# would break nothing anyone runs, and would turn a script's syntax error into
# an open door.
#
# ─── THE ORACLE IS NOT THE CLIENT ───────────────────────────────────────────
#
# A rejected client's connect() SUCCEEDS.  Both runtimes accept the descriptor
# first and close it after on_auth answers — the server with shutdown(SHUT_RDWR)
# then close_conn, the proxy with close_tracked — so from outside, a rejection
# looks like a connection that was made and then went away, which is also what a
# successful short-lived request looks like.  `nc` exits 0 either way.  Measured
# on this build, all five arms:
#
#     mode      nc exit    server bytes_in
#     true      0          0 -> 10
#     false     0          10 -> 10
#     nil       0          10 -> 10
#     non-bool  0          10 -> 10
#     error     0          10 -> 10
#
# So the oracle is the runtime's own figures, and they are different figures for
# the two runtime types, which is worth writing down because getting it wrong
# produces a test that always passes:
#
#   * SERVER: bytes_in.  NOT total_connections — the server increments that
#     before it calls on_auth (server_instance.cpp, at the accept), so it counts
#     rejected connections too and went 1,2,3,4,5 across the five arms above.
#     bytes_in only moves when a read completes, and a rejected connection never
#     has a read submitted.
#   * PROXY: total_connections.  The proxy increments it AFTER on_auth answers,
#     so for a proxy it is exactly the count of admitted clients.
#
# And on both, the second half of the claim: on_connect must not fire for a
# client that was turned away.  That is the callback a script hangs its
# per-connection state on, and a gate that rejects the traffic while still
# announcing the connection is a leak of a different kind.
#
# ─── THE CONTROL ────────────────────────────────────────────────────────────
#
# A runtime of each type with NO on_auth at all, driven by the same probe.  It
# is what separates "the gate rejected this" from "nothing was ever served",
# and it is also the third arm of the decision — absent means allow.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate luaauth

PB=$((SL_PORT_BASE+130))
SRV_PORT=$((PB + 0))       # server with the gate
SRV_OPEN_PORT=$((PB + 1))  # server with no gate — the control
BE_PORT=$((PB + 2))        # the proxy's backend
PRX_PORT=$((PB + 3))       # proxy with the gate
PRX_OPEN_PORT=$((PB + 4))  # proxy with no gate — the control

# Ten bytes, exactly, so the server's bytes_in delta is a number this file can
# name rather than a direction it can only point in.
PROBE='AUTHPROBE'
PROBE_BYTES=10

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
    "$BIN" stop  sa_gate sa_open be pa_gate pa_open 2>/dev/null || true
    sleep 0.3
    "$BIN" remove sa_gate sa_open be pa_gate pa_open 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: on_auth admits and refuses ==="

daemon_start "$BIN"

MODE_FILE="$SOCKETLEY_TMPD/authmode"
echo true > "$MODE_FILE"

# The gate script.  One runtime covers every arm because the decision is read
# from a file at each call — five runtimes each with a hard-coded answer would
# measure five interpreters rather than five branches, and would make the
# "on_connect did not fire" half harder to attribute.
#
# The heredoc is unquoted so that $MODE_FILE and $1 land in the script; nothing
# else in it is expanded, because nothing else in it uses a dollar sign.
write_gate() {
    cat > "$1" <<LUAEOF
local MODE_FILE = "$MODE_FILE"
local TAG = "$2"

local function mode()
    local f = io.open(MODE_FILE, "r")
    if not f then return "true" end
    local m = f:read("*l")
    f:close()
    return m or "true"
end

function on_auth(id)
    local m = mode()
    socketley.log(TAG .. " auth mode=" .. m)
    if m == "true"   then return true end
    if m == "false"  then return false end
    if m == "nil"    then return nil end
    if m == "nonbool" then return "yes" end
    if m == "error"  then error("on_auth refuses this one") end
    return true
end

function on_connect(id)
    socketley.log(TAG .. " connected")
end
LUAEOF
}
# The control script: everything the gate script logs, and no gate.
write_open() {
    cat > "$1" <<LUAEOF
function on_connect(id)
    socketley.log("$2 connected")
end
LUAEOF
}

SRV_LUA="$SOCKETLEY_TMPD/srv_auth.lua";  write_gate "$SRV_LUA" SRVGATE
OPEN_LUA="$SOCKETLEY_TMPD/srv_open.lua"; write_open "$OPEN_LUA" SRVOPEN
PRX_LUA="$SOCKETLEY_TMPD/prx_auth.lua";  write_gate "$PRX_LUA" PRXGATE
POPEN_LUA="$SOCKETLEY_TMPD/prx_open.lua"; write_open "$POPEN_LUA" PRXOPEN

create_ok "gated server created"    "$BIN" create server sa_gate \
    -p "$SRV_PORT" --mode in --lua "$SRV_LUA" -s
create_ok "ungated server created"  "$BIN" create server sa_open \
    -p "$SRV_OPEN_PORT" --mode in --lua "$OPEN_LUA" -s
create_ok "proxy backend created"   "$BIN" create server be -p "$BE_PORT" -s
create_ok "gated proxy created"     "$BIN" create proxy pa_gate \
    -p "$PRX_PORT" --backend "127.0.0.1:$BE_PORT" --lua "$PRX_LUA" -s
create_ok "ungated proxy created"   "$BIN" create proxy pa_open \
    -p "$PRX_OPEN_PORT" --backend "127.0.0.1:$BE_PORT" --lua "$POPEN_LUA" -s

for p in "$SRV_PORT" "$SRV_OPEN_PORT" "$PRX_PORT" "$PRX_OPEN_PORT"; do
    ready_tcp 127.0.0.1 "$p" 10 || echo "  NOTE: nothing accepted on $p"
done

# stat NAME KEY — one figure out of `stats`, or the empty string.
stat() {
    { "$BIN" stats "$1" 2>/dev/null || true; } \
        | awk -F: -v k="$2" '$1 == k { print $2; exit }'
}
# connects TAG — how many times this script has announced a connection.
connects() { grep -ac "$1 connected" "$SOCKETLEY_DLOG" 2>/dev/null || true; }
# probe PORT — one connection, ten bytes, then close.  Its exit status is
# deliberately discarded: see the header, it is 0 for an admitted client and 0
# for a refused one, which is the whole reason this file reads the runtime.
probe() { printf '%s\n' "$PROBE" | timeout 5 nc -q 1 127.0.0.1 "$1" >/dev/null 2>&1 || true; }

# ── The server: five answers from on_auth, one figure that tells them apart ──
#
# ─── WHY A REFUSAL IS FOLLOWED BY AN ADMISSION ──────────────────────────────
#
# "The figure did not move" is not a thing that can be waited for.  A worker
# pushes its figures to the daemon, so reading them straight after a probe reads
# a number that may simply not have arrived yet — and for the refusing arms that
# stale number is the expected one, so the assertion passes for the wrong
# reason.  Measured: with the gate rewritten to admit everybody, the proxy's
# four "refuses the client" assertions stayed green while every on_connect
# assertion beside them went red.
#
# So each refusal is followed by a probe that MUST be admitted, and the claim
# becomes "after both probes the figure moved by exactly one probe's worth".
# That has a positive event to wait for, and a refusal that was wrongly admitted
# overshoots it and cannot be mistaken for a push that has not landed.
#
# server_case MODE WANT_ADMITTED
server_case() {
    local mode=$1 admitted=$2
    local before_bytes before_conn want
    before_bytes=$(stat sa_gate bytes_in)
    before_conn=$(connects SRVGATE)
    want=$((before_bytes + PROBE_BYTES))

    echo "$mode" > "$MODE_FILE"
    probe "$SRV_PORT"

    if [ "$admitted" != yes ]; then
        # The one that has to be let through, so there is something to wait for.
        echo true > "$MODE_FILE"
        probe "$SRV_PORT"
    fi

    for _ in $(seq 1 60); do
        [ "$(stat sa_gate bytes_in)" = "$want" ] && break
        sleep 0.1
    done

    if [ "$admitted" = yes ]; then
        assert_eq "server: on_auth returning $mode admits the client" \
                  "$want" "$(stat sa_gate bytes_in)" \
                  "bytes_in must move by exactly the ten bytes the probe sent"
        assert_eq "server: on_auth returning $mode lets on_connect fire" \
                  "$((before_conn + 1))" "$(connects SRVGATE)"
    else
        assert_eq "server: on_auth returning $mode refuses the client" \
                  "$want" "$(stat sa_gate bytes_in)" \
                  "two probes were sent and only the second was meant to be" \
                  "served, so twenty bytes here means the refusal was admitted." \
                  "The client's connect() succeeded and nc exited 0 in both" \
                  "cases — this figure is the only thing that tells them apart"
        assert_eq "server: on_auth returning $mode suppresses on_connect" \
                  "$((before_conn + 1))" "$(connects SRVGATE)" \
                  "a gate that refuses the traffic and still announces the" \
                  "connection leaves a script holding state for a client that" \
                  "was never served"
    fi
}

server_case true    yes
server_case false   no
server_case nil     no
server_case nonbool no
server_case error   no

# The raised error is reported rather than swallowed — an operator whose script
# throws in the gate has to be able to find out.
#
# RED ON THE SANITIZE BUILD, and the build is wrong.  Measured there: the gate
# still REFUSES correctly (bytes_in stays 0, so fail-closed is intact) and
# nothing is logged at all — no "on_auth error" line, no sol2 line, nothing.
# cdf5b37 fixed exactly this for Release; the DEBUG build, where sol2's safety
# checks change how the error surfaces, still swallows it.  So an operator whose
# gate throws gets a silent outage on one of the two configurations this project
# ships tests for.  Left asserting the behaviour Release has, because that is
# the one cdf5b37 decided was right.
if grep -qa "on_auth error" "$SOCKETLEY_DLOG"; then pass; else
    fail "a raised on_auth is logged" "no 'on_auth error' line in the daemon log" \
         "the connection is refused either way, which means a script that" \
         "throws on every client is a silent outage unless this is written down"
fi

# ── The control: no on_auth at all ──────────────────────────────────────────
OPEN_BEFORE=$(stat sa_open bytes_in)
OPEN_CONN_BEFORE=$(connects SRVOPEN)
probe "$SRV_OPEN_PORT"
for _ in $(seq 1 60); do
    [ "$(stat sa_open bytes_in)" = "$((OPEN_BEFORE + PROBE_BYTES))" ] && break
    sleep 0.1
done
assert_eq "control: a server with no on_auth serves the same probe" \
          "$((OPEN_BEFORE + PROBE_BYTES))" "$(stat sa_open bytes_in)" \
          "without this, every 'refused' assertion above is also satisfied by" \
          "a build that serves nobody"
assert_eq "control: a server with no on_auth still fires on_connect" \
          "$((OPEN_CONN_BEFORE + 1))" "$(connects SRVOPEN)"

# ── The proxy: the same five answers, read off the proxy's own admissions ────
#
# Same shape as server_case, and same reason — see the note above it.
#
# proxy_case MODE WANT_ADMITTED
proxy_case() {
    local mode=$1 admitted=$2
    local before_conn before_cb want
    before_conn=$(stat pa_gate total_connections)
    before_cb=$(connects PRXGATE)
    want=$((before_conn + 1))

    echo "$mode" > "$MODE_FILE"
    # curl's status is discarded for the same reason nc's is; the TCP connection
    # is made in every arm.
    curl -s -o /dev/null --max-time 3 "http://127.0.0.1:$PRX_PORT/" >/dev/null 2>&1 || true

    if [ "$admitted" != yes ]; then
        echo true > "$MODE_FILE"
        curl -s -o /dev/null --max-time 3 "http://127.0.0.1:$PRX_PORT/" >/dev/null 2>&1 || true
    fi

    for _ in $(seq 1 60); do
        [ "$(stat pa_gate total_connections)" = "$want" ] && break
        sleep 0.1
    done

    if [ "$admitted" = yes ]; then
        assert_eq "proxy: on_auth returning $mode admits the client" \
                  "$want" "$(stat pa_gate total_connections)"
        assert_eq "proxy: on_auth returning $mode lets on_connect fire" \
                  "$((before_cb + 1))" "$(connects PRXGATE)"
    else
        assert_eq "proxy: on_auth returning $mode refuses the client" \
                  "$want" "$(stat pa_gate total_connections)" \
                  "the proxy counts a connection only after on_auth has said" \
                  "yes, so this figure is exactly its admissions — and two were" \
                  "attempted, of which one was meant to get in"
        assert_eq "proxy: on_auth returning $mode suppresses on_connect" \
                  "$((before_cb + 1))" "$(connects PRXGATE)"
    fi
}

proxy_case true    yes
proxy_case false   no
proxy_case nil     no
proxy_case nonbool no
proxy_case error   no

POPEN_BEFORE=$(stat pa_open total_connections)
curl -s -o /dev/null --max-time 3 "http://127.0.0.1:$PRX_OPEN_PORT/" >/dev/null 2>&1 || true
for _ in $(seq 1 60); do
    [ "$(stat pa_open total_connections)" = "$((POPEN_BEFORE + 1))" ] && break
    sleep 0.1
done
assert_eq "control: a proxy with no on_auth admits the same client" \
          "$((POPEN_BEFORE + 1))" "$(stat pa_open total_connections)" \
          "without this, every 'refused' assertion above is also satisfied by" \
          "a proxy that admits nobody"

# The daemon ran five rejections and a raised Lua error and is still here.
TOTAL=$((TOTAL+1))
if kill -0 "$SOCKETLEY_DPID" 2>/dev/null && daemon_alive "$SOCKETLEY_SOCKET"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL: the daemon did not survive the rejections"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
