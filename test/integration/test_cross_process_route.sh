#!/usr/bin/env bash
# Integration test: a connection served by one process, answered by another.
#
# ─── WHY THIS FILE EXISTS SEPARATELY ────────────────────────────────────────
# Three other files would go red if routing broke and none would say which of
# the five verbs did, so this one walks the whole life of one routed connection
# across a real process boundary asserting open, data, write, close and forget
# separately -- with `forget` the reason for the file, since it is the only
# verb with no other cover and the trigger is SIGKILL rather than `stop`,
# because a killed worker runs no teardown at all and a stop would pass against
# a build that only fixed the frame-ordering race; the kill is by pid out of
# `stats` and never by name, which has killed the killer on this machine
# before.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"

ORIGIN_PORT=$((SL_PORT_BASE+781))
TARGET_PORT=$((SL_PORT_BASE+782))

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
# Wait up to five seconds for the file $2 to hold $1, since each event crosses two workers and the daemon.
seen() { local _; for _ in $(seq 1 50); do grep -q "$1" "$2" 2>/dev/null && return 0; sleep 0.1; done; return 1; }

cleanup() {
    "$BIN" stop   xr_origin xr_target 2>/dev/null || true
    "$BIN" remove xr_origin xr_target 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: one connection, two processes ==="

daemon_isolate xrroute
daemon_start "$BIN"

# ─── The two scripts ────────────────────────────────────────────────────────
# The target logs every event with a tag the assertions grep for and answers
# with self.send on a handle for a connection it does not own, which is the
# call site whose absence made this feature look half-built.
TARGET_LUA="$SOCKETLEY_TMPD/target.lua"
cat > "$TARGET_LUA" <<'LUAEOF'
function on_connect(client_id)
    socketley.log("XR_GOT " .. tostring(client_id))
end
function on_disconnect(client_id)
    socketley.log("XR_LOST " .. tostring(client_id))
end
function on_client_message(client_id, msg)
    socketley.log("XR_MSG " .. tostring(msg))
    self.send(client_id, "answered-by-target")
end
LUAEOF

ORIGIN_LUA="$SOCKETLEY_TMPD/origin.lua"
cat > "$ORIGIN_LUA" <<'LUAEOF'
function on_connect(client_id)
    self.send(client_id, "ready")
end
function on_client_message(client_id, msg)
    -- "route" and not something shorter: a client message under three bytes is
    -- not delivered to on_client_message on this build, because protocol
    -- detection wants that many before it will decide.
    if msg == "route" then
        local ok = self.route(client_id, "xr_target")
        socketley.log("XR_ROUTE " .. tostring(ok))
    end
end
LUAEOF

# Neither takes --daemon-process, which is the whole point: both are workers,
# so every verb below crosses a real boundary.
create_ok "target created" "$BIN" create server xr_target \
          -p "$TARGET_PORT" --lua "$TARGET_LUA" -s
create_ok "origin created" "$BIN" create server xr_origin \
          -p "$ORIGIN_PORT" --lua "$ORIGIN_LUA" -s

# ── Control: they really are separate processes ─────────────────────────────
#
# Without this the whole file passes in one address space, where routing has
# always worked, and proves nothing about the boundary.
OPID=$("$BIN" stats xr_origin 2>/dev/null | awk -F: '/^pid:/ {print $2}')
TPID=$("$BIN" stats xr_target 2>/dev/null | awk -F: '/^pid:/ {print $2}')
if [ -n "${OPID:-}" ] && [ -n "${TPID:-}" ] && [ "$OPID" != "$TPID" ] \
   && [ "$OPID" != "$$" ]; then
    pass
else
    fail "control: origin and target are two processes" \
         "origin pid='${OPID:-}' target pid='${TPID:-}'" \
         "if they share a pid, or have none, every assertion below is about" \
         "in-process routing and the boundary is untested"
fi

# ─── One connection, held open, driven from a file ──────────────────────────
#
# Backgrounded so the kill happens while the connection is still live: a route
# that is torn down by the client leaving is the `close` path, and this file
# needs the ORIGIN to go first.
FIFO_IN="$SOCKETLEY_TMPD/in"
CLIENT_OUT="$SOCKETLEY_TMPD/client.out"
mkfifo "$FIFO_IN"
# Both ends held by this shell before the client starts, because a bare `echo >
# fifo` blocks until somebody opens the read end and a client that fails to
# connect would turn every assertion below into a hang.
exec 9<>"$FIFO_IN"
python3 - "$ORIGIN_PORT" "$FIFO_IN" "$CLIENT_OUT" <<'PY' &
import socket, sys, threading
port, fifo, out = int(sys.argv[1]), sys.argv[2], sys.argv[3]
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
except Exception as e:
    open(out, "w").write("CONNECT-FAILED %s\n" % e)
    sys.exit(1)
s.settimeout(20)
def reader():
    with open(out, "wb", buffering=0) as f:
        while True:
            try:
                b = s.recv(4096)
            except Exception:
                return
            if not b:
                return
            f.write(b)
threading.Thread(target=reader, daemon=True).start()
with open(fifo, "r") as f:
    for line in f:
        line = line.strip()
        if line == "QUIT":
            break
        s.sendall(line.encode() + b"\n")
s.close()
PY
CLIENT=$!
sleep 0.8

if grep -q 'CONNECT-FAILED' "$CLIENT_OUT" 2>/dev/null; then
    fail "the client reached the origin" \
         "$(cat "$CLIENT_OUT")" \
         "nothing below this can mean anything; the origin is not listening"
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
    exit "$FAIL"
fi

# ── Verb 1: open ────────────────────────────────────────────────────────────
echo "route" >&9
seen 'XR_ROUTE ' "$SOCKETLEY_DLOG"
seen 'XR_GOT ' "$SOCKETLEY_DLOG"

if grep -q 'XR_ROUTE true' "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "self.route() across processes answers true" \
         "the origin did not log 'XR_ROUTE true'" \
         "got: $(grep -a -o 'XR_ROUTE [a-z]*' "$SOCKETLEY_DLOG" | tail -1)"
fi

# route() answering true is not evidence the target heard anything, because the
# answer comes from the daemon's map deliberately, so a build where the frame
# is never written answers true and does nothing.
if grep -q 'XR_GOT ' "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "the target's on_connect fires for a routed connection" \
         "no XR_GOT in the daemon log" \
         "route() answered true and the target was never told, which is the" \
         "accepted-but-not-applied shape this tree refuses everywhere"
fi

# The id is a handle rather than a descriptor, out of the range conn_identity.h
# reserves, so a small number here means the target was handed the origin's
# descriptor.
XR_ID=$(grep -a -o 'XR_GOT [0-9]*' "$SOCKETLEY_DLOG" | tail -1 | awk '{print $2}')
if [ -n "${XR_ID:-}" ] && [ "$XR_ID" -ge 16777216 ]; then pass; else
    fail "a routed connection is named by a handle, not a descriptor" \
         "the target was handed id '${XR_ID:-<none>}'" \
         "anything below the reserved base is a descriptor number that means" \
         "something only in the origin's process"
fi

# ── Verb 2: data, origin -> target ──────────────────────────────────────────
echo "hello-from-client" >&9
seen 'XR_MSG hello-from-client' "$SOCKETLEY_DLOG"
seen 'answered-by-target' "$CLIENT_OUT"
if grep -q 'XR_MSG hello-from-client' "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "a routed client's message reaches the target's script" \
         "no XR_MSG line for it" \
         "the origin still holds the socket, so the bytes have to be relayed —" \
         "this is the verb that runs per message and must not wait for anything"
fi

# self.send() on a handle resolves the origin and asks it to write, so this is
# the only assertion here that fails if the reply path is missing while
# everything else works.
if grep -q 'answered-by-target' "$CLIENT_OUT" 2>/dev/null; then pass; else
    fail "the target's reply reaches the client" \
         "the client never saw 'answered-by-target'" \
         "it read: $(tr '\n' '|' < "$CLIENT_OUT" 2>/dev/null | cut -c1-120)"
fi

# ── Verb 5: forget ──────────────────────────────────────────────────────────
# SIGKILL and not `stop`, because a killed worker runs no teardown at all --
# with the connection count as the oracle rather than the log line alone, since
# the count is what an operator sees and what grew without bound before.
target_conns() {
    "$BIN" stats xr_target 2>/dev/null | awk -F: '/^connections:/ {print $2; exit}'
}
BEFORE=$(target_conns)
if [ "${BEFORE:-0}" -ge 1 ]; then pass; else
    fail "control: the target counts the routed connection before the kill" \
         "connections='${BEFORE:-}', wanted at least 1" \
         "the check below cannot show a count going to zero if it was never" \
         "anything else"
fi

# By pid, confirmed to be ours before signalling it, because a pid out of
# `stats` can have been reused between the read and the kill.
if [ -n "${OPID:-}" ] && grep -qa 'socketley' "/proc/$OPID/cmdline" 2>/dev/null; then
    kill -9 "$OPID" 2>/dev/null
    pass
else
    fail "the origin's worker could be identified and killed" \
         "pid '${OPID:-}' is not a socketley process any more" \
         "nothing was killed, so the assertion below is about a live origin"
fi

# Up to the health tick, which is the two seconds the daemon already runs at.
for _ in $(seq 1 40); do
    [ "$(target_conns)" = "0" ] && break
    sleep 0.25
done
AFTER=$(target_conns)

if [ "${AFTER:-1}" = "0" ]; then pass; else
    fail "the target lets go when the origin is killed" \
         "connections='${AFTER:-}' after the kill, wanted 0" \
         "the origin ran no teardown, so nothing it could have sent is the" \
         "mechanism — the daemon has to tell the target, and did not" \
         "target still holds: $(grep -a -c 'XR_GOT' "$SOCKETLEY_DLOG") opened," \
         "$(grep -a -c 'XR_LOST' "$SOCKETLEY_DLOG") closed"
fi

# And the script was told rather than the counter merely adjusted, because a
# build that dropped the entry without running on_disconnect leaves every
# script that allocates per connection leaking.
if grep -q 'XR_LOST ' "$SOCKETLEY_DLOG" 2>/dev/null; then pass; else
    fail "the target's on_disconnect runs for a route that went away" \
         "no XR_LOST in the log" \
         "the count may have been corrected without telling the script, which" \
         "leaks whatever the script allocated in on_connect"
fi

echo "QUIT" >&9 2>/dev/null || true
exec 9>&-
# Bounded, because a client that already died leaves `wait` with nothing to
# wait for and one wedged in recv would hold this file open past the suite's
# patience.
for _ in $(seq 1 20); do
    kill -0 "$CLIENT" 2>/dev/null || break
    sleep 0.25
done
kill -9 "$CLIENT" 2>/dev/null || true
wait "$CLIENT" 2>/dev/null || true

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
