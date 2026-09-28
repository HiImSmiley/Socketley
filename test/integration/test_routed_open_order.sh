#!/usr/bin/env bash
# Integration test: the first message of a routed connection cannot overtake
# its own `open` at the target.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
# A routed connection is a stream, and its `open` is the first frame of it:
# once a peer link is up, an open that took the daemon's leg while the first
# `data` took the link was applied second and the message dropped without a
# line in any log.  test_cross_process_route.sh sleeps a second between the
# route and the first message and so can never see the two meet; this file
# makes them meet, by routing every connection in on_connect, loading the
# target so its turns are long, and having hundreds of clients send their
# first line the moment they are connected -- with the peer link confirmed up
# first, because over the daemon's socket alone the two verbs share one stream
# and the order holds by construction.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"

ORIGIN_PORT=$((SL_PORT_BASE+783))
TARGET_PORT=$((SL_PORT_BASE+784))

# Enough connections that a turn of the target's loop carries several opens
# and several first messages at once; measured on the unfixed build below.
CLIENTS=${ROUTED_ORDER_CLIENTS:-300}

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

cleanup() {
    "$BIN" stop   ro_origin ro_target 2>/dev/null || true
    "$BIN" remove ro_origin ro_target 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a routed connection's first message waits for its open ==="

daemon_isolate routedorder
daemon_start "$BIN"

# The target tags what it hears; the counts of the two tags are the oracle.
TARGET_LUA="$SOCKETLEY_TMPD/target.lua"
cat > "$TARGET_LUA" <<'LUAEOF'
function on_connect(client_id)
    -- A handle and not a descriptor names a routed connection; the load
    -- clients below connect here directly and are not counted.
    if client_id >= 16777216 then
        socketley.log("RO_GOT " .. tostring(client_id))
    end
end
function on_client_message(client_id, msg)
    -- The load is what keeps a turn of this loop long enough that an open
    -- and the first message behind it are waiting together when it ends.
    if msg:sub(1, 5) == "load-" then
        local x = 0
        for i = 1, 4000 do x = x + i end
        return
    end
    socketley.log("RO_MSG " .. tostring(msg))
end
function on_disconnect(client_id)
    -- A load client's close is read after every line it sent, so its tag says
    -- the target has worked through that client's share of the load.
    if client_id < 16777216 then
        socketley.log("RO_LOAD_DONE " .. tostring(client_id))
    end
end
LUAEOF

# Routed at accept, so the client's first line is the first `data` frame and
# nothing the script does sits between the open and it.
ORIGIN_LUA="$SOCKETLEY_TMPD/origin.lua"
cat > "$ORIGIN_LUA" <<'LUAEOF'
function on_connect(client_id)
    local ok = self.route(client_id, "ro_target")
    socketley.log("RO_ROUTE " .. tostring(ok))
end
LUAEOF

create_ok "target created" "$BIN" create server ro_target \
          -p "$TARGET_PORT" --lua "$TARGET_LUA" -s
create_ok "origin created" "$BIN" create server ro_origin \
          -p "$ORIGIN_PORT" --lua "$ORIGIN_LUA" -s

# ── Control: two processes ──────────────────────────────────────────────────
OPID=$("$BIN" stats ro_origin 2>/dev/null | awk -F: '/^pid:/ {print $2}')
TPID=$("$BIN" stats ro_target 2>/dev/null | awk -F: '/^pid:/ {print $2}')
if [ -n "${OPID:-}" ] && [ -n "${TPID:-}" ] && [ "$OPID" != "$TPID" ]; then
    pass
else
    fail "control: origin and target are two processes" \
         "origin pid='${OPID:-}' target pid='${TPID:-}'" \
         "in one address space open and data are two function calls in" \
         "order, and nothing below says anything about the wire"
fi

counter() {   # counter <runtime> <name>
    "$BIN" stats "$1" 2>/dev/null |
        awk -F: -v k="^$2:" '$0 ~ k {s+=$2} END{print s+0}'
}

# ── Control: the peer link is up before the burst ───────────────────────────
# One connection relayed through the daemon is what makes the daemon introduce
# the two workers; every later connection's frames then take the link, which
# is the path this file is about.
python3 - "$ORIGIN_PORT" <<'PY'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
time.sleep(0.3)
s.sendall(b"warm-up-line\n")
time.sleep(0.5)
s.close()
PY
LINKS=0
for _ in $(seq 1 40); do
    LINKS=$(counter ro_origin peer_links)
    [ "$LINKS" -ge 1 ] && break
    sleep 0.25
done
if [ "$LINKS" -ge 1 ]; then
    pass
else
    fail "control: the origin holds a link to the target before the burst" \
         "peer_links is $LINKS after the warm-up connection" \
         "without a link every frame takes the daemon's socket, where the" \
         "order holds by construction and the assertion below cannot fail"
fi
WARM_MSG=$(grep -a -c 'RO_MSG warm-up-line' "$SOCKETLEY_DLOG" 2>/dev/null)
if [ "${WARM_MSG:-0}" -eq 1 ]; then
    pass
else
    fail "control: the warm-up line reached the target over the daemon" \
         "RO_MSG warm-up-line appears $WARM_MSG times, wanted 1" \
         "if the relayed path already loses messages this file is not" \
         "measuring the link"
fi
GOT_BEFORE=$(grep -a -c 'RO_GOT ' "$SOCKETLEY_DLOG" 2>/dev/null)
MSG_BEFORE=$(grep -a -c 'RO_MSG ' "$SOCKETLEY_DLOG" 2>/dev/null)

# ── The burst ───────────────────────────────────────────────────────────────
# Load clients speak to the target directly so its turns are long, and every
# routed client sends its line the instant connect() returns and holds the
# socket open long enough that no `close` can be mistaken for the drop.
python3 - "$ORIGIN_PORT" "$TARGET_PORT" "$CLIENTS" <<'PY'
import socket, sys, threading, time
oport, tport, n = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
stop = threading.Event()
failed = []
def load():
    try:
        s = socket.create_connection(("127.0.0.1", tport), timeout=5)
        s.settimeout(1)
        chunk = b"load-line\n" * 10
        while not stop.is_set():
            try:
                s.sendall(chunk)
            except socket.timeout:
                pass
            time.sleep(0.001)
        s.close()
    except Exception:
        pass
def one(i):
    try:
        s = socket.create_connection(("127.0.0.1", oport), timeout=10)
        s.sendall(("first-line-%d\n" % i).encode())
        time.sleep(2.0)
        s.close()
    except Exception:
        failed.append(i)
loaders = [threading.Thread(target=load, daemon=True) for _ in range(8)]
for t in loaders: t.start()
time.sleep(0.5)
ts = []
for i in range(n):
    t = threading.Thread(target=one, args=(i,), daemon=True)
    t.start(); ts.append(t)
for t in ts:
    t.join(timeout=30)
stop.set()
for t in loaders: t.join(timeout=5)
print("CONNECT_FAILED", len(failed))
PY

# ─── WAITING FOR THE TARGET, WITHOUT MISTAKING A LONG TURN FOR THE END ──────
#
# What the loaders left in the target's socket buffers is drained after they
# stop, so the count must not be taken while the log is still growing.  The
# first version of this waited for ONE second with no change and then counted,
# and that is not a test of "the stream ended" -- it is a test of "nothing was
# observed for one second", and this file goes out of its way to make the
# target's turns long.  Measured under Sanitize, sampling every second with no
# early break:
#
#     t=1s   opens=271  msgs=260
#     t=2s   opens=271  msgs=260   <- unchanged, so the old loop counted HERE
#     t=3s   opens=300  msgs=300   <- and one second later everything is in
#
# It reported 271 of 300 opens and 260 of 300 messages as lost, for six months,
# on a runtime that had dropped nothing.  Both halves of the fix matter:
#
#   * the fast path.  When both counts have reached what was asked for there is
#     nothing left to wait for, so a healthy run stops at once and this file
#     does not pay for the paranoia below.
#   * QUIET_NEEDED consecutive unchanged samples, not one.  A single long turn
#     cannot span five of them, and a run that genuinely lost frames still ends
#     -- after five quiet seconds -- and still fails, which is the point.
#   * and not before the load is drained.  Nobody logs the loaders' lines, so
#     on a loaded box the target spent its whole drain of them with both tags
#     unchanged: five quiet seconds passed with every routed open still queued
#     behind the load, and the file reported 0 of 300 (5 of 5 runs beside 14
#     busy cores; the log showed all 300 applied eleven seconds after the
#     route).  Each loader's close is read after its last line, so the quiet
#     count starts once all eight closes are in.
LOADERS=8
for _ in $(seq 1 300); do
    [ "$(grep -a -c 'RO_LOAD_DONE ' "$SOCKETLEY_DLOG" 2>/dev/null)" -ge "$LOADERS" ] && break
    sleep 1
done
QUIET_NEEDED=5
QUIET=0
LAST=-1
for _ in $(seq 1 90); do
    NOW_G=$(( $(grep -a -c 'RO_GOT ' "$SOCKETLEY_DLOG" 2>/dev/null) - GOT_BEFORE ))
    NOW_M=$(grep -a -c 'RO_MSG first-line-' "$SOCKETLEY_DLOG" 2>/dev/null)
    # Everything asked for has arrived; nothing further can change the verdict.
    [ "$NOW_G" -ge "$CLIENTS" ] && [ "$NOW_M" -ge "$CLIENTS" ] && break
    NOW=$((NOW_G + NOW_M))
    if [ "$NOW" = "$LAST" ]; then
        QUIET=$((QUIET + 1))
        [ "$QUIET" -ge "$QUIET_NEEDED" ] && break
    else
        QUIET=0
    fi
    LAST=$NOW
    sleep 1
done

GOT=$(( $(grep -a -c 'RO_GOT ' "$SOCKETLEY_DLOG" 2>/dev/null) - GOT_BEFORE ))
MSG=$(( $(grep -a -c 'RO_MSG first-line-' "$SOCKETLEY_DLOG" 2>/dev/null) ))
ROUTED=$(( $(grep -a -c 'RO_ROUTE true' "$SOCKETLEY_DLOG" 2>/dev/null) - 1 ))
# The origin's own adoption line, because route_path() takes any link that is
# alive and the request counters say nothing about routing frames.
ORIGIN_LINKED=$(grep -a -c 'peer links: ro_target is now one socket away' "$SOCKETLEY_DLOG" 2>/dev/null)

# ── Control: every route was granted and every open applied ─────────────────
if [ "$ROUTED" -eq "$CLIENTS" ]; then
    pass
else
    fail "control: every connection was routed" \
         "self.route() answered true $ROUTED times for $CLIENTS clients" \
         "a connection that was never routed sends nothing to the target and" \
         "a shortfall below would not be a reordering"
fi
if [ "$GOT" -eq "$CLIENTS" ]; then
    pass
else
    fail "control: every open reached the target" \
         "the target's on_connect ran $GOT times for $CLIENTS routed clients" \
         "the open takes the connection's own path once a link exists -- that" \
         "is what stops the first data frame overtaking it -- so a shortfall" \
         "here is delivery and not the order this file is about"
fi
if [ "${ORIGIN_LINKED:-0}" -ge 1 ]; then
    pass
else
    fail "control: the origin adopted its link before the burst" \
         "no 'ro_target is now one socket away' line from the origin" \
         "every frame relayed through the daemon, so the two verbs shared one" \
         "stream and the assertion below was never in question"
fi

# ── The assertion ───────────────────────────────────────────────────────────
if [ "$MSG" -eq "$CLIENTS" ]; then
    pass
else
    fail "every routed connection's first message reaches the target" \
         "the target heard $MSG first lines of $CLIENTS, $((CLIENTS - MSG)) lost" \
         "the open was applied for all $GOT and the daemon logged no drop:" \
         "a data frame arrived over the link before its own open had been" \
         "taken off the control socket, and deliver_routed found no handle"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
