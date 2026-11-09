#!/usr/bin/env bash
# Integration test: one client runtime holding --connections N to one target.
# suite: isolated
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
#   Each block names the build it fails on:
#
#   - all up and counted: a build that dials one connection, or counts the
#     slots it was asked for rather than the ones up, reads 1 or 8 at the wrong
#     side -- the server's own count is asked as well, so a client lying about
#     itself is caught by the peer
#   - request-answer: every connection runs five rounds, each answer carrying
#     the id it was sent for, so a send without an id that goes to connection 1
#     (or anywhere but the connection whose callback runs) logs WRONG, and an
#     on_message that is handed the wrong id does the same
#   - self.send with an id, and the refusal: outside every callback a send with
#     no id must be refused with words, an id must reach exactly that
#     connection, and an id that is not there must be refused
#   - one slot reconnecting: the kicked connection comes back with its own id,
#     and no other id sees a disconnect
#   - socketley send: sixteen messages over eight connections arrive two a
#     connection, which a build that always writes to the first one fails
#   - -w and the message log see every connection's messages
#   - edit: up opens the new ids and runs their callbacks, down closes the
#     highest ids, says so to the script, and leaves the rest serving
#   - TLS: four sessions on four sockets, each finishing its rounds, which a
#     build sharing one SSL or one write buffer between connections fails
#   - N=1: the id is still passed, 1, and `show` writes no "connections" key,
#     so a state file of a one-connection client is the one it always was
#
# Seen red with current_or_only() answering the first slot for every caller:
# five of 49, the rounds of ids 2..8 logged WRONG, -w held one last round
# instead of eight, and the ids an edit opened never finished theirs.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate client_conns

# lib_ports.sh's `exec 9>lockfile 2>/dev/null` applies both redirections to
# this shell, so stderr is put back before anything can need it.
exec 2>&1

P=$((SL_PORT_BASE+861))
PU=$((SL_PORT_BASE+862))
PT=$((SL_PORT_BASE+863))
N=8

PASS=0; FAIL=0; TOTAL=0
ok()  { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
bad() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', wanted '$3'"; fi; }

ALL="mc mc1 mcs mcu mcus mct mcts"
cleanup() {
    for r in $ALL; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in $ALL; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

stat_of() { "$BIN" stats "$1" 2>/dev/null | sed -n "s/^$2:\([0-9][0-9]*\)$/\1/p" | head -1; }
wait_stat() {  # name field want deadline_s
    local i=0
    while [ "$i" -lt $(($4 * 10)) ]; do
        [ "$(stat_of "$1" "$2")" = "$3" ] && return 0
        sleep 0.1; i=$((i+1))
    done
    return 1
}
# The number of distinct ids among log lines matching a pattern, the id read from " id=N ".
ids_matching() { grep -aE "$1" "$SOCKETLEY_DLOG" 2>/dev/null | sed -n 's/.* id=\([0-9]*\) .*/\1/p' | sort -un | tr '\n' ' ' | sed 's/ $//'; }
count_of() { grep -acE "$1" "$SOCKETLEY_DLOG" 2>/dev/null; }
wait_count() {  # pattern want deadline_s
    local i=0
    while [ "$i" -lt $(($3 * 10)) ]; do
        [ "$(count_of "$1")" -ge "$2" ] && return 0
        sleep 0.1; i=$((i+1))
    done
    return 1
}

echo "=== Integration: a client holding many connections ==="

daemon_start "$BIN"

SRV_LUA="$SOCKETLEY_TMPD/srv.lua"
cat > "$SRV_LUA" <<'LUAEOF'
function on_client_message(id, msg)
    if msg == "kick" then
        self.disconnect(id)
        return true
    end
    socketley.log("SRV from=" .. tostring(id) .. " msg=[" .. msg .. "]")
    self.send(id, "echo " .. msg)
    return true
end
LUAEOF

CLI_LUA="$SOCKETLEY_TMPD/cli.lua"
cat > "$CLI_LUA" <<'LUAEOF'
local probed = false

function on_connect(fd, id)
    socketley.log("CLI connect id=" .. tostring(id) .. " fd=" .. type(fd) .. " ")
    self.send("r1 " .. id)
end

function on_message(msg, id)
    socketley.log("CLI msg id=" .. tostring(id) .. " [" .. msg .. "]")
    local k, sent_for = msg:match("^echo r(%d+) (%d+)$")
    if not k then return end
    if tonumber(sent_for) ~= id then
        socketley.log("CLI WRONG id=" .. tostring(id) .. " carried " .. sent_for)
        return
    end
    k = tonumber(k)
    if k < 5 then
        self.send("r" .. (k + 1) .. " " .. id)
    else
        socketley.log("CLI done id=" .. id .. " ")
    end
end

function on_disconnect(fd, id)
    socketley.log("CLI disc id=" .. tostring(id) .. " ")
end

-- Outside every callback once all eight are up: a send with no id, with one, and with one that is not there.
function on_start()
    local t
    t = socketley.set_interval(50, function()
        if probed or self.connections() < 8 then return end
        probed = true
        socketley.clear_interval(t)
        local ok, err = self.send("outside")
        socketley.log("CLI outside ok=" .. tostring(ok) .. " err=" .. tostring(err))
        socketley.log("CLI named ok=" .. tostring(self.send("named 3", 3)))
        local ok3, err3 = self.send("x", 99)
        socketley.log("CLI badid ok=" .. tostring(ok3) .. " err=" .. tostring(err3))
        socketley.log("CLI pending sum=" .. tostring(self.pending()) .. " one=" .. tostring(self.pending(2))
                      .. " none=" .. tostring(self.pending(99)))
    end)
end
LUAEOF

ONE_LUA="$SOCKETLEY_TMPD/one.lua"
cat > "$ONE_LUA" <<'LUAEOF'
function on_connect(fd, id)
    socketley.log("ONE connect fd=" .. type(fd) .. " id=" .. tostring(id) .. " ")
    self.send("one")
end
function on_message(msg, id)
    socketley.log("ONE msg [" .. msg .. "] id=" .. tostring(id) .. " ")
end
LUAEOF

WFILE="$SOCKETLEY_TMPD/w.txt"

# ── refusals at the flag ─────────────────────────────────────────────────────
out=$("$BIN" create client mcbad -t "127.0.0.1:$P" --connections 0 2>&1); rc=$?
check "--connections 0 is refused" "$rc:$out" "1:invalid connection count"
out=$("$BIN" create client mcbad -t "127.0.0.1:$P" --connections 70000 2>&1); rc=$?
check "--connections above the bound is refused" "$rc:$out" "1:invalid connection count"
out=$("$BIN" create client mcbad -t "127.0.0.1:$P" --connections 2>&1); rc=$?
check "--connections without a count is refused" "$rc:$out" "1:--connections requires a count"

create_ok "server" "$BIN" create server mcs -p "$P" --lua "$SRV_LUA" -s
create_ok "client, eight connections" "$BIN" create client mc -t "127.0.0.1:$P" --connections $N \
    --reconnect --lua "$CLI_LUA" -w "$WFILE" -s
create_ok "client, one connection" "$BIN" create client mc1 -t "127.0.0.1:$P" --lua "$ONE_LUA" -s

# ── all up and counted ───────────────────────────────────────────────────────
if wait_stat mc connections $N 10; then ok
else bad "the client reports eight connections" "connections is '$(stat_of mc connections)'"; fi
if wait_stat mcs connections $((N + 1)) 10; then ok
else bad "the server sees eight and the one-connection client" "connections is '$(stat_of mcs connections)'"; fi
if wait_stat mc total_connections $N 10; then ok
else bad "each connection is counted once" "total_connections is '$(stat_of mc total_connections)'"; fi
check "on_connect ran once per id" "$(ids_matching 'CLI connect id=')" "1 2 3 4 5 6 7 8"
check "on_connect still gets its descriptor first" "$(count_of 'CLI connect id=[0-9]+ fd=number')" "$N"

# ── request-answer on every connection ───────────────────────────────────────
wait_count 'CLI done id=' $N 10 || true
check "five rounds finished on every id" "$(ids_matching 'CLI done id=')" "1 2 3 4 5 6 7 8"
check "no answer arrived on another connection" "$(count_of 'CLI WRONG')" "0"

# ── self.send with an id, without one, and the refusal ───────────────────────
wait_count 'CLI pending sum=' 1 10 || true
check "outside every callback a send without an id is refused" \
    "$(count_of 'CLI outside ok=false err=.*holds 8 connections.*self.send\(msg, id\)')" "1"
check "a send naming id 3 is taken" "$(count_of 'CLI named ok=true')" "1"
wait_count 'CLI msg id=3 \[echo named 3\]' 1 5 || true
check "and its answer comes back on connection 3" "$(count_of 'CLI msg id=[0-9]+ \[echo named 3\]')" \
    "$(count_of 'CLI msg id=3 \[echo named 3\]')"
check "that answer arrived at all" "$(count_of 'CLI msg id=3 \[echo named 3\]')" "1"
check "an id it does not have is refused" "$(count_of 'CLI badid ok=false err=.*no connection 99; its ids are 1 to 8')" "1"
check "pending answers a number for all, one id, and nil for none" \
    "$(count_of 'CLI pending sum=[0-9]+ one=[0-9]+ none=nil')" "1"

# ── socketley send: one message a call, round robin ──────────────────────────
for i in $(seq 1 16); do "$BIN" send mc "rr-$i" >/dev/null 2>&1; done
wait_count 'CLI msg id=[0-9]+ \[echo rr-' 16 10 || true
per=$(grep -aE 'CLI msg id=[0-9]+ \[echo rr-' "$SOCKETLEY_DLOG" | sed -n 's/.* id=\([0-9]*\) .*/\1/p' | sort -n | uniq -c \
      | awk '{print $1}' | sort -u | tr '\n' ' ' | sed 's/ $//')
check "sixteen sends over eight connections are two each" "$per" "2"
check "and every connection had its two" "$(ids_matching 'CLI msg id=[0-9]+ \[echo rr-')" "1 2 3 4 5 6 7 8"

# ── -w and a broadcast from the server ───────────────────────────────────────
"$BIN" send mcs bcast >/dev/null 2>&1
wait_count 'CLI msg id=[0-9]+ \[bcast\]' $N 10 || true
check "every connection's on_message saw the broadcast" "$(ids_matching 'CLI msg id=[0-9]+ \[bcast\]')" "1 2 3 4 5 6 7 8"
sleep 0.3
check "-w holds the broadcast once per connection" "$(grep -c '^bcast$' "$WFILE" 2>/dev/null)" "$N"
check "-w holds every connection's last round" "$(grep -cE '^echo r5 [1-8]$' "$WFILE" 2>/dev/null)" "$N"

# ── one slot reconnects ──────────────────────────────────────────────────────
"$BIN" send mc kick >/dev/null 2>&1
wait_count 'CLI disc id=' 1 5 || true
K=$(ids_matching 'CLI disc id=')
check "exactly one connection was dropped" "$(count_of 'CLI disc id=')" "1"
if wait_count "CLI connect id=$K " 2 10; then ok
else bad "the dropped connection came back under its own id" "connect lines for id $K: $(count_of "CLI connect id=$K ")"; fi
check "and no other id reconnected" "$(count_of 'CLI connect id=')" "$((N + 1))"
wait_stat mc connections $N 5 || true
check "eight connections again" "$(stat_of mc connections)" "$N"
wait_count "CLI done id=$K " 2 5 || true
check "the reconnected one ran its rounds again" "$(count_of "CLI done id=$K ")" "2"
check "still no answer on a wrong connection" "$(count_of 'CLI WRONG')" "0"

# ── edit up and down ─────────────────────────────────────────────────────────
"$BIN" edit mc --connections 12 >/dev/null 2>&1
check "edit up answers" "$?" "0"
if wait_stat mc connections 12 10; then ok
else bad "edit up opens four more" "connections is '$(stat_of mc connections)'"; fi
wait_count 'CLI done id=(9|10|11|12) ' 4 10 || true
check "the new ids ran their rounds" "$(ids_matching 'CLI done id=(9|10|11|12) ')" "9 10 11 12"
if wait_stat mcs connections 13 5; then ok
else bad "the server sees the four new ones" "connections is '$(stat_of mcs connections)'"; fi

"$BIN" edit mc --connections 3 >/dev/null 2>&1
check "edit down answers" "$?" "0"
if wait_stat mc connections 3 5; then ok
else bad "edit down closes nine" "connections is '$(stat_of mc connections)'"; fi
wait_count 'CLI disc id=' 10 5 || true
check "the script was told, for the highest ids" "$(ids_matching 'CLI disc id=([4-9]|1[0-2]) ' )" "4 5 6 7 8 9 10 11 12"
if wait_stat mcs connections 4 5; then ok
else bad "the server sees them go" "connections is '$(stat_of mcs connections)'"; fi
for i in 1 2 3; do "$BIN" send mc "after-$i" >/dev/null 2>&1; done
wait_count 'CLI msg id=[0-9]+ \[echo after-' 3 5 || true
check "the three left still serve" "$(ids_matching 'CLI msg id=[0-9]+ \[echo after-')" "1 2 3"
check "show stores the count" "$("$BIN" show mc 2>/dev/null | grep -c '"connections": 3')" "1"

"$BIN" stop mc >/dev/null 2>&1
"$BIN" start mc >/dev/null 2>&1
if wait_stat mc connections 3 10; then ok
else bad "a restart holds the edited count" "connections is '$(stat_of mc connections)'"; fi

# ── N=1, as it always was ────────────────────────────────────────────────────
check "one connection is passed id 1" "$(count_of 'ONE msg \[echo one\] id=1 ')" "1"
check "and its descriptor in on_connect" "$(count_of 'ONE connect fd=number id=1 ')" "1"
check "show writes no connections key for one" "$("$BIN" show mc1 2>/dev/null | grep -c '"connections"')" "0"
check "a one-connection client reports one" "$(stat_of mc1 connections)" "1"

# ── UDP: one socket a connection ─────────────────────────────────────────────
create_ok "udp server" "$BIN" create server mcus -p "$PU" --udp -s
create_ok "udp client, three sockets" "$BIN" create client mcu -t "127.0.0.1:$PU" --udp --connections 3 -s
sleep 0.5
check "three connected datagram sockets to the target" \
    "$(ss -HuanO state all "dst 127.0.0.1:$PU" 2>/dev/null | wc -l)" "3"
check "the udp client reports three" "$(stat_of mcu connections)" "3"

# ── TLS: a session a connection ──────────────────────────────────────────────
if openssl req -x509 -newkey rsa:2048 -keyout "$SOCKETLEY_TMPD/t.key" -out "$SOCKETLEY_TMPD/t.pem" \
       -nodes -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" -days 2 >/dev/null 2>&1; then
    TLS_LUA="$SOCKETLEY_TMPD/tls.lua"
    sed 's/socketley.log("CLI /socketley.log("TLS /; s/probed = false/probed = true/' "$CLI_LUA" > "$TLS_LUA"
    create_ok "tls server" "$BIN" create server mcts -p "$PT" --tls --cert "$SOCKETLEY_TMPD/t.pem" \
        --key "$SOCKETLEY_TMPD/t.key" --lua "$SRV_LUA" -s
    create_ok "tls client, four connections" "$BIN" create client mct -t "127.0.0.1:$PT" --tls \
        --ca "$SOCKETLEY_TMPD/t.pem" --connections 4 --lua "$TLS_LUA" -s
    wait_count 'TLS done id=' 4 15 || true
    check "four TLS connections each finished their rounds" "$(ids_matching 'TLS done id=')" "1 2 3 4"
    check "no TLS answer on another connection" "$(count_of 'TLS WRONG')" "0"
    check "the tls client reports four" "$(stat_of mct connections)" "4"
else
    echo "  SKIP: TLS block, no certificate could be made"
fi

echo ""
echo "  passed: $PASS / $TOTAL"
[ "$FAIL" -eq 0 ]
