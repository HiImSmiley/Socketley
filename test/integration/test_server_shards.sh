#!/usr/bin/env bash
# Integration test: --shards N on a server, and the rule that decides who gets it.
#
# ─── WHAT CHANGED, AND WHAT THE RULE IS ─────────────────────────────────────
# --shards is now open to a scripted server, and what this file asserts is that
# the door is open at every one of the five places the rule is asked -- create
# in both flag orders, edit, import, and a state file that never sees a parser
# -- because a rule removed from four of five is the shape the defect had, with
# the shard count read back rather than inferred from an exit code, a unix
# listener still refused because N processes would unlink each other's socket
# node, `ls` and the counters proving a shard is an implementation detail
# rather than a runtime, and cache and client still refused outright.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ [[ "$2" == "$3" ]] && ok "$1 ($2)" || bad "$1: expected '$3', got '$2'"; }

daemon_isolate srvshards
daemon_start "$BIN"

P_SRV=$((SL_PORT_BASE+740))
P_A=$((SL_PORT_BASE+741))
P_B=$((SL_PORT_BASE+742))
P_C=$((SL_PORT_BASE+743))
P_D=$((SL_PORT_BASE+744))
P_E=$((SL_PORT_BASE+745))
P_F=$((SL_PORT_BASE+746))
P_G=$((SL_PORT_BASE+747))
P_H=$((SL_PORT_BASE+748))

LUA=$(mktemp /tmp/srvshards-XXXXXX.lua)
SOCKNODE=/tmp/srvshards-$$-listen.sock

cleanup() {
    for n in ss_ok ss_lua ss_ed ss_imp ss_state ss_unix ss_http; do
        "$BIN" stop "$n"   >/dev/null 2>&1 || true
    done
    sleep 0.2
    for n in ss_ok ss_lua ss_ed ss_imp ss_state ss_unix ss_http; do
        "$BIN" remove "$n" >/dev/null 2>&1 || true
    done
    [[ -n "${HOLD_PID:-}" ]] && kill -9 "$HOLD_PID" 2>/dev/null
    rm -f "$LUA" "$SOCKNODE"
    daemon_stop
}
trap cleanup EXIT

# A script whose content is deliberately irrelevant, because the rule is "has a
# script at all" -- whether a table at file scope is shared state cannot be
# detected, which is why the flag is declared rather than inferred.
cat > "$LUA" <<'LUAEOF'
function on_connect(conn)
end
LUAEOF

# daemon_stop is not used because it deletes the state directory and the
# question here is what the directory brings back, and the log is emptied first
# because daemon_start waits by grepping it for a line the first daemon already
# wrote.
daemon_restart() {
    kill "$SOCKETLEY_DPID" 2>/dev/null || true
    for _ in $(seq 1 50); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
    kill -9 "$SOCKETLEY_DPID" 2>/dev/null || true
    : > "$SOCKETLEY_DLOG"
    daemon_start "$BIN"
}

# Not a fixed sleep, because a restored runtime's children are forked on the
# two-second health tick and any single number is a race against a timer.
await_workers() {
    local want=$1 i
    for i in $(seq 1 60); do
        [[ "$(worker_pids | grep -c .)" == "$want" ]] && return 0
        sleep 0.1
    done
    return 1
}

# Every worker process of this binary, never `pgrep -f`, which also matches the
# shell carrying the string in its own arguments.
worker_pids() {
    # Scoped to this run's daemon rather than to the binary, because matching
    # the binary counts the siblings' workers the moment two files run together
    # and the failure reads as a product defect.
    for p in $(pgrep -x socketley 2>/dev/null); do
        [[ "$(readlink /proc/$p/exe 2>/dev/null)" == "$BIN" ]] || continue
        grep -qz "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" "/proc/$p/environ" 2>/dev/null || continue
        tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q 'proxy-worker' && echo "$p"
    done
}

echo "== a server with no script may shard =="
out=$("$BIN" create server ss_ok -p $P_SRV --shards 4 2>&1); rc=$?
check "create server --shards 4 accepted" "$rc" "0"
[[ -z "$out" ]] && ok "and said nothing (silence is success)" \
                || bad "unexpected output: $out"
n=$("$BIN" show ss_ok 2>/dev/null | grep -c '"shards": 4')
check "the count was stored" "$n" "1"

echo "== a server with a script may too, in either flag order =="
# The count is read back rather than just the exit code, because a build that
# accepted the flag and dropped it would serve one process for a runtime `ls`
# reports as four.
out=$("$BIN" create server ss_lua -p $P_A --shards 4 --lua "$LUA" 2>&1); rc=$?
check "--shards before --lua accepted" "$rc" "0"
[[ -z "$out" ]] && ok "and said nothing (silence is success)" || bad "unexpected output: $out"
n=$("$BIN" show ss_lua 2>/dev/null | grep -c '"shards": 4')
check "the count was stored" "$n" "1"
"$BIN" remove ss_lua >/dev/null 2>&1

out=$("$BIN" create server ss_lua -p $P_A --lua "$LUA" --shards 4 2>&1); rc=$?
check "--lua before --shards accepted" "$rc" "0"
n=$("$BIN" show ss_lua 2>/dev/null | grep -c '"shards": 4')
check "the count was stored in this order too" "$n" "1"
"$BIN" remove ss_lua >/dev/null 2>&1

echo "== and edit may add shards to a scripted server =="
out=$("$BIN" create server ss_lua -p $P_A --lua "$LUA" 2>&1); rc=$?
check "the same script unsharded is still accepted" "$rc" "0"
out=$("$BIN" edit ss_lua --shards 4 2>&1); rc=$?
check "edit --shards onto a script accepted" "$rc" "0"
n=$("$BIN" show ss_lua 2>/dev/null | grep -c '"shards": 4')
check "and the edit stored the count" "$n" "1"
"$BIN" edit ss_lua --shards 1 >/dev/null 2>&1

echo "== and so may import, which never sees a flag parser =="
DOC=$("$BIN" show ss_lua 2>/dev/null)
CHANGED=$(printf '%s' "$DOC" | sed 's/"type": "server",/"type": "server", "shards": 4,/')
[[ "$CHANGED" != "$DOC" ]] && ok "the probe document really differs" \
                           || bad "could not inject shards into the document"
out=$(printf '%s' "$CHANGED" | "$BIN" import ss_lua 2>&1); rc=$?
check "import of shards onto a scripted server accepted" "$rc" "0"
n=$("$BIN" show ss_lua 2>/dev/null | grep -c '"shards": 4')
check "and the import applied the count" "$n" "1"
"$BIN" remove ss_lua >/dev/null 2>&1

echo "== --shards and --listen unix: are two different listeners =="
out=$("$BIN" create server ss_unix --shards 4 --listen "unix:$SOCKNODE" 2>&1); rc=$?
check "--shards before --listen refused" "$rc" "1"
[[ "$out" == *"--listen"* ]] && ok "and names --listen" || bad "reason: $out"
out=$("$BIN" create server ss_unix --listen "unix:$SOCKNODE" --shards 4 2>&1); rc=$?
check "--listen before --shards refused" "$rc" "1"
n=$("$BIN" ls 2>/dev/null | grep -c ' ss_unix ')
check "neither order left a runtime behind" "$n" "0"

# ...and the other direction, which no case label can catch on its own: the
# runtime already shards and --listen is the flag that completes the pair.
out=$("$BIN" edit ss_ok --listen "unix:$SOCKNODE" 2>&1); rc=$?
check "edit --listen onto a sharded server refused" "$rc" "1"
n=$("$BIN" show ss_ok 2>/dev/null | grep -c '"listen"')
check "the refused edit rolled the listen path back" "$n" "0"
n=$("$BIN" show ss_ok 2>/dev/null | grep -c '"shards": 4')
check "and left the shard count alone" "$n" "1"

# Five assertions about `--shards N --daemon-process` are gone with that flag,
# because a contradiction between two flags cannot be tested when one does not
# exist and the halves that could be kept would pass on any build.

echo "== a cache may shard now; a client still may not =="
# The cache's refusal is gone because ownership by key hash makes N shards one
# store, and this create takes a distinct name that is removed straight away --
# it used to fail, so reusing the name now makes the client create below fail
# as "runtime already exists" and read as a client defect.
out=$("$BIN" create cache ss_shcache -p $P_F --shards 4 2>&1); rc=$?
check "cache accepts --shards" "$rc" "0"
"$BIN" remove ss_shcache >/dev/null 2>&1
out=$("$BIN" create client ss_ed -t 127.0.0.1:$P_G --shards 4 2>&1); rc=$?
check "client refuses --shards" "$rc" "1"
[[ "$out" == *"client"* ]] && ok "client says why" || bad "client reason: $out"

echo "== four shards, one runtime =="
"$BIN" start ss_ok >/dev/null 2>&1
rc=$?
check "start of a sharded server" "$rc" "0"
await_workers 4

n=$(worker_pids | grep -c .)
check "four worker processes" "$n" "4"
n=$("$BIN" ls 2>/dev/null | grep -c '^[0-9a-f]\{6\} *ss_ok ')
check "ls shows ONE entry for a sharded runtime" "$n" "1"
n=$(ss -ltn 2>/dev/null | grep -c ":$P_SRV ")
check "four listeners share the port" "$n" "4"

echo "== the connection count is the sum, not the last shard to publish =="
python3 - "$P_SRV" <<'PY' &
import socket, sys, time
port = int(sys.argv[1])
socks = []
for _ in range(8):
    s = socket.create_connection(('127.0.0.1', port), 5); s.settimeout(5)
    socks.append(s)
time.sleep(8)
PY
HOLD_PID=$!
sleep 2.5
CONN=$("$BIN" ls 2>/dev/null | awk '$2=="ss_ok" {print $5}')
check "CONN is the sum over shards" "$CONN" "8"

# The oracle for the assertion above is that no single shard holds all eight,
# read from `shard_connections` rather than `connections`, which is now the
# runtime's own summed line and would fail this on a build whose shards share
# the work perfectly.
MAXSHARD=$("$BIN" stats ss_ok 2>/dev/null | awk -F: '/^shard_connections:/ {if ($2+0>m) m=$2+0} END {print m+0}')
[[ "$MAXSHARD" -gt 0 && "$MAXSHARD" -lt 8 ]] \
    && ok "no single shard holds all 8 (busiest has $MAXSHARD) — the sum is a real sum" \
    || bad "one shard holds all 8 (busiest=$MAXSHARD); the sum assertion proves nothing this run"

kill -9 "$HOLD_PID" 2>/dev/null; wait "$HOLD_PID" 2>/dev/null; HOLD_PID=
sleep 0.5

echo "== stop takes every shard down, start brings the same number back =="
"$BIN" stop ss_ok >/dev/null 2>&1
sleep 1.0
n=$(worker_pids | grep -c .)
check "no worker processes after stop" "$n" "0"
n=$(ss -ltn 2>/dev/null | grep -c ":$P_SRV ")
check "nothing bound to the port after stop" "$n" "0"

"$BIN" start ss_ok >/dev/null 2>&1
await_workers 4
n=$(worker_pids | grep -c .)
check "four shards again after start" "$n" "4"

echo "== and the count survives a daemon restart =="
daemon_restart
await_workers 4
n=$(worker_pids | grep -c .)
check "four shards after a daemon restart" "$n" "4"
n=$("$BIN" ls 2>/dev/null | grep -c '^[0-9a-f]\{6\} *ss_ok ')
check "still one ls entry" "$n" "1"

"$BIN" remove ss_ok >/dev/null 2>&1
sleep 1.0
n=$(worker_pids | grep -c .)
check "no worker processes after remove" "$n" "0"

echo "== and every shard actually serves, rather than merely binding =="
# Four listeners and four pids prove the forks happened but not that a shard
# answers, so 30 requests over 30 connections have to come back 200 -- with
# --http because it has a reply checkable without a script, and with the chance
# of all thirty landing on one shard at (1/4)^29.
mkdir -p "$SOCKETLEY_TMPD/docroot"
echo "sharded" > "$SOCKETLEY_TMPD/docroot/index.html"
"$BIN" create server ss_http -p $P_H --shards 4 \
       --http "$SOCKETLEY_TMPD/docroot" --http-cache -s >/dev/null 2>&1
rc=$?
check "create -s of a sharded --http server" "$rc" "0"
await_workers 4
OK200=0
for _ in $(seq 1 30); do
    printf 'GET /index.html HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n' \
        | timeout 3 nc 127.0.0.1 $P_H 2>/dev/null | grep -q '200' && OK200=$((OK200+1))
done
check "30 requests over 30 connections all answered 200" "$OK200" "30"

# ...and not all answered by one process, read from `shard_total_connections`
# rather than the runtime's summed line, and still polled because a shard's
# last accept may not yet have been counted by its own loop turn.
BUSIEST=0; TOTAL=0
for _ in $(seq 1 60); do
    S=$("$BIN" stats ss_http 2>/dev/null)
    BUSIEST=$(printf '%s' "$S" | awk -F: '/^shard_total_connections:/ {if ($2+0>m) m=$2+0} END {print m+0}')
    TOTAL=$(printf '%s' "$S" | awk -F: '/^shard_total_connections:/ {s+=$2+0} END {print s+0}')
    [[ "$TOTAL" -ge 30 ]] && break
    sleep 0.2
done
[[ "$TOTAL" -ge 30 && "$BUSIEST" -lt "$TOTAL" ]] \
    && ok "the 30 were spread over more than one shard (busiest $BUSIEST of $TOTAL)" \
    || bad "one shard answered everything: busiest=$BUSIEST total=$TOTAL"

"$BIN" remove ss_http >/dev/null 2>&1
sleep 0.8

echo "== a state file is the one door with no parser behind it =="
# Written by hand, which is how a document from another build arrives, because
# the gate in runtime_instance::start() is the only one the three command-level
# checks cannot speak for -- and a gate left refusing here fails at boot, where
# no operator is watching.
"$BIN" create server ss_state -p $P_A --lua "$LUA" >/dev/null 2>&1
rc=$?
check "the scripted server was created unsharded" "$rc" "0"
# Polled rather than read once, because state files are written on their own
# writer thread and a single read catches the .tmp about half the time.
SF=""
for _ in $(seq 1 50); do
    SF=$(find "$HOME/.local/share/socketley" -name 'ss_state.json' 2>/dev/null | head -1)
    [[ -n "$SF" ]] && break
    sleep 0.1
done
[[ -n "$SF" ]] && ok "found the state file" \
               || bad "no state file for ss_state under $HOME/.local/share/socketley: $(find "$HOME/.local/share/socketley" -type f 2>&1 | tr '\n' ' ')"
if [[ -n "$SF" ]]; then
    kill "$SOCKETLEY_DPID" 2>/dev/null || true
    for _ in $(seq 1 50); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
    kill -9 "$SOCKETLEY_DPID" 2>/dev/null || true
    sed -i 's/"type": "server",/"type": "server",\n    "shards": 4,/' "$SF"
    grep -q '"shards": 4' "$SF" && ok "the state file really carries shards: 4" \
                                || bad "could not inject shards into $SF"
    : > "$SOCKETLEY_DLOG"
    daemon_start "$BIN"
    sleep 1.0
    out=$("$BIN" start ss_state 2>&1); rc=$?
    check "start of a hand-edited sharded scripted server accepted" "$rc" "0"
    # Four processes rather than "it did not error", because the last gate
    # accepting and the daemon forking are two different things and only the
    # second is what the operator asked for.
    for _ in $(seq 1 50); do
        [[ "$(worker_pids | grep -c .)" == "4" ]] && break
        sleep 0.2
    done
    n=$(worker_pids | grep -c .)
    check "and forked all four shards" "$n" "4"
    "$BIN" stop ss_state >/dev/null 2>&1
fi

echo
echo "PASS: $PASS  FAIL: $FAIL"
[[ $FAIL -eq 0 ]]
