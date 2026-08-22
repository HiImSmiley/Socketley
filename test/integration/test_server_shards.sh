#!/usr/bin/env bash
# Integration test: --shards N on a server, and the rule that decides who gets it.
#
# ─── WHAT CHANGED, AND WHAT THE RULE IS ─────────────────────────────────────
#
# --shards was refused on everything but a proxy, then widened to a server with
# NO script, and is now open to a scripted server as well.  What removed the
# last refusal is that the three shapes a script can ask for cross a shard
# boundary: self.connections() sums every shard's counter, self.broadcast
# reaches every shard's clients once each, and self.clients()/self.send(id)
# name and reach a client whichever shard holds it.
#
# The behaviour is asserted by test_shard_lua_fanout.sh and
# test_shard_lua_route.sh.  What THIS file asserts is that the door is open at
# every one of the five places the rule is asked — create in both flag orders,
# edit, import, and a state file that never sees a parser — because a rule
# removed from four of five is the shape 4af38f0 was.
#
# ─── WHAT IS BEING ASSERTED, AND WHICH BROKEN BUILD EACH ONE CATCHES ────────
#
# THE RULE
#   server + --shards, no script     accepted.   Broken build: the old blanket
#                                                refusal, so the flag does
#                                                nothing for anybody.
#   --shards 4 --lua x               accepted.   Broken build: the refusal left
#   --lua x --shards 4               accepted.   in one of the five doors.  The
#                                                PAIR is still the assertion, and
#                                                still for the order reason: a
#                                                check left in the --shards case
#                                                label alone would refuse only
#                                                one of these two, and one
#                                                runtime with two answers is the
#                                                same defect whichever way the
#                                                answer falls.
#   the shard count is stored        Broken build: accepted and dropped, so `ls`
#                                                says Up and one process serves.
#                                                Acceptance alone cannot see
#                                                that; the count is read back.
#   edit --shards onto a script      accepted.   Broken build: the removed rule
#                                                still standing in cmd_edit.
#   import shards onto a script      accepted.   Broken build: the same, through
#                                                the door that never sees a flag
#                                                parser — 4af38f0's shape.
#   a state file with both           starts.     Broken build: the last gate, in
#                                                runtime_instance::start(), still
#                                                refusing what every command
#                                                above it now accepts — and
#                                                failing it at BOOT, where no
#                                                operator is watching.
#
# TWO CONFIGURATIONS THAT WOULD DO NOTHING, OR WORSE
#   --shards + --listen unix:        refused.    Broken build: N processes
#                                                unlink each other's socket node
#                                                and only the last to bind is
#                                                reachable — `ls` says Up, N
#                                                shards, and 1/N of nothing is
#                                                served.
#   --shards + --daemon-process      refused.    Broken build: reconcile only
#                                                forks for an out-of-process
#                                                runtime, so `show` reports four
#                                                and exactly one event loop
#                                                serves the port.  This one is
#                                                NOT new to servers; it is
#                                                reachable on a proxy on the
#                                                parent commit, and the control
#                                                below pins it there too.
#
# A SHARD IS AN IMPLEMENTATION DETAIL OF A RUNTIME, NOT A RUNTIME
#   ls           one line, not N.    Broken build: N lines.
#   listeners    N on the port.      Broken build: one — the flag was stored and
#                                    never acted on, which is what --rate-limit
#                                    did on a proxy for a year.
#   CONN         the sum over them.  Broken build: whichever shard published
#                                    last, which for 8 connections over 4 shards
#                                    is 1, 2 or 3 and never 8.  Paired with an
#                                    oracle that no single shard holds all 8, or
#                                    the assertion could pass on a build that
#                                    happened to put every connection on one.
#   stop/remove  take all down.      Broken build: a port still bound by the
#                                    shards nobody stopped.
#   restart      brings back N.      Broken build: one worker and a quarter of
#                                    the throughput that was configured,
#                                    reported by `ls` as Up and by nothing as
#                                    wrong.
#   daemon restart brings back N.    Broken build: the count is in the runtime
#                                    and not in the state file.
#
# AND THE TWO TYPES THAT STILL REFUSE IT OUTRIGHT
#   cache, client                    refused.    Broken build: a cache split into
#                                                N stores behind one port.
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
    for n in ss_ok ss_lua ss_dp ss_ed ss_imp ss_state ss_unix ss_http px_dp; do
        "$BIN" stop "$n"   >/dev/null 2>&1 || true
    done
    sleep 0.2
    for n in ss_ok ss_lua ss_dp ss_ed ss_imp ss_state ss_unix ss_http px_dp; do
        "$BIN" remove "$n" >/dev/null 2>&1 || true
    done
    [[ -n "${HOLD_PID:-}" ]] && kill -9 "$HOLD_PID" 2>/dev/null
    rm -f "$LUA" "$SOCKNODE"
    daemon_stop
}
trap cleanup EXIT

# A script that does nothing.  Its CONTENT is deliberately irrelevant: the rule
# is "has a script at all", not "has a script that broadcasts", because whether
# a table at file scope is shared state cannot be detected — which is the whole
# reason the flag is declared rather than inferred.
cat > "$LUA" <<'LUAEOF'
function on_connect(conn)
end
LUAEOF

# The daemon goes down and comes back on the same state directory, which is what
# a restart is.  daemon_stop is not used: it deletes the directory, and the whole
# question here is what the directory brings back.  The log is emptied first
# because daemon_start waits by grepping it for "daemon started" and the first
# daemon's line is still in it -- without that the wait returns immediately and
# the assertions race a daemon that has not bound yet.
daemon_restart() {
    kill "$SOCKETLEY_DPID" 2>/dev/null || true
    for _ in $(seq 1 50); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
    kill -9 "$SOCKETLEY_DPID" 2>/dev/null || true
    : > "$SOCKETLEY_DLOG"
    daemon_start "$BIN"
}

# Wait until this many workers exist, or give up.  Not a fixed sleep: the daemon
# forks a restored runtime's children from reconcile_proxy_workers(), which runs
# on the two-second health tick, so any single number is a race against a timer
# -- and a sleep long enough to be safe is one every run pays.
await_workers() {
    local want=$1 i
    for i in $(seq 1 60); do
        [[ "$(worker_pids | grep -c .)" == "$want" ]] && return 0
        sleep 0.1
    done
    return 1
}

# Every worker process of THIS binary.  Never `pgrep -f`: -f matches the whole
# command line, so it also matches the shell carrying the string in its own
# arguments -- including the one doing the matching.
worker_pids() {
    # Scoped to THIS run's daemon, not to the binary.  Matching the binary was
    # enough while the suite ran one file at a time; it counts the siblings'
    # workers the moment two files run together, and the failure reads as a
    # product defect -- "four worker processes: expected '4', got '14'".  The
    # socket path is in every worker's environ because the daemon inherited it
    # and the fork carries it.
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
# The count is read back, not just the exit code.  A build that accepted the
# flag and dropped it would pass an rc check and serve one process for a
# runtime `ls` reports as four — which is the --daemon-process trap this same
# file pins, arriving through a different door.
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

echo "== a shard IS a worker process, so --daemon-process is a contradiction =="
out=$("$BIN" create server ss_dp -p $P_B --shards 4 --daemon-process 2>&1); rc=$?
check "server --shards --daemon-process refused" "$rc" "1"
[[ "$out" == *"--daemon-process"* ]] && ok "and names --daemon-process" || bad "reason: $out"
# The same trap on a proxy.  It is reachable on the parent commit — `show`
# reported four shards while one event loop served the port — so this is not a
# server assertion, it is the flag's.
out=$("$BIN" create proxy px_dp -p $P_C --backend 127.0.0.1:$P_D --shards 4 --daemon-process 2>&1); rc=$?
check "proxy --shards --daemon-process refused too" "$rc" "1"
# Control: either flag alone is still fine, so the refusal is about the pair.
out=$("$BIN" create server ss_ed -p $P_E --daemon-process 2>&1); rc=$?
check "--daemon-process alone still accepted" "$rc" "0"
"$BIN" remove ss_ed >/dev/null 2>&1

echo "== a cache may shard now; a client still may not =="
# The cache's refusal is gone: ownership by key hash makes N shards one store,
# so the SET/GET miss it named cannot happen.  Its own behaviour is held down by
# test_cache_shard_*.sh -- what matters here is that the FLAG's type rule moved.
#
# A distinct name, and removed straight away.  This create used to FAIL, so the
# name it asked for stayed free for the client create below; now that it
# succeeds, reusing it made the client create fail with "runtime already exists"
# and read as a client defect.
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

# The oracle for the assertion above: no single shard is holding all eight, so
# a build that reports one shard's figure cannot report 8 by accident.
MAXSHARD=$("$BIN" stats ss_ok 2>/dev/null | awk -F: '/^connections:/ {if ($2+0>m) m=$2+0} END {print m+0}')
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
# The assertion the four above cannot make.  Four listeners on a port and four
# pids prove the forks happened; they do not prove a shard answers.  A build
# where each shard binds and then sits on its accept would pass every count
# assertion in this file and serve nothing.
#
# --http, because it has a reply that can be checked without a script -- which
# is the only kind of server this flag is offered on.  30 requests over 30
# separate connections, so SO_REUSEPORT spreads them: with four shards the
# chance of all thirty landing on one is (1/4)^29, and every one of them has to
# come back 200.
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

# ...and they were not all answered by one process.  Without this the assertion
# above is satisfied by a build where three shards bind and never accept: the
# kernel would hand every connection to the one that does.
#
# `shard_total_connections`, one line per shard, and NOT `total_connections`:
# that one is now the runtime's own line and is the SUM, so an awk that matched
# it would read busiest == total and fail this every time.  The distinction is
# the point of the two names -- see aggregate_worker_stats().
#
# Still polled, though it no longer has to be.  A worker-backed runtime's
# figures used to be PUSHED on a 250 ms timer, so a read taken the instant the
# last request returned answered from the snapshot before any of them: measured,
# busiest=0 total=0 with all thirty already answered 200.  They are summed out
# of shared memory at print time now and that window is gone; the loop is kept
# because it also covers a shard whose last accept has not yet been counted by
# its own loop turn, and because a bound that ends on the counter costs nothing
# when the counter is already right.
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
# Written by hand, which is exactly how a document from another build arrives:
# a scripted server carrying a shard count no command line ever produced.  The
# gate is the last one, in runtime_instance::start(), and it is the only place
# the three command-level checks cannot speak for.
#
# It used to have to REFUSE this.  It now has to accept it and fork, and that
# is the sharper assertion of the two: a gate left refusing here fails at BOOT,
# on the auto-restart path, where no operator is watching and the only trace is
# a line in the daemon log.
"$BIN" create server ss_state -p $P_A --lua "$LUA" >/dev/null 2>&1
rc=$?
check "the scripted server was created unsharded" "$rc" "0"
# Polled rather than read once.  State files are written on
# state_persistence's own writer thread, so `create` returns before the rename
# lands and a single read catches ss_state.json.tmp about half the time.
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
    # Four processes, not "it did not error".  The last gate accepting and the
    # daemon forking are two different things, and only the second is what the
    # operator asked for.
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
