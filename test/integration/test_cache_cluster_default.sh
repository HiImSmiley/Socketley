#!/usr/bin/env bash
# A cache of more than one shard on a port is in cluster mode unless told --no-cluster.
#
# ─── WHAT THIS FILE IS ACTUALLY ASSERTING ───────────────────────────────────
# The shared port answers every client the same in both modes, so the mode is
# read off what only it changes: cluster_enabled, the ports CLUSTER SLOTS names,
# and whether base+1..base+N are bound -- each read on both arms, because a
# build where the default stayed off passes every "off" case and a build where
# --no-cluster did nothing passes every "on" case.
# ─── AND WHERE IT MUST STAY OFF OR FAIL LOUDLY ──────────────────────────────
# A unix path has no successor port, so the default is off there and only a
# typed --cluster is refused; a busy shard port fails the start and the error
# names the way out; and the choice survives a daemon restart and an import.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate cachecdef

# Twenty apart, because a three-shard cache in cluster mode holds base..base+3.
PD=$((SL_PORT_BASE+1600))       # three shards, no flag: the default
PN=$((SL_PORT_BASE+1620))       # three shards, --no-cluster
PE=$((SL_PORT_BASE+1640))       # three shards, --cluster said aloud
PB=$((SL_PORT_BASE+1660))       # three shards, base+2 held by a stranger
PO=$((SL_PORT_BASE+1680))       # one shard, no flag
D=$SOCKETLEY_TMPD

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$3', got '$2'"; fi; }

HOLDER_PID=""
NAMES="cdd cdn cde cdb cdo cdu cdux cdx"
cleanup() {
    [ -n "$HOLDER_PID" ] && kill "$HOLDER_PID" 2>/dev/null
    for n in $NAMES; do "$BIN" stop "$n" >/dev/null 2>&1 || true; done
    sleep 0.4
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: cluster mode is a sharded cache's default, --no-cluster turns it off ==="

if ! command -v redis-cli >/dev/null 2>&1; then
    echo "  SKIP: redis-cli is the cluster client this file reads the map with"
    exit 0
fi

ready_resp() {
    local i
    for i in $(seq 1 80); do
        redis-cli "$@" PING 2>/dev/null | grep -q PONG && return 0
        sleep 0.25
    done
    return 1
}
# Whether anything accepts on a port, without the retries a ready check makes.
answers() { redis-cli -p "$1" -t 1 PING 2>/dev/null | grep -q PONG && echo yes || echo no; }
enabled() { redis-cli "$@" CLUSTER INFO 2>/dev/null | tr -d '\r' | sed -n 's/^cluster_enabled://p'; }
# How many of base+1..base+3 CLUSTER SLOTS names, read the way a client reads it.
named_ports() {
    local base=$1 slots n=0 i; shift
    slots=$(redis-cli "$@" CLUSTER SLOTS 2>/dev/null | sed 's/^ *//; s/ *$//')
    for i in 1 2 3; do printf '%s\n' "$slots" | grep -qx "$((base+i))" && n=$((n+1)); done
    echo "$n"
}
listeners_on() { ss -ltnH "sport = :$1" 2>/dev/null | grep -c . || true; }
said_for() { grep -c "cache \"$1\": .* shards share one address" "$SOCKETLEY_DLOG" 2>/dev/null || true; }

daemon_start "$BIN"

# ─── 1. No flag: the default is cluster mode ────────────────────────────────
"$BIN" create cache cdd -p "$PD" --shards 3 --resp -s >/dev/null 2>&1 \
    || daemon_bail "the default starts" "create cache cdd --shards 3 was refused"
ready_resp -p "$PD" || daemon_bail "the default answers" "nothing on $PD"
check "a three-shard cache with no flag reports cluster_enabled:1" "$(enabled -p "$PD")" "1"
# Waited for, since each shard binds its own port as it comes up.
B=0; for i in 1 2 3; do ready_resp -p $((PD+i)) && B=$((B+1)); done
check "and each shard answers on its own port, base+1..base+3" "$B" "3"
check "and CLUSTER SLOTS names all three" "$(named_ports "$PD" -p "$PD")" "3"
redis-cli -p "$PD" SET foo v >/dev/null 2>&1
# foo is slot 12182, which three shards put on the last of them.
MOVED=$(redis-cli -p $((PD+1)) GET foo 2>&1)
case "$MOVED" in *MOVED*12182*":$((PD+3))"*) ok "a shard port answers -MOVED for a key it does not hold" ;;
    *) bad "a shard port answers -MOVED for a key it does not hold" "got '$MOVED' from $((PD+1))" ;; esac
check "while the shared port still answers the value" "$(redis-cli -p "$PD" GET foo 2>&1)" "v"
check "and no shared-address warning is logged for it" "$(said_for cdd)" "0"
# Asked on the shared port, CLUSTER NODES names that port as a node of its own
# holding no slots and marks it myself: a client that maps myself to the address
# it dialled, as redis-benchmark and lettuce do, sends every key to a shard port
# and none through the relay, where the shard that took the connection used to
# call itself myself and its slots went back to the shared port.
NODES=$(redis-cli -p "$PD" CLUSTER NODES 2>/dev/null | tr -d '\r')
check "CLUSTER NODES on the shared port marks that port myself" \
    "$(echo "$NODES" | awk '/myself/ {split($2, a, "[:@]"); print a[2]}')" "$PD"
check "and gives it no slots" "$(echo "$NODES" | awk '/myself/ {print NF}')" "8"
check "while each shard's own port holds its range" \
    "$(echo "$NODES" | awk '!/myself/ && NF >= 9 {n++} END {print n + 0}')" "3"
check "and asked on a shard's port, that shard is myself with its slots" \
    "$(redis-cli -p $((PD+1)) CLUSTER NODES 2>/dev/null | tr -d '\r' | awk '/myself/ {split($2, a, "[:@]"); print a[2], NF}')" "$((PD+1)) 9"

# ─── 2. --no-cluster: one address, one node ─────────────────────────────────
"$BIN" create cache cdn -p "$PN" --shards 3 --resp --no-cluster -s >/dev/null 2>&1 \
    || daemon_bail "--no-cluster starts" "create cache cdn --no-cluster was refused"
ready_resp -p "$PN" || daemon_bail "--no-cluster answers" "nothing on $PN"
check "--no-cluster reports cluster_enabled:0" "$(enabled -p "$PN")" "0"
# Read once all three shards listen on the shared port, so "none" is not "not yet".
for _ in $(seq 1 80); do [ "$(listeners_on "$PN")" -ge 3 ] && break; sleep 0.1; done
check "all three --no-cluster shards listen on the shared port" "$(listeners_on "$PN")" "3"
B=0; for i in 1 2 3; do [ "$(answers $((PN+i)))" = yes ] && B=$((B+1)); done
check "and binds none of base+1..base+3" "$B" "0"
check "and CLUSTER SLOTS names no shard port" "$(named_ports "$PN" -p "$PN")" "0"
check "but names the shared port as the one node" \
    "$(redis-cli -p "$PN" CLUSTER SLOTS 2>/dev/null | sed 's/^ *//' | grep -cx "$PN")" "1"
redis-cli -p "$PN" SET foo w >/dev/null 2>&1
check "and a foreign key is fetched, not redirected" "$(redis-cli -p "$PN" GET foo 2>&1)" "w"
check "and the shared-address warning is logged once" "$(said_for cdn)" "1"
check "naming --no-cluster as its cause" \
    "$(grep "cache \"cdn\": .* shards share one address" "$SOCKETLEY_DLOG" | grep -c -- '--no-cluster')" "1"

# ─── 3. --cluster said aloud is the same as the default ─────────────────────
"$BIN" create cache cde -p "$PE" --shards 3 --resp --cluster -s >/dev/null 2>&1 \
    || daemon_bail "--cluster starts" "create cache cde --cluster was refused"
ready_resp -p "$PE" || daemon_bail "--cluster answers" "nothing on $PE"
check "--cluster still reports cluster_enabled:1" "$(enabled -p "$PE")" "1"
check "and names its three shard ports" "$(named_ports "$PE" -p "$PE")" "3"

# ─── 4. One shard: nothing to route, so standalone ──────────────────────────
"$BIN" create cache cdo -p "$PO" --resp -s >/dev/null 2>&1
ready_resp -p "$PO" || daemon_bail "one shard answers" "nothing on $PO"
check "an unsharded cache stays standalone (cluster_enabled:0)" "$(enabled -p "$PO")" "0"
check "and binds nothing at base+1" "$(answers $((PO+1)))" "no"

# ─── 5. A unix path: off by default, and a typed --cluster is refused ───────
"$BIN" create cache cdu --listen "unix:$D/cdu.sock" --shards 2 --resp -s >/dev/null 2>&1
ready_resp -s "$D/cdu#0.sock" || bad "a sharded cache on a unix path starts" "nothing on $D/cdu#0.sock"
check "a sharded cache on a unix path is not in cluster mode" "$(enabled -s "$D/cdu#0.sock")" "0"
OUT=$("$BIN" create cache cdux --listen "unix:$D/cdux.sock" --shards 2 --cluster -s 2>&1); RC=$?
LOGGED=$(grep -c -- '--listen and --cluster cannot be combined' "$SOCKETLEY_DLOG" || true)
if [ "$RC" -ne 0 ] && [ "$LOGGED" -ge 1 ]; then
    ok "but --cluster with --listen is refused, and says why"
else
    bad "but --cluster with --listen is refused, and says why" "exit $RC, log lines $LOGGED" "$OUT"
fi

# ─── 6. A shard port held by a stranger fails the start, naming the way out ─
python3 -c '
import socket, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1]))); s.listen(1)
time.sleep(120)' $((PB+2)) &
HOLDER_PID=$!
for _ in $(seq 1 50); do ss -ltnH "sport = :$((PB+2))" | grep -q . && break; sleep 0.1; done
OUT=$("$BIN" create cache cdb -p "$PB" --shards 3 --resp -s 2>&1); RC=$?
sleep 0.5
WHY=$(grep "could not bind its own port $((PB+2))" "$SOCKETLEY_DLOG" | head -1)
if [ "$RC" -ne 0 ] && printf '%s' "$WHY" | grep -q -- '--no-cluster'; then
    ok "a busy shard port fails the start, and the error names it and --no-cluster"
else
    bad "a busy shard port fails the start, and the error names it and --no-cluster" \
        "exit $RC, said: $(printf '%s' "$OUT" | head -c 160)" "log: ${WHY:-<no line naming $((PB+2))>}"
fi
# The shards that did bind are taken down after create has answered, which takes up to a second on a fast machine.
for _ in $(seq 1 50); do [ "$(answers "$PB")" = no ] && break; sleep 0.1; done
check "and the shared port of that cache is not left serving" "$(answers "$PB")" "no"
kill "$HOLDER_PID" 2>/dev/null; wait "$HOLDER_PID" 2>/dev/null; HOLDER_PID=""
"$BIN" stop cdb >/dev/null 2>&1; "$BIN" remove cdb >/dev/null 2>&1

# The daemon's own table holds the shard ports too, so another runtime cannot take one.
"$BIN" create server cdx -p $((PD+2)) >/dev/null 2>&1
OUT=$("$BIN" start cdx 2>&1); RC=$?
if [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -q 'cdd'; then
    ok "a runtime on a default cluster cache's shard port is refused, naming the cache"
else
    bad "a runtime on a default cluster cache's shard port is refused, naming the cache" \
        "exit $RC, said: $(printf '%s' "$OUT" | head -c 200)"
fi
"$BIN" stop cdx >/dev/null 2>&1; "$BIN" remove cdx >/dev/null 2>&1

# ─── 7. The choice is kept across a daemon restart ──────────────────────────
check "the state names --no-cluster" "$("$BIN" show cdn | grep -c '"no_cluster": true')" "1"
check "and the default names neither flag" "$("$BIN" show cdd | grep -cE '"(no_)?cluster"')" "0"
kill "$SOCKETLEY_DPID" 2>/dev/null
for _ in $(seq 1 60); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
wait "$SOCKETLEY_DPID" 2>/dev/null
for p in "$PD" "$PN" "$PE"; do for _ in $(seq 1 50); do [ "$(answers "$p")" = no ] && break; sleep 0.1; done; done
daemon_start "$BIN"
for p in "$PD" "$PN" "$PE"; do ready_resp -p "$p" || bad "a cache came back on $p" "nothing answers"; done
check "after a restart the default is still in cluster mode" "$(enabled -p "$PD")" "1"
check "and --no-cluster is still off" "$(enabled -p "$PN")" "0"
check "and still binds no shard port" "$(answers $((PN+1)))" "no"
check "and --cluster is still on" "$(enabled -p "$PE")" "1"

# ─── 8. And it is changed by an import, at a stop, not under a running cache ─
"$BIN" show cdd | sed 's/^{/{"no_cluster": true,/' > "$D/cdd.json"
OUT=$("$BIN" import cdd < "$D/cdd.json" 2>&1); RC=$?
if [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -q 'cannot change cluster mode while running'; then
    ok "a running cache refuses an import that turns cluster mode off"
else
    bad "a running cache refuses an import that turns cluster mode off" "exit $RC, said: $OUT"
fi
"$BIN" stop cdd >/dev/null 2>&1
OUT=$("$BIN" import cdd < "$D/cdd.json" 2>&1); RC=$?
check "a stopped one takes it" "$RC" "0"
"$BIN" start cdd >/dev/null 2>&1
ready_resp -p "$PD" || bad "it starts again" "nothing on $PD"
check "and starts with cluster_enabled:0" "$(enabled -p "$PD")" "0"
check "and no shard port" "$(answers $((PD+1)))" "no"
"$BIN" stop cdd >/dev/null 2>&1
"$BIN" show cdd | sed 's/"no_cluster": true/"no_cluster": false/' > "$D/cdd.json"
"$BIN" import cdd < "$D/cdd.json" >/dev/null 2>&1
"$BIN" start cdd >/dev/null 2>&1
ready_resp -p "$PD" || bad "it starts a third time" "nothing on $PD"
check "and an import back gives the default again" "$(enabled -p "$PD")" "1"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
