#!/usr/bin/env bash
# suite: isolated -- its own daemons, sockets, state directories and port window, so it runs beside the others
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
# test_raft_cluster proves the cluster forms and elects.  This file proves what
# the log is FOR: runtimes an operator declares once run on distinct nodes, and
# when a node dies its replicas run somewhere else with nobody typing anything.
# Three real daemons on one host, a real kill -9, and a real client asking each
# replica for a page over its own unix socket.
#
# ─── ONE HOST, ONE PORT ─────────────────────────────────────────────────────
# Every node of a cluster runtime runs the same flags, so on one host two
# replicas would ask for the same TCP port.  "{node}" in a spec's flags is the
# name of the node that runs the replica (--raft-name), and this file gives each
# replica its own socket by writing --listen unix:$T/api-{node}.sock.  On real
# hosts each node binds -p 8080 on its own machine and needs no placeholder;
# the same {node} also names per-node log paths and certificate files.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#  plain daemon    the four cluster verbs accepted, or answered in the words of
#                  the directory mode, on a daemon that is not in Raft mode
#  refusals        a cache with no -p or one that sets its own replication, or a
#                  --test spec, accepted; a typo in the flags found
#                  on every node at once instead of at the command; a duplicate,
#                  an unknown name or a no-op scale that exits 0
#  declare         a spec that reaches no node, a replica count not honoured,
#                  two replicas on one node, {node} not expanded, a create that
#                  returns before this node has applied it
#  ls and stats    a replica listed as though an operator had made it
#  hands off       stop, remove or edit reaching a replica from underneath the
#                  cluster, which would be undone at the next tick
#  blocked         the reconciler taking over, or removing, a local runtime of
#                  the same name
#  a proxy         a spec type other than a server that does not run
#  quoting         a flag value with a space in it split in two on its way to
#                  create, and a relative path left relative for the nodes
#  failover        a killed node's replica not running on a survivor within the
#                  bound, or running on three nodes at once at any poll
#  rejoin          a node that comes back and starts what moved away
#  scale           replicas beyond the count, or fewer than asked
#  whole restart   a desired state lost across kill -9 of every node, which is
#                  a WAL and snapshot that do not carry the cluster state
#  fencing         a node that has lost its quorum still serving its replica
#  remove          a replica left serving after its runtime was removed
#
# Not covered here: network partitions.  They need netns or iptables, which need
# root; test_cluster_brain runs them, with one-way cuts and late messages, in a
# simulation of the real Raft core and the real placement logic.  A daemon whose
# loop is frozen (SIGSTOP) cannot stop its workers either, and that gap is
# documented in the man page rather than tested here.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_raft.sh"

PASS=0; FAIL=0; TOTAL=0
T=$(mktemp -d /tmp/socketley-place-XXXXXX)
daemon_watch "$T"   # its processes go with it if it is killed
PB=$((SL_PORT_BASE + 1700))
NODES=()
RAFT_COMPACT_EVERY=6

echo "=== Integration: cluster runtimes placed and healed through Raft ==="

ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad()  { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL: $*"; }
check() { if eval "$1"; then ok; else bad "$2"; fi; }
# Whether a command succeeded and its output lacks a pattern, so a CLI that failed is not read as an empty listing.
unseen() {
    local pat=$1 o; shift
    o=$("$@" 2>&1) || return 1
    ! grep -qE -- "$pat" <<<"$o"
}

cleanup() {
    set +e
    local n
    for n in "${NODES[@]}" plain; do
        kill -9 "$(cat "$T/$n.pid" 2>/dev/null)" 2>/dev/null
        daemon_sweep "$(sock "$n")"
    done
    if [ -n "${SOCKETLEY_KEEP_TMPD:-}" ]; then echo "  kept: $T" >&2; else rm -rf "$T"; fi
}
trap cleanup EXIT

mkdir -p "$T/www"
echo "cluster-page" >"$T/www/index.html"

# The status line and body a replica of runtime $1 on node $2 answers with over its own socket, or nothing.
probe() {
    timeout 6 python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(2)
try:
    s.connect(sys.argv[1])
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    d = b""
    while True:
        c = s.recv(65536)
        if not c:
            break
        d += c
except Exception:
    sys.exit(1)
head, _, body = d.partition(b"\r\n\r\n")
print(head.split(b"\r\n")[0].decode("latin1") + " " + body.decode("latin1").strip())
' "$T/$1-$2.sock" 2>/dev/null || true
}
serves() { [[ "$(probe "$1" "$2")" == "HTTP/1.1 200 OK cluster-page"* ]]; }

# The nodes among $2... that serve runtime $1 right now, space separated.
holders() {
    local name=$1 n out=""; shift
    for n in "$@"; do serves "$name" "$n" && out="$out $n"; done
    echo "${out# }"
}
raft_port() { case $1 in a) echo $PB;; b) echo $((PB+1));; c) echo $((PB+2));; esac; }
start_member() {   # start_member <name> [--raft-join addr | --raft-init]
    local n=$1; shift
    node_start "$n" --raft-listen 127.0.0.1:"$(raft_port "$n")" --raft-insecure --raft-name "$n" "$@"
}

# ─── a daemon that is not in Raft mode ──────────────────────────────────────
mkdir -p "$T/plain/home"
HOME="$T/plain/home" SOCKETLEY_SOCKET="$(sock plain)" "$BIN" daemon >"$T/plain.log" 2>&1 &
echo $! >"$T/plain.pid"
wait_for 10 "[ -S $(sock plain) ]" || { echo "  FATAL: the plain daemon never came up"; exit 2; }
for verb in "create server x" "remove x" "scale x 2" "placement"; do
    out=$(as plain cluster $verb 2>&1) && rc=0 || rc=$?
    check '[ "$rc" = 1 ] && grep -q "Raft daemon" <<<"$out"' "cluster $verb on a plain daemon: exit $rc, said: $out"
done
kill -9 "$(cat "$T/plain.pid")" 2>/dev/null || true
daemon_sweep "$(sock plain)"

# ─── the failure timing is judged against the election timeout ──────────────
refuse_daemon() {
    local needle=$1; shift
    local out rc=0
    mkdir -p "$T/refuse/home"
    out=$(HOME="$T/refuse/home" SOCKETLEY_SOCKET="$T/refuse.sock" timeout 10 "$BIN" daemon "$@" 2>&1) || rc=$?
    daemon_sweep "$T/refuse.sock"
    check '[ "$rc" = 1 ] && grep -q -- "$needle" <<<"$out"' "daemon $* exited $rc saying: $out"
}
refuse_daemon "three election timeouts" --raft-listen 127.0.0.1:$((PB+9)) --raft-init --raft-insecure --raft-down-after 2s
refuse_daemon "takes a duration"        --raft-listen 127.0.0.1:$((PB+9)) --raft-init --raft-insecure --raft-down-after soon
refuse_daemon "need --raft-listen"      --raft-down-after 5s

# ─── three nodes form a cluster ─────────────────────────────────────────────
start_member a --raft-init
start_member b --raft-join 127.0.0.1:$PB
start_member c --raft-join 127.0.0.1:$PB
formed() { [ "$(voters a)" = 3 ] && [ "$(voters b)" = 3 ] && [ "$(voters c)" = 3 ] \
           && [ -n "$(leader a)" ] && [ "$(leader a)" = "$(leader b)" ] && [ "$(leader b)" = "$(leader c)" ]; }
check 'wait_for 25 formed' "three daemons did not agree on three voters and one leader within 25 s"
L=$(leader_of a b c || true)
follower=a; for n in a b c; do [ "$n" != "$L" ] && follower=$n; done

# ─── refusals at the command ────────────────────────────────────────────────
refuse() {   # refuse <needle> <cluster args...>: exit 1, said on stdout, nothing on stderr
    local needle=$1; shift
    local out err rc=0
    out=$(as "$follower" cluster "$@" 2>"$T/err") || rc=$?
    err=$(cat "$T/err")
    check '[ "$rc" = 1 ] && grep -q -- "$needle" <<<"$out" && [ -z "$err" ]' "cluster $*: exit $rc, stdout: $out, stderr: $err"
}
refuse "needs -p"            create cache db --replicas 2
refuse "the cluster's to set" create cache db -p 6300 --replicate 127.0.0.1:1 --replicas 2
refuse "dry run"             create server x --test
refuse "unknown flag"        create server x --nonsense
refuse "replicas must be"    create server x --replicas 0
refuse "takes a count"       create server x --replicas many
refuse "invalid runtime name" create server "bad..name"
refuse "not found"           remove ghost
refuse "not found"           scale ghost 2
refuse "usage: cluster create" create server
refuse "usage: cluster scale"  scale api

# ─── declare: a two-replica server, from a follower ─────────────────────────
before=$(as "$follower" ls 2>&1 | wc -l)
out=$(as "$follower" cluster create server api --listen "unix:$T/api-{node}.sock" --http "$T/www" --replicas 2 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 0 ] && [ -z "$out" ]' "cluster create from a follower: exit $rc, output: $out (success is silent)"
check 'saw "^api +server +2 " as "$follower" cluster placement' "the follower that took the command does not show api in its placement once create returned"
check 'wait_for 20 "[ \$(count_of \"\$(holders api a b c)\") = 2 ]"' "api did not come to serve on exactly two nodes within 20 s: [$(holders api a b c)]"
H=$(holders api a b c)
check '[ "$(count_of "$H")" = 2 ]' "api is served by [$H], not by two distinct nodes"
spare=""; for n in a b c; do [[ " $H " != *" $n "* ]] && spare=$n; done
check '[ -n "$spare" ] && ! serves api "$spare"' "the third node serves api too"

# The runtime is a replica on the two nodes and appears nowhere on the third.
h1=${H%% *}
check 'saw "api.*\[cluster\]" as "$h1" ls' "ls does not mark the replica as a cluster runtime"
check 'saw "\"name\":\"api\".*\"cluster\":true" as "$h1" ls --json' "ls --json does not say the replica is a cluster runtime"
check 'saw "^cluster:replica" as "$h1" stats api' "stats does not say the replica is a cluster runtime"
check 'unseen "^[^ ]* *api" as "$spare" ls' "the node holding no replica lists api"
check 'saw "^api +server +2 +2 " as "$h1" cluster placement' "placement does not report two replicas placed"
check 'saw "replicas on this node" as "$h1" cluster placement && saw "^  api +running" as "$h1" cluster placement' "placement does not say this node's replica is running"

# ─── hands off ──────────────────────────────────────────────────────────────
# restart and import are the same hands: restart is a stop and a start in one command, and import is the other door
# to what edit refuses here -- neither may go around the refusal by being one request instead of three.
for verb in "stop api" "remove api" "start api" "edit api --max-connections 5" \
            "restart api" "restart api --max-connections 5" "edit api --max-connections 5 --restart" \
            "import api {\"max_connections\":5}" "import api --restart {\"max_connections\":5}"; do
    out=$(as "$h1" $verb 2>&1) && rc=0 || rc=$?
    check '[ "$rc" = 1 ] && grep -q "is a cluster runtime" <<<"$out"' "$verb on a replica: exit $rc, said: $out"
done
check 'serves api "$h1"' "the replica stopped serving after the refused verbs"
# The refused bare restart names the verb that does bounce a replica, and that verb works where restart may not.
out=$(as "$h1" restart api 2>&1) || true
check 'grep -q "reload api" <<<"$out"' "the refused restart does not point at reload: $out"
out=$(as "$h1" reload api 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 0 ]' "reload on a replica: exit $rc, said: $out"
check 'wait_for 20 "serves api \"$h1\""' "the replica does not serve again after a reload"

# ─── refused as a duplicate, and a no-op ────────────────────────────────────
refuse "already exists" create server api --listen "unix:$T/x-{node}.sock"
refuse "already has 2"  scale api 2

# ─── a local runtime of the same name is not touched ────────────────────────
as b create server dup --listen "unix:$T/dup-b.sock" --http "$T/www" -s >/dev/null 2>&1 || true
check 'wait_for 10 "[[ \"\$(probe dup b)\" == \"HTTP/1.1 200\"* ]]"' "the local runtime dup did not come up on b"
out=$(as b cluster create server dup --listen "unix:$T/dup-{node}.sock" --http "$T/www" --replicas 3 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 1 ] && grep -q "local runtime named dup" <<<"$out"' "cluster create dup on the node holding a local dup: exit $rc, said: $out"
out=$(as a cluster create server dup --listen "unix:$T/dup-{node}.sock" --http "$T/www" --replicas 3 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 0 ]' "cluster create dup from a: exit $rc: $out"
check 'wait_for 20 "saw \"^  dup +blocked\" as b cluster placement"' "b does not report that its local dup blocks the replica"
check 'wait_for 20 "[ \$(count_of \"\$(holders dup a c)\") = 2 ]"' "dup did not run on the two nodes without a local dup: [$(holders dup a c)]"
check '[[ "$(probe dup b)" == "HTTP/1.1 200"* ]] && unseen "dup.*\[cluster\]" as b ls' "b's own dup was replaced or marked as a cluster runtime"
out=$(as a cluster remove dup 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 0 ] && [ -z "$out" ]' "cluster remove dup: exit $rc, output: $out"
check 'wait_for 20 "[ -z \"\$(holders dup a c)\" ]"' "dup still serves after the cluster runtime was removed"
check '[[ "$(probe dup b)" == "HTTP/1.1 200"* ]]' "removing the cluster dup removed b's local dup"

# ─── a proxy is a cluster runtime too ───────────────────────────────────────
as a create server back --listen "unix:$T/back-a.sock" --http "$T/www" -s >/dev/null 2>&1 || true
check 'wait_for 10 "[[ \"\$(probe back a)\" == \"HTTP/1.1 200\"* ]]"' "the local backend did not come up on a"
out=$(as c cluster create proxy px --listen "unix:$T/px-{node}.sock" --backend "unix:$T/back-a.sock" --protocol tcp --replicas 2 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 0 ] && [ -z "$out" ]' "cluster create proxy: exit $rc, output: $out"
check 'wait_for 20 "[ \$(count_of \"\$(holders px a b c)\") = 2 ]"' "the proxy did not come to serve on two nodes: [$(holders px a b c)]"
out=$(as b cluster remove px 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 0 ] && [ -z "$out" ]' "cluster remove px: exit $rc, output: $out"
check 'wait_for 20 "[ -z \"\$(holders px a b c)\" ]"' "the proxy still serves after cluster remove"

# ─── a flag with a space in it stays one argument, and a relative path is made absolute ─────
mkdir -p "$T/my www"
echo "cluster-page" >"$T/my www/index.html"
out=$(as a cluster create server sp --listen "unix:$T/sp-{node}.sock" --http "$T/my www" --replicas 2 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 0 ] && [ -z "$out" ]' "cluster create with a space in --http: exit $rc, output: $out"
check 'wait_for 20 "[ \$(count_of \"\$(holders sp a b c)\") = 2 ]"' "a replica whose --http path has a space in it does not serve on two nodes: [$(holders sp a b c)]"
out=$(cd "$T" && as b cluster create server rel --listen "unix:$T/rel-{node}.sock" --http "my www" --replicas 2 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 0 ] && [ -z "$out" ]' "cluster create with a relative --http: exit $rc, output: $out"
check 'wait_for 20 "[ \$(count_of \"\$(holders rel a b c)\") = 2 ]"' "a replica whose --http path was relative does not serve on two nodes: [$(holders rel a b c)]"
as c cluster remove sp >/dev/null 2>&1 || true
as c cluster remove rel >/dev/null 2>&1 || true
check 'wait_for 20 "[ -z \"\$(holders sp a b c)\" ] && [ -z \"\$(holders rel a b c)\" ]"' "the quoting runtimes still serve after cluster remove"

# ─── failover: kill -9 a node that holds a replica ──────────────────────────
declare -a TIMES=()
failover_round() {   # failover_round <label> <victim>
    local label=$1 v=$2 alive=() n dup=0
    for n in a b c; do [ "$n" != "$v" ] && alive+=("$n"); done
    local t0
    t0=$(date +%s%N)
    node_kill "$v"
    local got=0 ms=0
    while :; do
        ms=$(ms_since "$t0")
        local hs
        hs=$(holders api "${alive[@]}")
        [ "$(count_of "$hs")" -gt 2 ] && dup=1
        [ "$(count_of "$hs")" = 2 ] && { got=1; break; }
        [ "$ms" -gt 20000 ] && break
        sleep 0.1
    done
    check '[ "$got" = 1 ]' "$label: api did not run on both survivors within 20 s of kill -9 of $v"
    check '[ "$dup" = 0 ]' "$label: api ran on more than two nodes"
    TIMES+=("$ms")
    echo "  $label: kill -9 of $v, api served by ${alive[*]} again after ${ms} ms"
}

# The victim is a follower that holds a replica.
victim=""; for n in $H; do [ "$n" != "$L" ] && victim=$n; done
[ -n "$victim" ] || victim=${H%% *}
failover_round "round 1 (follower holder)" "$victim"

# It comes back: a follower again, holding nothing it no longer owns, and nothing ever runs three times.
start_member "$victim"
survivors=(); for n in a b c; do [ "$n" != "$victim" ] && survivors+=("$n"); done
check 'wait_for 20 "[ \"\$(role $victim)\" = follower ]"' "the restarted node $victim did not come back as a follower"
dup=0
for i in $(seq 1 25); do
    hs=$(holders api a b c)
    [ "$(count_of "$hs")" -gt 2 ] && dup=1
    sleep 0.3
done
check '[ "$dup" = 0 ]' "the restarted node started a replica that had moved away: api ran on [$hs]"
check '! serves api "$victim"' "the restarted node $victim serves api"
check '[ "$(count_of "$(holders api a b c)")" = 2 ]' "api is not served by exactly two nodes after the restart: [$(holders api a b c)]"
check 'saw "^api +server +2 +2 " as "$victim" cluster placement' "the restarted node does not know the runtime"

# The victim is the leader, holding a replica if any node does: the election comes first.
L=$(leader_of a b c || true)
H=$(holders api a b c)
victim=$L
[[ " $H " == *" $L "* ]] || victim=${H%% *}
failover_round "round 2 (${victim} is $([ "$victim" = "$L" ] && echo the leader || echo a follower))" "$victim"
start_member "$victim"
check 'wait_for 20 "[ \"\$(role $victim)\" = follower ]"' "the restarted node $victim did not come back as a follower"
check 'wait_for 10 "[ \$(count_of \"\$(holders api a b c)\") = 2 ]"' "api is not served by exactly two nodes after the second restart"

# A follower that holds a replica dies again, so the range is more than two samples.
L=$(leader_of a b c || true)
H=$(holders api a b c)
victim=""; for n in $H; do [ "$n" != "$L" ] && victim=$n; done
[ -n "$victim" ] || victim=${H%% *}
failover_round "round 3 (follower holder)" "$victim"
start_member "$victim"
check 'wait_for 20 "[ \"\$(role $victim)\" = follower ]"' "the restarted node $victim did not come back as a follower"
check 'wait_for 10 "[ \$(count_of \"\$(holders api a b c)\") = 2 ]"' "api is not served by exactly two nodes after the third restart"

# The victim holds nothing: the replicas do not move and are not restarted.
H=$(holders api a b c)
spare=""; for n in a b c; do [[ " $H " != *" $n "* ]] && spare=$n; done
pids_before=$(for n in $H; do as "$n" stats api | awk -F: '$1 == "pid" { print $2 }'; done | sort | tr '\n' ' ')
node_kill "$spare"
sleep 8
pids_after=$(for n in $H; do as "$n" stats api | awk -F: '$1 == "pid" { print $2 }'; done | sort | tr '\n' ' ')
check '[ -n "$pids_before" ] && [ "$pids_before" = "$pids_after" ]' "the replicas were restarted when a node holding none was killed ($pids_before -> $pids_after)"
check '[ "$(count_of "$(holders api $H)")" = 2 ]' "a node holding no replica died and api is no longer served by its two"
start_member "$spare"
check 'wait_for 20 "[ \"\$(role $spare)\" = follower ]"' "the restarted node $spare did not come back as a follower"

# ─── scale ──────────────────────────────────────────────────────────────────
check 'wait_for 20 formed' "the cluster has no leader every node agrees on after the restarts"
out=$(as a cluster scale api 3 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 0 ] && [ -z "$out" ]' "cluster scale api 3: exit $rc, output: $out"
check 'wait_for 20 "[ \$(count_of \"\$(holders api a b c)\") = 3 ]"' "api did not run on all three nodes after scaling to 3: [$(holders api a b c)]"
out=$(as b cluster scale api 1 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 0 ] && [ -z "$out" ]' "cluster scale api 1: exit $rc, output: $out"
check 'wait_for 20 "[ \$(count_of \"\$(holders api a b c)\") = 1 ]"' "api did not settle on one node after scaling to 1: [$(holders api a b c)]"
out=$(as c cluster scale api 4 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 0 ]' "cluster scale api 4: exit $rc: $out"
check 'wait_for 20 "[ \$(count_of \"\$(holders api a b c)\") = 3 ]"' "api did not run on the three nodes there are after scaling to 4"
check 'saw "^api +server +4 +3 .*1 replica unplaced" as a cluster placement' "placement does not report the replica there is no node for"
as a cluster scale api 2 >/dev/null 2>&1 || true
check 'wait_for 20 "[ \$(count_of \"\$(holders api a b c)\") = 2 ]"' "api did not settle on two nodes after scaling back to 2"

# ─── the whole cluster loses power ──────────────────────────────────────────
for n in a b c; do node_kill "$n"; done
check 'wait_for 5 "[ -z \"\$(holders api a b c)\" ]"' "a replica still serves with every node dead"
for n in a b c; do start_member "$n"; done
check 'wait_for 30 formed' "the cluster did not form again after every node was killed"
check 'wait_for 30 "[ \$(count_of \"\$(holders api a b c)\") = 2 ]"' "api did not come back on two nodes after every node was killed and restarted: [$(holders api a b c)]"
check 'saw "^cluster: *1 runtime\(s\) declared" status a' "the restarted node lost the declared runtimes"
check 'grep -q "installed a snapshot\|snapshot [1-9][0-9]* and" "$T/a.log" "$T/b.log" "$T/c.log"' "no node recovered from a snapshot, so the cluster state never went through one"

# ─── a node that loses its quorum stops serving ─────────────────────────────
H=$(holders api a b c)
keep=${H%% *}
others=(); for n in a b c; do [ "$n" != "$keep" ] && others+=("$n"); done
t0=$(date +%s%N)
for n in "${others[@]}"; do node_kill "$n"; done
gone=0
while [ "$(ms_since "$t0")" -lt 15000 ]; do
    serves api "$keep" || { gone=1; break; }
    sleep 0.2
done
ms=$(ms_since "$t0")
check '[ "$gone" = 1 ]' "$keep still serves api 15 s after it lost its quorum"
check '[ "$ms" -le 8000 ]' "$keep took ${ms} ms to stop serving without a quorum, past the lease"
echo "  a node without a quorum stopped serving after ${ms} ms"
check 'saw "NOT serving" as "$keep" cluster placement' "placement on the node without a quorum does not say it is not serving"
for n in "${others[@]}"; do start_member "$n"; done
check 'wait_for 30 formed' "the cluster did not form again after the quorum came back"
check 'wait_for 30 "[ \$(count_of \"\$(holders api a b c)\") = 2 ]"' "api did not serve on two nodes once the quorum was back: [$(holders api a b c)]"

# ─── remove ─────────────────────────────────────────────────────────────────
out=$(as c cluster remove api 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 0 ] && [ -z "$out" ]' "cluster remove api: exit $rc, output: $out"
check 'wait_for 20 "[ -z \"\$(holders api a b c)\" ]"' "api still serves after cluster remove"
check 'unseen "\[cluster\]" as a ls && unseen "\[cluster\]" as b ls && unseen "\[cluster\]" as c ls' "a replica is still listed after cluster remove"
check 'saw "no cluster runtimes declared" as a cluster placement' "placement still lists a runtime after cluster remove"

# ─── how long the failovers took ────────────────────────────────────────────
echo "  failover times (ms, kill -9 to served again): ${TIMES[*]}"
worst=0; for t in "${TIMES[@]}"; do [ "$t" -gt "$worst" ] && worst=$t; done
check '[ "$worst" -le 12000 ]' "a failover took ${worst} ms, past the failure timeout and an election"

echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
