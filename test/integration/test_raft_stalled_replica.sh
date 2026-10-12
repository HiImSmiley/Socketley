#!/usr/bin/env bash
# suite: isolated -- its own daemons, sockets, state directories and port window, so it runs beside the others
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
# A daemon has one loop, and Raft's heartbeats, a follower's lease requests and
# the node's own commands all run on it.  The reconciler starts a cluster
# replica from inside the Raft tick, and a `create -s` used to wait for the
# worker to say it was serving -- up to two seconds, retried every three.  One
# cluster runtime whose startup hangs (here a Lua file that busy-loops for 20 s
# at load) therefore stalled every node's loop in turn: measured on three nodes,
# the term went from 1 to 11 in 48 s, a leader election every five seconds, and
# with it every node's lease at risk.  A bad spec must cost its own replicas and
# nothing else, so this file declares one, watches the control plane for 15 s,
# and asserts three things:
#   * the Raft term never moves on any node (a stalled loop shows as elections);
#   * a healthy cluster runtime declared before it keeps serving on every poll;
#   * a node still answers `cluster placement` promptly while its replica hangs.
# It also asserts that the hung runtime is what is reported, not silently absent,
# and that it is a cluster runtime the operator can still remove.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_raft.sh"

PASS=0; FAIL=0; TOTAL=0
T=$(mktemp -d /tmp/socketley-stall-XXXXXX)
daemon_watch "$T"   # its processes go with it if it is killed
PB=$((SL_PORT_BASE + 1800))
NODES=()
RAFT_COMPACT_EVERY=1000

echo "=== Integration: a cluster replica that hangs at startup leaves the Raft loop alone ==="

ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad()  { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL: $*"; }
check() { if eval "$1"; then ok; else bad "$2"; fi; }

cleanup() {
    set +e
    local n
    for n in "${NODES[@]}"; do
        kill -9 "$(cat "$T/$n.pid" 2>/dev/null)" 2>/dev/null
        daemon_sweep "$(sock "$n")"
    done
    if [ -n "${SOCKETLEY_KEEP_TMPD:-}" ]; then echo "  kept: $T" >&2; else rm -rf "$T"; fi
}
trap cleanup EXIT

mkdir -p "$T/www"
echo "cluster-page" >"$T/www/index.html"
# Twenty seconds of a busy loop when the worker loads the script, which is the whole of its startup.
printf 'local t = os.time() + 20\nwhile os.time() < t do end\nfunction on_client_message(id, m) end\n' >"$T/hang.lua"

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
print(d.split(b"\r\n")[0].decode("latin1") + " " + d.partition(b"\r\n\r\n")[2].decode("latin1").strip())
' "$T/$1-$2.sock" 2>/dev/null || true
}
serves() { [[ "$(probe "$1" "$2")" == "HTTP/1.1 200 OK cluster-page"* ]]; }
count_serving() {
    local name=$1 n c=0; shift
    for n in "$@"; do serves "$name" "$n" && c=$((c+1)); done
    echo $c
}
# Whether the output of a command matches a pattern, read whole first because grep -q ends early and pipefail then blames the writer.
saw() { local pat=$1 o; shift; o=$("$@" 2>&1) || true; grep -qE -- "$pat" <<<"$o"; }
# Whether a command succeeded and its output lacks a pattern, so a CLI that failed is not read as an empty listing.
unseen() { local pat=$1 o; shift; o=$("$@" 2>&1) || return 1; ! grep -qE -- "$pat" <<<"$o"; }
terms() { local n s=""; for n in a b c; do s="$s $(field "$n" term)"; done; echo "${s# }"; }

raft_port() { case $1 in a) echo $PB;; b) echo $((PB+1));; c) echo $((PB+2));; esac; }
start_member() { local n=$1; shift; node_start "$n" --raft-listen 127.0.0.1:"$(raft_port "$n")" --raft-insecure --raft-name "$n" "$@"; }

start_member a --raft-init
start_member b --raft-join 127.0.0.1:$PB
start_member c --raft-join 127.0.0.1:$PB
formed() { [ "$(voters a)" = 3 ] && [ "$(voters b)" = 3 ] && [ "$(voters c)" = 3 ] \
           && [ -n "$(leader a)" ] && [ "$(leader a)" = "$(leader b)" ] && [ "$(leader b)" = "$(leader c)" ]; }
check 'wait_for 25 formed' "three daemons did not agree on three voters and one leader within 25 s"

# A healthy runtime first, then the one that hangs, on every node.
as a cluster create server okay --listen "unix:$T/okay-{node}.sock" --http "$T/www" --replicas 3 >/dev/null 2>&1 || true
check 'wait_for 20 "[ \$(count_serving okay a b c) = 3 ]"' "the healthy runtime did not come to serve on three nodes"
sleep 2
before=$(terms)
out=$(as a cluster create server hang --listen "unix:$T/hang-{node}.sock" --lua "$T/hang.lua" --replicas 3 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 0 ] && [ -z "$out" ]' "cluster create hang: exit $rc, output: $out"

# Fifteen seconds with three worker processes stuck in their script.
misses=0; slow=0; saw_placement=0
t0=$(date +%s)
while [ $(( $(date +%s) - t0 )) -lt 15 ]; do
    [ "$(count_serving okay a b c)" = 3 ] || misses=$((misses+1))
    s=$(date +%s%N)
    saw "^hang" as b cluster placement && saw_placement=1 || true
    [ $(( ($(date +%s%N) - s) / 1000000 )) -gt 1500 ] && slow=$((slow+1))
    sleep 0.3
done
after=$(terms)
check '[ "$before" = "$after" ]' "the Raft term moved while a replica hung: $before -> $after (a stalled loop shows as elections)"
check '[ "$misses" = 0 ]' "the healthy runtime stopped serving on $misses polls while a replica hung"
check '[ "$slow" = 0 ]' "cluster placement took more than 1.5 s on $slow polls"
check '[ "$saw_placement" -ge 1 ]' "the hung runtime is not in the placement"
check 'wait_for 5 formed' "the nodes no longer agree on one leader"
# Waited for, like every other fact about a node's view in this file: the line above only waits for the leader to be
# agreed again, and b learns what is placed on the tick after that -- so asserting it in the same breath is asserting
# that a cluster is instantaneous.  Red beside seven other files and green alone, which is how that reads from here.
listed_on_b() { saw "hang.*\[cluster\]" as b ls; }
check 'wait_for 10 listed_on_b' "the hung replica is not listed on b"

out=$(as b cluster remove hang 2>&1) && rc=0 || rc=$?
check '[ "$rc" = 0 ] && [ -z "$out" ]' "cluster remove hang: exit $rc, output: $out"
check 'wait_for 20 "unseen hang as a ls && unseen hang as b ls && unseen hang as c ls"' "the hung replica was not removed after cluster remove"
check '[ "$(count_serving okay a b c)" = 3 ]' "the healthy runtime stopped serving after the hung one was removed"

echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
