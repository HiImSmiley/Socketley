#!/usr/bin/env bash
# Integration test: --shards N on a proxy.
#
# ─── WHAT IS BEING ASSERTED, AND WHY EACH ASSERTION CAN FAIL ────────────────
#
# A shard is an implementation detail of a runtime and not a runtime, so the
# whole of the surface has to keep answering about the runtime:
#
#   ls           one line, not N.          Broken build: N lines.
#   CONN         the sum over the shards.  Broken build: whichever shard
#                                          published last — which for 8
#                                          connections over 4 shards is 1, 2 or
#                                          3, never 8.  This is the assertion
#                                          that catches apply_stats() writing
#                                          the placeholder directly again.
#   stop/remove  take all of them down.    Broken build: a port still bound by
#                                          the shards nobody stopped.
#   start        brings back the SAME       Broken build: one worker, and a
#                number.                    quarter of the throughput the
#                                           operator configured, reported by
#                                           `ls` as Up and by nothing as wrong.
#
# `send` is not asserted here and that is not an omission: cmd_send refuses a
# proxy outright ("send is only supported for server and client runtimes"), so
# there is no path from `send` to a sharded runtime to test.  The fan-out in
# deliver_to_worker() is written for the day a shardable type has one.
#
# ─── THE ONE THAT IS NOT ABOUT SHARDS ───────────────────────────────────────
#
# The last case is the parent-death guard, and it is the reason this file
# exists at all: SO_REUSEPORT shares a port with whoever asks, so a worker that
# outlived its daemon goes on serving 1/N of the traffic from a build nobody
# believes is running.  It is tested the only way that means anything — by
# deliberately leaving one behind, with SIGSTOP so it cannot act on the EOF and
# SIGKILL on the daemon so nothing tidies up after it.
#
# That case FAILED before this was added, and not only with shards: with one
# worker the frozen process was still alive and still bound fifteen seconds
# later.  So the control below runs the same experiment at one shard, which is
# the shape every runtime in this tree already had.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ [[ "$2" == "$3" ]] && ok "$1 ($2)" || bad "$1: expected '$3', got '$2'"; }

daemon_isolate shards
daemon_start "$BIN"
P_PROXY=$((SL_PORT_BASE+700))
P_BACK=$((SL_PORT_BASE+701))
P_STALE=$((SL_PORT_BASE+702))
P_STALEB=$((SL_PORT_BASE+703))
P_SPARE1=$((SL_PORT_BASE+704))
P_SPARE2=$((SL_PORT_BASE+705))
P_SPARE3=$((SL_PORT_BASE+706))

# A backend that is not the bottleneck and not this tree's code: several
# processes on one SO_REUSEPORT port, so a sharded proxy in front of it is not
# measuring a single-threaded backend.
BACKEND_PY=$(mktemp)
cleanup() {
    "$BIN" stop shp   >/dev/null 2>&1 || true
    sleep 0.2
    "$BIN" remove shp >/dev/null 2>&1 || true
    [[ -n "${BACK_PID:-}"  ]] && kill -9 "$BACK_PID"  2>/dev/null
    [[ -n "${SBACK:-}"     ]] && kill -9 "$SBACK"     2>/dev/null
    [[ -n "${HOLD_PID:-}"  ]] && kill -9 "$HOLD_PID"  2>/dev/null
    rm -f "$BACKEND_PY"
    daemon_stop
}
trap cleanup EXIT
cat > "$BACKEND_PY" <<'PY'
import socket, os, sys, selectors, ctypes, signal
port = int(sys.argv[1]); procs = int(sys.argv[2])

# Every forked child asks the kernel to kill it when this parent goes.  Without
# it the children outlive the test -- the shell only knows the pid it started,
# so `kill $BACK_PID` reaps one process of several and the rest keep the
# backend port bound for the next run to trip over.  Which is the same defect,
# in miniature, that the last section of this file tests the daemon for.
_libc = ctypes.CDLL("libc.so.6", use_errno=True)
def die_with_parent():
    _libc.prctl(1, signal.SIGKILL, 0, 0, 0)     # PR_SET_PDEATHSIG
    if os.getppid() == 1:                       # already orphaned: the signal
        os._exit(0)                             # will never come

def serve():
    s = socket.socket(); s.setblocking(False)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(('', port)); s.listen(1024)
    sel = selectors.DefaultSelector(); sel.register(s, selectors.EVENT_READ, None)
    while True:
        for key, _ in sel.select():
            if key.data is None:
                try:
                    c, _a = s.accept(); c.setblocking(False)
                    sel.register(c, selectors.EVENT_READ, True)
                except OSError: pass
            else:
                c = key.fileobj
                try:
                    d = c.recv(65536)
                    if not d: sel.unregister(c); c.close(); continue
                    c.sendall(d)
                except OSError:
                    try: sel.unregister(c); c.close()
                    except Exception: pass
for _ in range(procs - 1):
    if os.fork() == 0:
        die_with_parent()
        serve(); os._exit(0)
serve()
PY

# Every worker process of THIS binary.  Never `pgrep -f`: -f matches the whole
# command line, so it also matches the shell carrying the string in its own
# arguments -- including the one doing the matching.
shard_pids() {
    for p in $(pgrep -x socketley 2>/dev/null); do
        [[ "$(readlink /proc/$p/exe 2>/dev/null)" == "$BIN" ]] || continue
        tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q 'proxy-worker' && echo "$p"
    done
}

echo "== --shards is a declaration, and two types refuse it outright =="
out=$("$BIN" create cache shc -p $P_SPARE1 --shards 4 2>&1); rc=$?
check "cache refuses --shards" "$rc" "1"
[[ "$out" == *"not available on a cache"* ]] && ok "cache says why" || bad "cache reason: $out"

out=$("$BIN" create client shk -t 127.0.0.1:$P_BACK --shards 4 2>&1); rc=$?
check "client refuses --shards" "$rc" "1"

# A server used to be the third.  It is not any more: with no --lua it has no
# cross-connection state to lose and may shard, and with one it still may not.
# The whole of that rule and its five doors are test_server_shards.sh; this is
# the one line that keeps THIS file honest about which types are absolute.
out=$("$BIN" create server shs -p $P_SPARE2 --shards 4 2>&1); rc=$?
check "a server with no script is no longer refused" "$rc" "0"
"$BIN" remove shs >/dev/null 2>&1

out=$("$BIN" create proxy shbad -p $P_SPARE3 --backend 127.0.0.1:$P_BACK --shards 0 2>&1); rc=$?
check "--shards 0 refused" "$rc" "1"
out=$("$BIN" create proxy shbad -p $P_SPARE3 --backend 127.0.0.1:$P_BACK --shards 999 2>&1); rc=$?
check "--shards 999 refused" "$rc" "1"
out=$("$BIN" create proxy shbad -p $P_SPARE3 --backend 127.0.0.1:$P_BACK --shards x 2>&1); rc=$?
check "--shards with a non-number refused" "$rc" "1"

echo "== four shards, one runtime =="
python3 "$BACKEND_PY" $P_BACK 4 >/dev/null 2>&1 &
BACK_PID=$!
sleep 0.6

"$BIN" create proxy shp -p $P_PROXY --protocol tcp \
       --backend 127.0.0.1:$P_BACK --shards 4 -s >/dev/null 2>&1
rc=$?
check "create -s with --shards 4" "$rc" "0"
sleep 0.5

n=$(shard_pids | grep -c .)
check "four worker processes" "$n" "4"

n=$("$BIN" ls 2>/dev/null | grep -c '^[0-9a-f]\{6\} *shp ')
check "ls shows ONE entry for a sharded runtime" "$n" "1"

n=$(ss -ltn 2>/dev/null | grep -c ":$P_PROXY ")
check "four listeners share the port" "$n" "4"

echo "== the connection count is the sum, not the last shard to publish =="
# Held open from a background python so the count is non-zero while it is read.
python3 - "$P_PROXY" <<'PY' &
import socket, sys, time
port = int(sys.argv[1])
socks = []
for _ in range(8):
    s = socket.create_connection(('127.0.0.1', port), 5); s.settimeout(5)
    s.sendall(b'x'); s.recv(64)          # force the backend leg to exist too
    socks.append(s)
time.sleep(6)
PY
HOLD_PID=$!
sleep 2.0
CONN=$("$BIN" ls 2>/dev/null | awk '$2=="shp" {print $5}')
check "CONN is the sum over shards" "$CONN" "8"

# The oracle for the assertion above: no single shard is holding all eight, so
# a build that reports one shard's figure cannot report 8 by accident.  Without
# this the assertion could pass on a broken build that happened to put every
# connection on one shard.
MAXSHARD=$("$BIN" stats shp 2>/dev/null | awk -F: '/^connections:/ {if ($2+0>m) m=$2+0} END {print m+0}')
[[ "$MAXSHARD" -lt 8 ]] \
    && ok "no single shard holds all 8 (busiest has $MAXSHARD) — the sum is a real sum" \
    || bad "one shard holds all 8; the sum assertion proves nothing this run"

wait $HOLD_PID 2>/dev/null

echo "== stop takes every shard down =="
"$BIN" stop shp >/dev/null 2>&1
sleep 1.0
n=$(shard_pids | grep -c .)
check "no worker processes after stop" "$n" "0"
n=$(ss -ltn 2>/dev/null | grep -c ":$P_PROXY ")
check "nothing bound to the port after stop" "$n" "0"

echo "== show | import is a round trip, not a quiet reset =="
# `show` emits shards and `import` used to parse it and never apply it, so a
# round trip brought a four-shard proxy back with one -- Up in `ls`, and wrong
# nowhere.  Asserted while STOPPED, because the same field is refused while
# running; both halves are checked.
DOC=$("$BIN" show shp 2>/dev/null)
[[ "$DOC" == *'"shards"'* ]] && ok "show emits the shard count" \
                             || bad "show dropped the shard count: $DOC"
out=$(printf '%s' "$DOC" | "$BIN" import shp 2>&1); rc=$?
check "import of a stopped sharded runtime is accepted" "$rc" "0"
"$BIN" start shp >/dev/null 2>&1
sleep 1.0
n=$(shard_pids | grep -c .)
check "four shards survive show|import" "$n" "4"

# Refused only when it would CHANGE the count: re-importing the same document
# into a running runtime asks for nothing and is allowed, which is what makes
# the round trip above legal in the first place.  So the refusal has to be
# provoked with a different number, or the assertion passes on a build that
# refuses nothing.
out=$(printf '%s' "$DOC" | "$BIN" import shp 2>&1); rc=$?
check "an unchanged import is accepted while running" "$rc" "0"

CHANGED=$(printf '%s' "$DOC" | sed 's/"shards"[[:space:]]*:[[:space:]]*4/"shards": 2/')
[[ "$CHANGED" != "$DOC" ]] && ok "the probe document really differs" \
                           || bad "could not rewrite shards in the document"
out=$(printf '%s' "$CHANGED" | "$BIN" import shp 2>&1); rc=$?
[[ $rc -ne 0 && "$out" == *"shard count while running"* ]] \
    && ok "changing the shard count is refused while running" \
    || bad "running shard change: rc=$rc out=$out"
n=$(shard_pids | grep -c .)
check "the refused import changed nothing" "$n" "4"

"$BIN" stop shp >/dev/null 2>&1
sleep 0.8

echo "== the shard count survives a restart =="
"$BIN" start shp >/dev/null 2>&1
sleep 1.0
n=$(shard_pids | grep -c .)
check "four shards again after start" "$n" "4"

"$BIN" remove shp >/dev/null 2>&1
sleep 1.0
n=$(shard_pids | grep -c .)
check "no worker processes after remove" "$n" "0"

kill -9 $BACK_PID 2>/dev/null

echo "== a shard proves it belongs to the current daemon =="
# The whole point, and the only way to test it that means anything: leave one
# behind on purpose.  SIGSTOP so the shard cannot act on the EOF its control
# socket is about to get, then SIGKILL the daemon so nothing tidies up.
#
# Run against a daemon of its own -- this kills a daemon, and the suite's
# daemon has the rest of the tests to serve.
STALE_HOME=$(mktemp -d); STALE_SOCK=/tmp/skl-stale-$$.sock
python3 "$BACKEND_PY" $P_STALEB 2 >/dev/null 2>&1 &
SBACK=$!
sleep 0.5

env HOME="$STALE_HOME" SOCKETLEY_SOCKET="$STALE_SOCK" "$BIN" daemon >/dev/null 2>&1 &
for i in $(seq 1 40); do
    env HOME="$STALE_HOME" SOCKETLEY_SOCKET="$STALE_SOCK" "$BIN" ping >/dev/null 2>&1 && break
    sleep 0.15
done
SD=$(for p in $(pgrep -x socketley 2>/dev/null); do
        [[ "$(readlink /proc/$p/exe 2>/dev/null)" == "$BIN" ]] || continue
        grep -qs "SOCKETLEY_SOCKET=$STALE_SOCK" "/proc/$p/environ" 2>/dev/null || continue
        tr '\0' ' ' < "/proc/$p/cmdline" | grep -q ' daemon' && echo "$p"
     done | head -1)

env HOME="$STALE_HOME" SOCKETLEY_SOCKET="$STALE_SOCK" "$BIN" create proxy stp \
    -p $P_STALE --protocol tcp --backend 127.0.0.1:$P_STALEB --shards 2 -s >/dev/null 2>&1
sleep 0.8

SW=($(for p in $(pgrep -x socketley 2>/dev/null); do
        [[ "$(readlink /proc/$p/exe 2>/dev/null)" == "$BIN" ]] || continue
        grep -qs "SOCKETLEY_SOCKET=$STALE_SOCK" "/proc/$p/environ" 2>/dev/null || continue
        tr '\0' ' ' < "/proc/$p/cmdline" | grep -q 'proxy-worker' && echo "$p"
      done))

if [[ ${#SW[@]} -ne 2 || -z "$SD" ]]; then
    bad "stale-shard setup: daemon='$SD' shards=${#SW[@]} (expected 2)"
else
    kill -STOP "${SW[0]}"
    kill -9 "$SD"
    for i in $(seq 1 40); do
        sleep 0.25
        left=0
        for p in "${SW[@]}"; do [[ -d /proc/$p ]] && left=$((left+1)); done
        [[ $left -eq 0 ]] && break
    done
    left=0
    for p in "${SW[@]}"; do [[ -d /proc/$p ]] && left=$((left+1)); done
    check "a frozen shard does not outlive its daemon" "$left" "0"
    n=$(ss -ltn 2>/dev/null | grep -c ":$P_STALE ")
    check "the port is free once the daemon is gone" "$n" "0"

    for p in "${SW[@]}"; do kill -CONT $p 2>/dev/null; kill -9 $p 2>/dev/null; done
fi
kill -9 $SBACK 2>/dev/null
rm -rf "$STALE_HOME" "$STALE_SOCK"

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
