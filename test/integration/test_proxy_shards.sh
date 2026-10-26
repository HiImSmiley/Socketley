#!/usr/bin/env bash
# A shard is an implementation detail of a runtime and not a runtime, so `ls`
# shows one line, the connection count is the sum over the shards rather than
# whichever published last, stop and remove take all of them down, and start
# brings back the same number -- while `send` is not asserted because cmd_send
# refuses a proxy outright.
# ─── THE ONE THAT IS NOT ABOUT SHARDS ───────────────────────────────────────
# The parent-death guard is why this file exists, because SO_REUSEPORT lets a
# worker that outlived its daemon serve 1/N of the traffic from a build nobody
# believes is running -- tested by deliberately leaving one behind, with a
# control at one shard since that case failed there too.
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

# Every worker process of this binary, never `pgrep -f`, which also matches the
# shell carrying the string in its own arguments.
shard_pids() {
    # Scoped to this run's daemon rather than to the binary, because matching
    # the binary counts the siblings' workers the moment two files run together
    # and the failure reads as a product defect.
    for p in $(pgrep -x socketley 2>/dev/null); do
        [[ "$(readlink /proc/$p/exe 2>/dev/null)" == "$BIN" ]] || continue
        grep -qz "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" "/proc/$p/environ" 2>/dev/null || continue
        tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q 'proxy-worker' && echo "$p"
    done
}

echo "== --shards is a declaration, and one type refuses it outright =="
# A cache used to be the second absolute refusal, and what removed it was
# ownership by key hash rather than a decision to tolerate the miss -- this
# line only keeps this file honest about which types are absolute.
out=$("$BIN" create cache shc -p $P_SPARE1 --shards 4 2>&1); rc=$?
check "cache accepts --shards" "$rc" "0"
[[ "$out" != *"not available on a cache"* ]] && ok "and no longer says it cannot" \
    || bad "cache still refuses: $out"
"$BIN" remove shc >/dev/null 2>&1

out=$("$BIN" create client shk -t 127.0.0.1:$P_BACK --shards 4 2>&1); rc=$?
check "client refuses --shards" "$rc" "1"
[[ "$out" == *"not available on a client"* ]] && ok "and says why" || bad "client refusal reason: $out"

# A server used to be the third, and may now shard without --lua and still may
# not with one -- this line only keeps this file honest about which types are
# absolute.
out=$("$BIN" create server shs -p $P_SPARE2 --shards 4 2>&1); rc=$?
check "a server with no script is no longer refused" "$rc" "0"
"$BIN" remove shs >/dev/null 2>&1

out=$("$BIN" create proxy shbad -p $P_SPARE3 --backend 127.0.0.1:$P_BACK --shards 0 2>&1); rc=$?
check "--shards 0 refused" "$rc" "1"
[[ "$out" == *"invalid shard count"* ]] && ok "and says the count is invalid" || bad "--shards 0 refusal reason: $out"
out=$("$BIN" create proxy shbad -p $P_SPARE3 --backend 127.0.0.1:$P_BACK --shards 999 2>&1); rc=$?
check "--shards 999 refused" "$rc" "1"
[[ "$out" == *"must be between 1 and"* ]] && ok "and says the range" || bad "--shards 999 refusal reason: $out"
out=$("$BIN" create proxy shbad -p $P_SPARE3 --backend 127.0.0.1:$P_BACK --shards x 2>&1); rc=$?
check "--shards with a non-number refused" "$rc" "1"
[[ "$out" == *"invalid shard count"* ]] && ok "and says the count is invalid" || bad "--shards x refusal reason: $out"

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

# The oracle for the assertion above is that no single shard holds all eight,
# read from `shard_connections` rather than `connections`, which is now the
# runtime's own summed line and would fail this on a build whose shards share
# the work perfectly.
MAXSHARD=$("$BIN" stats shp 2>/dev/null | awk -F: '/^shard_connections:/ {if ($2+0>m) m=$2+0} END {print m+0}')
[[ "$MAXSHARD" -gt 0 && "$MAXSHARD" -lt 8 ]] \
    && ok "no single shard holds all 8 (busiest has $MAXSHARD) — the sum is a real sum" \
    || bad "one shard holds all 8 (busiest=$MAXSHARD); the sum assertion proves nothing this run"

wait $HOLD_PID 2>/dev/null

echo "== stop takes every shard down =="
"$BIN" stop shp >/dev/null 2>&1
sleep 1.0
n=$(shard_pids | grep -c .)
check "no worker processes after stop" "$n" "0"
n=$(ss -ltn 2>/dev/null | grep -c ":$P_PROXY ")
check "nothing bound to the port after stop" "$n" "0"

echo "== show | import is a round trip, not a quiet reset =="
# `import` used to parse the shard count and never apply it, bringing a
# four-shard proxy back with one, and it is asserted while stopped because the
# same field is refused while running.
DOC=$("$BIN" show shp 2>/dev/null)
[[ "$DOC" == *'"shards"'* ]] && ok "show emits the shard count" \
                             || bad "show dropped the shard count: $DOC"
out=$(printf '%s' "$DOC" | "$BIN" import shp 2>&1); rc=$?
check "import of a stopped sharded runtime is accepted" "$rc" "0"
"$BIN" start shp >/dev/null 2>&1
sleep 1.0
n=$(shard_pids | grep -c .)
check "four shards survive show|import" "$n" "4"

# Refused only when it would change the count, so the refusal has to be
# provoked with a different number or the assertion passes on a build that
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
# Leave one behind on purpose -- SIGSTOP so the shard cannot act on the EOF and
# SIGKILL on the daemon so nothing tidies up -- against a daemon of its own,
# since the suite's has the rest of the tests to serve.
STALE_HOME=$(mktemp -d); STALE_SOCK=/tmp/skl-stale-$$.sock
python3 "$BACKEND_PY" $P_STALEB 2 >/dev/null 2>&1 &
SBACK=$!
sleep 0.5

env HOME="$STALE_HOME" SOCKETLEY_SOCKET="$STALE_SOCK" "$BIN" daemon >/dev/null 2>&1 &
for i in $(seq 1 40); do
    env HOME="$STALE_HOME" SOCKETLEY_SOCKET="$STALE_SOCK" "$BIN" ping >/dev/null 2>&1 && break
    sleep 0.15
done
# The daemon is the one holding the socket: the ping above may have started one of its own, and the other leaves.
SD=$(ss -xlpn 2>/dev/null | grep -F "$STALE_SOCK " | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)

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
    [[ -n "$SD" ]] && kill -9 "$SD" 2>/dev/null
    for p in "${SW[@]}"; do kill -CONT $p 2>/dev/null; kill -9 $p 2>/dev/null; done
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
rm -rf "$STALE_HOME" "$STALE_SOCK" "$STALE_SOCK.lock"

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
