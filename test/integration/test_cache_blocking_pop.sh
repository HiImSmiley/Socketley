#!/usr/bin/env bash
# Integration test: BLPOP and BRPOP -- the one command here that answers on a
# later turn than the one it arrived on.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
#   THE LOST WAITER.  wake_one_waiter() took the client off the list and THEN
#   tried the pop.  The caller loops while it returns true, so the second call
#   picked the next waiter, removed it, found the list already empty and
#   answered false -- and that client waited out its whole timeout for an
#   element that had been pushed for it.  Measured as two of three clients
#   served.  Three waiters and three pushes is the smallest case that shows it;
#   one waiter and one push passes on the broken code.
#
#   THE REPLY THAT NEVER LEFT.  pump() parses and routes; moving replies into
#   the write queue is flush_responses()'s job.  Without it the command
#   pipelined behind a BLPOP was executed and its answer sat in a buffer
#   nothing drained -- the client had its BLPOP reply and then silence.
#
#   THE DANGLING WAITER.  A parked entry holds a DESCRIPTOR and not a pointer,
#   the way the subscriber set does, and is dropped in close_client() beside
#   unsubscribe_all().  A client that disconnects while blocked and a push that
#   arrives afterwards is the case that would use it.
#
#   AND THE ORDER.  Redis serves the longest-waiting client first.  A worker
#   pool that served its newest member would starve the one that has been idle
#   longest -- which is the member most likely to be healthy.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: a pop that waits for its element ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local l; for l in "${@:3}"; do echo "        $l"; done; }

P=$((SL_PORT_BASE+1441))
PS=$((SL_PORT_BASE+1443))
daemon_isolate cacheblpop
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"
"$BIN" create cache bp_c -p "$P" -s >/dev/null 2>&1
sleep 1.5

PY=$SOCKETLEY_TMPD/bp.py
cat > "$PY" <<'PYEOF'
import socket, sys, time, threading, json

def enc(cmd):
    p = ('*%d\r\n' % len(cmd)).encode()
    for a in cmd: p += ('$%d\r\n%s\r\n' % (len(a), a)).encode()
    return p

def once(port, cmds, wait=3.0, until=None):
    s = socket.create_connection(('127.0.0.1', port), timeout=wait + 2)
    for c in cmds: s.sendall(enc(c))
    s.settimeout(wait); out = b''
    try:
        while True:
            b = s.recv(65536)
            if not b: break
            out += b
            if until and until.encode() in out: break
            if not until and out.endswith(b'\r\n'): break
    except socket.timeout: pass
    s.close(); return out.decode('latin1')

mode, port = sys.argv[1], int(sys.argv[2])

if mode == 'fifo':
    # Three waiters, staggered so their arrival order is unambiguous, then
    # three pushes.  Each waiter reports what it got and in which slot.
    got = [None, None, None]
    def w(i):
        got[i] = once(port, [['BLPOP', 'f', '5']], wait=6.0)
    ts = []
    for i in range(3):
        t = threading.Thread(target=w, args=(i,)); t.start(); ts.append(t); time.sleep(0.25)
    time.sleep(0.4)
    for v in ('erst', 'zweit', 'dritt'):
        once(port, [['RPUSH', 'f', v]]); time.sleep(0.15)
    for t in ts: t.join()
    print(json.dumps(got))

elif mode == 'pipeline':
    print(json.dumps(once(port, [['BLPOP', 'pl', '1'], ['PING']], wait=4.0, until='PONG')))

elif mode == 'disconnect':
    s = socket.create_connection(('127.0.0.1', port), timeout=5)
    s.sendall(enc(['BLPOP', 'dc', '0']))
    time.sleep(0.3); s.close(); time.sleep(0.3)
    print(json.dumps(once(port, [['RPUSH', 'dc', 'x'], ['LLEN', 'dc']], wait=2.0)))

elif mode == 'woken':
    got = [None]
    def w(): got[0] = once(port, [['BLPOP', 'wk', '5']], wait=6.0)
    t = threading.Thread(target=w); t.start(); time.sleep(0.5)
    once(port, [['RPUSH', 'wk', 'hallo']])
    t.join(); print(json.dumps(got[0]))

elif mode == 'timing':
    t0 = time.time(); r = once(port, [['BLPOP', 'leer', '1']], wait=4.0)
    print(json.dumps([int((time.time() - t0) * 1000), r]))
PYEOF
py() { python3 "$PY" "$1" "${2:-$P}" 2>/dev/null; }

echo "--- 1. a list with something in it does not wait at all ---"
python3 "$PY" woken "$P" >/dev/null 2>&1 || true
got=$(python3 - "$P" <<'X'
import socket, sys
port=int(sys.argv[1])
def enc(c):
    p=('*%d\r\n'%len(c)).encode()
    for a in c: p+=('$%d\r\n%s\r\n'%(len(a),a)).encode()
    return p
s=socket.create_connection(('127.0.0.1',port),timeout=5)
s.sendall(enc(['DEL','q'])+enc(['RPUSH','q','a','b'])+enc(['BLPOP','q','0'])+enc(['BRPOP','q','0']))
s.settimeout(2); out=b''
try:
    while True:
        b=s.recv(65536)
        if not b: break
        out+=b
        if out.count(b'\r\n')>=10: break
except socket.timeout: pass
s.close(); print(out.decode('latin1').replace('\r\n',' | '))
X
)
case "$got" in *"q | "*a*) ok "blpop took the head without blocking" ;;
               *) bad "immediate" "no immediate reply" "got: $got" ;; esac
case "$got" in *b*) ok "brpop took the tail" ;; *) bad "brpop" "got: $got" ;; esac

echo "--- 2. an empty list waits, and answers nil when the time is up ---"
read -r ms rest <<<"$(py timing | python3 -c 'import json,sys; a=json.load(sys.stdin); print(a[0], json.dumps(a[1]))')"
[ "${ms:-0}" -ge 900 ] && [ "${ms:-0}" -lt 3000 ] \
    && ok "waited its timeout and no longer (${ms}ms)" \
    || bad "timeout" "waited ${ms}ms for a 1s timeout"
case "$rest" in *'*-1'*) ok "and answered a nil array" ;;
                *) bad "timeout" "did not answer nil" "got: $rest" ;; esac

echo "--- 3. a push wakes the waiter ---"
got=$(py woken)
case "$got" in *wk*hallo*) ok "the waiting client got the pushed element" ;;
               *) bad "woken" "got: $got" ;; esac

echo "--- 4. three waiters, three pushes, longest-waiting first ---"
# The case that catches the lost waiter: one waiter and one push passes even
# when the second is dropped on the floor.
got=$(py fifo)
n=$(printf '%s' "$got" | grep -o 'erst\|zweit\|dritt' | sort -u | wc -l)
[ "$n" -eq 3 ] && ok "all three waiters were served" \
               || bad "fifo" "only $n of 3 elements reached a waiter" "got: $got"
case "$got" in *erst*zweit*dritt*) ok "and in arrival order" ;;
               *) bad "fifo" "order was not arrival order" "got: $got" ;; esac

echo "--- 5. what was pipelined behind the BLPOP still gets its answer ---"
got=$(py pipeline)
case "$got" in *PONG*) ok "the command behind a blocked pop is answered" ;;
               *) bad "pipeline" "the PING never came back" "got: $got" ;; esac
case "$got" in *'*-1'*PONG*) ok "and in that order, not before it" ;;
               *) bad "pipeline" "order wrong" "got: $got" ;; esac

echo "--- 6. a client that leaves while blocked leaves nothing behind ---"
got=$(py disconnect)
case "$got" in *':1'*) ok "the push after the disconnect is served normally" ;;
               *) bad "disconnect" "got: $got" ;; esac
# The element must still be there: the waiter was gone, so nobody took it.
# RPUSH answers 1 and LLEN answers 1 -- two integers, and the second is the
# assertion.  The raw reply is compared, so the separator is \r\n and not the
# rendered form the other checks use.
case "$got" in *':1'*':1'*) ok "and the element stayed in the list" ;;
               *) bad "disconnect" "the element went somewhere" "got: $got" ;; esac

echo "--- 6b. a cross-runtime request has no connection to wait on ---"
# A blocking pop parks a waiter on a CONNECTION and answers it when a push
# arrives.  A request that crosses from another runtime is served on the cache's
# scratch connection, which has no descriptor, and the ticket it belongs to is
# answered and gone long before any push could wake it.
#
# Measured before this was refused: `socketley <cache> blpop key 0` answered
# NOTHING and exited 0, which reads exactly like "the list was empty" -- and at
# timeout 0 the waiter and its 100 ms timer stayed behind for good.
RC=0
OUT=$(timeout 10 "$BIN" bp_c blpop bp_nosuch 0 2>&1) || RC=$?
if [ "$RC" -ne 0 ]; then ok "a blocking pop over a crossing is refused"
else bad "crossing" "it answered '$OUT' and exited 0, which is what an empty list looks like"; fi
case "$OUT" in *"connection to wait on"*) ok "and says what is missing" ;;
    *) bad "crossing" "the refusal does not name the reason" "got: $OUT" ;; esac

# The pairing that keeps this honest is already section 3 above -- a push wakes
# a waiting client -- and it runs on the same cache, so refusing every blpop
# would turn it red.  A second, worse-built copy of it here would only be one
# more thing to get wrong.

echo "--- 7. sharded is refused by name ---"
"$BIN" create cache bp_s -p "$PS" --shards 4 --cluster -s >/dev/null 2>&1
for _ in $(seq 1 80); do
    [ "$(ss -ltn 2>/dev/null | awk -v a=$((PS+1)) -v d=$((PS+4)) -F: '{n=$NF+0; if(n>=a&&n<=d) c++} END{print c+0}')" -ge 4 ] && break
    sleep 0.2
done
got=$(python3 - "$PS" <<'X'
import socket, sys
port=int(sys.argv[1])
def enc(c):
    p=('*%d\r\n'%len(c)).encode()
    for a in c: p+=('$%d\r\n%s\r\n'%(len(a),a)).encode()
    return p
s=socket.create_connection(('127.0.0.1',port),timeout=5)
s.sendall(enc(['BLPOP','q','0'])); s.settimeout(3)
try: print(s.recv(4096).decode('latin1'))
except socket.timeout: print('TIMED OUT -- it blocked instead of refusing')
s.close()
X
)
case "$got" in *"sharded cache"*) ok "refused, naming the reason" ;;
               *) bad "sharded" "wrong answer" "got: $got" ;; esac

echo ""
echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && { echo "  OK"; exit 0; } || exit 1
