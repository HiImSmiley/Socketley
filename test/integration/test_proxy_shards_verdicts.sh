#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# A sharded proxy judges its backends once, not once per shard: each backend is
# probed by one shard, which the others take the verdict from, and a breaker
# one shard opens is open on all of them -- counted at the backends, which see
# one probe per interval rather than one per shard, and a broken one that is
# charged circuit_threshold failures rather than that many per shard.  The same
# for every shape of backend: one of a fixed list, one past its first 64, a
# node of a sharded backend, and a runtime an entrance routes a name to.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

daemon_isolate verdicts
daemon_start "$BIN"
P_PX=$((SL_PORT_BASE+740))
P_PX2=$((SL_PORT_BASE+741))
P_A=$((SL_PORT_BASE+742))
P_B=$((SL_PORT_BASE+743))
P_BAD=$((SL_PORT_BASE+744))
BACKEND_PY="$SOCKETLEY_TMPD/backend.py"
PIDS=()

cleanup() {
    for n in vp vb vn vs vm vh ve ve2 g1 g2; do "$BIN" stop $n >/dev/null 2>&1; "$BIN" remove $n >/dev/null 2>&1; done
    for p in "${PIDS[@]}"; do { kill -9 "$p"; wait "$p"; } 2>/dev/null; done
    daemon_stop
    rm -rf "$SOCKETLEY_TMPD"
}
trap cleanup EXIT

# One port, its accepts counted into a file: `ok` answers HTTP 200 to every
# request on the connection, `drop` closes each connection unanswered.  The
# port is listened on at every address of a comma list (127.0.0.1 if none), or
# a unix socket's path in place of the port.
cat > "$BACKEND_PY" <<'PY'
import socket, sys, selectors
port, mode, out = sys.argv[1], sys.argv[2], sys.argv[3]
sel = selectors.DefaultSelector()
if port.startswith('/'):
    s = socket.socket(socket.AF_UNIX); s.bind(port); s.listen(512); s.setblocking(False)
    sel.register(s, selectors.EVENT_READ, None)
else:
    for host in (sys.argv[4] if len(sys.argv) > 4 else '127.0.0.1').split(','):
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, int(port))); s.listen(512); s.setblocking(False)
        sel.register(s, selectors.EVENT_READ, None)
n = 0
def note():
    with open(out + '.tmp', 'w') as f: f.write(str(n))
    import os; os.replace(out + '.tmp', out)
note()
while True:
    for key, _ in sel.select():
        if key.data is None:
            try: c, _a = key.fileobj.accept()
            except OSError: continue
            n += 1; note()
            if mode == 'drop':
                c.close(); continue
            c.setblocking(False); sel.register(c, selectors.EVENT_READ, [b''])
        else:
            c = key.fileobj
            try: d = c.recv(65536)
            except OSError: d = b''
            if not d:
                sel.unregister(c); c.close(); continue
            buf = key.data[0] + d
            while b'\r\n\r\n' in buf:
                _h, buf = buf.split(b'\r\n\r\n', 1)
                try: c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')
                except OSError: break
            key.data[0] = buf
PY

backend() { python3 "$BACKEND_PY" "$1" "$2" "$SOCKETLEY_TMPD/count.${3:-$1}" "${4:-127.0.0.1}" >/dev/null 2>&1 & PIDS+=($!); }
count()   { cat "$SOCKETLEY_TMPD/count.$1" 2>/dev/null || echo 0; }

backend $P_A ok
backend $P_B ok
backend $P_BAD drop
sleep 0.5

echo "== four shards probe each backend once per interval =="
"$BIN" create proxy vp -p $P_PX --protocol tcp --backend "127.0.0.1:$P_A,127.0.0.1:$P_B" \
       --shards 4 --health-check tcp --health-interval 1 -s >/dev/null 2>&1 \
    && ok "four-shard proxy with a 1 s tcp health check started" || bad "create vp"
sleep 1.5
a0=$(count $P_A); b0=$(count $P_B)
sleep 5
a1=$(count $P_A); b1=$(count $P_B)
da=$((a1-a0)); db=$((b1-b0))
# One shard probing is 5 in 5 s, all four 20; nothing else connects to them.
[[ $da -ge 3 && $da -le 8 ]] && ok "backend A probed $da times in 5 s (one shard's sweep)" \
    || bad "backend A probed $da times in 5 s; 5 is one shard, 20 is every shard"
[[ $db -ge 3 && $db -le 8 ]] && ok "backend B probed $db times in 5 s (one shard's sweep)" \
    || bad "backend B probed $db times in 5 s; 5 is one shard, 20 is every shard"

echo "== a backend one shard finds down is down on every shard =="
{ kill -9 "${PIDS[1]}"; wait "${PIDS[1]}"; } 2>/dev/null
sleep 5
# Whichever shard each stats call reaches, it counts the dead one out.
down=0
for _ in 1 2 3 4 5 6 7 8; do
    h=$("$BIN" stats vp 2>/dev/null | awk -F': *' '/^healthy_backends:/ {print $2; exit}')
    [[ "$h" == "1" ]] && down=$((down+1))
done
[[ $down -eq 8 ]] && ok "every stats answer counts one healthy backend" \
    || bad "only $down of 8 stats answers counted B out"
"$BIN" stop vp >/dev/null 2>&1

echo "== a breaker one shard opens is open on all four =="
"$BIN" create proxy vb -p $P_PX2 --protocol http --backend "127.0.0.1:$P_A,127.0.0.1:$P_BAD" \
       --shards 4 --circuit-threshold 3 --circuit-timeout 60 --retry 1 -s >/dev/null 2>&1 \
    && ok "four-shard http proxy with a broken backend started" || bad "create vb"
sleep 1
# One request per connection, so every shard is reached, sent one after
# another so each shard has seen what came before.
python3 - "$P_PX2" > "$SOCKETLEY_TMPD/answers" 2>"$SOCKETLEY_TMPD/answers.err" <<'PY' 
import socket, sys
port = int(sys.argv[1]); good = 0
for _ in range(80):
    try:
        s = socket.create_connection(('127.0.0.1', port), 3); s.settimeout(3)
        s.sendall(b'GET /vb/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n')
        d = b''
        while True:
            r = s.recv(4096)
            if not r: break
            d += r
        good += d.startswith(b"HTTP/1.1 200")
        s.close()
    except OSError as e: print(e, file=sys.stderr)
print(good)
PY
good=$(cat "$SOCKETLEY_TMPD/answers")
[[ -s "$SOCKETLEY_TMPD/answers.err" ]] && head -3 "$SOCKETLEY_TMPD/answers.err"
nbad=$(count $P_BAD)
[[ "$good" == "80" ]] && ok "every request answered 200 through the retry" || bad "only $good of 80 answered 200"
# Three opens it on one shard; per shard it would be up to twelve.
[[ $nbad -ge 3 && $nbad -le 6 ]] && ok "the broken backend was tried $nbad times (the threshold, once)" \
    || bad "the broken backend was tried $nbad times; 3 is the threshold once, 12 is once per shard"
"$BIN" stop vb >/dev/null 2>&1

# N requests to PORT, one connection each so every shard is reached, sent one
# after another; prints how many were answered at all and how many with 200.
requests() {  # requests PORT N HOST PATH
    python3 - "$1" "$2" "$3" "${4:-/}" 2>/dev/null <<'PY'
import socket, sys
port, n, host, path = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
said = good = 0
for _ in range(n):
    try:
        s = socket.create_connection(('127.0.0.1', port), 3); s.settimeout(3)
        s.sendall(b'GET ' + path.encode() + b' HTTP/1.1\r\nHost: ' + host.encode() + b'\r\nConnection: close\r\n\r\n')
        d = b''
        while True:
            r = s.recv(4096)
            if not r: break
            d += r
        said += bool(d); good += d.startswith(b"HTTP/1.1 200")
        s.close()
    except OSError: pass
print(said, good)
PY
}

echo "== a dead node of a sharded backend is charged the threshold once =="
P_VS=$((SL_PORT_BASE+745)); P_VN=$((SL_PORT_BASE+746))
RTDIR="$SOCKETLEY_SOCKET.rt"
mkdir -p "$SOCKETLEY_TMPD/www"; echo ok > "$SOCKETLEY_TMPD/www/index.html"
"$BIN" create server vs -p $P_VS --shards 4 --http "$SOCKETLEY_TMPD/www" -s >/dev/null 2>&1
for _ in $(seq 1 40); do [[ $(ls "$RTDIR"/vs#*.sock 2>/dev/null | wc -l) -eq 4 ]] && break; sleep 0.1; done
# Node 0's path is taken over by a listener that counts each connection and
# closes it unanswered, while the shard behind it and the other three serve on.
rm -f "$RTDIR/vs#0.sock"
backend "$RTDIR/vs#0.sock" drop node0
for _ in $(seq 1 30); do [[ -S "$RTDIR/vs#0.sock" ]] && break; sleep 0.1; done
"$BIN" create proxy vn -p $P_VN --protocol tcp --backend vs --shards 4 \
       --circuit-threshold 3 --circuit-timeout 60 -s >/dev/null 2>&1 \
    && ok "four-shard tcp proxy over a four-shard server started" || bad "create vn"
sleep 1.5
read -r said _ < <(requests $P_VN 160 x)
n0=$(count node0)
[[ $said -ge 150 ]] && ok "$said of 160 connections answered by the three live nodes" \
    || bad "only $said of 160 connections were answered"
# Each proxy shard sends a quarter of its connections to node 0: per shard that
# is three failures at each of four, twelve in all.
[[ $n0 -ge 3 && $n0 -le 6 ]] && ok "the dead node was tried $n0 times (the threshold, once)" \
    || bad "the dead node was tried $n0 times; 3 is the threshold once, 12 is once per shard"
"$BIN" stop vn >/dev/null 2>&1

echo "== backends past the first 64 are judged once too =="
P_M=$((SL_PORT_BASE+747)); P_MBAD=$((SL_PORT_BASE+748)); P_VM=$((SL_PORT_BASE+749)); P_VH=$((SL_PORT_BASE+750))
# 64 good backends, one address each of 127.0.0.1-64, then two broken ones.
good_hosts=$(seq -s, -f '127.0.0.%g' 1 64)
backend $P_M ok many "$good_hosts"
backend $P_MBAD drop manybad 127.0.0.65,127.0.0.66
sleep 0.5
list=$(seq -s, -f "127.0.0.%g:$P_M" 1 64),127.0.0.65:$P_MBAD,127.0.0.66:$P_MBAD
"$BIN" create proxy vh -p $P_VH --protocol tcp --backend "$list" \
       --shards 4 --health-check tcp --health-interval 1 -s >/dev/null 2>&1 \
    && ok "four-shard proxy over 66 backends with a 1 s tcp health check started" || bad "create vh"
sleep 1.5
h0=$(count manybad); sleep 5; h1=$(count manybad)
# The two past 64, probed by one shard each: 10 in 5 s; by every shard, 40.
[[ $((h1-h0)) -ge 6 && $((h1-h0)) -le 16 ]] && ok "the two backends past 64 probed $((h1-h0)) times in 5 s" \
    || bad "the two backends past 64 probed $((h1-h0)) times in 5 s; 10 is one shard each, 40 is every shard"
"$BIN" stop vh >/dev/null 2>&1
sleep 0.5
m0=$(count manybad)
"$BIN" create proxy vm -p $P_VM --protocol http --backend "$list" \
       --shards 4 --circuit-threshold 3 --circuit-timeout 60 --retry 2 -s >/dev/null 2>&1 \
    && ok "four-shard http proxy over 66 backends started" || bad "create vm"
sleep 1
read -r _ good < <(requests $P_VM 800 x /vm/)
mb=$(( $(count manybad) - m0 ))
[[ $good -ge 795 ]] && ok "$good of 800 requests answered 200" || bad "only $good of 800 requests answered 200"
# Each shard goes round all 66 about three times, which per shard is three
# failures at each broken one: 24 in all, against 6 when they are counted once.
[[ $mb -ge 6 && $mb -le 12 ]] && ok "the two broken backends past 64 were tried $mb times (the threshold, once each)" \
    || bad "the two broken backends past 64 were tried $mb times; 6 is the threshold once each, 24 is once per shard"
"$BIN" stop vm >/dev/null 2>&1

echo "== an entrance judges the runtimes it routes a name to once =="
P_G1=$((SL_PORT_BASE+751)); P_G2=$((SL_PORT_BASE+752)); P_VE=$((SL_PORT_BASE+753))
# Two runtimes with one name: g1 serves it, g2 is never started, so its port is
# a listener that closes every connection unanswered.
"$BIN" create server g1 -p $P_G1 -g vgrp --domain svc.example.test --http "$SOCKETLEY_TMPD/www" -s >/dev/null 2>&1
"$BIN" create server g2 -p $P_G2 -g vgrp --domain svc.example.test --http "$SOCKETLEY_TMPD/www" >/dev/null 2>&1
backend $P_G2 drop g2
"$BIN" create proxy ve -p $P_VE --shards 4 --circuit-threshold 3 --circuit-timeout 60 -s >/dev/null 2>&1 \
    && ok "four-shard entrance started" || bad "create ve"
for _ in $(seq 1 40); do read -r _ good < <(requests $P_VE 1 svc.example.test); [[ $good == 1 ]] && break; sleep 0.2; done
e0=$(count g2)
read -r _ good < <(requests $P_VE 80 svc.example.test)
ng=$(( $(count g2) - e0 ))
# The request g2 was sent and closed on has no retry, since it may have been acted on.
[[ $((good + ng)) -ge 80 ]] && ok "$good of 80 requests to the name answered 200, the rest by g2's closing" \
    || bad "only $good of 80 answered 200 with g2 tried $ng times"
# The entrance takes turns between the two; per shard g2 costs three, twelve in all.
[[ $ng -le 4 ]] && ok "the runtime that closes every connection was tried $ng times (the threshold, once)" \
    || bad "the runtime that closes every connection was tried $ng times; 3 is the threshold once, 12 is once per shard"
"$BIN" stop ve >/dev/null 2>&1
P_VE2=$((SL_PORT_BASE+754))
"$BIN" create proxy ve2 -p $P_VE2 --shards 4 --health-check tcp --health-interval 1 -s >/dev/null 2>&1 \
    && ok "four-shard entrance with a 1 s tcp health check started" || bad "create ve2"
sleep 1.5
p0=$(count g2); sleep 5; p1=$(count g2)
# Probed by one shard: 5 in 5 s; by every shard, 20.
[[ $((p1-p0)) -ge 3 && $((p1-p0)) -le 8 ]] && ok "a runtime behind the entrance probed $((p1-p0)) times in 5 s" \
    || bad "a runtime behind the entrance probed $((p1-p0)) times in 5 s; 5 is one shard, 20 is every shard"

echo
echo "passed: $PASS  failed: $FAIL"
[[ $FAIL -eq 0 ]]
