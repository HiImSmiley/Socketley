#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# A sharded proxy judges its backends once, not once per shard: each backend is
# probed by one shard, which the others take the verdict from, and a breaker
# one shard opens is open on all of them -- counted at the backends, which see
# one probe per interval rather than one per shard, and a broken one that is
# charged circuit_threshold failures rather than that many per shard.
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
    for n in vp vb; do "$BIN" stop $n >/dev/null 2>&1; "$BIN" remove $n >/dev/null 2>&1; done
    for p in "${PIDS[@]}"; do { kill -9 "$p"; wait "$p"; } 2>/dev/null; done
    daemon_stop
    rm -rf "$SOCKETLEY_TMPD"
}
trap cleanup EXIT

# One port, its accepts counted into a file: `ok` answers HTTP 200 to every
# request on the connection, `drop` closes each connection unanswered.
cat > "$BACKEND_PY" <<'PY'
import socket, sys, selectors
port, mode, out = int(sys.argv[1]), sys.argv[2], sys.argv[3]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', port)); s.listen(512); s.setblocking(False)
sel = selectors.DefaultSelector(); sel.register(s, selectors.EVENT_READ, None)
n = 0
def note():
    with open(out + '.tmp', 'w') as f: f.write(str(n))
    import os; os.replace(out + '.tmp', out)
note()
while True:
    for key, _ in sel.select():
        if key.data is None:
            try: c, _a = s.accept()
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

backend() { python3 "$BACKEND_PY" "$1" "$2" "$SOCKETLEY_TMPD/count.$1" >/dev/null 2>&1 & PIDS+=($!); }
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

echo
echo "passed: $PASS  failed: $FAIL"
[[ $FAIL -eq 0 ]]
