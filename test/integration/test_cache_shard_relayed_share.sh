#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a sharded cache says how much of its shared port it relays, in `stats` and once in the log.
#
# Cluster mode is the default, so a sharded cache no longer warns at start that keys on its shared port are relayed
# to the shard that owns them -- and an ordinary client there still pays for every relay.  Each shard now counts the
# commands that arrived on the shared port and those of them that were relayed, and shard 0 says once, under load,
# when at least half were, naming the two ways out.
#
# What it would catch:
#   * no figures: four shards' shared_port_commands and relayed_commands lines are read, and their ratio is the
#     (N-1)/N random keys give at four shards
#   * a per-shard port counted as the shared one: commands sent there leave shared_port_commands where it was
#   * no line, or a line per shard or per window: exactly one, naming the cache, the per-shard ports and the switch
#   * a line about a cache that is barely used: a second one, given a handful of commands, says nothing
#   * the figures at one shard, where nothing is relayed: neither line is there
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ [[ "$2" == "$3" ]] && ok "$1 ($2)" || bad "$1: expected '$3', got '$2'"; }

echo "=== Integration: a sharded cache names what its shared port relays ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_isolate cacherelayshare
P=$((SL_PORT_BASE + 1500))        # and P+1..P+4, the shard ports
Q=$((SL_PORT_BASE + 1510))        # and Q+1..Q+4
O=$((SL_PORT_BASE + 1520))
cleanup() {
    for n in rs rq ro; do "$BIN" stop "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT
daemon_start "$BIN"
"$BIN" create cache rs -p "$P" --shards 4 --resp -s >/dev/null 2>&1 || bad "a cache of four shards is made"
"$BIN" create cache rq -p "$Q" --shards 4 --resp -s >/dev/null 2>&1 || bad "a second one is made"
"$BIN" create cache ro -p "$O" --resp -s >/dev/null 2>&1 || bad "a cache of one shard is made"

sum()   { "$BIN" stats "$1" 2>/dev/null | awk -F: -v k="$2" '$1==k {s+=$2; n++} END{print (n ? s : "none") " " n+0}'; }
said()  { grep -c "cache \"$1\": .* of the commands on its shared port named a key another shard owns" "$SOCKETLEY_DLOG" 2>/dev/null || true; }

OUT=$(python3 - "$P" "$Q" "$O" <<'PY'
import random, socket, sys, time
p, q, o = (int(x) for x in sys.argv[1:4])

def cmd(*a):
    a = [x if isinstance(x, bytes) else str(x).encode() for x in a]
    return b"*%d\r\n" % len(a) + b"".join(b"$%d\r\n%s\r\n" % (len(x), x) for x in a)

def ready(port):
    for _ in range(80):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1); s.sendall(cmd("PING"))
            if s.recv(64) == b"+PONG\r\n":
                s.close(); return True
        except OSError:
            pass
        time.sleep(0.25)
    return False

def replies(s, n):
    # Counts n whole replies of the shapes sent here: +OK, :n, $len and $-1.
    buf = b""; got = 0; i = 0
    while got < n:
        d = s.recv(1 << 16)
        if not d:
            raise OSError("closed")
        buf += d
        while True:
            nl = buf.find(b"\r\n", i)
            if nl < 0:
                break
            if buf[i:i+1] == b"$" and buf[i+1:i+2] != b"-":
                ln = int(buf[i+1:nl])
                if len(buf) < nl + 2 + ln + 2:
                    break
                i = nl + 2 + ln + 2
            else:
                i = nl + 2
            got += 1
    return got

print("ready", int(ready(p) and ready(q) and ready(o)))

# Six seconds of pipelined random keys over 32 connections, so shard 0 (which a connection misses 1 in 10,000 runs)
# sees several windows under load.
socks = [socket.create_connection(("127.0.0.1", p), timeout=20) for _ in range(32)]
end = time.time() + 6.5; sent = 0
while time.time() < end:
    for s in socks:
        batch = b"".join(cmd("SET", "rs:%d" % random.randrange(100000), "v") if j % 2 else
                         cmd("GET", "rs:%d" % random.randrange(100000)) for j in range(100))
        s.sendall(batch)
    for s in socks:
        replies(s, 100)
    sent += 100 * len(socks)
print("sent", sent)

# A handful on the second cache and on the one-shard cache, far below what a window under load is.
for port in (q, o):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(b"".join(cmd("SET", "k%d" % i, "v") for i in range(50))); replies(s, 50); s.close()
PY
)
echo "$OUT" | sed 's/^/    /'
check "the caches answer" "$(echo "$OUT" | awk '$1=="ready" {print $2}')" "1"

sleep 1.5   # a worker publishes its figures on an interval
read -r SHARED NS <<< "$(sum rs shared_port_commands)"
read -r RELAYED NR <<< "$(sum rs relayed_commands)"
check "every shard says what came to the shared port" "$NS" "4"
check "and what of it was relayed" "$NR" "4"
SENT=$(echo "$OUT" | awk '$1=="sent" {print $2}')
if [[ "$SHARED" =~ ^[0-9]+$ ]] && [ "$SHARED" -ge "${SENT:-1}" ]; then
    ok "the shared port's count holds every command sent ($SHARED of $SENT)"
else
    bad "the shared port's count holds every command sent ($SHARED of ${SENT:-?})"
fi
SHARE=$(awk -v r="$RELAYED" -v s="$SHARED" 'BEGIN{ if (s+0 > 0) printf "%d", 100*r/s; else print -1 }')
if [ "$SHARE" -ge 65 ] && [ "$SHARE" -le 85 ]; then
    ok "random keys over four shards are relayed three times in four ($SHARE%)"
else
    bad "random keys over four shards are relayed three times in four ($SHARE%)"
fi

# A per-shard port is a cluster-aware client's, and not counted as the shared one.
python3 - "$((P+1))" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
s.sendall(b"*1\r\n$4\r\nPING\r\n" * 200)
b = b""
while b.count(b"\r\n") < 200:
    b += s.recv(1 << 16)
PY
sleep 1.5
read -r SHARED2 _ <<< "$(sum rs shared_port_commands)"
check "two hundred commands on a per-shard port leave the shared port's count alone" "$SHARED2" "$SHARED"

check "shard 0 said it once" "$(said rs)" "1"
grep "cache \"rs\": .* of the commands on its shared port" "$SOCKETLEY_DLOG" 2>/dev/null | head -1 | sed 's/^/    /'
LINE=$(grep "cache \"rs\": .* of the commands on its shared port" "$SOCKETLEY_DLOG" 2>/dev/null | head -1)
[[ "$LINE" == *"($((P+1))..$((P+4)))"* && "$LINE" == *"SOCKETLEY_CACHE_HANDOFF"* ]] \
    && ok "naming the per-shard ports and the handoff switch" || bad "naming the per-shard ports and the handoff switch"
check "a barely used sharded cache says nothing" "$(said rq)" "0"
check "one shard has no shared-port figure" "$(sum ro shared_port_commands)" "none 0"
check "and no relayed one" "$(sum ro relayed_commands)" "none 0"

echo
echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
