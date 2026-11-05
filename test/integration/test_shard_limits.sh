#!/usr/bin/env bash
# Integration test: a limit given to a sharded runtime is the runtime's, not each shard's.
#
# --max-connections, --maxmemory and --global-rate-limit are documented as the
# runtime's, and each shard enforced the whole value on its own: four shards
# admitted four times the connections, held four times the memory and took
# four times the rate.
#
#   connections  a server of four shards with --max-connections 8 keeps 8 of
#                24 clients, where each shard counting alone kept all 24
#   maxmemory    a cache of four shards with --maxmemory 4M says 4M, and holds
#                no more than that however much is written into it
#   rate         a cache of four shards with --global-rate-limit 100 takes about
#                100 writes from 16 clients in its first second, not 400
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ [[ "$2" == "$3" ]] && ok "$1 ($2)" || bad "$1: expected '$3', got '$2'"; }

daemon_isolate shardlimits
daemon_start "$BIN"

P_SRV=$((SL_PORT_BASE+1420))
P_CACHE=$((SL_PORT_BASE+1421))
P_RATE=$((SL_PORT_BASE+1422))

cleanup() {
    for n in lim4 mem4 rate4; do "$BIN" stop $n >/dev/null 2>&1 || true; done
    sleep 0.2
    for n in lim4 mem4 rate4; do "$BIN" remove $n >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

echo "== --max-connections on four shards =="
"$BIN" create server lim4 -p $P_SRV --shards 4 --max-connections 8 -s >/dev/null 2>&1
sleep 1.5
# One at a time, so each shard has published what it holds before the next arrives.
KEPT=$(python3 - "$P_SRV" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
socks = []
for _ in range(24):
    socks.append(socket.create_connection(("127.0.0.1", port), timeout=5))
    time.sleep(0.05)
time.sleep(0.5)
kept = 0
for s in socks:
    s.setblocking(False)
    try:
        kept += s.recv(1) != b""
    except BlockingIOError:
        kept += 1
    except OSError:
        pass
print(kept)
PY
)
check "four shards keep 8 of 24 clients, the runtime's limit" "$KEPT" "8"

echo "== --maxmemory on four shards =="
"$BIN" create cache mem4 -p $P_CACHE --shards 4 --maxmemory 4M --eviction allkeys-lru -s >/dev/null 2>&1
for i in $(seq 1 40); do
    python3 -c "import socket;s=socket.create_connection(('127.0.0.1',$P_CACHE),timeout=1);s.sendall(b'ping\n');s.recv(64)" 2>/dev/null && break
    sleep 0.25
done
read -r MAXMEM USED < <(python3 - "$P_CACHE" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=30)
f = s.makefile("rb")
def ask(line):
    s.sendall(line + b"\n")
    return f.readline().strip()
val = b"v" * 8192
for i in range(2000):
    s.sendall(b"set k%d %s\n" % (i, val))
for i in range(2000):
    f.readline()
print(ask(b"maxmemory").decode(), ask(b"memory").decode())
PY
)
check "the cache says the 4M it was given, not four times it" "$MAXMEM" "4194304"
[ -n "$USED" ] && [ "$USED" -le $((4194304 * 11 / 10)) ] \
    && ok "and 16 MB written into it leave it holding no more ($USED bytes)" \
    || bad "and 16 MB written into it leave it holding no more: ${USED:-no answer} bytes against 4194304"

echo "== --global-rate-limit on four shards =="
"$BIN" create cache rate4 -p $P_RATE --shards 4 --global-rate-limit 100 -s >/dev/null 2>&1
sleep 1.5
# Sixteen clients so every shard has some, sixty writes each at once: the four buckets start full at their share.
TAKEN=$(python3 - "$P_RATE" <<'PY'
import socket, sys
port = int(sys.argv[1])
socks = [socket.create_connection(("127.0.0.1", port), timeout=10) for _ in range(16)]
for i, s in enumerate(socks):
    s.sendall(b"".join(b"set r%d_%d x\n" % (i, j) for j in range(60)))
taken = 0
for s in socks:
    f = s.makefile("rb")
    for _ in range(60):
        line = f.readline().strip().lower()
        taken += line in (b"ok", b"+ok")
print(taken)
PY
)
[ -n "$TAKEN" ] && [ "$TAKEN" -ge 80 ] && [ "$TAKEN" -le 150 ] \
    && ok "the four shards take about the runtime's 100 writes at once ($TAKEN of 960)" \
    || bad "the four shards take about the runtime's 100 writes at once: ${TAKEN:-no answer} of 960"

echo
echo "shard limits: PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]]
