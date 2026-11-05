#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a sharded cache's DBSIZE, INFO and the figures beside them are the runtime's, read from what every
# shard published, with no crossing.
#
# What it would catch:
#   * DBSIZE asking every sibling over the mesh each call, three crossings on four shards for one integer
#   * a DBSIZE on one shard missing a write another shard has already acknowledged
#   * INFO reporting the used_memory, maxmemory and keys of whichever shard holds the connection, a quarter of the
#     truth on four shards, where CONFIG GET says the runtime's
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ [[ "$2" == "$3" ]] && ok "$1 ($2)" || bad "$1: expected '$3', got '$2'"; }

echo "=== Integration: a sharded cache's figures are the runtime's ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_isolate cachefigures
P=$((SL_PORT_BASE + 1500))
trap 'daemon_stop' EXIT
daemon_start "$BIN"
"$BIN" create cache fig -p "$P" --shards 4 --resp --maxmemory 64M -s >/dev/null 2>&1 || bad "a cache of four shards is made"
for _ in $(seq 1 80); do
    python3 -c "import socket;s=socket.create_connection(('127.0.0.1',$P),timeout=1);s.sendall(b'*1\r\n\$4\r\nPING\r\n');s.recv(64)" 2>/dev/null && break
    sleep 0.25
done
crossings() { "$BIN" stats fig 2>/dev/null | awk -F: '/^mesh_direct:/ {s+=$2} /^mesh_relayed:/ {s+=$2} END{print s+0}'; }

OUT=$(python3 - "$P" <<'PY'
import socket, sys
port = int(sys.argv[1])
def cmd(*a):
    return b"*%d\r\n" % len(a) + b"".join(b"$%d\r\n%s\r\n" % (len(x), x) for x in (y if isinstance(y, bytes) else str(y).encode() for y in a))
def ask(*a):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(cmd(*a))
    b = b""
    while True:
        b += s.recv(1 << 16)
        if b.startswith(b"$") and b"\r\n" in b:
            n = int(b[1:b.index(b"\r\n")])
            if len(b) >= b.index(b"\r\n") + 2 + n + 2:
                break
        elif b.endswith(b"\r\n") and not b.startswith(b"*"):
            break
        elif b.startswith(b"*") and b.count(b"\r\n") >= 5:
            break
    s.close()
    return b
# Each on a connection of its own, so the write and the count land on shards the kernel picks apart.
behind = 0
for i in range(60):
    ask("SET", "f:%d" % i, "v" * 100)
    if ask("DBSIZE") != b":%d\r\n" % (i + 1):
        behind += 1
print("behind", behind)
infos = [dict(l.split(":", 1) for l in ask("INFO").decode().split("\r\n") if ":" in l and not l.startswith("$"))
         for _ in range(12)]
print("used", len({i["used_memory"] for i in infos}))
print("maxmemory", infos[0]["maxmemory"])
print("keys", infos[0].get("db0", ""))
print("config", ask("CONFIG", "GET", "maxmemory").split(b"\r\n")[4].decode())
PY
)
get() { printf '%s\n' "$OUT" | awk -v k="$1" '$1==k {print $2}'; }
check "a DBSIZE on any shard counts every write already answered on another" "$(get behind)" "0"
check "INFO says one used_memory whichever shard answers it" "$(get used)" "1"
check "INFO's maxmemory is the runtime's, as CONFIG GET says" "$(get maxmemory)" "$(get config)"
check "INFO's keyspace counts every shard's keys" "$(get keys)" "keys=60,expires=0,avg_ttl=0"

# The figures are published at most every stats interval, so the writes above are counted before this is read.
sleep 1.5
before=$(crossings)
python3 - "$P" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
s.sendall(b"*1\r\n$6\r\nDBSIZE\r\n" * 200)
got = b""
while got.count(b"\r\n") < 200:
    got += s.recv(1 << 16)
PY
sleep 1.5
after=$(crossings)
check "two hundred DBSIZE cross to no sibling" "$((after - before))" "0"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
