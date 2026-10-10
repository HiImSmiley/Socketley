#!/usr/bin/env bash
# Integration test: COMMAND describes the commands this cache serves.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# COMMAND answered an empty array, on the grounds that the cache kept no table
# of arity and key positions.  redis-py's RedisCluster builds its key routing
# from exactly that reply, so against an empty one it raised "command doesn't
# exist" for every command naming a key -- a user following the README's
# advice to point a cluster-aware client at a --cluster cache could connect
# and could not GET.  The table now exists, with Redis 7's values.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# Every name COMMAND LIST reports is sent, bare, on a connection of its own,
# and none may come back "unknown command" -- so the table cannot claim a
# command the cache does not serve.  The key positions a router reads are
# checked on the shapes that differ: one key, every key, every other key.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate cmdtable

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1))
        if [ "$1" = "$2" ]; then PASS=$((PASS+1)); echo "  PASS: $3"
        else FAIL=$((FAIL+1)); echo "  FAIL [$3]: got '$1', want '$2'"; fi; }
cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: COMMAND describes what the cache serves ==="
command -v redis-cli >/dev/null 2>&1 || { echo "  FAIL: redis-cli required"; exit 1; }
daemon_start "$BIN"
P=$((SL_PORT_BASE + 1900))
"$BIN" create cache ct -p "$P" -s >/dev/null 2>&1
for _ in $(seq 1 100); do redis-cli -p "$P" ping 2>/dev/null | grep -q PONG && break; sleep 0.1; done

N=$(redis-cli -p "$P" command count 2>/dev/null)
ok "$([ "${N:-0}" -gt 100 ] 2>/dev/null && echo many || echo "$N")" "many" "COMMAND COUNT names the table (${N:-0})"

info() { redis-cli -p "$P" command info "$1" 2>/dev/null | tr '\n' ' ' | sed 's/ $//'; }
case "$(info get)" in "get 2 readonly fast 1 1 1") ok y y "GET: arity 2, one key at 1" ;;
    *) ok "$(info get)" "get 2 readonly fast 1 1 1" "COMMAND INFO get" ;; esac
case "$(info mset)" in "mset -3 write denyoom 1 -1 2") ok y y "MSET: every other argument is a key" ;;
    *) ok "$(info mset)" "mset -3 write denyoom 1 -1 2" "COMMAND INFO mset" ;; esac
case "$(info del)" in "del -2 write 1 -1 1") ok y y "DEL: every argument is a key" ;;
    *) ok "$(info del)" "del -2 write 1 -1 1" "COMMAND INFO del" ;; esac

UNKNOWN=$(python3 - "$P" "$(redis-cli -p "$P" command list 2>/dev/null | tr '\n' ' ')" <<'PYEOF'
import socket, sys
port, names = int(sys.argv[1]), sys.argv[2].split()
bad = []
for n in names:
    s = socket.create_connection(("127.0.0.1", port), timeout=2)
    s.sendall(b"*1\r\n$%d\r\n%s\r\n" % (len(n), n.encode()))
    try:
        r = s.recv(4096)
    except socket.timeout:
        r = b""
    if b"unknown command" in r:
        bad.append(n)
    s.close()
# An empty or short list probes nothing, so it is not a clean result.
print(" ".join(bad) if bad else ("none" if len(names) > 100 else "only %d names listed" % len(names)))
PYEOF
)
ok "$UNKNOWN" "none" "every command COMMAND lists is one the cache serves"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
