#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: storage keeps a large object's file open between GETs, and lets go of it when the object changes.
#
# What each part would catch:
#   * a kept file answered after a PUT replaced the object or a DELETE removed it: the old bytes, or a 200 for nothing
#   * a deleted or replaced object's file still held open by the worker, so its disk space never comes back
#   * a GET whose head went at once losing the body behind it, on a connection kept alive for a second GET
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: storage keeps a large object's file open, and lets go of it when the object changes ==="
daemon_isolate stgkept
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1956))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"
"$BIN" create storage objs -p "$P" --dir "$T/d" --anonymous -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 0.1; done
B="http://127.0.0.1:$P/bkt"
curl -s -X PUT "$B" >/dev/null
U="$B/o.bin"
head -c 300000 /dev/urandom > "$T/v1"; curl -s -X PUT --data-binary @"$T/v1" "$U" >/dev/null

# Two GETs on one connection: the second is answered from the kept file.
curl -s -m 10 -o "$T/g1" "$U" -o "$T/g2" "$U"
if cmp -s "$T/g1" "$T/v1" && cmp -s "$T/g2" "$T/v1"; then ok
else bad "an object is sent, and again from its kept file on the same connection" "bytes differ"; fi

head -c 300000 /dev/urandom > "$T/v2"; curl -s -X PUT --data-binary @"$T/v2" "$U" >/dev/null
curl -s -m 10 -o "$T/g3" "$U"
cmp -s "$T/g3" "$T/v2" && ok || bad "an object replaced by a PUT is the new one" \
    "$(cmp -s "$T/g3" "$T/v1" && echo 'the old bytes' || echo 'other bytes')"

pid=$(ss -ltnpH "( sport = :$P )" | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
gone_open() { find "/proc/$pid/fd" -maxdepth 1 -lname "$T/d/*(deleted)" 2>/dev/null | wc -l; }
curl -s -m 10 -o /dev/null "$U"
curl -s -X DELETE "$U" >/dev/null
code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' "$U")
if [ "$code" = 404 ]; then ok; else bad "a deleted object is gone" "got $code"; fi
if [ -n "$pid" ] && [ "$(gone_open)" = 0 ]; then ok
else bad "no file of a replaced or deleted object stays open in the worker" "pid '${pid:-none}', $(gone_open) held"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
