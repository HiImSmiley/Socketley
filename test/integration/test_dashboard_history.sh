#!/usr/bin/env bash
# Integration test: the dashboard's history of the last day.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   reading     /api/history needs a session, as the figures do
#   the points  a runtime's messages per second, its memory, and the daemon's
#               own series, in the buckets asked for, null where there is no
#               point; the range and the number of buckets are held in bounds
#   a restart   the points are written to the state directory, private, and a
#               daemon started again shows them before it has taken one of its
#               own -- the runtimes it restores come after its first reading
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate dashhist
T="$SOCKETLEY_TMPD"
M=$((SL_PORT_BASE+1950))
S=$((SL_PORT_BASE+1951))
trap 'daemon_stop' EXIT

echo "=== Integration: the dashboard's history ==="

ADMIN="AKIADASHHISTADMIN000:dashhistadminsecretdashhistadminsecret00"
printf '[admin]\nadmin = true\n%s\n' "$ADMIN" > "$T/creds"
cat > "$T/daemon.lua" <<EOF
daemon = { metrics_port = $M, dashboard_credentials = "$T/creds" }
EOF
export SOCKETLEY_CONFIG="$T/daemon.lua"
daemon_start "$BIN"
U="http://127.0.0.1:$M"
for _ in $(seq 1 50); do curl -s -o /dev/null "$U/" && break; sleep 0.1; done
curl -s -X POST -c "$T/jar" -u "$ADMIN" "$U/api/session" >/dev/null
hist() { curl -s -m 10 -b "$T/jar" "$U/api/history?$1"; }
# A python expression over the answer `d`.
j() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

expect "the history needs a session" "$(curl -s -o /dev/null -w '%{http_code}' "$U/api/history")" 401

"$BIN" create storage st -p "$S" --dir "$T/st" --anonymous -s >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$S/" && break; sleep 0.1; done
curl -s -o /dev/null -X PUT "http://127.0.0.1:$S/b"
# Two readings ten seconds apart make the first point; traffic all through it.
end=$((SECONDS + 23))
while [ $SECONDS -lt $end ]; do curl -s -o /dev/null "http://127.0.0.1:$S/b"; sleep 0.05; done

h=$(hist "runtime=st&range=60&points=12")
expect "a runtime's last minute comes in the buckets asked for, each of its figures" \
    "$(echo "$h" | j "sorted(k for k in d if isinstance(d[k], list) and len(d[k]) == 12)")" \
    "['conn', 'cpu', 'in', 'msg', 'out', 'rss']"
expect "with the messages it was sent, per second" "$(echo "$h" | j "max(v or 0 for v in d['msg']) > 2")" True
expect "and its memory" "$(echo "$h" | j "max(v or 0 for v in d['rss']) > 1e6")" True
expect "a bucket without a point is null, not 0" "$(echo "$h" | j "d['msg'][0]")" None
expect "the daemon's own is there too" "$(hist "range=60&points=12" | j "max(v or 0 for v in d['msg']) > 2")" True
expect "a runtime never seen has none" "$(hist "runtime=nope")" "{}"
expect "the buckets are held in bounds" "$(hist "runtime=st&range=60&points=3" | j "len(d['msg'])") $(hist "runtime=st&range=60&points=99999" | j "len(d['msg'])")" "10 1440"
now=$(date +%s)
expect "and the range to a day" "$(hist "runtime=st&range=9999999&points=10" | j "abs(d['from'] - ($now - 86400)) <= 2")" True

# ─── a restart ──────────────────────────────────────────────────────────────
kill "$SOCKETLEY_DPID"; wait "$SOCKETLEY_DPID" 2>/dev/null
file=$(find "$HOME" -name .history -type f | head -1)
expect "the points are written to the state directory when the daemon stops" "$([ -s "$file" ] && echo yes)" yes
expect "readable by the daemon's user alone" "$(stat -c %a "$file" 2>/dev/null)" 600
: > "$SOCKETLEY_DLOG"
daemon_start "$BIN"
for _ in $(seq 1 50); do curl -s -o /dev/null "$U/" && break; sleep 0.1; done
curl -s -X POST -c "$T/jar" -u "$ADMIN" "$U/api/session" >/dev/null
expect "a daemon started again shows them at once" "$(hist "runtime=st&range=120&points=12" | j "max(v or 0 for v in d['msg']) > 2")" True
sleep 1
expect "and keeps them past its first reading, taken before its runtimes are back" \
    "$(hist "runtime=st&range=120&points=12" | j "max(v or 0 for v in d['msg']) > 2")" True

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
