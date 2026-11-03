#!/usr/bin/env bash
# Integration test: the dashboard's history, which the metrics runtime the daemon makes for it keeps.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   reading     /api/history needs a session, as the figures do
#   the points  a runtime's messages per second, its memory, and the daemon's
#               own series, in the buckets asked for, null where there is no
#               point; the range and the number of buckets are held in bounds
#   the overall the overview's memory line counts the daemon as its figure does,
#               so its last point is the figure and not 9 MB short of it
#   the store   a daemon whose dashboard signs people in is given a metrics
#               runtime, private on disk, and the page reads it
#   a restart   a daemon started again shows the points from before, once its
#               metrics runtime is back
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
for _ in $(seq 1 50); do "$BIN" ls 2>/dev/null | grep -qE '^[0-9a-f]+ +metrics +metrics .*Up' && break; sleep 0.1; done
expect "the daemon made a metrics runtime for its dashboard" "$("$BIN" ls | grep -cE '^[0-9a-f]+ +metrics +metrics .*Up')" 1
# Its samples ten seconds apart, so a rate needs two of them; traffic all through.
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
# The overview's line ends where its figure stands: the daemon's own memory is counted in both, as the tile says.
expect "the daemon's own memory is a series of its own" \
    "$(curl -s -m 10 -b "$T/jar" "$U/metrics" | awk '$1=="socketley_daemon_memory_bytes" {print ($2 > 1e6)}')" 1
for _ in $(seq 1 30); do
    ov=$(curl -s -m 10 -b "$T/jar" "$U/api/overview" | j "d['memory_bytes']")
    last=$(hist "range=60&points=12" | j "[v for v in d['rss'] if v][-1]")
    awk -v a="$ov" -v b="$last" 'BEGIN{exit !(a > 0 && (a - b) / a < 0.15 && (b - a) / a < 0.15)}' && break
    sleep 1
done
expect "and the overview's memory line ends at the memory the overview says, daemon and workers" \
    "$(awk -v a="$ov" -v b="$last" 'BEGIN{print (a > 0 && (a - b) / a < 0.15 && (b - a) / a < 0.15) ? "near" : "apart " b " of " a}')" near
expect "a runtime never seen has none" "$(hist "runtime=nope")" "{}"
expect "the buckets are held in bounds" "$(hist "runtime=st&range=60&points=3" | j "len(d['msg'])") $(hist "runtime=st&range=60&points=99999" | j "len(d['msg'])")" "10 1440"
now=$(date +%s)
expect "and the range to a year" "$(hist "runtime=st&range=99999999&points=10" | j "abs(d['from'] - ($now - 366 * 86400)) <= 2")" True
# A page that holds the buckets up to its last is sent those after it on its own grid and the two before, not the range.
h=$(hist "runtime=st&range=600&points=60")
last=$(echo "$h" | j "d['from'] + d['step'] * len(d['msg'])")
sleep 1
inc=$(hist "runtime=st&range=600&points=60&since=$last")
expect "a page's next ask is sent the buckets after its last and the two before" \
    "$(echo "$inc" | j "(d['from'] == $last - 3 * d['step'], 2 <= len(d['msg']) <= 4)")" "(True, True)"
expect "and one too old for the range the whole of it" "$(hist "runtime=st&range=600&points=60&since=1000" | j "len(d['msg'])")" 60
expect "a value is said in four figures, as many as a line shows" \
    "$(echo "$h" | j "all(float('%.4g' % v) == v for k in ('rss','in','out','msg','cpu') for v in d[k] if v is not None)")" True
# Sent gzipped to a browser that takes it.
enc=$(curl -s -m 10 -b "$T/jar" -H 'Accept-Encoding: gzip' -D - -o "$T/gz" "$U/api/history?runtime=&range=900&points=90" | tr -d '\r' | sed -n 's/^Content-Encoding: //Ip')
expect "what a page asks every two seconds is one answer" \
    "$(curl -s -m 10 -b "$T/jar" "$U/api/live" | j "(sorted(d), 'memory_bytes' in d['overview'], any(x['name'] == 'st' for x in d['runtimes']))")" \
    "(['alerts', 'overview', 'runtimes'], True, True)"
expect "the history is sent gzipped to a client that takes it" "$enc $(gzip -dc "$T/gz" | j "len(d['msg'])")" "gzip 90"

# ─── a restart ──────────────────────────────────────────────────────────────
dir=$(find "$HOME" -type d -path '*/metrics/metrics' | head -1)
expect "its store lies in the state directory, the daemon's user's alone" "$(stat -c %a "$dir" 2>/dev/null)" 700
kill "$SOCKETLEY_DPID"; wait "$SOCKETLEY_DPID" 2>/dev/null
: > "$SOCKETLEY_DLOG"
daemon_start "$BIN"
for _ in $(seq 1 50); do curl -s -o /dev/null "$U/" && break; sleep 0.1; done
curl -s -X POST -c "$T/jar" -u "$ADMIN" "$U/api/session" >/dev/null
for _ in $(seq 1 50); do [ "$(hist "runtime=st&range=120&points=12" | j "max(v or 0 for v in d['msg']) > 2" 2>/dev/null)" = True ] && break; sleep 0.1; done
expect "a daemon started again shows the points from before" "$(hist "runtime=st&range=120&points=12" | j "max(v or 0 for v in d['msg']) > 2")" True
expect "and no second metrics runtime is made" "$("$BIN" ls | grep -c ' metrics ')" 1

# A configuration file of a fresh daemon that declares its own metrics runtime gets that one, not a second made first.
daemon_stop
daemon_isolate dashhist_own
T2="$SOCKETLEY_TMPD"
M2=$((SL_PORT_BASE+1952))
mkdir -p "$T2/runtimes"
printf '[admin]\nadmin = true\n%s\n' "$ADMIN" > "$T2/creds"
cat > "$T2/runtimes/metrics.lua" <<EOF
return { type = "metrics", name = "metrics", port = $((SL_PORT_BASE+1953)), bind = "127.0.0.1", domain = { "watch" },
         logs = true, start = true }
EOF
cat > "$T2/daemon.lua" <<EOF
daemon = { metrics_port = $M2, dashboard_credentials = "$T2/creds" }
runtimes = { include "runtimes/metrics.lua" }
EOF
export SOCKETLEY_CONFIG="$T2/daemon.lua"
daemon_start "$BIN"
for _ in $(seq 1 50); do "$BIN" ls | grep -qE ' metrics .* Up ' && break; sleep 0.1; done
OWN=$("$BIN" show metrics 2>/dev/null)
expect "a metrics runtime the configuration file declares is the daemon's, as the file says" \
    "$(printf '%s' "$OWN" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("domain"), d.get("logs"))' 2>/dev/null) $("$BIN" ls | grep -c ' metrics ')" \
    "watch True 1"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
