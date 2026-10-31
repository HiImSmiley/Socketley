#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: the metrics runtime -- this daemon's series taken without text, targets scraped, the Prometheus
# HTTP API Grafana reads, its rules and the alerts they hand the daemon's notifier, and the dashboard reading it.
#
# What each part would catch:
#   * a local feed that misses a runtime made after the start, or a counter that moves
#   * a scrape whose series lose their job/instance, an up that stays 1 for a dead target, a series that does not end
#   * an API answer Grafana cannot read: the envelope, POST forms, label values, buildinfo, an error's errorType
#   * a guarded API that answers without a key, and a target that sends none when bearer= names one
#   * a rule that never fires, fires without a notification reaching the webhook, or is not resolved
#   * a store that forgets its series across a restart
#   * the dashboard's history and alerts no longer coming from the runtime the daemon made for it
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
has() { if printf '%s' "$2" | grep -qE -- "$3"; then ok; else bad "$1" "no /$3/ in: $(printf '%s' "$2" | head -c 400)"; fi; }
hasnt() { if printf '%s' "$2" | grep -qE -- "$3"; then bad "$1" "/$3/ in: $(printf '%s' "$2" | head -c 400)"; else ok; fi; }
expect() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }
# Polls until `cmd` prints something matching, for at most $3 tenths of a second.
until_has() { local i; for i in $(seq 1 "$3"); do eval "$1" 2>/dev/null | grep -qE -- "$2" && return 0; sleep 0.1; done; return 1; }

echo "=== Integration: the metrics runtime ==="
daemon_isolate metricsrt
T=$SOCKETLEY_TMPD
B=$((SL_PORT_BASE + 300))
PM=$((B+0)); PA=$((B+1)); PB=$((B+2)); PC=$((B+3)); PDEAD=$((B+4)); PHOOK=$((B+5)); PG=$((B+6)); PSV=$((B+7))
HOOK_PID=""
unset SOCKETLEY_CONFIG
trap '[ -n "$HOOK_PID" ] && kill "$HOOK_PID" 2>/dev/null; daemon_stop' EXIT

# A webhook that keeps every body it is sent, one a line.
python3 - "$PHOOK" "$T/hook.log" <<'PY' &
import http.server, sys
port, log = int(sys.argv[1]), sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        b = self.rfile.read(int(self.headers.get('content-length', 0)))
        open(log, 'ab').write(b.replace(b'\n', b' ') + b'\n')
        self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()
PY
HOOK_PID=$!
: > "$T/hook.log"

ADMIN="AKIAMETRICSRTADMIN00:metricsrtadminsecretmetricsrtadmin00"
printf '[admin]\nadmin = true\n%s\n' "$ADMIN" > "$T/creds"
mkdir -p "$HOME/.config/socketley"
printf 'config = {\n    metrics_port = %s,\n    dashboard_credentials = "%s",\n    alert_webhook = "http://127.0.0.1:%s/hook"\n}\n' \
    "$PM" "$T/creds" "$PHOOK" > "$HOME/.config/socketley/config.lua"
daemon_start "$BIN"
S() { "$BIN" "$@"; }

# ── the runtime the daemon makes for its dashboard ──────────────────────────
until_has 'S ls' 'socketley-metrics|metrics +metrics' 50 || true
LS=$(S ls)
has "a daemon with a dashboard is given a metrics runtime" "$LS" '\bmetrics +metrics +[0-9]+ .*Up'
DPORT=$(printf '%s\n' "$LS" | awk '$2=="metrics" && $3=="metrics" {print $4}')
[ -n "$DPORT" ] || DPORT=9090
S stop metrics >/dev/null; S remove metrics >/dev/null
kill "$SOCKETLEY_DPID"; wait "$SOCKETLEY_DPID" 2>/dev/null
daemon_start "$BIN"
hasnt "one removed is not made again at the next start" "$(S ls)" '\bmetrics +metrics'

# ── a runtime of its own, this daemon's series without text ─────────────────
S create cache c1 -p "$PC" -s >/dev/null
printf 'grafana metricsrtgrafanakeymetricsrtgr\n' > "$T/keys"; chmod 600 "$T/keys"
printf 'metricsrtscrapetoken0000000000\n' > "$T/token"; chmod 600 "$T/token"
cat > "$T/scrape" <<EOF
# a guarded one with its token, an open one, and one nothing answers
peer http://127.0.0.1:$PB/metrics every=1s
guarded http://127.0.0.1:$PA/metrics every=1s bearer=$T/grafana-token team=ops
dead http://127.0.0.1:$PDEAD/metrics every=1s
EOF
printf 'metricsrtgrafanakeymetricsrtgr\n' > "$T/grafana-token"
cat > "$T/rules" <<'EOF'
every=1s
alert CacheStopped critical keep=1s summary="cache {{ $labels.name }} stopped" description="it was asked to"
    : socketley_runtime_state{type="cache",state="stopped"} == 1
record cache_running : sum(socketley_runtime_state{type="cache",state="running"})
off TargetDown
EOF
OUT=$(S create metrics mb -p "$PB" --every 1s -s 2>&1); expect "an open metrics runtime starts" "$OUT" ""
OUT=$(S create metrics ma -p "$PA" --every 1s --keys "$T/keys" --scrape "$T/scrape" --rules "$T/rules" -s 2>&1)
expect "a guarded one with targets and rules starts" "$OUT" ""
K='Authorization: Bearer metricsrtgrafanakeymetricsrtgr'
Q() { curl -s -H "$K" "http://127.0.0.1:$PA$1"; }
F() { curl -s -H "$K" --data-urlencode "query=$2" "${@:3}" "http://127.0.0.1:$PA$1"; }

until_has 'Q "/api/v1/query?query=socketley_runtime_state%7Bname%3D%22c1%22%2Cstate%3D%22running%22%7D"' '"1"\]' 50 || true
has "a runtime's state arrives through the local feed" \
    "$(Q '/api/v1/query?query=socketley_runtime_state%7Bname%3D%22c1%22%2Cstate%3D%22running%22%7D')" \
    '"job":"socketley".*"value":\[[0-9.]+,"1"\]'
until_has 'Q "/api/v1/query?query=up%7Bjob%3D%22socketley%22%7D"' '"1"\]' 30 || true
has "the local feed has its own up" "$(Q '/api/v1/query?query=up%7Bjob%3D%22socketley%22%7D')" '"value":\[[0-9.]+,"1"\]'
for i in 1 2 3 4 5; do printf 'SET k%s v\r\n' "$i" | nc -q0 127.0.0.1 "$PC" >/dev/null 2>&1; done
until_has 'F /api/v1/query "socketley_runtime_messages_total{name=\"c1\"}"' '"[1-9][0-9]*"\]' 40 || true
has "a counter that moves is seen moving" "$(F /api/v1/query 'socketley_runtime_messages_total{name="c1"}')" '"[1-9][0-9]*"\]'
S create cache c2 -p $((B+8)) -s >/dev/null
until_has 'F /api/v1/query "socketley_runtime_state{name=\"c2\",state=\"running\"}"' '"1"\]' 30 || true
has "a runtime made after the start is in at once" "$(F /api/v1/query 'socketley_runtime_state{name="c2",state="running"}')" '"1"\]'

# ── scraping ────────────────────────────────────────────────────────────────
until_has 'Q /api/v1/targets' '"scrapePool":"guarded"[^}]*"health":"up"' 50 || true
until_has 'Q /api/v1/targets' '"scrapePool":"dead"[^}]*"health":"down"' 50 || true
TG=$(Q /api/v1/targets)
has "an open target is up" "$TG" '"scrapePool":"peer"[^}]*"health":"up"'
has "a guarded target is reached with its bearer= token" "$TG" '"scrapePool":"guarded"[^}]*"health":"up"'
has "a dead target is down, and says why" "$TG" '"scrapePool":"dead"[^}]*"lastError":"[^"]+"'
UP=$(Q '/api/v1/query?query=up')
has "a scraped series carries job and instance" "$UP" "\"instance\":\"127.0.0.1:$PB\",\"job\":\"peer\""
has "a target's own labels are added" "$UP" '"job":"guarded","team":"ops"'
has "up is 0 for the dead one" "$UP" '"job":"dead"\},"value":\[[0-9.]+,"0"\]'
has "a scraped target's own series are stored" "$(F /api/v1/query 'socketley_metrics_series{job="peer"}')" '"job":"peer"'
# A target that goes away ends its series with a staleness marker, and up turns 0.
S stop mb >/dev/null
until_has 'Q "/api/v1/query?query=up%7Bjob%3D%22peer%22%7D"' '"0"\]' 50 || true
has "a target that stops answering is down" "$(Q '/api/v1/query?query=up%7Bjob%3D%22peer%22%7D')" '"0"\]'
sleep 1.2
hasnt "its series end at once, not five minutes later" "$(F /api/v1/query 'socketley_metrics_series{job="peer"}')" '"job":"peer"'
S start mb >/dev/null

# ── the API, as Grafana calls it ────────────────────────────────────────────
expect "no key, no answer" "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PA/api/v1/labels")" 401
expect "a wrong key, no answer" \
    "$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer nope' "http://127.0.0.1:$PA/api/v1/labels")" 401
has "buildinfo says a Prometheus version Grafana takes" "$(Q /api/v1/status/buildinfo)" '"version":"2\.[0-9]+\.[0-9]+"'
has "labels" "$(Q /api/v1/labels)" '^\{"status":"success","data":\[.*"__name__".*"job"'
has "label values" "$(Q /api/v1/label/job/values)" '"dead".*"guarded".*"peer".*"socketley"'
NOW=$(date +%s)
R=$(F /api/v1/query_range 'sum(rate(socketley_runtime_messages_total[10s]))' --data "start=$((NOW-20))&end=$NOW&step=2")
has "query_range by POST form answers a matrix" "$R" '"resultType":"matrix".*"values":\[\['
has "series by match[]" "$(curl -s -H "$K" -G --data-urlencode 'match[]=up{job="dead"}' "http://127.0.0.1:$PA/api/v1/series")" \
    '"data":\[\{"__name__":"up","instance":"127.0.0.1:'"$PDEAD"'","job":"dead"\}\]'
has "metadata" "$(Q '/api/v1/metadata?metric=socketley_runtime_messages_total')" '"type":"counter"'
has "a bad query is bad_data" "$(F /api/v1/query 'sum(')" '"status":"error","errorType":"bad_data"'
expect "a bad query is a 400" "$(curl -s -o /dev/null -w '%{http_code}' -H "$K" "http://127.0.0.1:$PA/api/v1/query?query=sum(")" 400
expect "health" "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PA/-/healthy")" 200
has "its own /metrics" "$(Q /metrics)" '^# HELP socketley_metrics_series'

# ── rules, alerts and the notifier ──────────────────────────────────────────
has "a recording rule writes its series" "$(F /api/v1/query cache_running)" '"value":\[[0-9.]+,"2"\]'
has "the built-in rules are loaded with the file's" "$(Q '/api/v1/rules?type=alert')" '"name":"RuntimeFailed".*"name":"CacheStopped"'
hasnt "off leaves a built-in rule out" "$(Q /api/v1/rules)" '"name":"TargetDown"'
S stop c2 >/dev/null
until_has 'cat "$T/hook.log"' 'cache c2 stopped' 60 || true
H=$(cat "$T/hook.log")
has "a firing alert reaches the daemon's webhook" "$H" '"text":"[^"]*cache c2 stopped\\nit was asked to","state":"firing"'
has "with the alert as the dashboard reads it" "$H" '"alert":\{"id":"CacheStopped:[^"]*","level":"critical","runtime":"c2"'
has "the alert is listed" "$(S metrics ma alerts)" '^firing	CacheStopped	critical	.*name=c2'
has "and the rules are a table as targets are, its own rule firing among them" "$(S metrics ma rules)" '^alert	CacheStopped	firing	critical	'
hasnt "not the API's JSON" "$(S metrics ma rules)" '^\{"status"'
has "ALERTS is written" "$(F /api/v1/query 'ALERTS{alertname="CacheStopped"}')" '"alertstate":"firing"'
S start c2 >/dev/null
until_has 'cat "$T/hook.log"' 'cache c2 stopped -- resolved' 60 || true
has "a resolved alert is told too" "$(cat "$T/hook.log")" 'cache c2 stopped -- resolved","state":"resolved"'
has "the recent ones are kept" "$(S metrics ma alerts --recent --json)" '"recent":\[\{"at":[0-9]+,"raised":false'
echo 'alert Broken warning : sum(' >> "$T/rules"
sleep 11.5
has "a rules file that does not read keeps the rules before" "$(Q /api/v1/rules)" '"name":"CacheStopped"'
grep -q "rules before stay" "$SOCKETLEY_DLOG" && ok || bad "rules" "the refusal was not logged"

# ── the CLI, edits and refusals ─────────────────────────────────────────────
has "query" "$(S metrics ma query 'count(up)')" '^[0-9]+$|^\{\} [0-9]+'
has "targets" "$(S metrics ma targets)" '^dead	http://127.0.0.1:'"$PDEAD"'/metrics	down'
has "stats" "$(S metrics ma stats)" '^series:[1-9]'
has "--shards is refused" "$(S create metrics mx -p $((B+9)) --shards 2 2>&1)" 'not available on a metrics runtime'
has "--every past an hour is refused" "$(S create metrics my -p $((B+10)) --every 2h 2>&1)" 'from 1s to 1h'
has "--notify takes no other word" "$(S create metrics mz -p $((B+11)) --notify pager 2>&1)" '--notify'
has "an open API on the network is refused" "$(S create metrics mw -p $((B+12)) --bind 0.0.0.0 -s 2>&1)" 'guard it'
has "--every is changed at a start" "$(S edit ma --every 2s 2>&1)" '--restart'
S edit ma --every 2s --restart >/dev/null 2>&1
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PA/-/ready" && break; sleep 0.1; done
has "and kept with --restart" "$(S show ma)" '"every": 2,'
has "a start with a rules file that does not read runs the built-in rules" "$(S ls)" '\bma +metrics .*Up'
grep -q "the built-in rules run until it reads" "$SOCKETLEY_DLOG" && ok || bad "rules at start" "the fallback was not logged"

# ── max-series ──────────────────────────────────────────────────────────────
S create metrics mm -p $((B+13)) --every 1s --max-series 5 -s >/dev/null
sleep 2.5
has "past --max-series new series are refused and counted" \
    "$(curl -s "http://127.0.0.1:$((B+13))/metrics")" 'socketley_metrics_series_refused_total\{name="mm"\} [1-9]'

# ── a restart keeps what was stored ─────────────────────────────────────────
BEFORE=$(F /api/v1/query 'count(count by (__name__)({__name__=~".+"}))' | grep -oE '"[0-9]+"\]' | tr -dc 0-9)
S stop ma >/dev/null; S start ma >/dev/null
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PA/-/ready" && break; sleep 0.1; done
AFTER=$(F /api/v1/query 'count(count by (__name__)({__name__=~".+"}))' --data "time=$(( $(date +%s) - 1 ))" | grep -oE '"[0-9]+"\]' | tr -dc 0-9)
if [ -n "$BEFORE" ] && [ -n "$AFTER" ] && [ "$AFTER" -ge "$BEFORE" ]; then ok; else bad "restart" "names before $BEFORE, after $AFTER"; fi
has "a restart keeps the samples before it" \
    "$(F /api/v1/query 'count_over_time(socketley_runtime_state{name="c1",state="running"}[1m])')" '"[1-9][0-9]*"\]'

# ── remote_write and the archive ────────────────────────────────────────────
# Samples three days old, sent as a Prometheus sends them; their block is cut at once and copied to a storage runtime.
mkdir -p "$T/s3/arch"
S create storage arch -p $((B+14)) --dir "$T/s3" --access-key AKMETRICSRTARCHIVE00 \
    --secret-key metricsrtarchivesecretmetricsrtarc0 -s >/dev/null
printf 'access_key = AKMETRICSRTARCHIVE00\nsecret_key = metricsrtarchivesecretmetricsrtarc0\n' > "$T/s3cred"
chmod 600 "$T/s3cred"
has "--archive needs its credentials" "$(S create metrics mq -p $((B+16)) --archive "http://127.0.0.1:$((B+14))/arch" -s 2>&1)" \
    'archive-credentials'
S create metrics mr -p $((B+15)) --receive --archive "http://127.0.0.1:$((B+14))/arch/home" \
    --archive-credentials "$T/s3cred" -s >/dev/null
W=$(python3 - "$((B+15))" <<'PY'
import struct, sys, time, urllib.request
def varint(n):
    out = b""
    while True:
        b = n & 0x7f; n >>= 7
        if n: out += bytes([b | 0x80])
        else: return out + bytes([b])
def field(num, wt, data): return varint((num << 3) | wt) + data
def ld(num, data): return field(num, 2, varint(len(data)) + data)
ts = b"".join(ld(1, ld(1, k.encode()) + ld(2, v.encode())) for k, v in [("__name__", "far_metric"), ("job", "far")])
start = int(time.time() * 1000) - 3 * 86400 * 1000
for i in range(360):
    ts += ld(2, field(1, 1, struct.pack("<d", float(i))) + field(2, 0, varint(start + i * 10000)))
req = ld(1, ts)
# Snappy with the whole request as one literal, which every reader takes.
body = varint(len(req)) + bytes([0xFC]) + struct.pack("<I", len(req) - 1) + req
r = urllib.request.Request("http://127.0.0.1:%s/api/v1/write" % sys.argv[1], data=body, method="POST",
                           headers={"Content-Type": "application/x-protobuf", "Content-Encoding": "snappy"})
print(urllib.request.urlopen(r).status)
PY
)
expect "remote_write is taken" "$W" 204
has "and its samples stored" "$(S metrics mr query 'count_over_time(far_metric[2h] offset 2d22h)')" '\{job="far"\} [1-9][0-9]+'
expect "remote_write is refused without --receive" \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST --data x "http://127.0.0.1:$((B+13))/api/v1/write")" 404
until_has 'S metrics mr stats' '^archived_blocks:[1-9]' 120 || true
has "a finished block is copied to the archive" "$(S metrics mr stats)" 'archived_blocks:[1-9]'
has "once, and remembered" "$(cat "$(find "$HOME" -path '*metrics/mr/archived' | head -1)" 2>/dev/null)" '^(raw|s[0-9]+)_[0-9]+_[0-9]+\.blk$'

# ── the dashboard reads its history and alerts from a metrics runtime ───────
S create metrics metrics -p "$PG" --every 1s -s >/dev/null
sleep 3
curl -s -X POST -c "$T/jar" -u "$ADMIN" "http://127.0.0.1:$PM/api/session" >/dev/null
D() { curl -s -m 10 -b "$T/jar" "http://127.0.0.1:$PM$1"; }
HI=$(D '/api/history?runtime=c1&range=60&points=10')
has "the dashboard's history comes from the metrics runtime" "$HI" '^\{"from":[0-9]+,"step":6,"conn":\[.*\],"msg":\[.*"rss":\[[^]]*[0-9]'
has "the dashboard's alerts come from it too" "$(D /api/alerts)" '"active":\[.*"webhook":true,"store":"metrics"'
[ -e "$HOME/.local/share/socketley" ] && hasnt "no .history is kept any more" "$(find "$HOME/.local/share/socketley" -name .history)" '.'

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
