#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a metrics runtime's --logs, every line the daemon and its runtimes write, kept and asked with
# LogQL over Loki's API as Grafana's Loki data source asks it, and from the CLI.
#
# What each part would catch:
#   * a line of the daemon's or a worker's that never reaches the store, or reaches it twice after a restart
#   * a line of the daemon's own about a runtime not under that runtime's name
#   * a selector, a line filter or a regex filter that takes the wrong lines
#   * a metric query over lines (count_over_time, rate, sum by) that counts wrong, or an answer Grafana cannot read
#   * Grafana's health check `vector(1)+vector(1)` refused, which fails the data source
#   * logs asked of a runtime that keeps none answered as if it did
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
has() { if printf '%s' "$2" | grep -qE -- "$3"; then ok; else bad "$1" "no /$3/ in: $(printf '%s' "$2" | head -c 400)"; fi; }
hasnt() { if printf '%s' "$2" | grep -qE -- "$3"; then bad "$1" "/$3/ in: $(printf '%s' "$2" | head -c 400)"; else ok; fi; }
expect() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

echo "=== Integration: a metrics runtime keeps the logs ==="
daemon_isolate metricslogs
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 450))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"
S() { "$BIN" "$@"; }
L() { curl -s --data-urlencode "query=$2" "${@:3}" "http://127.0.0.1:$P/loki/api/v1/$1"; }

S create metrics m -p "$P" --every 1s --logs -s >/dev/null
S create metrics plain -p $((P+1)) -s >/dev/null
echo '-- fine' > "$T/s.lua"
S create server broke -p $((P+2)) --lua "$T/s.lua" -s >/dev/null
echo 'this is not lua (' > "$T/s.lua"
S stop broke >/dev/null; S start broke >/dev/null 2>&1
for _ in $(seq 1 200); do S metrics m logs '{name="broke", level="error"}' 2>/dev/null | grep -q . && break; sleep 0.1; done
sleep 1.2

# ── the lines, and the CLI ──────────────────────────────────────────────────
A=$(S metrics m logs)
has "the daemon's own lines are kept" "$A" 'daemon started'
has "a worker's stderr is kept" "$A" '\[lua broke\] script error'
B=$(S metrics m logs '{name="broke"}')
has "a line of the daemon's about a runtime is that runtime's" "$B" "\\[ERROR\\] runtime 'broke': "
hasnt "and only that runtime's" "$B" 'daemon started'
has "a level selects" "$(S metrics m logs '{level="error"}')" "runtime 'broke'"
hasnt "and leaves the others out" "$(S metrics m logs '{level="error"}')" 'daemon started'
has "a line filter" "$(S metrics m logs '{job="socketley"} |= "script error"')" 'script error'
hasnt "a negative one" "$(S metrics m logs '{name="broke"} != "script"')" 'script error'
has "a regex one, found anywhere in the line" "$(S metrics m logs '{name="broke"} |~ "exit.d unexp"')" 'exited unexpectedly'

# ── Loki's API, as Grafana asks it ──────────────────────────────────────────
R=$(L query_range '{name="broke", level="error"}')
has "query_range answers streams" "$R" '^\{"status":"success","data":\{"resultType":"streams","result":\[\{"stream":\{"instance":"[^"]+","job":"socketley","level":"error","name":"broke"\},"values":\[\["[0-9]{19}","'
has "a metric query, grouped" "$(L query 'sum by (level) (count_over_time({job="socketley"}[5m]))')" \
    '"resultType":"vector","result":\[.*\{"metric":\{"level":"error"\},"value":\[[0-9.]+,"[1-9][0-9]*"\]'
has "over a range, a matrix" "$(L query_range 'rate({name="broke"}[1m])' --data step=10)" '"resultType":"matrix".*"values":\[\['
has "Grafana's check" "$(L query 'vector(1)+vector(1)')" '"value":\[[0-9.]+,"2"\]'
has "labels" "$(curl -s "http://127.0.0.1:$P/loki/api/v1/labels")" '"data":\["instance","job","level","name"\]'
has "label values" "$(curl -s "http://127.0.0.1:$P/loki/api/v1/label/name/values")" '"broke"'
has "a query that does not parse is bad_data" "$(L query_range '{name="broke"')" '"errorType":"bad_data"'
has "lines are counted for the rules" "$(S metrics m query 'socketley_log_lines_total{name="broke",level="error"}')" ' [1-9][0-9]*$'
has "a runtime without --logs keeps none" "$(L query_range '{job="socketley"}' -o /dev/null -w '%{http_code}' --url "http://127.0.0.1:$((P+1))/loki/api/v1/query_range")" '404'

# ── a restart takes no line twice ───────────────────────────────────────────
S metrics m logs --limit 5000 > "$T/before"
S stop m >/dev/null; S start m >/dev/null
sleep 2.5
S metrics m logs --limit 5000 > "$T/after"
n=$(wc -l < "$T/before")
# Oldest first, so what was kept is the start of what is kept now, and the lines of the restart come after it.
if [ "$n" -gt 0 ] && head -n "$n" "$T/after" | cmp -s - "$T/before"; then ok
else bad "every line kept before a restart is there once after it" "$(diff "$T/before" <(head -n "$n" "$T/after") | head -5)"; fi
has "and the restart's own lines after them" "$(tail -n +$((n+1)) "$T/after")" "metrics 'm'"
has "the files are kept" "$(S metrics m stats)" '^log_files:[1-9]'

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
