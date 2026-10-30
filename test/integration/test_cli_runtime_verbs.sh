#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: `socketley <runtime> <verb> ...`, whatever belongs to one runtime said with its name first, and the
# older forms answering the same.
#
# What each part would catch:
#   * a verb read against the wrong type, or put to the command it stands for with its words in the wrong place
#   * an older form (db-query, mqtt-sessions, metrics <rt> query, mqtt-passwd) that no longer answers as the new one does
#   * a runtime named as its type's command (metrics) not reached by its verbs
#   * the lifecycle not reachable by a runtime's name, or a verb of no type taken silently
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
has() { if printf '%s' "$2" | grep -qE -- "$3"; then ok; else bad "$1" "no /$3/ in: $(printf '%s' "$2" | head -c 300)"; fi; }
expect() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }
same() { if [ "$2" = "$3" ] && [ -n "$2" ]; then ok; else bad "$1" "new '$(printf '%s' "$2" | head -c 200)' old '$(printf '%s' "$3" | head -c 200)'"; fi; }

echo "=== Integration: a runtime's verbs after its name ==="
daemon_isolate cliverbs
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 500))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"
S() { "$BIN" "$@"; }

printf 'backend dbbackendsecret0123456789\n' > "$T/keys"; chmod 600 "$T/keys"
S create cache kv -p "$P" -s >/dev/null
S create db shop -p $((P+1)) --keys "$T/keys" -s >/dev/null
S create mqtt broker -p $((P+2)) --anonymous -s >/dev/null
S create metrics m -p $((P+3)) --every 1s -s >/dev/null
S create metrics metrics -p $((P+4)) --every 1s -s >/dev/null
S create server web -p $((P+5)) -s >/dev/null
sleep 2

# ── each type's verbs, and the older form beside it ─────────────────────────
S kv set greeting hello >/dev/null
expect "a cache's verb" "$(S kv get greeting)" hello
same "a db's query" "$(S shop query notes 2>&1)" "$(S db-query shop notes 2>&1)"
same "an mqtt broker's sessions" "$(S broker sessions 2>&1)" "$(S mqtt-sessions broker 2>&1)"
same "a metrics runtime's query" "$(S m query 'count(up)' 2>&1)" "$(S metrics m query 'count(up)' 2>&1)"
has "the runtime named metrics, by its verbs" "$(S metrics query 'count(up)' 2>&1)" '^[0-9]+$|^\{\} [0-9]+$'
same "and its older form" "$(S metrics targets 2>&1 | cut -f1,3)" "$(S metrics metrics targets 2>&1 | cut -f1,3)"
expect "a backup by the db's name" "$(S shop backup "$T/shop.bak" >/dev/null 2>&1; echo $?) $([ -s "$T/shop.bak" ] && echo kept)" "0 kept"

# ── the lifecycle by a runtime's name ───────────────────────────────────────
S web stop >/dev/null
has "a runtime stopped by its name first" "$(S ls)" '\bweb +server .*Stopped'
S web start >/dev/null
has "and started" "$(S ls)" '\bweb +server .*Up'
has "show" "$(S web show)" '"name": "web"'

# ── help, and what no type takes ────────────────────────────────────────────
has "help lists a type's verbs" "$(S shop help)" 'query <collection>.*|backup <file>'
has "and every runtime's" "$(S shop help)" 'start stop restart remove show stats edit'
has "a broker's help" "$(S broker help)" 'pub \[--qos'
out=$(S web frobnicate 2>&1); rc=$?
expect "a verb of no type is refused" "$rc" 1
has "and says where they are listed" "$out" 'is no verb of a server runtime; socketley web help'
has "a name nobody has is said so" "$(S nobody get x 2>&1)" 'nobody'

# ── a topic's own command ───────────────────────────────────────────────────
printf 'pw\n' | S mqtt passwd "$T/users" alice >/dev/null 2>&1
has "mqtt passwd writes the users file" "$(cat "$T/users" 2>/dev/null)" '^alice:'
printf 'pw\n' | S mqtt-passwd "$T/users2" alice >/dev/null 2>&1
has "as mqtt-passwd did" "$(cat "$T/users2" 2>/dev/null)" '^alice:'

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
