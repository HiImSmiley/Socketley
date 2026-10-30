#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a metrics runtime through export, import and export --full with restore.
#
# What each part would catch:
#   * a setting `show` and an export write as seconds that create and edit then refuse (`--every 2`)
#   * show | import that leaves a metrics runtime's settings as they were
#   * an export --full of a running runtime without the samples its open chunks held, so a restore loses the last
#     hours, or one that leaves its merges held after it
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
expect() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

echo "=== Integration: a metrics runtime exported, imported and restored ==="
daemon_isolate metricsexp
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 400))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"
S() { "$BIN" "$@"; }

printf 'every=5s\n' > "$T/rules"
S create metrics m -p "$P" --every 1s --rules "$T/rules" --keep 2d --downsample 5m:30d --notify webhook -s >/dev/null
sleep 3

# ── export <dir> and --lua ───────────────────────────────────────────────────
expect "export writes the setup" "$(S export "$T/setup" >/dev/null 2>&1; echo $?)" 0
L=$(cat "$T/setup/runtimes/m.lua" 2>/dev/null)
has "with its settings" "$L" 'every = 1,'
has "and its rules file named as one to bring" "$(cat "$T/setup/config.lua")" "$T/rules"

# ── show | import ───────────────────────────────────────────────────────────
S show m | sed 's/"every": 1/"every": 3/; s/"keep": 172800/"keep": 259200/' > "$T/m.json"
expect "show | import takes a metrics runtime's settings" "$(S import m --restart < "$T/m.json" >/dev/null 2>&1; echo $?)" 0
has "every" "$(S show m)" '"every": 3,'
has "keep" "$(S show m)" '"keep": 259200,'
has "and it runs" "$(S ls)" '\bm +metrics .*Up'
S edit m --every 1s --restart >/dev/null 2>&1
sleep 3

# ── export --full of a running runtime, and restore ─────────────────────────
before=$(S metrics m query 'count_over_time(up{job="socketley"}[1h])' | grep -oE '[0-9]+$')
S export --full "$T/full.tar" >/dev/null 2>&1
expect "export --full of a running metrics runtime" "$?" 0
has "holds its head, written out for it" "$(tar tf "$T/full.tar" | grep '/metrics/m/head/.')" '\.log$'
has "and lets its maintenance go again" "$(S metrics m stats)" '^maintenance_held:0'
kill "$SOCKETLEY_DPID"; wait "$SOCKETLEY_DPID" 2>/dev/null
rm -rf "$HOME/.local/share/socketley"
S restore "$T/full.tar" >/dev/null 2>&1
expect "restore" "$?" 0
daemon_start "$BIN"
for _ in $(seq 1 50); do S ls 2>/dev/null | grep -qE '\bm +metrics .*Up' && break; sleep 0.1; done
after=$(S metrics m query 'count_over_time(up{job="socketley"}[1h])' | grep -oE '[0-9]+$')
if [ -n "$before" ] && [ -n "$after" ] && [ "$after" -ge "$before" ]; then ok
else bad "the samples before the export are back" "before $before, after $after"; fi
has "with its settings" "$(S show m)" '"rules": "'"$T"'/rules"'

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
