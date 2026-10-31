#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a runtime renamed takes along what it keeps under the state directory in its name.
#
# What each part would catch:
#   * an idp renamed losing its accounts and keys, so nobody signs in to it again
#   * a tunnel edge renamed losing its agents, which it then refuses every few seconds (found on a live edge)
#   * a metrics runtime renamed starting over with no history, or any of them leaving the old name's files behind
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

echo "=== Integration: a renamed runtime keeps its state ==="
daemon_isolate renamestate
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 600))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"
rename() {   # rename <from> <to>
    "$BIN" stop "$1" >/dev/null 2>&1
    "$BIN" show "$1" 2>/dev/null | sed "s/\"name\": \"$1\"/\"name\": \"$2\"/" > "$T/$1.json"
    "$BIN" import "$1" < "$T/$1.json" >/dev/null 2>&1
}
state_root() { find "$HOME/.local/share" -maxdepth 3 -type d -name 'runtimes*' 2>/dev/null | head -1; }

# ── an idp and its accounts ─────────────────────────────────────────────────
"$BIN" create idp auth -p "$P" --issuer "http://127.0.0.1:$P" -s >/dev/null 2>&1
for _ in $(seq 1 50); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/jwks")" = 200 ] && break; sleep 0.1; done
"$BIN" idp-user auth add alice --password alicepassword1 >/dev/null 2>&1
rename auth gate
"$BIN" start gate >/dev/null 2>&1
for _ in $(seq 1 50); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/jwks")" = 200 ] && break; sleep 0.1; done
case "$("$BIN" idp-user gate list 2>&1)" in *alice*) ok ;; *) bad "an idp renamed keeps its accounts" "$("$BIN" idp-user gate list 2>&1)" ;; esac
R=$(state_root)
expect "and nothing of it stays under the old name" "$(ls "$R/idp" 2>/dev/null | grep -c '^auth\.')" 0

# ── a tunnel edge and what it registered ────────────────────────────────────
"$BIN" create tunnel t --mode edge -p $((P+1)) -s >/dev/null 2>&1
sleep 0.5
printf 'probe\n' > "$R/tunnel/t/agents"
rename t edge
expect "a tunnel edge renamed takes its directory along" \
    "$(cat "$R/tunnel/edge/agents" 2>/dev/null) $([ -e "$R/tunnel/t" ] && echo left || echo gone)" "probe gone"

# ── a metrics runtime and its store ─────────────────────────────────────────
"$BIN" create metrics m -p $((P+2)) --every 1s -s >/dev/null 2>&1
for _ in $(seq 1 50); do [ -d "$R/metrics/m" ] && break; sleep 0.1; done
rename m watch
expect "a metrics runtime renamed takes its store along" \
    "$([ -d "$R/metrics/watch" ] && echo there) $([ -e "$R/metrics/m" ] && echo left || echo gone)" "there gone"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
