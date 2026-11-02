#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a file socketley keeps whole is written under a name of its own and never through a link left
# beside it.
#
# What each part would catch:
#   * a tunnel's agents written through a fixed "<file>.new" opened without O_EXCL and O_NOFOLLOW: a link left at that
#     name had its target overwritten with the registry
#   * a write that leaves its file beside the one it replaces
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a file kept whole is written under a name of its own ==="
daemon_isolate nolink
T=$SOCKETLEY_TMPD
PE=$((SL_PORT_BASE + 1998))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"
"$BIN" create tunnel t --mode edge -p "$PE" -s >/dev/null 2>&1
"$BIN" tunnel t invite first --http web >/dev/null 2>&1
agents=$(find "$HOME/.local/share" -path '*tunnel/t/agents' 2>/dev/null | head -1)
if [ -z "$agents" ]; then
    echo "  FATAL: the edge kept no agents file: $(find "$HOME" -path '*tunnel*' | head -5)"
    echo "=== Results: 0 passed, 1 failed ==="; exit 1
fi

# A link at the name the old writer used, pointing at a file that is someone else's.
printf 'not the registry\n' > "$T/victim"
ln -s "$T/victim" "$agents.new"
"$BIN" tunnel t invite second --http other >/dev/null 2>&1
if [ "$(cat "$T/victim")" = "not the registry" ]; then ok
else bad "a link beside the agents file is not written through" "its target now holds: $(head -c 80 "$T/victim")"; fi
grep -q second "$agents" && ok || bad "and the agents file has the new agent" "$(cat "$agents")"
rm -f "$agents.new"

# Nothing is left beside them that a crash did not leave.
left=$(find "$(dirname "$agents")" -name '*.tmp' -o -name '*.new' | wc -l)
[ "$left" = 0 ] && ok || bad "and no file is left beside them" "$(find "$(dirname "$agents")" -name '*.tmp' -o -name '*.new')"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
