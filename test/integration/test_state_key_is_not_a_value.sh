#!/usr/bin/env bash
# Integration test: a runtime whose NAME spells a config field keeps its own
# settings across a daemon restart.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# The state file is read back with json_get_string(), which found a key by
# scanning for the quoted token and then taking `json.find(':', after_key)` --
# the next colon anywhere ahead.  format_json_pretty writes "name" first, so a
# client named `target` produced:
#
#     {
#         "name": "target",        <- the VALUE matches the key being sought
#         "id": "174b8a",          <- and this colon is the one find() returns
#         ...
#         "target": "127.0.0.1:22662",
#
# and restored with its target set to its own id.  Two sibling scanners in the
# same file, json_has_key() and json_collect_keys(), each require the colon to
# follow immediately and say why -- "A key is followed by a colon, without
# which the scan also matches a value that reads like a key name".  The
# chokepoint every scalar field goes through was the one that did not ask.
#
# runtime_manager::valid_name allows every field name: alnum, dash, underscore,
# dot.  There is no reserved-word list.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   before the restart        a test that watches the wrong field -- the live
#                             instance never went through the parser
#   the control restores      a broken restart, which would make the subject
#                             fail for a reason that is not this one
#   the subject restores      the defect: target reads back as the id
#   the id and the target     that the two are distinguishable at all, so
#   are different             "unchanged" is a claim with content
#   was_running survives      the same scan on a different field, with a
#                             different consequence: a bool that reads as the
#                             id is neither "true" nor "false", so it takes
#                             the default and the runtime does not come back
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate statekey

P_SRV=$((SL_PORT_BASE+1664))
P_WR=$((SL_PORT_BASE+1665))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
        local l; for l in "${@:3}"; do echo "        $l"; done; }

cleanup() {
    for n in target plain srv was_running; do
        "$BIN" stop "$n" >/dev/null 2>&1 || true
    done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: a runtime named after a config field keeps its own settings ==="

daemon_start "$BIN"
"$BIN" create server srv -p "$P_SRV" -s                >/dev/null 2>&1
"$BIN" create client target -t "127.0.0.1:$P_SRV" -s   >/dev/null 2>&1
"$BIN" create client plain  -t "127.0.0.1:$P_SRV" -s   >/dev/null 2>&1
"$BIN" create server was_running -p "$P_WR" -s         >/dev/null 2>&1
sleep 1.5

field() { "$BIN" show "$1" 2>/dev/null | sed -n "s/.*\"$2\": \"\\([^\"]*\\)\".*/\\1/p" | head -1; }

T_BEFORE=$(field target target)
ID_BEFORE=$(field target id)

if [ "$T_BEFORE" = "127.0.0.1:$P_SRV" ]; then ok
else bad "before the restart the target is the address it was given" \
         "got '$T_BEFORE', wanted '127.0.0.1:$P_SRV'" \
         "the live instance never went through the parser, so this must hold" \
         "on any build -- if it does not, this test is watching the wrong field"; fi

if [ -n "$ID_BEFORE" ] && [ "$ID_BEFORE" != "$T_BEFORE" ]; then ok
else bad "the id and the target are different strings" \
         "id '$ID_BEFORE', target '$T_BEFORE'" \
         "if they were the same, 'the target is unchanged' would be empty"; fi

# ── the restart, with the state directory kept ─────────────────────────────
kill "$SOCKETLEY_DPID" 2>/dev/null || true
for _ in $(seq 1 100); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
wait "$SOCKETLEY_DPID" 2>/dev/null || true

: > "$SOCKETLEY_DLOG"
"$BIN" daemon >>"$SOCKETLEY_DLOG" 2>&1 &
SOCKETLEY_DPID=$!
for _ in $(seq 1 100); do
    grep -q "daemon started" "$SOCKETLEY_DLOG" 2>/dev/null && break
    sleep 0.1
done
sleep 1.5

C_AFTER=$(field plain target)
T_AFTER=$(field target target)

echo "  control 'plain'  -> ${C_AFTER:-<nothing>}"
echo "  subject 'target' -> ${T_AFTER:-<nothing>}   (its id is $ID_BEFORE)"

if [ "$C_AFTER" = "127.0.0.1:$P_SRV" ]; then ok
else bad "a runtime with an ordinary name restores its target" \
         "got '${C_AFTER:-<nothing>}'" \
         "the restart itself is broken, so the subject below proves nothing"; fi

if [ "$T_AFTER" = "127.0.0.1:$P_SRV" ]; then ok
else bad "a runtime NAMED 'target' restores its target" \
         "got '${T_AFTER:-<nothing>}', wanted '127.0.0.1:$P_SRV'" \
         "reading back its own id here is the scan matching the VALUE on the" \
         "name line and then taking the colon that belongs to \"id\""; fi

# Matched on the row, not on the line start: `ls` puts the id column first.
WR_STATE=$("$BIN" ls 2>/dev/null | grep -E '[[:space:]]was_running[[:space:]]' | head -1)
echo "  subject 'was_running' -> ${WR_STATE:-<not listed>}"
# Matched on the STATUS column and not on the row: the first pattern written
# here was *running*, which matches the runtime's own NAME and passed while the
# row plainly read Created -- the defect class this suite was just audited for,
# committed in the test hunting it.
WR_STATUS=$(printf '%s\n' "$WR_STATE" | awk '{print $7}')
if [ -z "$WR_STATE" ]; then
    bad "a runtime named 'was_running' comes back up" "it is not listed at all"
elif [ "$WR_STATUS" = "Up" ]; then
    ok
else
    bad "a runtime named 'was_running' comes back up" \
        "the STATUS column reads '${WR_STATUS:-<none>}', not 'Up'" \
        "its was_running flag read back as its id, which is neither \"true\"" \
        "nor \"false\", so json_get_bool took the default"
fi

echo
echo "  $PASS/$TOTAL passed"
[ "$FAIL" -eq 0 ] || exit 1
