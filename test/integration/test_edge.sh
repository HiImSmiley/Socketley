#!/usr/bin/env bash
# Integration test: names runtimes are reached by, and the entrance that routes requests by them.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   ownership    a name belongs to one runtime: a second one is refused at
#                create, edit and import, whatever its case or trailing dot,
#                and across types; the runtimes of one group share a name; the
#                entrance, a proxy without --backend, has none of its own
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate edge
P=$((SL_PORT_BASE+1740))
T="$SOCKETLEY_TMPD"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
has() { case "$2" in *"$3"*) ok "$1" ;; *) bad "$1" "'$3' not in: $2" ;; esac; }

cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: names and the entrance ==="
daemon_start "$BIN"

# ── ownership ───────────────────────────────────────────────────────────────
expect "a runtime takes a name" "$("$BIN" create server a -p "$P" --domain chat 2>&1)" ""
has "a second runtime is refused it, whatever its case and trailing dot" \
    "$("$BIN" create server b -p $((P+1)) --domain Chat. 2>&1)" "chat is already the name of runtime 'a'"
has "and so is a runtime of another type" \
    "$("$BIN" create storage s -p $((P+2)) --dir "$T/s" --anonymous --domain chat 2>&1)" "already the name of runtime 'a'"
expect "the runtimes of one group share a name" \
    "$("$BIN" create server g1 -p $((P+3)) -g web --domain www 2>&1)$("$BIN" create server g2 -p $((P+4)) -g web --domain www 2>&1)" ""
has "edit cannot take another's name" "$("$BIN" edit g1 --domain chat 2>&1)" "already the name of runtime 'a'"
has "nor import" "$("$BIN" import a '{"name":"a","domain":"www"}' 2>&1)" "already the name of runtime"
has "and the refused import left the runtime as it was" "$("$BIN" show a 2>&1)" '"domain": "chat"'
has "the entrance has no name of its own" "$("$BIN" create proxy e -p $((P+5)) --domain x 2>&1)" "has no name of its own"
expect "and nothing refused was made" "$("$BIN" ls 2>/dev/null | awk 'NR>1 {print $2}' | sort | tr '\n' ' ')" "a g1 g2 "

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
