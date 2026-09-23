#!/usr/bin/env bash
# Integration test: what json_escape writes, json_unescape reads back.
#
# ─── WHY ────────────────────────────────────────────────────────────────────
#
# json_escape turns every byte below 0x20 into a \uXXXX escape -- it has to, or
# the document is not JSON, and its comment says so.  json_unescape had no `u`
# arm at all, so the escape came back as the six literal characters spelling
# it.
#
# Nothing validates a path, and a Linux path may hold any byte but '/' and NUL,
# so the reachable case is a control character in --log, --lua, --write-file or
# any of the `extra` fields.  Measured before this, on a path spelt a<0x01>b:
#
#     state file           "log_file": "/tmp/x/a\u0001b.log"
#     show, fresh daemon   "log_file": "/tmp/x/a\u0001b.log"
#     show, after restart  "log_file": "/tmp/x/a\\u0001b.log"
#
# The doubled backslash in the last line is `show` escaping what the daemon now
# holds: seven characters where there were three.  The daemon and the file
# named different paths from that point on, and the same bytes go to the worker
# in the config frame.
#
# ─── WHAT KEEPS IT HONEST ───────────────────────────────────────────────────
#
# The comparison is between the value before the restart and the value after,
# both read through `show`, so a build that changed how the field is displayed
# cannot pass by changing both ends of it.  And the ordinary path beside it,
# which must be unchanged either way.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate stateesc

PASS=0; FAIL=0; TOTAL=0
pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"
         local l; for l in "${@:3}"; do echo "        $l"; done; }
cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== Integration: a control character in a path survives a restart ==="
daemon_start "$BIN"
P=$((SL_PORT_BASE + 1580))

CTRL=$(printf '%s/a\001b.log' "$SOCKETLEY_TMPD")
PLAIN="$SOCKETLEY_TMPD/plain.log"

"$BIN" create server esc_ctrl  -p "$P"       --log "$CTRL"  >/dev/null 2>&1 || true
"$BIN" create server esc_plain -p $((P + 1)) --log "$PLAIN" >/dev/null 2>&1 || true
sleep 0.6

field() { "$BIN" show "$1" 2>/dev/null | sed -n 's/.*"log_file": "\([^"]*\)".*/\1/p' | head -1; }

BEFORE=$(field esc_ctrl)
BEFORE_PLAIN=$(field esc_plain)

# The premise: the escape is in the document at all, or there is nothing here
# for a reader to get wrong.
case "$BEFORE" in
    *'\u0001'*) pass ;;
    *) fail "the premise: the control byte is written as an escape" \
            "show reads [${BEFORE:-<nothing>}] before any restart" ;;
esac

restart_daemon() {
    kill "$SOCKETLEY_DPID" 2>/dev/null || true
    local i; for i in $(seq 1 60); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
    wait "$SOCKETLEY_DPID" 2>/dev/null || true
    : > "$SOCKETLEY_DLOG"
    "$BIN" daemon >>"$SOCKETLEY_DLOG" 2>&1 & SOCKETLEY_DPID=$!
    for i in $(seq 1 100); do
        grep -q "daemon started" "$SOCKETLEY_DLOG" 2>/dev/null && break; sleep 0.1
    done
    sleep 1.2
}
restart_daemon

AFTER=$(field esc_ctrl)
if [ "$AFTER" = "$BEFORE" ]; then pass
else fail "the escaped path reads back as the path it was" \
          "before [$BEFORE], after [$AFTER]" \
          "a doubled backslash here is show escaping what the daemon now" \
          "holds: the six characters of the escape instead of the one byte"; fi

AFTER_PLAIN=$(field esc_plain)
if [ "$AFTER_PLAIN" = "$BEFORE_PLAIN" ]; then pass
else fail "an ordinary path is unchanged too" \
          "before [$BEFORE_PLAIN], after [$AFTER_PLAIN]"; fi

# Control: a build that restored nothing would pass both comparisons on two
# empty answers.
if [ -n "$AFTER" ] && [ -n "$AFTER_PLAIN" ]; then pass
else fail "both runtimes came back with a log path at all" \
          "ctrl [${AFTER:-<nothing>}] plain [${AFTER_PLAIN:-<nothing>}]"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
