#!/usr/bin/env bash
# Integration test: the hint `dashboard` prints when metrics are off.
#
# It used to read:
#
#     add metrics_port = 9100 to socketley.conf to enable the dashboard
#
# and every part of that after "add" was wrong.  There is no socketley.conf --
# the daemon reads config.lua, at /etc/socketley/config.lua or
# ~/.config/socketley/config.lua, or wherever SOCKETLEY_CONFIG points.  And a
# bare `metrics_port = 9100` in that file is a Lua global, while the reader only
# looks inside a `daemon` (or `config`) table, so it is parsed, ignored, and
# never mentioned again.
#
# Measured before the fix, on a private daemon with a config of its own:
#
#     config.lua: metrics_port = 22980       -> "metrics endpoint not configured
#                                               add metrics_port = 9100 to
#                                               socketley.conf ..."
#     config.lua: daemon = { metrics_port = 22980 }
#                                            -> "Dashboard: http://127.0.0.1:22980/"
#
# So an operator who did exactly what they were told got the same message back.
# That is the shape this file tests, and it is why the assertion is not "the
# message mentions config.lua": it FOLLOWS the message, byte for byte, by piping
# the indented line out of the daemon's own output into the file the same output
# named, and then asks whether it worked.  A message can name the right file and
# still be unusable; only executing it settles that.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate dashhint
MPORT=$((SL_PORT_BASE+1985))
PASS=0; FAIL=0; TOTAL=0

cleanup() { daemon_stop; }
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

# A restart that keeps this test's socket, state directory and config, because
# daemon_stop deletes all three and the config is the thing under test.  The log
# is truncated because daemon_start waits for "daemon started" and would
# otherwise match the previous run's line.
daemon_restart() {
    if [ -n "${SOCKETLEY_DPID:-}" ]; then
        for c in $(pgrep -P "$SOCKETLEY_DPID" 2>/dev/null); do kill -9 "$c" 2>/dev/null || true; done
        kill -9 "$SOCKETLEY_DPID" 2>/dev/null || true
        wait "$SOCKETLEY_DPID" 2>/dev/null || true
    fi
    for _ in $(seq 1 50); do [ -S "$SOCKETLEY_SOCKET" ] || break; sleep 0.1; done
    rm -f "$SOCKETLEY_SOCKET"
    : > "$SOCKETLEY_DLOG"
    daemon_start "$BIN"
}

echo "=== Integration: the dashboard hint can be followed ==="

# A config file of this daemon's own, empty to start with -- and exported before
# daemon_start, since the path is read once at boot.  This also overrides the
# suite-wide SOCKETLEY_CONFIG, which names a build directory and no file.
CONF="$SOCKETLEY_TMPD/config.lua"
: > "$CONF"
export SOCKETLEY_CONFIG="$CONF"

daemon_start "$BIN"

HINT=$("$BIN" dashboard 2>&1) || true

# It must name a file that exists on this machine, not a name from a manual.
if grep -qF "$CONF" <<<"$HINT"; then ok; else
    bad "the hint names this daemon's own config file" \
        "expected '$CONF' in: $(tr '\n' '|' <<<"$HINT")"; fi

# `socketley.conf` is not the name of any file this binary reads, anywhere.
if grep -q "socketley\.conf" <<<"$HINT"; then
    bad "the hint does not name a file that does not exist" \
        "it still says socketley.conf"
else ok; fi

# And the setting it suggests must be inside the table the reader looks at.
if grep -q "daemon = {" <<<"$HINT" && grep -q "metrics_port" <<<"$HINT"; then ok; else
    bad "the hint gives the table, not a bare global" \
        "got: $(tr '\n' '|' <<<"$HINT")"; fi

# ─── now follow it ──────────────────────────────────────────────────────────
# The indented line out of the daemon's own output, with only the example port
# changed to one this test owns.  Nothing else is retyped, so a hint that drifts
# from what the reader accepts fails here rather than passing on a grep.
SUGGESTED=$(sed -n 's/^    //p' <<<"$HINT" | sed "s/9100/$MPORT/")
if [ -n "$SUGGESTED" ]; then ok; else
    bad "the hint has a line to copy" "no indented line in: $(tr '\n' '|' <<<"$HINT")"; fi
printf '%s\n' "$SUGGESTED" >> "$CONF"

daemon_restart

AFTER=$("$BIN" dashboard 2>&1) || true
if grep -q "http://127.0.0.1:$MPORT/" <<<"$AFTER"; then ok; else
    bad "following the hint enables the dashboard" \
        "config.lua is '$(cat "$CONF")' and dashboard says: $(tr '\n' '|' <<<"$AFTER")"; fi

# And the port really answers, because "configured" and "bound" are different
# answers and this command has given the first while meaning the second before.
if curl -fsS --max-time 3 "http://127.0.0.1:$MPORT/metrics" >/dev/null 2>&1; then ok; else
    bad "the port the hint produced is actually serving" \
        "nothing answered on $MPORT"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
