#!/usr/bin/env bash
# Integration test: --reconnect brings a client back, in a worker and in the daemon
#
# --reconnect had no test at all.  Not a thin one -- zero mentions of the flag
# anywhere under test/, which is how it came to be accepted, stored, reported by
# `show`, and silently inert for the mode that is the default.
#
# The shape that matters is the pair.  `--reconnect` with no value means
# "infinite attempts" and is written as 0; `--reconnect N` means N.  A test that
# only exercised one of them passes on the build this file was written against:
# runtime_config_apply.cpp guarded the hand-off with `if (cfg.reconnect != 0)`,
# so the sentinel that means infinite was the one value never applied, while
# every explicit count worked.  Both forms are therefore asserted, and so is the
# arm that must NOT come back -- a client without the flag -- because "it
# reconnected" is equally true of a build that reconnects unconditionally.
#
# The oracle is the client's own connection count (client_instance.cpp reports
# m_connected ? 1 : 0), not the server's.  A server counts a connection only
# once it has classified its protocol, so a client that dials and stays silent
# is invisible there -- the wrong instrument for this question.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate client_reconnect

# lib_ports.sh:99 runs `exec 9>lockfile 2>/dev/null`, and an exec with no
# command applies BOTH redirections to the shell -- so sourcing it sends this
# file's stderr to /dev/null for the rest of the run.  Every file here inherits
# that; it is fixed on fix/p0-crashes (b72a776) and that branch has not reached
# main.  Put back, because a test whose error output is discarded reports "it
# failed" and nothing else, which cost an hour of this file's own development.
exec 2>&1

S_INF=$((SL_PORT_BASE+300))     # server for the infinite-attempts client
S_CNT=$((SL_PORT_BASE+301))     # server for the counted client
S_OFF=$((SL_PORT_BASE+302))     # server for the client with no flag
S_DMN=$((SL_PORT_BASE+303))     # server for the in-daemon client

PASS=0; FAIL=0; TOTAL=0      # TOTAL is lib_create.sh's convention; create_ok maintains it
ok()  { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
bad() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  FAIL [$1]: $2"; }

cleanup() {
    for r in c_inf c_cnt c_off c_dmn s_inf s_cnt s_off s_dmn; do
        "$BIN" stop "$r" >/dev/null 2>&1 || true
    done
    sleep 0.3
    for r in c_inf c_cnt c_off c_dmn s_inf s_cnt s_off s_dmn; do
        "$BIN" remove "$r" >/dev/null 2>&1 || true
    done
    daemon_stop
}
trap cleanup EXIT

# conn count of a runtime, from `ls`
conns() { "$BIN" ls 2>/dev/null | awk -v n="$1" '$2==n{print $5}'; }

# Poll for a runtime to report a given connection count, to a deadline.
#
# A deadline and not a sleep: the documented backoff starts at one second and
# doubles, so the honest assertion is that the client converges, and the honest
# failure is that it did not within a stated bound.  20s covers attempts at
# roughly 1, 3, 7 and 15 seconds -- four chances -- so a build that reconnects
# at all will be seen doing it, and one that never schedules an attempt cannot
# pass by being slow.
wait_conns() {  # name want deadline_s
    local i=0
    while [ "$i" -lt "$3" ]; do
        [ "$(conns "$1")" = "$2" ] && return 0
        sleep 1; i=$((i+1))
    done
    return 1
}

echo "=== Integration: --reconnect brings a client back ==="

daemon_start "$BIN"

create_ok "server for the infinite-attempts client" "$BIN" create server s_inf -p "$S_INF" --mode inout -s
create_ok "server for the counted client"           "$BIN" create server s_cnt -p "$S_CNT" --mode inout -s
create_ok "server for the client with no flag"      "$BIN" create server s_off -p "$S_OFF" --mode inout -s
create_ok "server for the in-daemon client"         "$BIN" create server s_dmn -p "$S_DMN" --mode inout -s

create_ok "client, --reconnect with no value"  "$BIN" create client c_inf -t "127.0.0.1:$S_INF" --reconnect -s
create_ok "client, --reconnect 5"              "$BIN" create client c_cnt -t "127.0.0.1:$S_CNT" --reconnect 5 -s
create_ok "client, no --reconnect"             "$BIN" create client c_off -t "127.0.0.1:$S_OFF" -s
create_ok "client, --reconnect --daemon-process" "$BIN" create client c_dmn -t "127.0.0.1:$S_DMN" --reconnect --daemon-process -s

# ── Control ─────────────────────────────────────────────────────────────────
#
# Every assertion below is about a client coming back.  If one never arrived,
# "it did not come back" is true of a build where nothing is wrong with
# reconnect at all, and the three interesting assertions would be measuring the
# fixture.  So the fixture is checked first, and it is checked for all four.
for c in c_inf c_cnt c_off c_dmn; do
    if wait_conns "$c" 1 10; then ok
    else bad "control: $c connects at all" "never reported a connection; the rest of this file cannot be read"; fi
done

# ── The outage ──────────────────────────────────────────────────────────────
#
# `remove`, not `stop`.  A stopped server was ambiguous as an outage: a client
# whose reconnect works dials again every second or two, and during the
# teardown it could come back briefly, so "the client noticed" sampled once a
# second saw 1 and failed a control that was describing the fixture rather than
# the product.  Removing the runtime leaves nothing to reconnect to, which is
# the unambiguous version of the same event, and the servers are created again
# on the same ports to end it.
for s in s_inf s_cnt s_off s_dmn; do "$BIN" remove "$s" >/dev/null 2>&1 || true; done

for c in c_inf c_cnt c_off c_dmn; do
    if wait_conns "$c" 0 10; then ok
    else bad "control: $c notices the outage" "still reports a connection after its server stopped"; fi
done

"$BIN" create server s_inf -p "$S_INF" --mode inout -s >/dev/null 2>&1 || true
"$BIN" create server s_cnt -p "$S_CNT" --mode inout -s >/dev/null 2>&1 || true
"$BIN" create server s_off -p "$S_OFF" --mode inout -s >/dev/null 2>&1 || true
"$BIN" create server s_dmn -p "$S_DMN" --mode inout -s >/dev/null 2>&1 || true

# ── What the flag promises ──────────────────────────────────────────────────
if wait_conns c_inf 1 20; then ok
else bad "--reconnect with no value comes back" \
         "still disconnected 20s after the server returned; 0 means infinite attempts, and it is the default form of the flag"; fi

if wait_conns c_cnt 1 20; then ok
else bad "--reconnect 5 comes back" "still disconnected 20s after the server returned"; fi

if wait_conns c_dmn 1 20; then ok
else bad "--reconnect comes back in the daemon too" \
         "still disconnected 20s after the server returned; this arm passed while the worker arm did not, which is what named the defect"; fi

# ── And what its absence promises ───────────────────────────────────────────
#
# The one assertion that fails on a build which reconnects unconditionally.
# Without it, all three above are satisfied by ignoring the flag entirely.
sleep 5
if [ "$(conns c_off)" = "0" ]; then ok
else bad "no --reconnect stays down" \
         "a client created without the flag reconnected anyway, so the three assertions above prove nothing about the flag"; fi

echo ""
echo "  passed: $PASS / $TOTAL"
[ "$FAIL" -eq 0 ]
