#!/usr/bin/env bash
# Integration test: --udp with --mode master, which the man page has called
# impossible since the flag existed and which nothing enforced.
#
# It is not merely a useless pair.  Master mode claims a CONNECTION as the
# master, charges failed attempts to it, and forwards from it -- and a datagram
# has none, so handle_udp_read() reaches the mode_master case with a null
# sender.  A datagram beginning "master " then dereferenced it.  Measured before
# the fix, on a private daemon, with an idle control either side:
#
#     4 s idle              pid 176729, total_messages 0    stable
#     datagram "plainmsg"   pid 176729, total_messages 1    survives
#     datagram "master ..." pid 176788, total_messages 0    new worker
#     daemon log            worker ... was killed by signal 11
#
# One unauthenticated packet, no password, no connection.  The runtime came back
# and did it again on the next one.
#
# ─── WHY THREE LAYERS AND NOT ONE ───────────────────────────────────────────
#
#   CREATE refuses the pair, checked as a set after every flag is parsed, so
#   --mode and --udp may be typed in either order.
#
#   START refuses it too, because a state file written before this check exists
#   already carries the pair and is read at daemon boot, not at create.
#
#   THE CASE guards the dereference, because that is the line that actually
#   segfaults and neither refusal is what makes it safe.  Proven separately by
#   disabling both refusals, rebuilding, and re-sending the packet: the worker
#   survived, pid stable, zero `signal 11`.
#
# ─── READING A CRASH CORRECTLY ──────────────────────────────────────────────
#
# Two earlier attempts at this test reported "survived" and both were wrong: the
# worker is restarted within a second, so a pid read too soon is the NEW pid and
# looks like the old one never died.  This file therefore takes the pid from
# `stats` (the runtime's own report), holds an idle control interval first to
# prove the pid is stable without traffic, waits past the restart, and reads the
# daemon's log for the signal rather than inferring death from a number.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate udpmaster
PORT=$((SL_PORT_BASE+1950))
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    for n in um_plain um_boot; do
        "$BIN" stop "$n" 2>/dev/null || true
    done
    sleep 0.3
    for n in um_plain um_boot; do
        "$BIN" remove "$n" 2>/dev/null || true
    done
    daemon_stop
}
trap cleanup EXIT

ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad()  { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

refused() {   # label needle -- then the command
    local label=$1 needle=$2; shift 2
    local out
    out=$("$@" 2>&1) || true
    if grep -q "$needle" <<<"$out"; then ok; else
        bad "$label" "expected a refusal naming '$needle', got '$out'"; fi
}

worker_pid() { "$BIN" stats "$1" 2>/dev/null | awk -F: '/^pid:/{print $2}'; }

# A restart that keeps the isolation.  daemon_stop() cannot be used here: it
# deletes SOCKETLEY_TMPD, which is where the state file being planted lives, so
# calling it would destroy the thing under test and the next daemon_start would
# fail on a missing log.  The log is truncated on the way through because
# daemon_start waits for "daemon started" and would otherwise match the previous
# run's line and return before the new daemon had bound anything.
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

echo "=== Integration: --udp is refused with --mode master ==="

daemon_start "$BIN"

# Both orders, because the check is made as a set once every flag is seen and a
# per-flag check would only catch whichever came second.
refused "--udp then --mode master" "cannot be combined with --mode master" \
    "$BIN" create server um_bad1 -p "$PORT" --udp --mode master --master-pw pw

refused "--mode master then --udp" "cannot be combined with --mode master" \
    "$BIN" create server um_bad2 -p "$PORT" --mode master --master-pw pw --udp

# A plain UDP server is untouched by the refusal -- the guard must not cost the
# ordinary case.
create_ok "a plain UDP server still starts" \
    "$BIN" create server um_plain -p "$PORT" --udp -s
sleep 0.8
PID_A=$(worker_pid um_plain)
if [ -n "$PID_A" ]; then ok; else bad "the plain UDP server is running" "no pid from stats"; fi

# And it still answers, so the refusal did not take UDP away.
sleep 0.4
BEFORE=$("$BIN" stats um_plain 2>/dev/null | awk -F: '/^total_messages:/{print $2}')
python3 -c "
import socket
socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'plainmsg\n', ('127.0.0.1', $PORT))" 2>/dev/null
sleep 1.0
AFTER=$("$BIN" stats um_plain 2>/dev/null | awk -F: '/^total_messages:/{print $2}')
if [ "${AFTER:-0}" -gt "${BEFORE:-0}" ]; then ok; else
    bad "a plain datagram is still ingested" "total_messages ${BEFORE:-?} -> ${AFTER:-?}"; fi

# ─── the state file a pre-check daemon left behind ──────────────────────────
#
# `start` restarts from the in-memory instance and never re-reads the file, so
# the pair has to be planted and the DAEMON restarted for this to test anything.
# An earlier draft edited the file and called `start`, and the runtime came up
# as mode 0 -- the test passed and had exercised nothing.
"$BIN" stop um_plain >/dev/null 2>&1 || true
sleep 0.4
create_ok "a runtime to plant the pair into" \
    "$BIN" create server um_boot -p "$PORT" --udp
# Polled, not slept for: state_persistence enqueues onto a writer thread, so the
# file appears a moment after `create` returns.  Looking immediately found
# nothing and read as "a runtime without -s is never persisted", which is false.
SF=""
for _ in $(seq 1 60); do
    SF=$(find "${HOME}/.local/share/socketley" -name 'um_boot.json' 2>/dev/null | head -1)
    [ -n "$SF" ] && break
    sleep 0.1
done
if [ -z "$SF" ]; then
    bad "the state file exists to plant into" "no um_boot.json found"
else
    python3 - "$SF" <<'PYJSON'
import json, sys
d = json.load(open(sys.argv[1]))
d["mode"] = "master"; d["master_pw"] = "pw"; d["udp"] = True
json.dump(d, open(sys.argv[1], "w"), indent=4)
PYJSON
    daemon_restart
    sleep 0.8
    # The daemon has read the pair off disk: mode 3 with udp true.
    PLANTED=$("$BIN" stats um_boot 2>/dev/null | awk -F: '/^mode:/{print $2}')
    if [ "${PLANTED:-}" = "3" ]; then ok; else
        bad "the daemon read master mode off disk" "stats says mode=${PLANTED:-<none>}"; fi

    refused "a planted pair refuses to START" "cannot be combined with --mode master" \
        "$BIN" start um_boot

    # And it really did not come up, read off a stats call that answered, since a failed one has no pid either.
    ST=$("$BIN" stats um_boot 2>/dev/null) || ST=""
    if ! grep -q '^name:um_boot' <<<"$ST"; then
        bad "the planted runtime stayed down" "stats did not answer: '${ST:-<nothing>}'"
    elif grep -q '^pid:' <<<"$ST"; then
        bad "the planted runtime stayed down" "it has a pid"
    else ok; fi
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
