#!/usr/bin/env bash
# Integration test: --retry in front of a @group.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# `--backend @grp` is ONE entry in m_backends, and try_retry() moved to the
# next backend BY INDEX -- so for a group there was nowhere to move to and the
# loop found nothing.  It never got that far anyway: retries_remaining was set
# on the three non-group paths and not on the group one, so try_retry() answered
# false on its first line.  A request that hit a dead member got its 502 or its
# 504 and stopped there, while the manual promises the retry with no exception
# for groups.  No test covered group plus retry: test_proxy_failover_load.sh
# uses three separate backends, which is the case that worked.
#
# The dead member is made by REMOVING ITS NODE, not by stopping it.  A stopped
# runtime leaves the group, so the proxy would never choose it and the test
# would pass on any build.  member_dial() hands out the node paths alone when a
# member has them, so unlinking one leaves the member published, healthy, and
# unreachable -- which is exactly the shape this is about.
#
# The proxy is created AFTER the removal: a proxy that had already pooled a leg
# to that member keeps answering over it, and the assertion would pass without
# a retry ever happening.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: --retry in front of a group ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

PA=$((SL_PORT_BASE+1408))
PB=$((SL_PORT_BASE+1409))
PX=$((SL_PORT_BASE+1410))
PY=$((SL_PORT_BASE+1411))
PZ=$((SL_PORT_BASE+1417))

daemon_isolate proxygroupretry
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

RTDIR="$SOCKETLEY_SOCKET.rt"
WA="$SOCKETLEY_TMPD/wa"; mkdir -p "$WA"; printf '<h1>MEMBER-A</h1>\n' > "$WA/index.html"
WB="$SOCKETLEY_TMPD/wb"; mkdir -p "$WB"; printf '<h1>MEMBER-B</h1>\n' > "$WB/index.html"

"$BIN" create server gr_a -p "$PA" --group gr_g --http "$WA" -s >/dev/null 2>&1
"$BIN" create server gr_b -p "$PB" --group gr_g --http "$WB" -s >/dev/null 2>&1
sleep 2

# How many of N sequential requests came back 200 with a body, and how many
# came back as a gateway error.  Sequential on purpose: every request has to
# take its own turn of the round-robin, which is what puts some of them on the
# dead member.
run_n() {   # run_n PORT NAME N -> "<ok> <bad>"
    python3 -c "
import socket
good = bad = 0
for i in range($3):
    try:
        s = socket.create_connection(('127.0.0.1', $1), timeout=5)
        s.sendall(b'GET /$2/ HTTP/1.1\r\nHost: p\r\nConnection: close\r\n\r\n')
        d = b''
        while True:
            c = s.recv(4096)
            if not c: break
            d += c
        s.close()
        if b'MEMBER-' in d: good += 1
        else: bad += 1
    except Exception:
        bad += 1
print(good, bad)" 2>/dev/null
}

# ── 1. Both members answer while both are reachable ────────────────────────
"$BIN" create proxy gr_ctl -p "$PY" --backend @gr_g --strategy round-robin -s >/dev/null 2>&1
sleep 1.5
read -r CTL_OK CTL_BAD <<<"$(run_n "$PY" gr_ctl 20)"
NODES=$(ls "$RTDIR"/gr_a.sock "$RTDIR"/gr_b.sock 2>/dev/null | wc -l)
if [ "$CTL_OK" -eq 20 ] && [ "$NODES" -eq 2 ]; then
    ok "the control: 20 of 20 answered while both members are reachable, 2 nodes bound"
else
    bad "the group serves before a member is taken out" \
        "answered $CTL_OK of 20 ($CTL_BAD failed) with $NODES of 2 nodes bound;" \
        "nothing below would mean anything"
fi
"$BIN" stop gr_ctl >/dev/null 2>&1; "$BIN" remove gr_ctl >/dev/null 2>&1

# ── 2. One member unreachable, and --retry carries the request ─────────────
rm -f "$RTDIR/gr_b.sock"

# The same proxy without --retry has to lose requests, or the removed node left
# the member reachable and 20 of 20 below would need no retry at all.
"$BIN" create proxy gr_nr -p "$PZ" --backend @gr_g --strategy round-robin -s >/dev/null 2>&1
sleep 1.5
read -r NR_OK NR_BAD <<<"$(run_n "$PZ" gr_nr 20)"
if [ "${NR_BAD:-0}" -ge 1 ]; then
    ok "the control: without --retry, $NR_BAD of 20 failed on the unreachable member"
else
    bad "the removed node makes the member unreachable" \
        "without --retry ${NR_OK:-0} of 20 answered and none failed;" \
        "the dead member was never chosen or is still reachable, so the retry below is not measured"
fi
"$BIN" stop gr_nr >/dev/null 2>&1; "$BIN" remove gr_nr >/dev/null 2>&1

"$BIN" create proxy gr_p -p "$PX" --backend @gr_g --retry 1 --strategy round-robin -s >/dev/null 2>&1
sleep 1.5
read -r GOT BADN <<<"$(run_n "$PX" gr_p 20)"
if [ "$GOT" -eq 20 ]; then
    ok "with one member unreachable, --retry 1 answered 20 of 20"
else
    bad "--retry moves a group request to another member" \
        "answered $GOT of 20, $BADN failed;" \
        "roughly half is the round-robin handing every other request to the dead" \
        "member and try_retry() answering false -- retries_remaining was never set" \
        "on the group path, and the index walk has nowhere to go when @grp is one entry"
fi

for n in gr_p gr_a gr_b; do
    "$BIN" stop "$n" >/dev/null 2>&1; "$BIN" remove "$n" >/dev/null 2>&1
done
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
