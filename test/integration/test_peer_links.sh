#!/usr/bin/env bash
# Integration test: two runtimes crossing without the daemon in the middle.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# A cross-runtime request has always worked: worker → daemon → worker, and back
# the same way.  A direct link is a second route to the same answer, and the
# fallback that keeps a dead link from being an outage is also what would let a
# link that never forms go unnoticed -- every value would still read back.
#
# So the assertions here are about the ROUTE:
#
#   before: peer_links 0   the link is made when a crossing is carried, not at
#                          the fork -- two runtimes are created at different
#                          moments and there is no instant with both processes
#                          up and neither started.
#   after:  peer_links 1   and peer_direct > 0: the crossings went over it.
#           peer_relayed 0 a link that forms and then quietly relays reports
#                          peer_links 1 and would pass a weaker assertion.
#   off:    peer_links 0   with SOCKETLEY_NO_PEER_LINKS the same commands still
#                          answer, over the daemon.  This is the arm every
#                          measurement compares against, so it has to be
#                          known-good.
#   sharded: peer_links 1  a sharded target is linked at shard 0, which is where
#                          the daemon's own sink for the bare name points, so
#                          the link replaces the daemon's leg and not the
#                          cache's own routing behind it.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: two runtimes cross without the daemon ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

if ! command -v nc >/dev/null 2>&1; then
    echo "  (nc absent -- this file needs it to speak to a server)"
    echo "  Results: 0/0 passed (0 failed)"
    echo "  OK"
    exit 0
fi

PORT=$((SL_PORT_BASE+1310))

# `stats` prints one counter line per worker; a server has one, so these are
# sums over a set of one and stay right if that ever changes.
counter() {   # counter <runtime> <name>
    "$BIN" stats "$1" 2>/dev/null |
        awk -F: -v k="^$2:" '$0 ~ k {s+=$2} END{print s+0}'
}

# The server's own protocol, one command per connection because that is what
# the other cache tests do and the route is the same either way.
say() { printf '%s\n' "$1" | timeout 5 nc -q1 127.0.0.1 "$2" 2>/dev/null | head -1; }

# ── 1. A link is made when a crossing is carried, not at the fork ──────────
daemon_isolate peerlinks
daemon_start "$BIN"

"$BIN" create cache  pl_cache -p "$PORT"         -s >/dev/null 2>&1
"$BIN" create server pl_srv   -p $((PORT+1)) --cache pl_cache -s >/dev/null 2>&1
sleep 1.5

BEFORE=$(counter pl_srv peer_links)
if [ "$BEFORE" -eq 0 ]; then
    ok "no link before the first crossing (peer_links $BEFORE)"
else
    bad "no link before the first crossing" \
        "peer_links is $BEFORE with nothing having crossed yet;" \
        "a link made at the fork cannot exist for a runtime created later"
fi

# ── 2. The answers, which every route gives ────────────────────────────────
SET=$(say "cache set pk pv" $((PORT+1)))
sleep 1
GOT=$(say "cache get pk" $((PORT+1)))
if [ "$GOT" = "pv" ]; then
    ok "the value crosses and comes back (set said '${SET:-<nothing>}')"
else
    bad "the value crosses and comes back" \
        "get said '${GOT:-<nothing>}', set said '${SET:-<nothing>}'"
fi

# Enough crossings after the link is up that a counter of them cannot be zero
# by accident, and a beat for the stats frame the worker pushes.
for i in $(seq 1 20); do say "cache get pk" $((PORT+1)) >/dev/null; done
sleep 3

LINKS=$(counter pl_srv peer_links)
DIRECT=$(counter pl_srv peer_direct)
RELAY=$(counter pl_srv peer_relayed)

if [ "$LINKS" -eq 1 ]; then
    ok "the crossing built one link (peer_links $LINKS)"
else
    bad "the crossing built one link" \
        "peer_links is $LINKS, expected 1 -- the daemon carried a crossing" \
        "between two single-worker runtimes and did not introduce them"
fi
if [ "$DIRECT" -gt 0 ]; then
    ok "and the crossings went over it ($DIRECT direct)"
else
    bad "and the crossings went over it" \
        "peer_direct is $DIRECT -- every crossing still went through the" \
        "daemon, which answers correctly and measures as the build without links"
fi
if [ "$RELAY" -eq 0 ]; then
    ok "none of them fell back (peer_relayed $RELAY)"
else
    bad "none of them fell back" \
        "$RELAY of $((DIRECT+RELAY)) relayed; a link that forms and then gives" \
        "up quietly still reports peer_links 1 and peer_direct above zero"
fi
if grep -q "now cross directly" "$SOCKETLEY_DLOG" 2>/dev/null; then
    ok "the daemon says which two it introduced"
else
    bad "the daemon says which two it introduced" \
        "nothing in the log names the pair, so an operator reading it cannot" \
        "tell a build with links from one without"
fi

"$BIN" stop pl_srv >/dev/null 2>&1; "$BIN" remove pl_srv >/dev/null 2>&1
"$BIN" stop pl_cache >/dev/null 2>&1; "$BIN" remove pl_cache >/dev/null 2>&1
daemon_stop

# ── 3. A sharded target is wired at shard 0 ────────────────────────────────
daemon_isolate peerlinksharded
daemon_start "$BIN"
# Twenty up, because the four shards also bind the four ports above it, where pl_ss and pl_c2 sit.
"$BIN" create cache  pl_sc -p $((PORT+20)) --shards 4 -s >/dev/null 2>&1
"$BIN" create server pl_ss -p $((PORT+5)) --cache pl_sc -s >/dev/null 2>&1
sleep 2
say "cache set sk sv" $((PORT+5)) >/dev/null
sleep 1
SGOT=$(say "cache get sk" $((PORT+5)))
for i in $(seq 1 10); do say "cache get sk" $((PORT+5)) >/dev/null; done
sleep 3
SLINKS=$(counter pl_ss peer_links)
if [ "$SGOT" = "sv" ] && [ "$SLINKS" -eq 1 ]; then
    ok "a sharded target is linked at shard 0 and answers (peer_links $SLINKS)"
else
    bad "a sharded target is linked at shard 0 and answers" \
        "get said '${SGOT:-<nothing>}', peer_links is $SLINKS, expected 1;" \
        "the daemon sends the bare name to shard 0 either way, so a link there" \
        "replaces its leg without touching the cache's own routing"
fi
"$BIN" stop pl_ss >/dev/null 2>&1; "$BIN" remove pl_ss >/dev/null 2>&1
"$BIN" stop pl_sc >/dev/null 2>&1; "$BIN" remove pl_sc >/dev/null 2>&1
daemon_stop

# ── 4. The arm every measurement compares against ──────────────────────────
daemon_isolate peerlinksoff
export SOCKETLEY_NO_PEER_LINKS=1
daemon_start "$BIN"
"$BIN" create cache  pl_c2 -p $((PORT+8))         -s >/dev/null 2>&1
"$BIN" create server pl_s2 -p $((PORT+9)) --cache pl_c2 -s >/dev/null 2>&1
sleep 1.5
say "cache set ok ov" $((PORT+9)) >/dev/null
sleep 0.5
OGOT=$(say "cache get ok" $((PORT+9)))
for i in $(seq 1 10); do say "cache get ok" $((PORT+9)) >/dev/null; done
sleep 3
OLINKS=$(counter pl_s2 peer_links)
if [ "$OGOT" = "ov" ] && [ "$OLINKS" -eq 0 ]; then
    ok "with links disabled the same value still crosses (peer_links $OLINKS)"
else
    bad "with links disabled the same value still crosses" \
        "get said '${OGOT:-<nothing>}', peer_links is $OLINKS;" \
        "the control arm has to be known-good or no measurement against it means anything"
fi
unset SOCKETLEY_NO_PEER_LINKS
"$BIN" stop pl_s2 >/dev/null 2>&1; "$BIN" remove pl_s2 >/dev/null 2>&1
"$BIN" stop pl_c2 >/dev/null 2>&1; "$BIN" remove pl_c2 >/dev/null 2>&1
daemon_stop

# ── 5. A REPLACED link is armed under its own name ─────────────────────────
#
# When a peer restarts, the daemon grants a fresh link and adopt_peer_link()
# pushes it BEHIND the live entry it replaces -- one grant at a time per peer,
# so at most two entries ever share a name and the one to retire is always at
# the lower index.
#
# arm_pending_peers() used to walk m_peer_links with a range-for while an inner
# loop erased from the SAME vector, holding the outer reference across it.
# erase() moves the later elements down and destroys the last slot, which is
# exactly the slot the reference named, so the three statements after the inner
# loop read and wrote a moved-from entry.  Measured, the signature is a log line
# with no runtime in it at all:
#
#     peer links: pp_srv is now one socket away
#     peer links:  is now one socket away        <- the dead entry
#     peer links: pp_cache is now one socket away
#
# five lines where a healthy run has four, because the real link is armed on a
# later pass instead.
#
# Asserted on the log rather than on the counters, and not on the sanitizer:
# ASan is SILENT here.  The read is inside the vector's own buffer, past size()
# and onto a destroyed object, which it only sees with
# _GLIBCXX_SANITIZE_VECTOR -- and premake5.lua does not set it.
daemon_isolate peerlinkreplace
daemon_start "$BIN"
"$BIN" create cache  pl_rc -p $((PORT+12))         -s >/dev/null 2>&1
"$BIN" create server pl_rs -p $((PORT+13)) --cache pl_rc -s >/dev/null 2>&1
sleep 1.5
say "cache set rk rv" $((PORT+13)) >/dev/null
for i in $(seq 1 15); do say "cache get rk" $((PORT+13)) >/dev/null; done
sleep 3

FIRST_LINKS=$(counter pl_rs peer_links)
if [ "$FIRST_LINKS" -eq 1 ]; then
    ok "a link is up before the peer restarts (peer_links $FIRST_LINKS)"
else
    bad "a link is up before the peer restarts" \
        "peer_links is $FIRST_LINKS -- with no first link there is no" \
        "replacement to test and everything below measures nothing"
fi

# The peer goes and comes back, so the daemon has a fresh link to grant to the
# server's worker, which has not restarted and still holds the old entry.
"$BIN" restart pl_rc >/dev/null 2>&1
sleep 2
say "cache set rk2 rv2" $((PORT+13)) >/dev/null
for i in $(seq 1 25); do say "cache get rk2" $((PORT+13)) >/dev/null; done
sleep 4

RGOT=$(say "cache get rk2" $((PORT+13)))
if [ "$RGOT" = "rv2" ]; then
    ok "the value still crosses after the peer restarted"
else
    bad "the value still crosses after the peer restarted" \
        "get said '${RGOT:-<nothing>}'"
fi

NAMELESS=$(grep -c "peer links:  is now" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "${NAMELESS:-0}" -eq 0 ]; then
    ok "every armed link is named in the log"
else
    bad "every armed link is named in the log" \
        "$NAMELESS line(s) read 'peer links:  is now one socket away' with no" \
        "runtime in them -- that empty string is a moved-from peer_entry, read" \
        "through a reference that did not survive an erase from its own vector"
fi

# And the replacement really is the one that got armed: the last arming line
# names the peer, rather than the peer being armed before the empty pass.
LAST_ARM=$(grep -o "peer links: [a-z_0-9]* is now one socket away" "$SOCKETLEY_DLOG" 2>/dev/null | tail -1)
if [ -n "$LAST_ARM" ]; then
    ok "the last link armed carries a name ($LAST_ARM)"
else
    bad "the last link armed carries a name" \
        "no complete arming line in the log at all"
fi

"$BIN" stop pl_rs >/dev/null 2>&1; "$BIN" remove pl_rs >/dev/null 2>&1
"$BIN" stop pl_rc >/dev/null 2>&1; "$BIN" remove pl_rc >/dev/null 2>&1
daemon_stop

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
