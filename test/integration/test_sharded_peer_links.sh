#!/usr/bin/env bash
# Integration test: a sharded runtime's crossings go direct too.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# The daemon refused a peer link to any runtime with more than one worker:
#
#     // The asking side must be one worker: N shards asking would give the far
#     // side N links under one name, and the name is how a routing frame finds
#     // the link to send itself on.
#
# The objection was real and the answer was to give up, so every shard of every
# sharded runtime relayed every crossing through the daemon -- 10.49 us of round
# trip and 10.75 us of CPU per request, for the life of the runtime, and not
# just until things fell quiet.
#
# A link is now granted per shard and the far side registers it as `origin#k`.
# conn_ref carries its minting shard in the top six bits of its serial, so the
# ref itself says which link a frame belongs on, which is what the bare name
# could not say for N of them.
#
# The assertion is peer_direct, not peer_links.  A link that exists and carries
# nothing is what the old code would have produced if the refusal had simply
# been deleted: arm_pending_peers() waits for a quiet turn before switching, and
# a link nobody uses is not the fix.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: peer links for a sharded runtime ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

PC=$((SL_PORT_BASE+1414))
PS=$((SL_PORT_BASE+1415))
PU=$((SL_PORT_BASE+1416))

daemon_isolate shardedpeerlinks
trap 'daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

# NO script, and that is the point rather than a shortcut: a runtime linked
# with --cache crosses to it on every message by itself.  The first version of
# this file carried a Lua fixture that called cache.set() -- which is nil in a
# server script, `cache` being the cache runtime's own alias for self -- so it
# raised on every message and the crossings being counted were never the ones
# the fixture claimed to make.  They were real; the fixture was not.
"$BIN" create cache spl_c -p "$PC" -s >/dev/null 2>&1
sleep 1.2
"$BIN" create server spl_s -p "$PS" --shards 4 --cache spl_c --mode inout -s >/dev/null 2>&1
"$BIN" create server spl_u -p "$PU"            --cache spl_c --mode inout -s >/dev/null 2>&1
sleep 2

# Concurrent, and repeated with a pause: the grant is offered when the daemon
# sees crossings, and the switch to the link waits for a turn with nothing
# outstanding.  One burst gives the first and not the second.
load() {   # load PORT
    python3 -c "
import socket, threading
def one(i):
    try:
        s = socket.create_connection(('127.0.0.1', $1), timeout=3)
        for j in range(20):
            s.sendall(('m%d-%d\n' % (i, j)).encode())
        s.close()
    except Exception:
        pass
ts = [threading.Thread(target=one, args=(i,)) for i in range(32)]
for t in ts: t.start()
for t in ts: t.join()" 2>/dev/null
}
for _ in 1 2 3; do load "$PS"; load "$PU"; sleep 2; done

# One line per shard, in shard order.
col() { "$BIN" stats "$1" 2>/dev/null | sed -n "s/^$2:\([0-9][0-9]*\)$/\1/p" | tr '\n' ' '; }

LINKS=$(col spl_s peer_links)
DIRECT=$(col spl_s peer_direct)
BUSY=$(printf '%s\n' $DIRECT | awk '$1 > 0 { n++ } END { print n+0 }')
LINKED=$(printf '%s\n' $LINKS | awk '$1 > 0 { n++ } END { print n+0 }')
GRANTS=$(grep -c "now cross directly" "$SOCKETLEY_DLOG" 2>/dev/null || true)

if [ "$LINKED" -eq 4 ] && [ "$BUSY" -eq 4 ]; then
    ok "all 4 shards hold a link and all 4 crossed directly (direct: $DIRECT)"
else
    bad "every shard of a sharded runtime gets its own link" \
        "links per shard: ${LINKS:-<none>} ($LINKED of 4), direct per shard: ${DIRECT:-<none>} ($BUSY of 4)," \
        "the daemon granted $GRANTS link(s);" \
        "0 links is the old refusal -- the asking side had to be one worker, so every" \
        "shard relayed every crossing through the daemon for the life of the runtime"
fi

# The grants name the shard, which is what makes N of them distinguishable on
# the far side.
NAMED=$(grep -c "peer links: spl_s#[0-9] and spl_c" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "${NAMED:-0}" -ge 4 ]; then
    ok "the far side registered them one per shard ($NAMED named grants)"
else
    bad "a sharded origin's links are named per shard" \
        "the log named spl_s#k $NAMED time(s), expected at least 4;" \
        "N links under one bare name are N answers to one question, which is the" \
        "objection the old refusal was answering"
fi

# The unsharded case is unchanged, so a build that started handing links to
# everything indiscriminately would not pass by accident.
ULINK=$(col spl_u peer_links)
UDIRECT=$(col spl_u peer_direct)
if [ "${ULINK% }" = "1" ] && [ "${UDIRECT% }" != "0" ]; then
    ok "an unsharded runtime still gets exactly one link and uses it (direct: ${UDIRECT% })"
else
    bad "the unsharded case is unchanged" \
        "links '${ULINK:-<none>}' direct '${UDIRECT:-<none>}', expected 1 and non-zero"
fi

for n in spl_s spl_u spl_c; do
    "$BIN" stop "$n" >/dev/null 2>&1; "$BIN" remove "$n" >/dev/null 2>&1
done
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
