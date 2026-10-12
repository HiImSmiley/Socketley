#!/usr/bin/env bash
# suite: isolated
# Integration test: a runtime the daemon only holds costs it no connection table.
#
# A proxy indexes its connections by descriptor, in a table sized for the most a
# process may hold.  Written as a plain member array it is a megabyte of zeroes
# written at construction, so every instance pays it whole the moment it exists
# -- including the placeholder the daemon keeps for a runtime whose worker is the
# one serving, which never accepts a connection at all.  Measured before this:
# 2,068 kB of the daemon per proxy, one shard or four, and six proxies on a live
# box held 12 MB of the daemon in tables nothing would ever read.
#
# The table now comes from calloc, which the kernel hands over already zero and
# makes resident a page at a time as descriptors are used.  What this asserts is
# the property, not the figure: what a proxy adds to the DAEMON, against what it
# would cost if the table were written out in full.  A worker's own table is not
# the subject -- it is the one process that does index connections by descriptor.
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: the daemon holds no connection tables ==="
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

daemon_isolate dtables
trap 'daemon_stop' EXIT
daemon_start "$BIN"

# The daemon's own pid, not a worker's: the socket is this run's, from mktemp.
dpid() {
    for p in $(pgrep -x socketley 2>/dev/null || true); do
        grep -qz "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" "/proc/$p/environ" 2>/dev/null || continue
        case "$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)" in *" daemon"*|*" daemon ") echo "$p"; return;; esac
    done
}
D=$(dpid)
anon() { awk '/^RssAnon/{print $2}' "/proc/$D/status" 2>/dev/null || echo 0; }
if [ -z "${D:-}" ] || ! [ "$(anon)" -gt 0 ] 2>/dev/null; then
    echo "  FATAL: no daemon pid or no RssAnon for it, so no figure below means anything"
    echo "  Results: 0/0 passed (0 failed)"; exit 2
fi

# A table of 65,536 descriptors, as the proxy sizes it; what one costs written out in full.
TABLE=$((65536 * 16 / 1024))
N=4
P=$((SL_PORT_BASE + 1760))
BEFORE=$(anon)
for i in $(seq 1 $N); do
    "$BIN" create proxy "dt$i" -p $((P + i)) --bind 127.0.0.1 --backend "127.0.0.1:$((P))" -s >/dev/null 2>&1
done
# Every one of them up, or the figure is of however many happened to be.
up=0
for _ in $(seq 1 150); do
    up=0
    for i in $(seq 1 $N); do ss -ltn 2>/dev/null | grep -q ":$((P + i)) " && up=$((up + 1)); done
    [ "$up" = "$N" ] && break
    sleep 0.1
done
sleep 1
AFTER=$(anon)
EACH=$(( (AFTER - BEFORE) / N ))

if [ "$up" != "$N" ]; then
    bad "every proxy came up" "only $up of $N are listening, so the daemon's growth is not $N proxies'"
else ok; fi

# A quarter of one table is the line, where three of them written out is what a
# proxy used to cost: measured after, 29 kB, so there is room on both sides and
# the figure itself is not what is being asserted.
LINE=$((TABLE / 4))
if [ "$EACH" -lt "$LINE" ]; then
    echo "  a proxy adds ${EACH} kB to the daemon (a quarter of one descriptor table is ${LINE} kB)"
    ok
else
    bad "a proxy the daemon only holds does not cost it a descriptor table" \
        "${EACH} kB each, against ${LINE} kB, a quarter of one table written out in full"
fi

# And the daemon gives it back: the growth is the runtimes', not the daemon's own.
for i in $(seq 1 $N); do "$BIN" remove "dt$i" --force >/dev/null 2>&1; done
sleep 1
ENDED=$(anon)
if [ "$ENDED" -lt "$((BEFORE + N * TABLE))" ]; then ok
else bad "the daemon lets the runtimes' memory go again" "$BEFORE kB before, $AFTER with them, $ENDED after they were removed"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ]
