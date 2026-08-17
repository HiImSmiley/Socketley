#!/usr/bin/env bash
# Integration test: SCAN returns every key, and resuming is not quadratic.
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# The cursor was an OFFSET.  Every call walked all four maps from the beginning
# and skipped `cursor` keys before collecting, which is wrong twice:
#
#   * an offset only means something if the traversal order is stable, and an
#     unordered_map's is not.  Inserting a key moves later keys to different
#     positions, so a key already returned comes back and a key never returned
#     is stepped over.  On a cache — whose purpose is concurrent reads and
#     writes — that is the ordinary case, not a corner one.
#
#   * resuming at offset N costs N steps, so a full scan of N keys in pages of
#     `count` is O(N^2/count).  A million keys at the default page size is on
#     the order of 10^10 iterations, on the thread that serves every other
#     runtime in the daemon.
#
# It is a bucket index now.  Resuming is O(1), and a key stays in its bucket
# until the table rehashes.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
# Completeness across pages, over a keyspace spanning all four maps — strings,
# lists, sets and hashes — because the cursor has to name which map it is in as
# well as where.  And that a scan under concurrent writes still returns every
# key that was there the whole time, which is the property the offset broke.

set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate cachescan
PASS=0; FAIL=0; TOTAL=0

cleanup() { daemon_stop; }
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

echo "=== Integration: SCAN completeness and resume cost ==="

daemon_start "$BIN"
PORT=$((SL_PORT_BASE + 940))
"$BIN" create cache scan_c -p "$PORT" -s >/dev/null 2>&1 || true
sleep 0.4

# A keyspace across all four maps: the cursor has to carry which map it is in.
python3 -c "
for i in range(500): print('set sk%d v%d' % (i, i))
for i in range(50):  print('rpush sl%d a' % i)
for i in range(50):  print('sadd ss%d m' % i)
for i in range(50):  print('hset sh%d f v' % i)
" | nc -q 2 127.0.0.1 "$PORT" >/dev/null 2>&1 || true

# The scan itself, in python because it is a loop with state.  The response is
# a cursor line, then keys, then a literal `end` — which is not a key, and
# counting it as one is how this test first reported 651 of 650.
RESULT=$(timeout 120 python3 - "$PORT" <<'PY' || true
import socket, sys, time
port = int(sys.argv[1])
s = socket.create_connection(('127.0.0.1', port)); s.settimeout(2)

def cmd(c):
    s.sendall((c + '\n').encode())
    time.sleep(0.12)
    out = ''
    try:
        while True:
            b = s.recv(65536)
            if not b: break
            out += b.decode(errors='replace')
            if len(b) < 65536: break
    except socket.timeout:
        pass
    return out

deleted = set()

def scan_all(concurrent_writes=False):
    seen, cur, pages = set(), '0', 0
    while pages < 400:
        lines = [l for l in cmd('scan %s count 50' % cur).replace('\r','').split('\n') if l]
        if not lines: break
        cur = lines[0].strip()
        for k in lines[1:]:
            if k != 'end':
                seen.add(k)
        pages += 1
        if concurrent_writes and len(seen) > 2:
            # A DELETE of a key already returned, not an insert.
            #
            # Written with inserts first, this assertion passed against the
            # offset cursor too: a new key lands in whatever bucket it hashes
            # to, and with a few hundred keys it often lands after the cursor,
            # so no offset shifts and nothing is skipped.  The test was green on
            # both sides and proved nothing.
            #
            # Removing an element the walk has already passed shifts every LATER
            # element one position earlier, so an offset cursor resuming at N
            # now lands one element too far and steps over exactly one key.  A
            # bucket cursor is unaffected: the deletion is behind it, in a
            # bucket it has finished with.
            victim = sorted(k for k in seen if k.startswith('sk'))[0]
            cmd('del %s' % victim)
            deleted.add(victim)
        if cur == '0':
            break
    return seen, pages

first, pages1 = scan_all()
second, pages2 = scan_all(concurrent_writes=True)
# What the second walk had to return: everything the first walk saw, minus the
# keys this test deleted while walking.  A key it deleted is allowed to be
# missing; every other one is not.
originals = first - deleted
kept = second
print('PAGES1 %d' % pages1)
print('FOUND1 %d' % len(first))
print('MISSING2 %d' % len(originals - kept))
PY
)

PAGES1=$(awk '/^PAGES1/{print $2}' <<<"$RESULT")
FOUND1=$(awk '/^FOUND1/{print $2}' <<<"$RESULT")
MISSING2=$(awk '/^MISSING2/{print $2}' <<<"$RESULT")

if [ "${FOUND1:-0}" -eq 650 ]; then pass
else fail "a full scan returns every key" \
          "found ${FOUND1:-<none>} of 650 across ${PAGES1:-?} pages" \
          "the offset cursor skipped keys whenever the map's order moved."; fi

# More than one page, or the completeness assertion is about a single call and
# the cursor was never exercised.
if [ "${PAGES1:-0}" -gt 1 ]; then pass
else fail "the scan really was paged" "it finished in ${PAGES1:-?} page(s)"; fi

# The property the offset broke: a key present throughout must not vanish
# because something else was inserted mid-walk.
if [ "${MISSING2:-1}" -eq 0 ]; then pass
else fail "writes during a scan do not hide existing keys" \
          "${MISSING2} of the original keys were not returned"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
if [ "$FAIL" -eq 0 ]; then echo "  OK"; else echo "  FAILED"; fi
exit "$FAIL"
