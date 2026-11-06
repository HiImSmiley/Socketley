#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a cache shard's journal stays bounded under a write load that never stops, and a kill -9 at any
# point -- between snapshots or with one cut short -- still brings back every write.
#
# The journal was cut only by a clean stop, FLUSH or LOAD, so a cache that ran for a month journaled a month, and the
# start after an unclean stop replayed all of it.  A shard now snapshots once its journal passes
# max(SOCKETLEY_CACHE_SNAPSHOT_MB, its last dump), from a forked child, and keeps only what came after.
#
# What it would catch:
#   * bounded              the journal files, sampled through a load that writes eight times the bound per shard, stay
#                          under three times the bound; without snapshots they reach eight
#   * snapshots counted    both shards report journal_snapshots > 0 and no failures
#   * every write back     after kill -9 every key holds its last value and every counter its count: an INCR replayed
#                          twice (a snapshot that kept what it absorbed) or lost (one that cut what it did not) is off
#   * failed               a snapshot whose dump cannot be written leaves its set-aside journal and is counted, and a
#                          kill -9 then still brings back every write, the set-aside ones replayed before the journal
#   * served meanwhile     the load is answered in full while snapshots run
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ [[ "$2" == "$3" ]] && ok "$1 ($2)" || bad "$1: expected '$3', got '$2'"; }

echo "=== Integration: a cache shard snapshots its journal on its own ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_isolate cachejsnap
P=$((SL_PORT_BASE + 1720))
WORK=$(mktemp -d /tmp/skl-jsnap-XXXXXX)
DUMP="$WORK/s.rdb"
CLIENT="$WORK/client.py"
trap '"$BIN" stop js >/dev/null 2>&1; sleep 0.3; "$BIN" remove js >/dev/null 2>&1; daemon_stop; rm -rf "$WORK"' EXIT

cat > "$CLIENT" <<'PY'
import os, socket, sys, time
port, what, dump = int(sys.argv[1]), sys.argv[2], sys.argv[3]
KEYS, VAL = 200, 1000

def resp(*a):
    out = b'*%d\r\n' % len(a)
    for x in a:
        x = x if isinstance(x, bytes) else str(x).encode()
        out += b'$%d\r\n%s\r\n' % (len(x), x)
    return out

def replies(s, n):
    buf, got, out = b'', 0, []
    while len(out) < n:
        d = s.recv(1 << 16)
        if not d:
            raise EOFError
        buf += d
        while True:
            i = buf.find(b'\r\n')
            if i < 0:
                break
            if buf[:1] == b'$' and buf[1:2] != b'-':
                ln = int(buf[1:i])
                if len(buf) < i + 4 + ln:
                    break
                out.append(buf[i + 2:i + 2 + ln]); buf = buf[i + 4 + ln:]
            else:
                out.append(buf[:i]); buf = buf[i + 2:]
    return out

def journals():
    # A snapshot removes what it set aside at any moment, the moment between the listing and the size included.
    d, out = os.path.dirname(dump), {}
    for n in os.listdir(d):
        if '.journal' in n:
            try:
                out[n] = os.path.getsize(os.path.join(d, n))
            except FileNotFoundError:
                pass
    return out

def load(first, rounds):
    # Every key rewritten each round, with the round in its value, and one counter per key tag incremented once.
    s = socket.create_connection(('127.0.0.1', port), timeout=30)
    peak = 0
    for r in range(first, first + rounds):
        s.sendall(b''.join(resp('SET', 'k:%d' % i, (b'%08d' % r) + b'v' * (VAL - 8)) for i in range(KEYS)) +
                  b''.join(resp('INCR', 'c:%d' % i) for i in range(8)))
        got = replies(s, KEYS + 8)
        if got[:KEYS] != [b'+OK'] * KEYS:
            print('refused', r, got[:3]); return
        peak = max([peak] + [v for n, v in journals().items() if n.endswith('.journal')])
    print('peak', peak)

def verify(rounds):
    s = socket.create_connection(('127.0.0.1', port), timeout=30)
    s.sendall(b''.join(resp('GET', 'k:%d' % i) for i in range(KEYS)) + b''.join(resp('GET', 'c:%d' % i) for i in range(8)))
    got = replies(s, KEYS + 8)
    want = b'%08d' % (rounds - 1)
    stale = sum(1 for v in got[:KEYS] if not v.startswith(want))
    counts = sorted(set(got[KEYS:]))
    print('stale', stale, 'counts', b','.join(counts).decode())

if what == 'load':
    load(int(sys.argv[4]), int(sys.argv[5]))
elif what == 'verify':
    verify(int(sys.argv[4]))
elif what == 'asides':
    print(sum(1 for n in journals() if not n.endswith('.journal')))
PY

client() { timeout 120 python3 -I "$CLIENT" "$P" "$1" "$DUMP" "${@:2}" 2>&1 | tail -1; }
# Every shard listens on the shared port, and a snapshot child holds none of a worker's sockets.
pids()   { ss -Hltnp "sport = :$P" 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u | tr '\n' ' '; }
figure() { "$BIN" stats js 2>/dev/null | awk -F: -v f="$1" '$1==f {s+=$2; n++; if ($2+0 > 0) p++} END{print s+0, n+0, p+0}'; }
wait_up(){ local i; for i in $(seq 1 120); do
    python3 -c "import socket;s=socket.create_connection(('127.0.0.1',$P),timeout=1);s.sendall(b'*1\r\n\$4\r\nPING\r\n');assert s.recv(64)==b'+PONG\r\n'" 2>/dev/null && return 0
    sleep 0.25; done; return 1; }
kill_workers() {
    local p ps i alive
    ps=$(pids); [ -n "$ps" ] || return 1
    for p in $ps; do grep -qa socketley "/proc/$p/cmdline" 2>/dev/null && kill -9 "$p" 2>/dev/null; done
    for i in $(seq 1 40); do
        alive=0; for p in $ps; do kill -0 "$p" 2>/dev/null && alive=1; done
        [ "$alive" = 0 ] && return 0; sleep 0.25
    done
    return 1
}
revive() { wait_up && return 0; "$BIN" start js >/dev/null 2>&1; wait_up; }
# Run with the client's arguments: "load first rounds" -> stdout of the client; called in the parent shell.
run() { client "$@"; }

SOCKETLEY_CACHE_SNAPSHOT_MB=1 daemon_start "$BIN"
"$BIN" create cache js -p "$P" --shards 2 --persistent "$DUMP" --persistent-interval 1s -s >/dev/null 2>&1 \
    || bad "a two-shard cache with a journal is made"
wait_up || bad "it answers"

# ─── bounded, and every write back after kill -9 ───────────────────────────
# 80 rounds of 200 KB is about 8 MiB of journal per shard against a bound of 1 MiB.
OUT=$(run load 0 80)
echo "    $OUT"
PEAK=$(echo "$OUT" | awk '$1=="peak" {print $2}')
if [[ "$PEAK" =~ ^[0-9]+$ ]] && [ "$PEAK" -lt $((3 << 20)) ]; then
    ok "the journal stays under three times its bound through the load (peak $PEAK bytes)"
else
    bad "the journal stays under three times its bound through the load: peak ${PEAK:-?} ($OUT)"
fi
sleep 1.5
read -r SN SHARDS SPOS <<< "$(figure journal_snapshots)"
if [ "$SHARDS" = 2 ] && [ "$SPOS" = 2 ]; then ok "both shards snapshotted on their own ($SN in all)"
else bad "both shards snapshotted on their own: total $SN, $SPOS of $SHARDS shards"; fi
check "no snapshot failed" "$(figure journal_snapshot_failures | awk '{print $1}')" "0"

kill_workers || bad "the workers are killed"
revive || bad "the cache comes back after kill -9"
check "every key and counter after kill -9" "$(run verify 80)" "stale 0 counts 80"

# ─── snapshots that fail, then kill -9 ─────────────────────────────────────
# A directory where each shard's dump is first written makes every snapshot fail, so what each set aside stays.
mkdir "$DUMP.shard0.tmp" "$DUMP.shard1.tmp"
OUT=$(run load 80 40)
echo "    $OUT"
sleep 1.5
ASIDES=$(run asides)
if [[ "$ASIDES" =~ ^[0-9]+$ ]] && [ "$ASIDES" -ge 2 ]; then ok "a failed snapshot leaves what it set aside ($ASIDES file(s))"
else bad "a failed snapshot leaves what it set aside: ${ASIDES:-?}"; fi
read -r FN _ FPOS <<< "$(figure journal_snapshot_failures)"
if [ "$FPOS" = 2 ]; then ok "and both shards count it ($FN)"; else bad "and both shards count it: $FN, $FPOS shard(s)"; fi
kill_workers || bad "the workers are killed with snapshots set aside"
rmdir "$DUMP.shard0.tmp" "$DUMP.shard1.tmp"
revive || bad "the cache comes back"
check "every key and counter after failed snapshots" "$(run verify 120)" "stale 0 counts 120"

# And the next snapshot or a clean stop absorbs what was set aside.
"$BIN" stop js >/dev/null 2>&1
for i in $(seq 1 40); do [ -z "$(pids)" ] && break; sleep 0.25; done     # stop answers before the workers are down
check "a clean stop absorbs every set-aside journal" "$(run asides)" "0"

echo "  Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
