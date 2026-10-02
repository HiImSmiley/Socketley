#!/usr/bin/env bash
# Integration test: a sharded storage runtime stopped under load and started
# again under another shard count loses nothing and leaves no marker behind.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
# Sixteen clients put small objects and overwrite keys of their own through the
# shared port while `stop` lands; the shard count is edited and the runtime
# started at once, going 4 -> 2 -> 4 -> 2, and then 2 again.  The old shards are
# still finishing their stops when the new ones open, and a new shard reads and
# takes over files that old shards of other numbers owned, so a new shard waits
# until every old shard under the other count has let go.  Held down per round:
#
#   start      the start right after the stop succeeds
#   answered   every put answered before the stop is read back by the new split
#   markers    no .clean.<n> is left in the directory while the new split runs,
#              which a stop finishing after the new shards opened would leave,
#              and the next start after a crash would then trust
#   clean      under the same count, every shard's start trusts its journal: a
#              put waiting on a sibling when the stop came is answered as failed
#              rather than holding the stop past its second
#
# The old shards' stops are held past their drains (SOCKETLEY_STORAGE_STOP_HOLD_MS,
# longer the higher the shard), so a new shard that did not wait for the old
# shards under the other count would open before shards 2 and 3 of four wrote
# their markers.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgreshard

PORT=$((SL_PORT_BASE+1646))
DATA="$SOCKETLEY_TMPD/objects"
FAILS=0

cleanup() {
    "$BIN" stop stgrs >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove stgrs >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

ok()  { echo "  ok: $1"; }
bad() { echo "  FAIL [$1]: $2"; FAILS=$((FAILS+1)); }

up() {
    for _ in $(seq 1 100); do
        curl -s -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

echo "=== Integration: a sharded storage runtime stopped under load and started under another count ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }

# Shard k's stop is held 150 ms x (k+1) past its drain, so the old shards let go one by one while the new ones open.
SOCKETLEY_STORAGE_COMPACT_FLOOR=16 SOCKETLEY_STORAGE_STOP_HOLD_MS=150 daemon_start "$BIN"
if ! "$BIN" create storage stgrs -p "$PORT" --dir "$DATA" --anonymous --shards 4 -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
up || { echo "  FAIL [up]: the runtime never answered"; exit 1; }
curl -s -o /dev/null -X PUT "http://127.0.0.1:$PORT/bkt"

r=0
prev=4
for n in 2 4 2 2; do
    r=$((r+1))
    ACKED="$SOCKETLEY_TMPD/acked.$r"
    # Clients put until the runtime stops answering, each answered key written down.
    python3 - "$PORT" "$r" "$ACKED" <<'EOF' &
import http.client, sys, threading
port, rnd, acked = int(sys.argv[1]), sys.argv[2], sys.argv[3]
lock = threading.Lock()
done = []
def client(t):
    n = 0
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        while True:
            hot = n % 4 != 0
            key = "hot-%d" % t if hot else "k-%s-%d-%d" % (rnd, t, n)
            c.request("PUT", "/bkt/" + key, body=("%s-%d-%d" % (rnd, t, n)).encode())
            resp = c.getresponse()
            resp.read()
            if resp.status == 200 and not hot:
                with lock:
                    done.append(key)
            n += 1
    except Exception:
        pass
ts = [threading.Thread(target=client, args=(t,)) for t in range(16)]
for t in ts: t.start()
for t in ts: t.join()
with open(acked, "w") as f:
    f.write("\n".join(done))
EOF
    LOAD=$!
    sleep 1

    "$BIN" stop stgrs >/dev/null 2>&1 || bad "round $r: stop" "stop failed"
    LOGGED=$(wc -l < "$SOCKETLEY_DLOG")
    same=0
    if [ "$n" -eq "$prev" ]; then
        same=1
    else
        "$BIN" edit stgrs --shards "$n" >/dev/null 2>&1 || bad "round $r: edit" "the shard count was not edited to $n"
    fi
    prev=$n
    if ! "$BIN" start stgrs >/dev/null 2>&1; then
        bad "round $r: start" "the start under $n shards right after the stop failed: $(tail -3 "$SOCKETLEY_DLOG" | tr '\n' ' ')"
        wait "$LOAD"
        continue
    fi
    wait "$LOAD"
    up || { bad "round $r: up" "the runtime did not answer under $n shards"; continue; }
    ok "round $r: started under $n shards right after the stop"

    # Past the longest any old shard's stop may take, so a marker it would write is there to be seen.
    sleep 2
    STALE=$(cd "$DATA" && ls -a | grep '^\.clean\.' | tr '\n' ' ')
    [ -z "$STALE" ] && ok "round $r: no marker is left while the $n shards run" \
                    || bad "round $r: markers" "left behind while the new split runs: $STALE"

    if [ "$same" -eq 1 ]; then
        CLEAN=$(tail -n +"$((LOGGED+1))" "$SOCKETLEY_DLOG" | grep -c '(clean stop)'); CLEAN=${CLEAN:-0}
        [ "$CLEAN" -eq "$n" ] && ok "round $r: every one of the $n shards started clean after a stop under load" \
                              || bad "round $r: clean" "$CLEAN of $n shards started clean after the stop"
    fi

    N=$(grep -c . "$ACKED" 2>/dev/null); N=${N:-0}
    MISSING=$(python3 - "$PORT" "$SOCKETLEY_TMPD" "$r" <<'EOF'
import http.client, sys
c = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=10)
gone = 0
for rnd in range(1, int(sys.argv[3]) + 1):
    for k in open("%s/acked.%d" % (sys.argv[2], rnd)).read().split():
        c.request("HEAD", "/bkt/" + k)
        r = c.getresponse()
        r.read()
        gone += r.status != 200
print(gone)
EOF
)
    if [ "${MISSING:-x}" = "0" ] && [ "$N" -gt 0 ]; then
        ok "round $r: $N answered puts this round, and every answered put of every round reads back"
    else
        bad "round $r: answered" "${MISSING:-?} answered puts are gone ($N this round)"
    fi
done

if [ "$FAILS" -ne 0 ]; then
    echo "  FAILED ($FAILS)"
    exit 1
fi
echo "  PASSED"
exit 0
