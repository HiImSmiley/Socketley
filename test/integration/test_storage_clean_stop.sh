#!/usr/bin/env bash
# Integration test: a storage runtime stopped in the middle of a burst of puts
# starts again clean.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
# Sixteen clients put small objects as fast as they are answered, beside
# overwrites of one key that keep the journal compacting (the floor is lowered
# to 16 records), and `stop` lands while they do: answered puts still syncing
# their directories, journal records being written and a compaction under way.
# The stop lets that work finish, so the next start trusts the journal and reads
# no object file (start_files_read 0, "clean stop" in the log), the restart
# waits for the old worker to let go of the directory rather than failing, and
# every put answered before the stop reads back.  Three rounds.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgclean

PORT=$((SL_PORT_BASE+1645))
DATA="$SOCKETLEY_TMPD/objects"
ROUNDS=3
FAILS=0

cleanup() {
    "$BIN" stop stgc >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove stgc >/dev/null 2>&1 || true
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

# A figure from the worker now serving, not from the one that was stopped.
stat_of() {
    "$BIN" stats stgc 2>/dev/null | sed -n "s/^$1://p"
}

echo "=== Integration: a storage runtime stopped mid-burst starts again clean ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }

SOCKETLEY_STORAGE_COMPACT_FLOOR=16 daemon_start "$BIN"
if ! "$BIN" create storage stgc -p "$PORT" --dir "$DATA" --anonymous -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
up || { echo "  FAIL [up]: the runtime never answered"; exit 1; }
curl -s -o /dev/null -X PUT "http://127.0.0.1:$PORT/bkt"

for r in $(seq 1 "$ROUNDS"); do
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

    # Running long enough that compactions are happening when the stop lands.
    for _ in $(seq 1 50); do
        C=$(stat_of journal_compactions)
        [ "${C:-0}" -gt 0 ] 2>/dev/null && break
        sleep 0.1
    done
    sleep 0.3
    [ "${C:-0}" -gt 0 ] 2>/dev/null || bad "round $r: compacting" "no compaction while the clients ran (journal_compactions=${C:-?})"
    OLD=$(stat_of pid)

    "$BIN" stop stgc >/dev/null 2>&1 || bad "round $r: stop" "stop failed"
    wait "$LOAD"
    if ! "$BIN" start stgc >/dev/null 2>&1; then
        bad "round $r: start" "the start right after the stop failed: $(tail -3 "$SOCKETLEY_DLOG" | tr '\n' ' ')"
        continue
    fi
    up || { bad "round $r: up" "the runtime did not answer after the start"; continue; }
    NEW=""
    for _ in $(seq 1 100); do
        NEW=$(stat_of pid)
        [ -n "$NEW" ] && [ "$NEW" != "$OLD" ] && break
        sleep 0.1
    done

    N=$(grep -c . "$ACKED" 2>/dev/null); N=${N:-0}
    READ="the stopped worker's"
    [ -n "$NEW" ] && [ "$NEW" != "$OLD" ] && READ=$(stat_of start_files_read)
    if [ "${READ:-x}" = "0" ] && [ "$N" -gt 0 ]; then
        ok "round $r: $N answered puts, and the start after the stop read no object file"
    else
        bad "round $r: clean" "the start after the stop read ${READ:-?} object files ($N answered puts)"
    fi
    CLEAN=$(grep -c '(clean stop)' "$SOCKETLEY_DLOG" 2>/dev/null); CLEAN=${CLEAN:-0}
    [ "$CLEAN" -ge "$r" ] || bad "round $r: log" "$CLEAN starts logged a clean stop after $r stops"

    MISSING=$(python3 - "$PORT" "$ACKED" <<'EOF'
import http.client, sys
c = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=10)
gone = 0
for k in open(sys.argv[2]).read().split():
    c.request("HEAD", "/bkt/" + k)
    r = c.getresponse()
    r.read()
    gone += r.status != 200
print(gone)
EOF
)
    [ "${MISSING:-x}" = "0" ] && ok "round $r: every answered put reads back" \
                              || bad "round $r: answered" "${MISSING:-?} of $N answered puts are gone"
done

if [ "$FAILS" -ne 0 ]; then
    echo "  FAILED ($FAILS)"
    exit 1
fi
echo "  PASSED"
exit 0
