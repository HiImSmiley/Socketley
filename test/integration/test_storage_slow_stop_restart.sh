#!/usr/bin/env bash
# Integration test: a restart whose old worker takes longer to stop than a
# start would wait for its directory still succeeds, and starts clean.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
# The old worker's stop is held 2.5 s past its drain (SOCKETLEY_STORAGE_STOP_HOLD_MS),
# longer than the 1.5 s a new worker waits for the shard's lock.  The daemon
# forks the new worker only once the old one has exited, so:
#
#   restart    `restart` answers 0, after the old worker's stop and not before it
#   reload     `reload` does the same, being a stop and a start in the daemon
#   clean      the start after each logs "(clean stop)", and every put answered
#              before it reads back
#   loop       the daemon answers `ls` within a second while a restart waits
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgslow

PORT=$((SL_PORT_BASE+1647))
DATA="$SOCKETLEY_TMPD/objects"
FAILS=0

cleanup() {
    "$BIN" stop stgsl >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove stgsl >/dev/null 2>&1 || true
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

ms() { date +%s%3N; }

echo "=== Integration: a restart whose old worker is slow to stop ==="
command -v python3 >/dev/null 2>&1 || { echo "  FAIL: python3 is required"; exit 1; }

SOCKETLEY_STORAGE_STOP_HOLD_MS=2500 daemon_start "$BIN"
if ! "$BIN" create storage stgsl -p "$PORT" --dir "$DATA" --anonymous -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
up || { echo "  FAIL [up]: the runtime never answered"; exit 1; }
curl -s -o /dev/null -X PUT "http://127.0.0.1:$PORT/bkt"

r=0
for verb in restart reload; do
    r=$((r+1))
    for i in $(seq 1 20); do
        curl -s -o /dev/null -X PUT --data-binary "v$r-$i" "http://127.0.0.1:$PORT/bkt/k$r-$i"
    done
    LOGGED=$(wc -l < "$SOCKETLEY_DLOG")

    T0=$(ms)
    "$BIN" "$verb" stgsl > "$SOCKETLEY_TMPD/$verb.out" 2>&1 &
    CMD=$!
    # Asked while the command waits for the old worker, which the daemon's loop must not.
    sleep 0.5
    L0=$(ms)
    "$BIN" ls >/dev/null 2>&1
    LS=$(( $(ms) - L0 ))
    wait "$CMD"
    RC=$?
    T=$(( $(ms) - T0 ))

    [ "$LS" -lt 1000 ] && ok "$verb: the daemon answered ls in ${LS} ms while the $verb waited" \
                       || bad "$verb: loop" "ls took ${LS} ms while the $verb waited"
    if [ "$RC" -eq 0 ] && [ "$T" -ge 2500 ]; then
        ok "$verb: answered 0 after ${T} ms, once the old worker had stopped"
    else
        bad "$verb" "answered $RC after ${T} ms: $(tr '\n' ' ' < "$SOCKETLEY_TMPD/$verb.out")"
    fi
    up || { bad "$verb: up" "the runtime did not answer after the $verb"; continue; }

    CLEAN=$(tail -n +"$((LOGGED+1))" "$SOCKETLEY_DLOG" | grep -c '(clean stop)'); CLEAN=${CLEAN:-0}
    [ "$CLEAN" -eq 1 ] && ok "$verb: the start after it was clean" \
                       || bad "$verb: clean" "$CLEAN starts logged a clean stop after the $verb"

    MISSING=0
    for i in $(seq 1 20); do
        [ "$(curl -s "http://127.0.0.1:$PORT/bkt/k$r-$i")" = "v$r-$i" ] || MISSING=$((MISSING+1))
    done
    [ "$MISSING" -eq 0 ] && ok "$verb: every put answered before it reads back" \
                         || bad "$verb: answered" "$MISSING of 20 answered puts are gone"
done

if [ "$FAILS" -ne 0 ]; then
    echo "  FAILED ($FAILS)"
    exit 1
fi
echo "  PASSED"
exit 0
