#!/usr/bin/env bash
# Integration test: a start that outlasts the daemon's two seconds is waited for by the CLI
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A storage runtime reads every object file at a start after a crash or under
# a new shard count, which for a large store takes longer than the two seconds
# a command waits for a worker.  The daemon cannot wait longer without holding
# every other command, so the CLI does: it asks `startup` until the runtime
# serves or fails, as long as its workers keep using CPU, and gives up only
# once they have used none for 15 seconds.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * create -s, start or restart answering 2 ("did not report back") for a
#     start that is only slow, or answering before the runtime serves
#   * a start that uses no CPU waited for without end, or answered 0
# suite: isolated
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: a slow start is waited for by the CLI ==="
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }
now_ms() { date +%s%3N; }

daemon_isolate stgslowstart
trap 'daemon_stop' EXIT
export SOCKETLEY_STORAGE_START_SPIN_MS=3500
daemon_start "$BIN"
P=$((SL_PORT_BASE + 1881)); P2=$((SL_PORT_BASE + 1882))
serves() { curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$1/"; }

t0=$(now_ms)
out=$("$BIN" create storage slow -p "$P" --dir "$SOCKETLEY_TMPD/slow" --anonymous -s 2>&1); rc=$?
took=$(( $(now_ms) - t0 ))
check "create -s of a start that works 3.5 s answers 0" "$rc:$out" "0:"
[ "$took" -ge 3000 ] && ok || bad "and answers once it serves" "answered after $took ms"
check "and it serves" "$(serves "$P")" 200

"$BIN" stop slow >/dev/null 2>&1
out=$("$BIN" start slow 2>&1); rc=$?
check "start of it answers 0" "$rc:$out" "0:"
check "and it serves" "$(serves "$P")" 200
out=$("$BIN" restart slow 2>&1); rc=$?
check "restart of it answers 0" "$rc:$out" "0:"
check "and it serves" "$(serves "$P")" 200
"$BIN" stop slow >/dev/null 2>&1

# A start that does nothing for 20 s is given up on 15 s after it last used CPU.
daemon_stop
unset SOCKETLEY_STORAGE_START_SPIN_MS
export SOCKETLEY_STORAGE_START_SLEEP_MS=20000
daemon_isolate stgslowstart2
daemon_start "$BIN"
t0=$(now_ms)
out=$("$BIN" create storage wedged -p "$P2" --dir "$SOCKETLEY_TMPD/wedged" --anonymous -s 2>&1); rc=$?
took=$(( $(now_ms) - t0 ))
check "a start that uses no CPU is answered 2" "$rc" 2
check "saying so" "$(echo "$out" | grep -c 'has used no CPU for 15s')" 1
[ "$took" -ge 15000 ] && [ "$took" -lt 20000 ] && ok || bad "after 15 s without CPU" "answered after $took ms"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
