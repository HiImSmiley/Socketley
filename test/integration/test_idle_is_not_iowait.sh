#!/usr/bin/env bash
# suite: quiet -- reads the machine's count of tasks in I/O wait, which any other test's disk work moves.
# Integration test: an idle daemon and its runtimes are not counted as waiting on I/O
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a loop waiting on its ring with accepts armed counted by the kernel as a
#     task blocked on I/O, so a host idle but for socketley reads one per
#     process in /proc/stat's procs_blocked, its load average and its iowait
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

echo "=== Integration: an idle daemon is not counted as waiting on I/O ==="

# IORING_FEAT_NO_IOWAIT arrived in 6.15; before it every kernel counts the wait, and nothing can say otherwise.
read -r major minor < <(uname -r | sed 's/^\([0-9]*\)\.\([0-9]*\).*/\1 \2/')
if [ "$major" -lt 6 ] || { [ "$major" -eq 6 ] && [ "$minor" -lt 15 ]; }; then
    echo "  SKIP: kernel $(uname -r) counts every io_uring wait as I/O wait"
    exit 0
fi

daemon_isolate idleiowait
trap 'daemon_stop' EXIT
PASS=0; FAIL=0; TOTAL=0

# The fewest tasks blocked on I/O across twenty samples a tenth of a second apart, so a passing disk write elsewhere
# is not read as ours.
blocked() {
    local least=999999 n
    for _ in $(seq 1 20); do
        n=$(awk '/^procs_blocked/ { print $2 }' /proc/stat)
        [ "$n" -lt "$least" ] && least=$n
        sleep 0.1
    done
    echo "$least"
}

before=$(blocked)
daemon_start "$BIN"
P=$((SL_PORT_BASE + 1960))
"$BIN" create storage idle -p "$P" --dir "$SOCKETLEY_TMPD/idle" --access-key AKIAIDLEIOWAIT000000 \
    --secret-key idleiowaitsecretidleiowaitsecretidle0000 --shards 4 -s >/dev/null 2>&1
for _ in $(seq 1 50); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/")" != 000 ] && break; sleep 0.1; done
sleep 1
after=$(blocked)

TOTAL=$((TOTAL+1))
if [ "$after" -le "$before" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [a daemon and four idle shards add no task blocked on I/O]: procs_blocked $before before, $after with them"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
