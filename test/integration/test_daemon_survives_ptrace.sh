#!/usr/bin/env bash
# Integration test: attaching a tracer to the daemon does not stop it
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# The daemon's loop left on any negative return of io_uring_wait_cqe, and a
# signal that is no stop request of ours -- the one ptrace sends to attach,
# a SIGSTOP -- ends that wait with -EINTR: `strace -p <daemon>` for a look at a
# production daemon logged "daemon stopped", exited 0 and took every runtime
# down with it.  Found by the agent building the cluster cache, whose
# hung-daemon test resumed a SIGSTOPped daemon and saw it go.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * the daemon gone after a tracer attached and detached
#   * its runtime no longer serving afterwards
#   * a SIGTERM no longer stopping it, now that an interrupted wait resumes
#
# Needs a tracer with permission to attach (sudo -n strace, since yama's
# ptrace_scope usually forbids it for a non-child); skipped without one.
set -euo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: attaching a tracer to the daemon does not stop it ==="
if ! command -v strace >/dev/null 2>&1 || ! sudo -n true 2>/dev/null; then
    echo "  SKIP: needs strace and sudo -n to attach to a non-child"
    echo "  Results: 0/0 passed (0 failed)"; exit 0
fi

PASS=0; FAIL=0; TOTAL=0
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; for l in "${@:3}"; do echo "        $l"; done; }

daemon_isolate ptrace
trap daemon_stop EXIT
PORT=$((SL_PORT_BASE + 1831))

daemon_start "$BIN"
"$BIN" create server s -p "$PORT" -s >/dev/null

serves(){ python3 -c "import socket,sys;socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=2).close()" "$PORT" 2>/dev/null; }

# Three attaches, each detached by the timeout, with the daemon idle in its wait.
for _ in 1 2 3; do
    sleep 0.5
    sudo -n timeout 1 strace -p "$SOCKETLEY_DPID" -e trace=none >/dev/null 2>&1 || true
done
sleep 0.5
if kill -0 "$SOCKETLEY_DPID" 2>/dev/null; then pass
else fail "attach" "the daemon is gone after a tracer attached and detached" "$(tail -3 "$SOCKETLEY_DLOG")"; fi

if serves; then pass
else fail "serving" "the runtime no longer accepts after the attaches"; fi

# A stop request still stops it, through the handler's eventfd and not the interrupted wait.
kill -TERM "$SOCKETLEY_DPID" 2>/dev/null || true
for _ in $(seq 1 50); do kill -0 "$SOCKETLEY_DPID" 2>/dev/null || break; sleep 0.1; done
if ! kill -0 "$SOCKETLEY_DPID" 2>/dev/null && grep -q 'daemon stopped' "$SOCKETLEY_DLOG"; then pass
else fail "sigterm" "SIGTERM did not stop the daemon within 5 s"; fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" = 0 ]
