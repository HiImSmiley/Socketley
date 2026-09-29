#!/usr/bin/env bash
# Integration test: --cpus on a storage runtime.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
# A ring's CPU set belongs to the process that made it, so a runtime states what
# it requires and the daemon refuses a requirement its ring does not meet -- for
# a storage runtime as for a server.  With a daemon pinned to 0-1 a storage
# runtime asking for 0-1 is made, and `stats` names the set in force, which the
# worker reads from the ring it built: a worker that ignored the config would
# say `max`, and would still sit on 0-1 because it inherited the daemon's
# affinity, so the field and not the affinity is what tells them apart.  The
# worker's own affinity is asserted as well.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgcpus

P=$((SL_PORT_BASE+1660))
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

cleanup() {
    "$BIN" stop sc_a >/dev/null 2>&1 || true
    sleep 0.3
    "$BIN" remove sc_a >/dev/null 2>&1 || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: --cpus on a storage runtime ==="
if [ "$(nproc)" -lt 2 ]; then
    echo "  SKIP: needs at least 2 CPUs"
    echo "  Results: 0/0 passed (0 failed)"
    exit 0
fi

SOCKETLEY_CPUS=0-1 daemon_start "$BIN"

out=$("$BIN" create storage sc_x -p "$P" --dir "$SOCKETLEY_TMPD/ox" --anonymous --cpus 0 2>&1); rc=$?
expect "a requirement the daemon's ring does not meet is refused" "$rc" 1
case "$out" in *"already pinned to"*) ok "and says which set the ring is pinned to";; *) bad "the refusal names the pinned set" "$out";; esac
"$BIN" remove sc_x >/dev/null 2>&1 || true

"$BIN" create storage sc_a -p "$P" --dir "$SOCKETLEY_TMPD/oa" --anonymous --cpus 0-1 -s >/dev/null 2>&1 \
    || bad "create" "sc_a was not made"
for _ in $(seq 1 100); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/")" = 200 ] && break
    sleep 0.1
done
expect "the runtime serves" "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/")" 200
# The worker's first publish may not have reached the daemon yet.
got=""
for _ in $(seq 1 50); do
    got=$("$BIN" stats sc_a | sed -n 's/^cpus://p')
    [ -n "$got" ] && break
    sleep 0.1
done
expect "stats names the set the worker's ring is pinned to" "$got" "0-1"
pid=$("$BIN" stats sc_a | sed -n 's/^pid://p')
expect "the worker's affinity is that set" "$(sed -n 's/^Cpus_allowed_list:[[:space:]]*//p' "/proc/$pid/status")" "0-1"
shown=$("$BIN" show sc_a 2>&1)
case "$shown" in *'"cpus": "0-1"'*) ok "show keeps it";; *) bad "show keeps --cpus" "$shown";; esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
