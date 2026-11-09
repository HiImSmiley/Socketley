#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a worker starts with nothing of the daemon's that the spawn could leave behind -- no signal held
# off, the daemon as its parent, the daemon's answers to the ring probes -- and it serves.
#
# What it would catch: a worker that inherits a signal mask the daemon held at the spawn, which never sees SIGTERM;
# a child that is not the daemon's own, which is
# one the daemon cannot reap or claim; and a worker not handed the probes' answers builds five throwaway rings.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
daemon_isolate spawnstate
T=$SOCKETLEY_TMPD; P=$((SL_PORT_BASE+1790))
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
trap 'daemon_stop' EXIT

cat >"$T/echo.lua" <<'LUA'
function on_client_message(id, msg) self.send(id, "echo " .. msg) return true end
LUA

worker_pid() { "$BIN" stats "$1" 2>/dev/null | awk -F: '/^pid:/{print $2}' | tr -d ' '; }
field() { awk -v k="$2:" '$1 == k {print $2}' "/proc/$1/status" 2>/dev/null; }

echo "=== Integration: a worker starts clean of its spawn ==="
daemon_start "$BIN"
"$BIN" create server w -p "$P" --lua "$T/echo.lua" -s >/dev/null || bad "create" "refused"
wpid=$(worker_pid w)
if [ -z "$wpid" ] || [ "$wpid" = "$SOCKETLEY_DPID" ]; then
    bad "the runtime has a worker of its own" "pid '$wpid', daemon $SOCKETLEY_DPID"
else
    ok
    blk=$(field "$wpid" SigBlk)
    [ "$blk" = "0000000000000000" ] && ok || bad "no signal is held off in the worker" "SigBlk $blk"
    ppid=$(field "$wpid" PPid)
    [ "$ppid" = "$SOCKETLEY_DPID" ] && ok || bad "the worker is the daemon's own child" "PPid $ppid, daemon $SOCKETLEY_DPID"
    facts=$(tr '\0' '\n' < "/proc/$wpid/environ" 2>/dev/null | sed -n 's/^SOCKETLEY_RING_FACTS=//p')
    # The five the daemon's own ring asked at its start; the sixth is asked only by a server that bundles receives.
    case "$facts" in
        [01][01][01][01][01]?) ok ;;
        *) bad "the worker was handed the daemon's ring answers" "SOCKETLEY_RING_FACTS='$facts'" ;;
    esac

    # SIGTERM reaches it: a stop ends the worker, which a worker holding signals off would sleep through.
    got=$(printf 'hi\n' | timeout 3 nc -q 1 127.0.0.1 "$P" 2>/dev/null | head -1 | tr -d '\r')
    [ "$got" = "echo hi" ] && ok || bad "the worker serves" "got '$got'"
    kill -TERM "$wpid" 2>/dev/null
    for _ in $(seq 1 50); do kill -0 "$wpid" 2>/dev/null || break; sleep 0.1; done
    kill -0 "$wpid" 2>/dev/null && bad "a SIGTERM ends the worker" "pid $wpid still alive after five seconds" || ok
fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
