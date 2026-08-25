#!/usr/bin/env bash
# Integration test: a worker-backed cache's figures are the worker's, and they
# include bytes.
#
# Two defects held down here, different in kind:
#
#   1. The cache never counted bytes at all.  Three runtimes fed
#      m_stat_bytes_in/out from their completion handlers and the fourth
#      forgot, so `stats` printed bytes_in:0 for a cache that had just served
#      hundreds of commands — in every mode, worker or --daemon-process.
#      Watched red against HEAD before the fix: the two byte assertions below
#      failed while keys/total_messages passed.
#
#   2. A worker-backed placeholder that has never received a report printed
#      keys:0 and commands_processed:0 out of its own empty store — a reading
#      indistinguishable from a running cache with no traffic.  Now it says
#      worker_report:none instead, and prints no store figures it does not
#      have.  Provoked deterministically below by SIGSTOPping the worker
#      inside the window between fork and its first publish (the first stats
#      frame goes out no earlier than one publish interval after the worker's
#      loop starts, and `start` returns on the hello frame well before that).
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

daemon_isolate cachewstats

PORT=$((SL_PORT_BASE+1760))
PORT2=$((SL_PORT_BASE+1761))

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

# Pull one integer figure out of a stats dump; empty when the line is absent.
figure() { printf '%s\n' "$1" | sed -n "s/^$2:\([0-9]*\)$/\1/p" | head -1; }

STOPPED_PID=""
cleanup() {
    [ -n "$STOPPED_PID" ] && kill -CONT "$STOPPED_PID" 2>/dev/null
    "$BIN" stop wsc 2>/dev/null || true; "$BIN" stop wsc2 2>/dev/null || true
    sleep 0.3
    "$BIN" remove wsc 2>/dev/null || true; "$BIN" remove wsc2 2>/dev/null || true
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: worker cache stats carry bytes, and no report says so ==="

if ! command -v nc >/dev/null 2>&1; then
    echo "  SKIP: nc is required to speak RESP to the cache"
    exit 0
fi

daemon_start "$BIN"
DAEMON_PID="${SOCKETLEY_DPID:-}"

# ── the counting: N confirmed SETs, then every figure must have moved ────────
"$BIN" create cache wsc -p "$PORT" --resp -s >/dev/null 2>&1

# The worker forks, execs, and builds its ring on the config frame; wait until
# it answers rather than sleeping a guess.
UP=0
for _ in $(seq 1 40); do
    R=$(printf '*1\r\n$4\r\nPING\r\n' | timeout 2 nc -q1 127.0.0.1 "$PORT" 2>/dev/null)
    case "$R" in *PONG*) UP=1; break;; esac
    sleep 0.25
done
if [ "$UP" = 1 ]; then ok; else
    bad "the worker cache answers on its port" "no PONG on $PORT after 10s"
fi

N=30
OKS=$(for i in $(seq 1 $N); do
          printf '*3\r\n$3\r\nSET\r\n$6\r\nkey%03d\r\n$6\r\nval%03d\r\n' "$i" "$i"
      done | timeout 5 nc -q1 127.0.0.1 "$PORT" 2>/dev/null | grep -c '+OK')
if [ "$OKS" = "$N" ]; then ok; else
    bad "every SET was confirmed" "expected $N +OK, saw ${OKS:-0}"
fi

# One publish interval, so the worker's frame has certainly gone out.
sleep 0.6
ST=$("$BIN" stats wsc 2>&1 || true)

KEYS=$(figure "$ST" keys)
MSGS=$(figure "$ST" total_messages)
BIN_IN=$(figure "$ST" bytes_in)
BIN_OUT=$(figure "$ST" bytes_out)

if [ "${KEYS:-0}" = "$N" ]; then ok; else
    bad "stats report the worker's keys" "expected keys:$N, got keys:'${KEYS:-absent}'" \
        "$(printf '%s' "$ST" | tr '\n' '|')"
fi
if [ "${MSGS:-0}" -ge "$N" ] 2>/dev/null; then ok; else
    bad "stats report the commands the worker served" \
        "expected total_messages>=$N, got '${MSGS:-absent}'"
fi

# Each SET above is 37 bytes of RESP on the wire and each +OK is 5 back, so
# after N confirmed commands both figures have hard floors — not merely
# "nonzero", which a stray PING could satisfy.
if [ "${BIN_IN:-0}" -ge $((N * 37)) ] 2>/dev/null; then ok; else
    bad "the cache counts bytes in" \
        "expected bytes_in>=$((N * 37)) after $N SETs, got '${BIN_IN:-absent}'" \
        "$(printf '%s' "$ST" | tr '\n' '|')"
fi
if [ "${BIN_OUT:-0}" -ge $((N * 5)) ] 2>/dev/null; then ok; else
    bad "the cache counts bytes out" \
        "expected bytes_out>=$((N * 5)) after $N confirmed replies, got '${BIN_OUT:-absent}'"
fi

# ── the placeholder that never heard from its worker ─────────────────────────
#
# A worker stopped before its first publish never reports, and the daemon must
# say so rather than print an empty store's keys:0 as though it had looked.
# The window is real but not narrow: the first stats frame leaves no earlier
# than one publish interval (250 ms) after the worker's loop starts, and
# create -s returns on the hello frame.  If the SIGSTOP loses the race anyway,
# the run says SKIP rather than asserting on a state it failed to produce.
"$BIN" create cache wsc2 -p "$PORT2" --resp -s >/dev/null 2>&1
WPID=$(ss -ltnp 2>/dev/null | awk -v p=":$PORT2" '$4 ~ p' \
       | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
if [ -n "$WPID" ] && [ "$WPID" != "$DAEMON_PID" ]; then
    kill -STOP "$WPID" 2>/dev/null && STOPPED_PID="$WPID"
fi

if [ -n "$STOPPED_PID" ]; then
    sleep 0.5
    ST2=$("$BIN" stats wsc2 2>&1 || true)
    case "$ST2" in
    *mesh_links:*)
        # The worker's frame beat the SIGSTOP; the never-reported state was not
        # produced, so there is nothing to assert against.
        echo "  SKIP [no-report window]: the worker published before it was stopped"
        ;;
    *)
        case "$ST2" in
        *worker_report:none*) ok;;
        *) bad "a placeholder that never heard from its worker says so" \
               "no worker_report:none line" \
               "$(printf '%s' "$ST2" | tr '\n' '|')";;
        esac
        # And it must not dress the silence up as an inspected, empty store.
        case "$ST2" in
        *keys:*) bad "the unreported placeholder does not print store figures" \
                     "a keys: line is the placeholder's own empty store, printed as if the worker had answered" \
                     "$(printf '%s' "$ST2" | tr '\n' '|')";;
        *) ok;;
        esac
        ;;
    esac
    kill -CONT "$STOPPED_PID" 2>/dev/null
    STOPPED_PID=""
else
    echo "  SKIP [no-report window]: could not find the worker's pid on $PORT2"
fi

# Once the worker runs again its report supersedes the marker.
sleep 0.8
ST3=$("$BIN" stats wsc2 2>&1 || true)
case "$ST3" in
*keys:0*) ok;;
*) bad "after the worker resumes, its real (empty) store is reported" \
       "$(printf '%s' "$ST3" | tr '\n' '|')";;
esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
