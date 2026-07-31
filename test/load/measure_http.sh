#!/usr/bin/env bash
# Repeatability of the proxy's HTTP path under concurrent load.
#
# Was scratchpad/measure_http.sh.  Same discipline as measure_tcp.sh, applied to
# HTTP: 20 concurrent keep-alive connections, 100 request/response pairs each,
# every response checked against the marker that was asked for.
#
# The marker check is the point.  lib/httpharness.py labels every request
# "<connection>-<sequence>" and the backend echoes it, so four failures that all
# look like "slow" from the outside are told apart:
#
#   missing    the response never arrived
#   wrong-seq  a response arrived out of order on its own connection
#   crossed    a response belonging to a DIFFERENT connection arrived here
#   garbled    the body matched no marker at all
#
# "crossed" is what a stale descriptor looks like from outside the process, and
# it is the failure this project has hit repeatedly.
#
# COVERS:      proxy in http mode, keep-alive, request/response correlation.
# DOES NOT:    chunked bodies, request smuggling (test/fuzz/fuzz_http_request.cpp
#              covers that), TLS, WebSocket upgrade (measure_ws.sh does).
#
# FAILS WHEN:  any round reports any failure kind, or the harness cannot be run,
#              or the backend never came up.  The original always exited 0.
#
#   ROUNDS=n            counted rounds per pass (default 40)
#   PASSES=n            passes (default 3)
#   LOAD_MAX_BAD=n      tolerated bad rounds in total (default 0)

HARNESS_NAME="measure_http"
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

require_bin
require_lib httpharness.py

ROUNDS="${ROUNDS:-40}"
PASSES="${PASSES:-3}"
WARMUPS="${WARMUPS:-3}"
MAX_BAD="${LOAD_MAX_BAD:-0}"
BE="${BE_PORT:-23100}"
PX="${PX_PORT:-23101}"

RUNDIR="$(make_run_dir)"
BPID=""
cleanup() {
    [ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null
    [ -n "$BPID" ] && kill "$BPID" 2>/dev/null
    rm -rf "$RUNDIR"
}
trap cleanup EXIT

echo "=== Proxy HTTP path — $PASSES passes of $ROUNDS rounds ==="
announce_environment

pin_load python3 "$LIB/httpharness.py" --mode backend --port "$BE" >"$RUNDIR/backend.log" 2>&1 &
BPID=$!
sleep 1
kill -0 "$BPID" 2>/dev/null || {
    echo "--- backend log ---"; cat "$RUNDIR/backend.log"
    nothing_measured "the echo backend did not start on port $BE"
}

start_daemon "$RUNDIR" || nothing_measured "daemon did not start"

"$BIN" create proxy pxh -p "$PX" --backend "127.0.0.1:$BE" --protocol http -s >/dev/null 2>&1
sleep 1.5

# One probe before any measuring: if the path does not work at all, every round
# below would fail identically and the run would look like a defect rather than
# like a broken harness.
if ! out="$(pin_load python3 "$LIB/httpharness.py" --mode drive --port "$PX" --prefix /pxh --clients 2 --count 2 2>&1)"; then
    echo "  probe output: $out"
    nothing_measured "the proxy did not serve a single request — harness or setup is broken, nothing was measured"
fi

total_bad=0
total_rounds=0
dirty_passes=0

for pass_n in $(seq 1 "$PASSES"); do
    settle
    dirty=0
    preflight || dirty=1
    tw0="$(time_wait_count)"
    ld0="$(cut -d' ' -f1 /proc/loadavg)"

    for w in $(seq 1 "$WARMUPS"); do
        pin_load python3 "$LIB/httpharness.py" --mode drive --port "$PX" --prefix /pxh \
            --clients 20 --count 100 >/dev/null 2>&1
    done

    bad=0; ran=0; first=""
    for r in $(seq 1 "$ROUNDS"); do
        out="$(pin_load python3 "$LIB/httpharness.py" --mode drive --port "$PX" --prefix /pxh \
                 --clients 20 --count 100 2>&1)"
        rc=$?
        if [ -z "$out" ]; then
            nothing_measured "the harness produced no output — rounds after this one would be meaningless"
        fi
        ran=$((ran + 1))
        if [ "$rc" -ne 0 ] || [ "$out" != "OK" ]; then
            bad=$((bad + 1))
            [ -z "$first" ] && first="$(echo "$out" | head -3 | tr '\n' ' ')"
        fi
    done

    printf "  pass%-6s %2d of %d rounds bad   (TIME_WAIT before %s, load %s)%s\n" \
        "$pass_n" "$bad" "$ran" "$tw0" "$ld0" \
        "$([ "$dirty" = 1 ] && echo '   [dirty start]')"
    [ -n "$first" ] && echo "      first: $first"

    total_bad=$((total_bad + bad))
    total_rounds=$((total_rounds + ran))
    dirty_passes=$((dirty_passes + dirty))
done

[ "$total_rounds" -eq 0 ] && nothing_measured "no rounds ran"
daemon_alive || fail "the daemon died during the run"

note=""
[ "$dirty_passes" -gt 0 ] && note=" ($dirty_passes pass(es) started from a dirty machine)"

if [ "$total_bad" -gt "$MAX_BAD" ]; then
    fail "$total_bad of $total_rounds rounds bad, tolerated $MAX_BAD$note"
fi
pass "$total_rounds rounds, $total_bad bad$note"
