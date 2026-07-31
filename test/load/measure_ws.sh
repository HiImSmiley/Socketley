#!/usr/bin/env bash
# Repeatability of the proxy's WebSocket path under concurrent load.
#
# Was scratchpad/measure_ws.sh.  Same discipline as measure_http.sh.  The proxy
# runs in http mode; the upgrade passes through it and the connection then
# carries frames rather than requests, which is a different route through the
# read handlers than either plain HTTP or splice — so a clean measure_http.sh
# says nothing about this path.
#
# Same marker scheme as the HTTP harness ("<connection>-<sequence>"), so a frame
# delivered on the wrong connection is distinguishable from one that is merely
# late or missing.
#
# COVERS:      upgrade through the proxy, 20 concurrent WS connections,
#              100 masked text frames each, echo correlation per connection.
# DOES NOT:    frame parsing edge cases (test/fuzz/fuzz_ws_frame.cpp does that),
#              fragmentation, control frames, permessage-deflate, TLS.
#
# FAILS WHEN:  any round reports any failure kind, or the upgrade never worked.
#              The original always exited 0.

HARNESS_NAME="measure_ws"
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

require_bin
require_lib wsharness.py

ROUNDS="${ROUNDS:-40}"
PASSES="${PASSES:-3}"
WARMUPS="${WARMUPS:-3}"
MAX_BAD="${LOAD_MAX_BAD:-0}"
BE="${BE_PORT:-23200}"
PX="${PX_PORT:-23201}"

RUNDIR="$(make_run_dir)"
BPID=""
cleanup() {
    [ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null
    [ -n "$BPID" ] && kill "$BPID" 2>/dev/null
    rm -rf "$RUNDIR"
}
trap cleanup EXIT

echo "=== Proxy WebSocket path — $PASSES passes of $ROUNDS rounds ==="
announce_environment

pin_load python3 "$LIB/wsharness.py" --mode backend --port "$BE" >"$RUNDIR/backend.log" 2>&1 &
BPID=$!
sleep 1
kill -0 "$BPID" 2>/dev/null || {
    echo "--- backend log ---"; cat "$RUNDIR/backend.log"
    nothing_measured "the WebSocket echo backend did not start on port $BE"
}

start_daemon "$RUNDIR" || nothing_measured "daemon did not start"

"$BIN" create proxy pxw -p "$PX" --backend "127.0.0.1:$BE" --protocol http -s >/dev/null 2>&1
sleep 1.5

if ! out="$(pin_load python3 "$LIB/wsharness.py" --mode drive --port "$PX" --prefix /pxw/ --clients 2 --count 2 2>&1)"; then
    echo "  probe output: $out"
    nothing_measured "not one WebSocket upgrade succeeded — harness or setup is broken, nothing was measured"
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
        pin_load python3 "$LIB/wsharness.py" --mode drive --port "$PX" --prefix /pxw/ \
            --clients 20 --count 100 >/dev/null 2>&1
    done

    bad=0; ran=0; first=""
    for r in $(seq 1 "$ROUNDS"); do
        out="$(pin_load python3 "$LIB/wsharness.py" --mode drive --port "$PX" --prefix /pxw/ \
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
