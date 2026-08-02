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
#
# ─── WHAT THIS HARNESS FOUND, AND WHAT IT MEASURES NOW ──────────────────────
#
# It reported NO DATA from the day it was written until 2026-08-02, on the
# probe, on the runner and on a developer box — the nightly could not build
# between 2026-07-28 and 2026-08-01, so 2026-08-01's run (30719890629) is the
# first time anyone saw the result.  Taken apart stage by stage, what it had
# found was this:
#
#   * the upgrade SUCCEEDED.  The proxy returned "HTTP/1.1 101 Switching
#     Protocols" with the backend's Sec-WebSocket-Accept, for GET /pxw and for
#     GET /pxw/ alike.
#   * the first data frame was never echoed.  The client sent one masked text
#     frame and waited; nothing came back and the connection was not closed, so
#     wsharness.py recorded "timeout" — which is what the probe saw.
#   * the same two clients sending the same frames straight to the backend,
#     bypassing the proxy, were echoed correctly.
#
# The failure was downstream of the handshake: the proxy had no Upgrade path at
# all — no occurrence of 101, "Switching Protocols" or any notion of a tunnel
# anywhere in socketley/runtime/proxy/ — so it relayed the 101 as an ordinary
# HTTP response and then went back to expecting a request on a connection that
# now carried frames.  Every frame the client sent was buffered and none was
# forwarded, because the branch it fell into forwards min(body_remaining, n)
# bytes and an upgrade request declares no body.
#
# The proxy now relays the connection after a 101.  This harness measures the
# repeatability of that under concurrent load; the claims themselves — that the
# upgrade reaches the backend intact, that frames flow both ways, that either
# side can close, that the socket is never pooled — are stated one by one in
# test/integration/test_proxy_websocket_tunnel.sh.
#
# One thing this harness still cannot see, and it is what hid half the defect:
# its backend answers 101 on the strength of Sec-WebSocket-Key alone.  A proxy
# that strips the Upgrade and Connection headers — which is what a proxy does
# to hop-by-hop headers by default, and what this one did — therefore still gets
# a 101 out of it, while the request the backend actually received was an
# ordinary GET.  The integration test uses a strict backend for that reason.

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

start_load_bg python3 "$LIB/wsharness.py" --mode backend --port "$BE" >"$RUNDIR/backend.log" 2>&1
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
    echo "  A 'timeout' here is the state described at the top of this file: the"
    echo "  upgrade completes and the frames after it are not relayed.  That is a"
    echo "  proxy regression, not a harness fault — see"
    echo "  test/integration/test_proxy_websocket_tunnel.sh, which says which part."
    nothing_measured "the probe did not complete one WebSocket exchange through the proxy"
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
