#!/usr/bin/env bash
# Repeated create/serve/remove churn across all three runtime kinds, in a fresh
# daemon each repeat, counting how many daemons die.
#
# Was scratchpad/churn_repro.sh.  Where runtime_churn_leak.sh watches one
# long-lived daemon for growth, this one is a crash reproducer: it restarts the
# daemon for every repeat, so a defect that only fires from a cold start —
# during the first few cycles, before pools and buffers have settled — is
# reached over and over instead of once.  The warm-up switch exists for exactly
# that reason: the failure this was written for showed up with warm-up off and
# hid with it on, so the switch is a parameter of the experiment, not a
# convenience.
#
# COVERS:      cache, server and proxy runtimes; create -> serve -> remove;
#              cold-start behaviour; daemon survival.
# DOES NOT:    growth over time (a fresh daemon per repeat cannot show it),
#              stop/start, state persistence, protocol correctness beyond
#              "the echo came back".
#
# FAILS WHEN:  any daemon died, or when no repeat managed to serve anything.
#              The original printed "DIED n/m" and exited 0.
#
#   ./churn_repro.sh [repeats] [cycles] [conns] [payload] [warmup:0|1] [kind]
#
#   repeats  fresh daemons        (default 5)
#   cycles   create/remove cycles per daemon  (default 12)
#   conns    concurrent connections per cycle (default 8)
#   payload  bytes per message    (default 256)
#   warmup   1 = discard a warm-up round first (default 0 — see above)
#   kind     cache|server|proxy|all  (default all)

HARNESS_NAME="churn_repro"
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

require_bin
require_lib probe.py churn_be.py

REP="${1:-5}"
CYC="${2:-12}"
CONNS="${3:-8}"
PAY="${4:-256}"
WARM="${5:-0}"
KIND="${6:-all}"

BEP="${BE_PORT:-19599}"
BASEP="${BASE_PORT:-19600}"
WARMP="${WARM_PORT:-19700}"

echo "=== Churn reproducer — $REP daemons x $CYC cycles, kind=$KIND, warmup=$WARM ==="
announce_environment

died=0
served_total=0
codes=""

for r in $(seq 1 "$REP"); do
    RUNDIR="$(make_run_dir)"

    pin_load python3 "$LIB/churn_be.py" "$BEP" >"$RUNDIR/backend.log" 2>&1 &
    BEPID=$!

    if ! start_daemon "$RUNDIR"; then
        kill "$BEPID" 2>/dev/null
        rm -rf "$RUNDIR"
        nothing_measured "daemon did not start on repeat $r"
    fi

    if [ "$WARM" = 1 ]; then
        pin_load python3 "$LIB/probe.py" "$BIN" "$WARMP" "$BEP" 3 3 "$CONNS" "$PAY" wu churn "$KIND" \
            >/dev/null 2>&1
        sleep 0.6
    fi

    pin_load python3 "$LIB/probe.py" "$BIN" "$BASEP" "$BEP" "$CYC" 3 "$CONNS" "$PAY" pr churn "$KIND" \
        >"$RUNDIR/probe.out" 2>&1
    sleep 0.5

    # probe.py's last line is
    #   TOTALS cycles=N created=N served=N removed=N closed=N ops=N secs=N
    totals="$(grep '^TOTALS' "$RUNDIR/probe.out" | tail -1)"
    served=0
    if [ -n "$totals" ]; then
        served="$(echo "$totals" | sed -n 's/.*served=\([0-9]*\).*/\1/p')"
        [ -z "$served" ] && served=0
    fi
    served_total=$((served_total + served))

    if daemon_alive; then
        kill "$DAEMON_PID" 2>/dev/null
        wait "$DAEMON_PID" 2>/dev/null
        status="alive"
    else
        wait "$DAEMON_PID" 2>/dev/null
        rc=$?
        died=$((died + 1))
        codes="$codes rc=$rc"
        status="DIED rc=$rc"
        echo "  repeat $r: daemon $status"
        echo "  --- last 20 lines of the daemon log ---"
        tail -20 "$RUNDIR/daemon.log" 2>/dev/null | sed 's/^/      /'
        echo "  --- probe output ---"
        sed 's/^/      /' "$RUNDIR/probe.out" 2>/dev/null | tail -5
    fi

    echo "  repeat $r: $status, ${totals:-<no totals line>}"

    kill "$BEPID" 2>/dev/null
    kill -9 "$DAEMON_PID" 2>/dev/null
    rm -rf "$RUNDIR"
done

# A run in which nothing was ever served did not churn anything: it started and
# stopped daemons.  Reporting that as a pass is the exact false green this
# harness was moved in-repo to stop producing.
if [ "$served_total" -eq 0 ]; then
    nothing_measured "$REP repeats served nothing at all — the probe never reached a runtime"
fi

if [ "$died" -gt 0 ]; then
    fail "$died of $REP daemons died during churn ($codes)"
fi
pass "$REP daemons survived $CYC cycles each, $served_total cycles served"
