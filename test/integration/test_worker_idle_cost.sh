#!/usr/bin/env bash
# Integration test: what a runtime that is doing nothing costs.
#
# ─── WHAT THIS IS FOR ───────────────────────────────────────────────────────
#
# A runtime out of process is a worker process, and a worker process has a loop.
# For as long as that loop waited on a constant rather than on a deadline, every
# idle runtime on the machine bought 50 wakeups a second against an empty ring:
#
#     0 runtimes    0.000% of a core
#     8 runtimes    0.967%          }  30 s windows, three interleaved
#    32 runtimes    3.044%          }  repetitions, quiet box:
#   100 runtimes    7.878%          }  790-1210 us/s per idle runtime
#
# and 50.0 context switches a second in each of those workers — the timeout,
# exactly, not a rate that anything about the workload explains.  A hundred idle
# runtimes is not an unusual inventory and it was costing most of a core to hold
# still.
#
# The loop waits until its own next deadline now.  The only periodic thing it
# owes anybody is the stats publish, so the wakeup rate an idle worker should
# show is the publish rate — worker_proto::stats_interval_ms, 4 Hz — and nothing
# else.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
# Section 1  wakeups, upper bound.  A build that puts a fixed clock back into
#            the worker loop.  The binary this file was written against reads
#            50.0/s here; the bound is 12/s, which is three times the publish
#            rate and a quarter of the rate being ruled out.
#
# Section 2  wakeups, lower bound.  A build whose worker has stopped waking at
#            all — an untimed wait with no notification standing in the ring is
#            the shape of change this defect invites, and a wedged worker scores
#            perfectly on section 1.  Nothing else in this directory would
#            notice: the runtime is idle, so nothing it fails to do is visible.
#
# Section 3  CPU per idle runtime.  The number the whole change is about, at a
#            bound loose enough that only a regression of the same kind can
#            reach it (see the figure quoted at the assertion).
#
# Section 4  the freshness contract.  The cheapest way to make sections 1-3
#            green is to publish less often, and that is not free: figures_age_ms
#            is what `stats` answers "how old is this" with, what lib_ready.sh's
#            ready_conns waits on, and what tells an operator a worker has
#            wedged.  Pinning it here is what makes the other three honest.
#
# Section 5  the wait still ends on a frame and not on its deadline.  A build
#            that lengthened the timeout and lost the poll armed on the control
#            socket would pass every section above — it would score better on
#            them — and answer every request that needs the worker a publish
#            period late.  Watched red at 224 ms and 240 ms against a build whose
#            arm_control() set the flag without submitting anything.
#
# Its own daemon, its own state directory, its own ports: see lib_daemon.sh.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

daemon_isolate idlecost
PORT=$((SL_PORT_BASE + 1600))

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  ok: $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

cleanup() { daemon_stop; }
trap cleanup EXIT

echo "=== worker idle cost ==="
daemon_start "$BIN"

# ─── Fixtures ───────────────────────────────────────────────────────────────
#
# Eight of them, because section 3 divides by the count and one process's CPU
# time is reported truncated to the kernel's clock tick — a single worker's whole
# share of a window is a couple of ticks, and the truncation is then most of the
# reading.  Eight independent processes average that error out; they are also
# what the 8-runtime row in the table above was measured on.
N=8
for i in $(seq 1 $N); do
    "$BIN" create server "idle$i" -p $((PORT + i)) -s >/dev/null 2>&1 || true
done

# Every worker this run's daemon forked.  By parentage rather than by name: the
# binary is often a copy under another name in this tree, and matching a command
# line is what the note at the top of lib_daemon.sh is about.
workers() { pgrep -P "$SOCKETLEY_DPID" 2>/dev/null; }

# Let the workers finish coming up before anything is timed: a worker that is
# still binding its listener is not idle, and its first turns are the ones that
# read the config, build the ring and answer the daemon.
sleep 3

NW=$(workers | wc -l)
if [ "$NW" -eq "$N" ]; then
    ok "the daemon forked $N workers"
else
    bad "expected $N worker processes, the daemon has $NW" \
        "(nothing below is measuring what it says it is)"
fi
[ "$NW" -gt 0 ] || { echo " Summary: $PASS passed, $FAIL failed"; exit 1; }

W=$(workers | head -1)

# Voluntary switches only.  An idle worker's wakeups are its own — it blocks and
# something ends the block — while involuntary ones are the scheduler taking the
# CPU away, which is a fact about the machine the suite is running on and not
# about this build.  On a box under load the involuntary count moves; this one
# does not.
vctx() { awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }
cpu_us() { awk '{printf "%d", ($14+$15)*1000000/'"$(getconf CLK_TCK)"'}' "/proc/$1/stat" 2>/dev/null || echo 0; }

# Twenty seconds, and eight runtimes, because of how CPU time is reported.
# This kernel accounts precisely (CONFIG_VIRT_CPU_ACCOUNTING_GEN) but /proc
# truncates to the clock tick, so each process's figure is off by up to one tick
# — 10 ms — in either direction.  Nine processes over ten seconds is up to 90 ms
# of slack on a total of about 100 ms, which is not a measurement.  Over twenty
# seconds with the error averaging across nine independent processes the slack
# is around 50 us/s per runtime, against the several hundred that separate the
# two builds.
WINDOW=20

# ─── 1 & 2: how often an idle worker wakes ──────────────────────────────────
C0=$(vctx "$W")
T0=0; for w in $(workers); do T0=$((T0 + $(cpu_us "$w"))); done
T0=$((T0 + $(cpu_us "$SOCKETLEY_DPID")))
sleep "$WINDOW"
C1=$(vctx "$W")
T1=0; for w in $(workers); do T1=$((T1 + $(cpu_us "$w"))); done
T1=$((T1 + $(cpu_us "$SOCKETLEY_DPID")))

RATE=$(( (C1 - C0) / WINDOW ))
echo "  idle worker $W: $RATE voluntary wakeups/s"

# 12/s: three times the 4 Hz publish this loop legitimately has, and a quarter
# of the 50 Hz it used to run at.  A build sitting between those two — a 20 Hz
# clock, say — is still the defect and is still caught.
if [ "$RATE" -le 12 ]; then
    ok "an idle worker wakes $RATE times/s (bound 12; a fixed-timeout loop reads 50)"
else
    bad "an idle worker wakes $RATE times/s, over the bound of 12." \
        " A worker with no traffic should wake only to publish its figures"
    echo "         (4 Hz).  A rate near 50 is the fixed 20 ms timeout back in"
    echo "         the loop; whatever the rate, it is a clock nothing asked for."
fi

# The other side of the same number, and on the raw count rather than the rate:
# the floor is "this process is still taking turns at all", which a build that
# merely publishes more slowly should not trip — section 4 is what answers for
# the publish rate.  Zero is not a better score than four, it is a worker that
# has stopped, which is what an untimed wait with nothing armed to end it
# produces and which no other assertion in this directory would see on a runtime
# that is deliberately doing nothing.
if [ "$((C1 - C0))" -ge 1 ]; then
    ok "the idle worker is still taking its turns ($((C1 - C0)) in ${WINDOW}s, floor 1)"
else
    bad "the idle worker woke $((C1 - C0)) times in ${WINDOW}s — it is not waiting" \
        "on anything that will end, which is a wedged worker and not a cheap one"
fi

# ─── 3: CPU per idle runtime ────────────────────────────────────────────────
PER=$(( (T1 - T0) / WINDOW / N ))
echo "  $N idle runtimes: $PER us/s of CPU each (daemon + its workers)"

# 650 us/s per runtime, and the two figures it sits between were both measured
# on this machine over 30 s windows, three interleaved repetitions each:
#
#              8 runtimes   32 runtimes   100 runtimes
#   fixed 20 ms timeout      1208            951            788   us/s each
#   waiting on the deadline   347            368            357
#
# So the bound is roughly twice what a correct build costs and two thirds of
# what the defect costs at its cheapest.  It is deliberately not tighter: most
# of what remains on the correct side is the 4 Hz publish and the daemon's read
# of it, which this change does not touch and a tighter bound would be
# forbidding by accident.
if [ "$PER" -le 650 ]; then
    ok "an idle runtime costs $PER us/s (bound 650; a fixed-timeout loop costs ~790-1210)"
else
    bad "an idle runtime costs $PER us/s, over the bound of 650 us/s." \
        " A hundred idle runtimes would be $((PER / 100))% of a core spent on nothing."
    echo "         daemon+workers went from $T0 to $T1 us over ${WINDOW}s across $N runtimes."
fi

# ─── 4: the figures did not get older to pay for it ─────────────────────────
#
# Read after the window above, so the runtime has been idle for the whole of it
# and any publish backoff would have had time to open up.
AGE=$("$BIN" stats idle1 2>/dev/null | awk -F: '$1 == "figures_age_ms" { print $2; exit }')
case "$AGE" in
    ''|*[!0-9]*)
        bad "stats printed no usable figures_age_ms for an out-of-process runtime (got '$AGE')" ;;
    *)
        # One publish period is 250 ms; 1000 leaves room for the round trip and
        # for a drain that happened to land late, and still fails a build that
        # has stretched the publish to buy the sections above.
        if [ "$AGE" -le 1000 ]; then
            ok "an idle runtime's figures are ${AGE} ms old (bound 1000)"
        else
            bad "an idle runtime's figures are ${AGE} ms old, over the bound of 1000." \
                " Publishing less often is the cheap way to pass sections 1-3 and it"
            echo "         breaks ready_conns, the age stats prints, and the one signal"
            echo "         an operator has that a worker has wedged."
        fi
        ;;
esac

# ─── 5: a frame still ends the wait, the deadline does not ──────────────────
#
# The wait above is safe to lengthen only because a poll armed on the control
# socket ends it the instant a frame arrives.  Take that away and the loop is
# back to being woken by its own clock, and every request from the daemon waits
# for it.
#
# `reload-lua` is the command that shows it, and it took finding: most of the
# CLI does not need the worker's answer at all.  `stop`, `stats`, `ls` and
# `remove` are answered by the daemon out of the placeholder it holds — measured
# at 4-6 ms against a worker whose arm had been deliberately broken, which is to
# say they would pass this section with the notification gone entirely.
# reload-lua is not: proxy_supervisor::await_routes() blocks on the child's
# declaration frame, so the number below is a real round trip through the
# worker's wait.  Against that same broken build it measured 224 ms and 240 ms —
# one publish period, which is exactly the loop's deadline doing the work the
# poll should have done.
#
# Its own runtime, created after the measurements above so that nothing in
# sections 1-3 was watching a runtime with a script attached.
LUA="$SOCKETLEY_TMPD/rt.lua"
cat > "$LUA" <<'EOF'
function on_start() end
EOF
"$BIN" create server idlert -p $((PORT + N + 1)) --lua "$LUA" -s >/dev/null 2>&1
sleep 1

S=$(date +%s%3N)
"$BIN" reload-lua idlert >/dev/null 2>&1
E=$(date +%s%3N)
MS=$((E - S))
echo "  reload-lua against an idle worker: ${MS} ms"

# 150 ms: an order of magnitude above the 6 ms this takes when the arm ends the
# wait, and safely below the 250 ms publish period a loop woken only by its own
# deadline cannot beat.
if [ "$MS" -le 150 ]; then
    ok "a control frame ended the worker's wait in ${MS} ms (bound 150; a broken arm reads ~230)"
else
    bad "reload-lua took ${MS} ms against an idle worker (bound 150)." \
        " At or above one publish period the frame is waiting for the loop's"
    echo "         deadline instead of waking it.  The poll armed on the control"
    echo "         socket is what makes a long wait safe, and it is not working —"
    echo "         see arm_control() and m_ctl_armed in proxy_worker.cpp."
fi

echo ""
echo " Summary: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
