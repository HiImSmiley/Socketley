#!/usr/bin/env bash
# suite: quiet -- asserts microseconds of CPU per second per idle runtime.
# Under a parallel run that number is the parallel run's.
# Integration test: what a runtime that is doing nothing costs.
#
# ─── WHAT THIS IS FOR ───────────────────────────────────────────────────────
#
# A runtime out of process is a worker process, and a worker process has a loop.
# For as long as that loop waited on a constant rather than on a deadline, every
# idle runtime on the machine bought 50 wakeups a second against an empty ring:
#
#     0 runtimes    0.000% of a core
#    32 runtimes    3.044%          }  30 s windows, three interleaved
#   100 runtimes    7.878%          }  repetitions, quiet box:
#                                   }  951 and 788 us/s per idle runtime
#
# and 50.0 context switches a second in each of those workers — the timeout,
# exactly, not a rate that anything about the workload explains.  A hundred idle
# runtimes is not an unusual inventory and it was costing most of a core to hold
# still.
#
# The loop waits until its own next deadline now, and it no longer has one.  The
# stats publish was the last periodic thing it owed anybody; the counters moved
# into a shared table the worker stores into once per turn and the daemon sums
# when it prints, so the frame is sent only when the part `stats` cannot
# compute — the ring's flags, a table walk — has CHANGED, which for an idle
# runtime is never.
#
# Measured on this box, 2026-08-22, 100 idle runtimes, 30 s windows, three
# interleaved repetitions, and again at 32:
#
#                              100 runtimes        32 runtimes    worker
#                             (us/s each)         (us/s each)     wakeups/30s
#   pushed every 250 ms       216 / 150 / 193     208 / 177       66-68
#   published on change         3 /   6 /  10       0 /  10        1
#
# One wakeup in thirty seconds is idle_wait_ms exactly: nothing else in the
# system wakes an idle worker, and that constant is a backstop and not a
# schedule.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
# Section 1  wakeups, upper bound.  A build that puts a periodic clock back into
#            the worker loop — a fixed timeout, or a publish on a timer.  The
#            fixed 20 ms loop read 50/s here and the 250 ms publish 2.2/s; the
#            bound is 10 in 30 s, which is six times what a correct build reads
#            and a sixth of what the publish read.
#
# Section 2  the worker still wakes when something happens.  This used to be a
#            LOWER bound on the wakeup count, which was available while the
#            worker had a heartbeat and is not any more: 0 wakeups is now the
#            correct reading and a wedged worker scores the same.  So liveness
#            is asked for directly — a connection is opened and the runtime has
#            to see it — which is the thing the wakeup count was standing in for
#            and is the assertion an untimed wait with nothing armed fails.
#
# Section 3  CPU per idle runtime.  The number the whole change is about.
#            Release only: under a sanitizer the separation is smaller than the
#            machine's own load moves the number by — the reasoning, and the
#            reading that proved it, are at the assertion.
#
# Section 4  the freshness the cheap pass would cost.  Publishing less often is
#            the cheap way to make sections 1-3 green, and while the figures
#            were pushed it was caught by pinning figures_age_ms.  There is no
#            age to pin now, so what is pinned is the property that replaced it:
#            the FIRST `stats` after a connection already reports it.  Measured
#            here: 253 ms median before this change, 4 ms after, and the 4 ms is
#            the CLI round trip.
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
# Thirty-two of them, because section 3 divides by the count and one process's
# CPU time is reported truncated to the kernel's clock tick.  Eight over twenty
# seconds put the resolution at 62 us/s per tick, and the correct build reads
# ONE tick over the whole window: base and fix came out 62-125 against 0-62,
# which is a one-tick difference reported as a measurement.  Thirty-two over
# thirty seconds is 10.4 us/s per tick, and the two builds then read 177-208
# against 0-10 — six ticks of separation instead of one.
N=32
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
WINDOW=30

# ─── 1 & 2: how often an idle worker wakes ──────────────────────────────────
C0=$(vctx "$W")
T0=0; for w in $(workers); do T0=$((T0 + $(cpu_us "$w"))); done
T0=$((T0 + $(cpu_us "$SOCKETLEY_DPID")))
sleep "$WINDOW"
C1=$(vctx "$W")
T1=0; for w in $(workers); do T1=$((T1 + $(cpu_us "$w"))); done
T1=$((T1 + $(cpu_us "$SOCKETLEY_DPID")))

WAKES=$((C1 - C0))
echo "  idle worker $W: $WAKES voluntary wakeups in ${WINDOW}s"

# On the count and not on a rate: a correct build reads 1 here, and integer
# division by the window turns every reading under one per second into the same
# 0.  10 in 30 s is six times what a correct build reads, a sixth of the 66 the
# 250 ms publish read, and a fiftieth of the 1500 the fixed 20 ms timeout read.
# A build sitting anywhere between those — a 20 Hz clock, a 1 Hz heartbeat — is
# still a clock nothing asked for and is still caught.
if [ "$WAKES" -le 10 ]; then
    ok "an idle worker woke $WAKES times in ${WINDOW}s (bound 10; a 250 ms publish reads 66)"
else
    bad "an idle worker woke $WAKES times in ${WINDOW}s, over the bound of 10." \
        " A worker with no traffic and nothing to say should wake only for"
    echo "         idle_wait_ms, which is once every 30 s.  Whatever the rate,"
    echo "         a periodic wakeup here is a clock nothing asked for."
fi

# ─── 2: it still wakes for something that IS happening ──────────────────────
#
# This used to be a floor on the count above, which worked while the worker had
# a heartbeat to be missing.  It has none now: 0 is the correct reading, and a
# worker wedged in a callback reads 0 too.  A count cannot tell them apart, so
# the question is asked directly.
#
# A bare TCP connect, and then the runtime has to say it has one.  That needs
# three things a wedged or blind worker does not have: an accept standing in the
# ring, a loop turn that reaches the completion, and the store into the shared
# table at the end of that turn.  An untimed wait with nothing armed — the shape
# of change this constant invites — fails it and fails nothing else in this
# directory, because an idle runtime's failures are all invisible.
#
# bash's own /dev/tcp, so the connection is held by this shell and closes with
# the descriptor rather than with somebody else's process.
LIVE_PORT=$((PORT + 1))
LIVE=""
if exec 9<>"/dev/tcp/127.0.0.1/$LIVE_PORT" 2>/dev/null; then
    for _ in $(seq 1 40); do
        LIVE=$("$BIN" stats idle1 2>/dev/null | awk -F: '$1 == "connections" { print $2; exit }')
        [ "$LIVE" = "1" ] && break
        sleep 0.05
    done
    exec 9>&-
fi
if [ "$LIVE" = "1" ]; then
    ok "the idle worker woke for a connection and counted it"
else
    bad "an idle worker was sent a connection and reported '$LIVE' connections." \
        " It is waiting on something that a connection does not end, which is a"
    echo "         wedged worker and not a cheap one — see arm_control() and the"
    echo "         accept armed on the runtime's own ring."
fi

# ─── 3: CPU per idle runtime ────────────────────────────────────────────────
#
# The figure the whole change is about, and the one assertion here that has to
# say what build it is talking about.
#
# 60 us/s per runtime, between two sets of numbers measured on this machine on
# 2026-08-22, interleaved on a quiet box:
#
#                            32 runtimes    100 runtimes
#   pushed every 250 ms      208 / 177      216 / 150 / 193
#   published on change        0 /  10        3 /   6 /  10
#
# and, further back, 788-951 for the fixed 20 ms timeout that came before the
# publish.  The bound is six times the most expensive correct reading and three
# times the cheapest reading of the defect it is ruling out, which is as much
# headroom in both directions as this instrument has: one clock tick at N=32 and
# WINDOW=30 is 10.4 us/s, so a correct build is measured to within one tick of
# zero and the bound is six ticks above it.
#
# ─── AND WHY IT DOES NOT RUN ON A SANITIZER BUILD ───────────────────────────
#
# Because it cannot be made to mean the same thing there.  While the figures
# were pushed, the same source measured 1375 us/s per idle runtime under
# ASan/UBSan against 2437 for the fixed-timeout defect — a 1.8x separation
# rather than Release's 2.7x, because instrumentation makes a publish far more
# expensive than it makes a bare wakeup, and a bound with less headroom than the
# machine's own load is a coin toss reported as a defect.  It was: this file's
# first Sanitize run read 1500 and failed against a bound calibrated on Release.
# The bound has moved since and the reason has not, so it is still Release only.
#
# Sections 1 and 2 are unaffected by any of that -- a wakeup count is a count,
# and it reads 4/s on both builds -- so the sanitizer run keeps the assertion
# that names the mechanism and loses only the one about its price.
PER=$(( (T1 - T0) / WINDOW / N ))
echo "  $N idle runtimes: $PER us/s of CPU each (daemon + its workers)"

# Asked of the binary rather than of $SOCKETLEY_CONFIG or the path: agents in
# this tree copy the build elsewhere under other names, which is the same reason
# lib_daemon.sh stopped identifying daemons by process name.
if grep -aqm1 __asan_init "$BIN"; then
    echo "  (not asserted: this is a sanitizer build — see the note above)"
elif [ "$PER" -le 60 ]; then
    ok "an idle runtime costs $PER us/s (bound 60; a 250 ms publish costs ~180-215)"
else
    bad "an idle runtime costs $PER us/s, over the bound of 60 us/s." \
        " A hundred idle runtimes would be $((PER / 100))% of a core spent on nothing."
    echo "         daemon+workers went from $T0 to $T1 us over ${WINDOW}s across $N runtimes."
    echo "         Check section 1 first: if the worker woke more than a handful of"
    echo "         times this is a periodic clock, and if it did not it is a busy"
    echo "         machine rather than a build that regressed."
fi

# ─── 4: the figures did not get older to pay for it ─────────────────────────
#
# Publishing less often is the cheap way to pass sections 1-3, and while the
# figures were pushed this section caught it by pinning figures_age_ms under
# 1000 ms.  There is no age to pin now — there is no interval between the
# reading and the printing to have one — so what is pinned is the property that
# replaced it, in the two halves it has.
#
# FIRST: the label is gone and stays gone.  A build that goes back to a pushed
# figure has to print an age again, and one that prints a pushed figure WITHOUT
# an age is worse than the build this whole change replaced.
STALE=$("$BIN" stats idle1 2>/dev/null | grep -c '^figures_age_ms:\|^figures:' || true)
if [ "$STALE" -eq 0 ]; then
    ok "stats reports no age for a worker-backed runtime, because there is none"
else
    bad "stats printed $STALE figures:/figures_age_ms line(s) for idle1." \
        " Those exist only where a figure is pushed on a timer.  If this build"
    echo "         pushes again, sections 1-3 are being paid for out of freshness."
fi

# SECOND, and this is the discriminating half: the first read already sees it.
#
# A connection is opened and `stats` is asked ONCE, immediately.  A build that
# sums the shared table at print time answers 1; a build that reports the last
# pushed sample answers 0 until its next publish.  Measured on this box: 253 ms
# median to see a new connection while the figures were pushed, 4 ms after they
# moved into shared memory — and the 4 ms is the CLI round trip, not the worker.
#
# Ten of them, because one first-read is a coin toss against a 250 ms publish
# whose phase this script does not control: a pushed build passes a single
# attempt whenever the connect lands just before a publish.  Ten make that
# 1-in-1000, and a correct build scores 10 every time because the count cannot
# be behind its own loop turn.
FRESH=0
for i in $(seq 1 10); do
    if exec 8<>"/dev/tcp/127.0.0.1/$LIVE_PORT" 2>/dev/null; then
        SEEN=$("$BIN" stats idle1 2>/dev/null | awk -F: '$1 == "connections" { print $2; exit }')
        [ "$SEEN" = "1" ] && FRESH=$((FRESH+1))
        exec 8>&-
        # Back to zero before the next attempt, so each one is asking the same
        # question.  Bounded: a reap this loop never sees would otherwise make
        # every later attempt read 1 for the wrong reason.
        for _ in $(seq 1 40); do
            [ "$("$BIN" stats idle1 2>/dev/null | awk -F: '$1 == "connections" { print $2; exit }')" = "0" ] && break
            sleep 0.05
        done
    fi
done
if [ "$FRESH" -ge 9 ]; then
    ok "the first stats after a connection saw it $FRESH times out of 10"
else
    bad "the first stats after a connection saw it only $FRESH times out of 10." \
        " A figure summed at print time cannot be behind the loop turn that"
    echo "         counted the accept.  A score near zero is a pushed figure back"
    echo "         in front of these counters; see runtime_instance::worker_figures()."
fi

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
