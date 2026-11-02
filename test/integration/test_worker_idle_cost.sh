#!/usr/bin/env bash
# suite: quiet -- asserts microseconds of CPU per second per idle runtime,
# which under a parallel run is the parallel run's number.
# ─── WHAT THIS IS FOR ───────────────────────────────────────────────────────
# A worker loop that waited on a constant bought 50 wakeups a second against an
# empty ring, so a hundred idle runtimes cost most of a core to hold still; the
# loop waits on its own next deadline now and has none, because the counters
# moved into a shared table the daemon sums at print time and the frame is sent
# only when what `stats` cannot compute has changed -- which for an idle
# runtime is never.
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
# Five sections: an upper bound on wakeups catches a periodic clock put back
# into the loop, a direct liveness check replaces the lower bound a heartbeat
# used to provide, CPU per idle runtime is the figure the change is about and
# is Release only, the freshness the cheap pass would cost is pinned as "the
# first `stats` after a connection already reports it", and the wait still has
# to end on a frame rather than on its deadline -- which a build that
# lengthened the timeout and lost the poll would pass every other section of.
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
# Thirty-two of them, because section 3 divides by the count and one process's
# CPU time is truncated to the kernel's clock tick -- eight over twenty seconds
# gave a one-tick difference reported as a measurement, while thirty-two over
# thirty gives six ticks of separation.
N=32
# A sanitizer worker holds about 200 MiB, and past the memory a run has they measure reclaim, not an idle loop.
case "$BIN" in *Sanitize*)
    . "$(dirname "$0")/../lib_suite.sh"
    if [ "$(suite_mem_slots 209715200)" -le "$N" ]; then
        echo "  SKIP: $((N + 1)) sanitizer processes of ~200 MiB do not fit in the memory this run may use"
        exit 0
    fi ;;
esac
for i in $(seq 1 $N); do
    "$BIN" create server "idle$i" -p $((PORT + i)) -s >/dev/null 2>&1 || true
done

# Every worker this run's daemon forked, by parentage rather than by name,
# because the binary is often a copy under another name in this tree.
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

# Voluntary switches only, because an idle worker's wakeups are its own while
# involuntary ones are the scheduler taking the CPU away, which is a fact about
# the machine rather than about this build.
vctx() { awk '/^voluntary_ctxt_switches/{print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }
cpu_us() { awk '{printf "%d", ($14+$15)*1000000/'"$(getconf CLK_TCK)"'}' "/proc/$1/stat" 2>/dev/null || echo 0; }

# Twenty seconds and eight runtimes because /proc truncates CPU time to the
# clock tick, so a shorter window is up to 90 ms of slack on a total of about
# 100 ms -- which is not a measurement.
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

# On the count and not on a rate, because integer division by the window turns
# every reading under one per second into the same 0 -- and a build sitting
# anywhere between a correct one and the old timeout is still a clock nothing
# asked for.
if [ "$WAKES" -le 10 ]; then
    ok "an idle worker woke $WAKES times in ${WINDOW}s (bound 10; a 250 ms publish reads 66)"
else
    bad "an idle worker woke $WAKES times in ${WINDOW}s, over the bound of 10." \
        " A worker with no traffic and nothing to say should wake only for"
    echo "         idle_wait_ms, which is once every 30 s.  Whatever the rate,"
    echo "         a periodic wakeup here is a clock nothing asked for."
fi

# Liveness is asked directly rather than as a floor on the count, because 0
# wakeups is now the correct reading and a wedged worker scores the same -- a
# bare /dev/tcp connect from this shell, measured against a baseline read a
# moment earlier so that what is asserted is that the count moved.
conns() { "$BIN" stats idle1 2>/dev/null | awk -F: '$1 == "connections" { print $2; exit }'; }
LIVE_PORT=$((PORT + 1))
LIVE_BASE=$(conns)
case "$LIVE_BASE" in ''|*[!0-9]*) LIVE_BASE=0 ;; esac
LIVE_WANT=$((LIVE_BASE + 1))
LIVE=""
if exec 9<>"/dev/tcp/127.0.0.1/$LIVE_PORT" 2>/dev/null; then
    for _ in $(seq 1 40); do
        LIVE=$(conns)
        [ "$LIVE" = "$LIVE_WANT" ] && break
        sleep 0.05
    done
    exec 9>&-
fi
if [ "$LIVE" = "$LIVE_WANT" ]; then
    ok "the idle worker woke for a connection and counted it"
else
    bad "an idle worker was sent a connection and reported '$LIVE', wanted $LIVE_WANT." \
        " It is waiting on something that a connection does not end, which is a"
    echo "         wedged worker and not a cheap one — see arm_control() and the"
    echo "         accept armed on the runtime's own ring."
fi

# ─── 3: CPU per idle runtime ────────────────────────────────────────────────
# The bound is six times the most expensive correct reading and three times the
# cheapest reading of the defect it rules out, which is as much headroom as
# this instrument has -- and it is Release only because instrumentation makes a
# publish far more expensive than a bare wakeup, leaving less separation than
# the machine's own load, while sections 1 and 2 are unaffected and stay.
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

# Publishing less often is the cheap way to pass sections 1-3, and with no age
# left to pin the property that replaced it is pinned in two halves -- the
# first being that the age label is gone and stays gone, since a pushed figure
# without an age is worse than the build this replaced.
STALE=$("$BIN" stats idle1 2>/dev/null | grep -c '^figures_age_ms:\|^figures:' || true)
if [ "$STALE" -eq 0 ]; then
    ok "stats reports no age for a worker-backed runtime, because there is none"
else
    bad "stats printed $STALE figures:/figures_age_ms line(s) for idle1." \
        " Those exist only where a figure is pushed on a timer.  If this build"
    echo "         pushes again, sections 1-3 are being paid for out of freshness."
fi

# The discriminating half is how long after a connection the runtime says so,
# taken as the median of ten because a single attempt against a publish whose
# phase this script does not control is a coin toss -- with 9999 the sentinel
# for a count that never moved, which against a pushed figure is a real reading
# rather than a broken one.
lag_once() {                       # -> milliseconds, or 9999 if it never moved
    local base t0 v i
    base=$(conns)
    case "$base" in ''|*[!0-9]*) printf '9999'; return ;; esac
    exec 8<>"/dev/tcp/127.0.0.1/$LIVE_PORT" 2>/dev/null || { printf '9999'; return; }
    t0=$(mono_ms)
    v="$base"
    for i in $(seq 1 400); do
        v=$(conns)
        [ "$v" != "$base" ] && break
    done
    if [ "$v" = "$base" ]; then printf '9999'
    else printf '%s' "$(( $(mono_ms) - t0 ))"; fi
    exec 8>&-
    for i in $(seq 1 60); do
        [ "$(conns)" = "$base" ] && break
        sleep 0.05
    done
}

LAGS=""
for _ in $(seq 1 10); do LAGS="$LAGS $(lag_once)"; done
MEDIAN=$(printf '%s\n' $LAGS | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')
# A lag is at least one `stats` round trip, and under Sanitize on a slow box
# that round trip alone reached the old flat bound: medians of 103 ms failed it
# with live figures.  So the round trip is timed, as a median of ten, and the
# bound is on what the lag adds to it, as test_worker_stats_live.sh does.
CLI=""
for _ in $(seq 1 10); do
    t0=$(mono_ms); conns >/dev/null
    CLI="$CLI $(( $(mono_ms) - t0 ))"
done
CLI_MS=$(printf '%s\n' $CLI | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')
echo "  lag from connection to stats reporting it: median ${MEDIAN} ms ($LAGS ), one stats round trip ${CLI_MS} ms"

# 100 ms past one round trip is ten times the worst correct reading and under
# half what a 250 ms publish adds, because this separates two mechanisms rather
# than timing a fast path.
if [ "$MEDIAN" -le $(( CLI_MS + 100 )) ] 2>/dev/null; then
    ok "a new connection is visible in ${MEDIAN} ms (bound ${CLI_MS} + 100; a 250 ms publish reads ~200 more)"
else
    bad "a new connection took ${MEDIAN} ms to become visible, over the bound of ${CLI_MS} + 100." \
        " Publishing less often is the cheap way to pass sections 1-3, and this"
    echo "         is what it costs.  See runtime_instance::worker_figures()."
fi

# `reload-lua` is the command that shows the poll is armed, because stop,
# stats, ls and remove are answered by the daemon out of its placeholder and
# would pass with the notification gone entirely -- and it gets its own
# runtime, created after the measurements above so nothing in sections 1-3
# watched a runtime with a script attached.
LUA="$SOCKETLEY_TMPD/rt.lua"
cat > "$LUA" <<'EOF'
function on_start() end
EOF
if "$BIN" create server idlert -p $((PORT + N + 1)) --lua "$LUA" -s >/dev/null 2>&1; then
    ok "the reload runtime is created"
else
    bad "the reload runtime was not created, so the reload below would time a refusal"
fi
sleep 1

# The bound is on what the reload adds to one CLI round trip, because under
# Sanitize the CLI process alone costs ~170 ms before it reaches the daemon.
RT=""
for _ in $(seq 1 5); do
    t0=$(mono_ms); "$BIN" stats idlert >/dev/null 2>&1
    RT="$RT $(( $(mono_ms) - t0 ))"
done
RT_MS=$(printf '%s\n' $RT | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')

# A median of three, each after a second's quiet so the worker is back in its idle wait.
RL=""; RL_FAILED=0
for _ in $(seq 1 3); do
    sleep 1
    t0=$(mono_ms); "$BIN" reload-lua idlert >/dev/null 2>&1 || RL_FAILED=$((RL_FAILED+1))
    RL="$RL $(( $(mono_ms) - t0 ))"
done
# A refused reload is fast and would pass the bound without the worker ever being woken.
if [ "$RL_FAILED" -eq 0 ]; then ok "every reload-lua succeeded"
else bad "$RL_FAILED of 3 reload-lua calls failed, so their timings measure a refusal"; fi
RL_MS=$(printf '%s\n' $RL | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')
MS=$((RL_MS - RT_MS))
echo "  reload-lua against an idle worker: median ${RL_MS} ms ($RL ), one stats round trip ${RT_MS} ms ($RT ), ${MS} ms added"

# 150 ms past one round trip: over ten times what a reload adds when the arm ends
# the wait, and far below the 2000 ms await_routes() deadline a deaf worker reads.
if [ "$MS" -le 150 ]; then
    ok "a control frame ended the worker's wait ${MS} ms past one round trip (bound 150; a broken arm adds ~2000)"
else
    bad "reload-lua took ${RL_MS} ms against an idle worker, ${MS} ms past one round trip (bound 150)." \
        " The frame is waiting for the loop's deadline, or for the daemon's,"
    echo "         instead of waking the worker.  The recv armed on the control"
    echo "         socket is what makes a long wait safe, and it is not working —"
    echo "         see arm_control() and m_ctl_armed in worker_main.cpp."
fi

echo ""
echo " Summary: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
