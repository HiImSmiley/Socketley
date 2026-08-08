#!/usr/bin/env bash
# Integration test: a runtime restarted with traffic in flight comes back whole.
#
# stop() runs teardown(), start() runs setup(), and the two have to agree about
# who owns what.  Every runtime in this tree carries a comment at the top of its
# setup() saying that nothing is cleaned up there any more, because teardown()
# deliberately keeps some of it alive — connection struct pools, pooled backend
# descriptors, subscriptions.  A setup() that goes back to freeing those frees
# storage the kernel still has a request against, and the restart is the only
# moment that can be observed: created -> running is a fresh setup() over state
# a teardown() just decided to keep.
#
# Restarting an idle runtime proves almost nothing — nothing is in flight, so
# nothing is owed.  This test restarts a cache and a proxy alternately while
# several connections per runtime are mid-request, and after each restart makes
# a fresh connection and requires a correct answer on it.
#
# WHAT IT CATCHES
#   - a restart that loses the runtime entirely (probe fails, port never
#     answers again, or the daemon dies and every later assertion fails loudly)
#   - a restart that leaves the runtime answering wrongly: '*_bad' counts a
#     reply whose *content* was wrong, which is what stale state from the
#     previous run looks like from a client
#   - descriptors or memory that a restart never gives back (both runtimes are
#     stopped again before the final sample, so teardown has to have released
#     everything it took)
#
# WHAT IT DOES NOT CATCH
#   - a use-after-free that happens not to touch a page that has been reused;
#     that is a sanitizer's job, not a black-box test's
#   - anything about restart while a *Lua* callback is mid-flight, or TLS, or
#     UDP: only plain TCP cache and proxy traffic is driven here
#   - single-restart races.  Six restarts is a standing chance of hitting a
#     narrow window, not a proof.  When hunting this class deliberately, loop:
#       for i in $(seq 20); do bash test/integration/test_restart_under_load.sh || break; done
#
# HONEST ABOUT TIMING — 'live_at_stop' is the guard against the failure window
# never opening: before each stop the harness checks that the counter for that
# runtime is still moving.  If a future change makes the traffic threads stall,
# this test says so instead of quietly restarting an idle runtime and reporting
# a pass.
#
# That guard is a claim about the HARNESS, not about the build, and the two are
# reported differently now — see the floor argument at the assertion itself.  It
# used to require all six cycles and print a shortfall in the same voice as a
# use-after-free, which cost a full-suite run an hour of somebody's attention
# for a scheduling artifact.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# shellcheck source=lib_create.sh
. "$(dirname "$0")/lib_create.sh"
# For daemon_sweep in cleanup.  This file keeps its own inline isolation; sourcing
# defines functions without running anything, so nothing here changes hands.
# shellcheck source=lib_daemon.sh
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

if ! command -v python3 >/dev/null 2>&1; then
    echo "=== Integration: restart under load ==="
    echo "  SKIP: python3 not available"
    exit 0
fi

# Own daemon, socket and state directory.  Against the shared daemon this test
# does not discriminate at all: auto-restart puts a crashed runtime back and the
# probe passes over the corpse.
TMPDIR_T=$(mktemp -d /tmp/socketley-restart-XXXXXX)
export HOME="$TMPDIR_T/home"
export SOCKETLEY_SOCKET="$TMPDIR_T/daemon.sock"
mkdir -p "$HOME"
DPID=""
BEPID=""

CACHE_PORT=$((SL_PORT_BASE+500))
PROXY_PORT=$((SL_PORT_BASE+501))
BE_PORT=$((SL_PORT_BASE+502))
FINAL_PORT=$((SL_PORT_BASE+503))
CACHE_NAME=rl_cache
PROXY_NAME=rl_proxy
CYCLES=6            # restarts; alternates cache, proxy, cache, ...
MIN_OK=40           # per runtime: below this the load was too thin to mean much
MIN_LIVE=$((CYCLES - 1))   # stops whose failure window must be provably open

# Tolerance for the descriptor check.  Both samples are taken at the same point
# in the lifecycle — both runtimes created but stopped, after a settle — so the
# listener, the io_uring registrations and every lazily-opened one-time
# descriptor are present in both.  What can still differ by a few is transient:
# the IPC connection serving the command that triggered the sample, a state file
# being rewritten.  A real leak in this family is one descriptor per connection
# or per restart, i.e. hundreds, so 6 separates the two without being tight
# enough to flake.
FD_TOLERANCE=6

# RSS bound.  GUESSED, NOT MEASURED — this was written without a run, so treat
# it as a ceiling that catches gross leakage (a few KiB per connection over a
# few thousand connections, or a whole runtime's worth per restart), not as a
# certified allocator profile.  The actual growth is printed on every run,
# passing or failing: use the first real numbers to tighten this, and do not
# assume a value that has never fired is correct.  A Release figure — see the
# sanitizer note below for why it is not asserted in an instrumented build.
RSS_BOUND_KB=24576

# ─── ONE CHECK THAT MEASURES THE SANITIZER, NOT THE PRODUCT ─────────────────
#
# This file runs in the nightly under ASan+UBSan and under TSan as well as under
# Release, and RSS_BOUND_KB has no defined meaning in an instrumented build.
#
# The bound above is a ceiling on how much a Release daemon may grow over six
# restarts under load.  An ASan daemon keeps eight bytes of shadow for every
# byte of application memory and a redzone around every allocation, so it starts
# an order of magnitude higher and every page this test's traffic faults in
# costs its shadow as well:
#
#     Release   base 14204 kB   growth  2192 kB   (2026-08-02, this machine)
#     ASan      base 78972 kB   growth 38028 kB   (2026-08-02, this machine)
#
# The base alone is five and a half times the Release base, and the growth is
# seventeen times the Release growth against a bound only eleven times it.  The
# first ASan run of this file in five weeks, on the same commit, reported base
# 78520 kB and growth 40220 kB: the two agree within 6%, which is what a
# sanitizer's fixed overhead looks like and not what a leak looks like.  There
# is no bound that both catches "a whole runtime's worth per restart" in Release
# and clears ASan's floor — one that did would have stopped bounding anything.
#
# So it is printed and not asserted in a sanitized build, loudly, with the
# numbers, so nobody reads a quiet log as a checked one.  EVERYTHING ELSE STAYS
# ASSERTED IN EVERY BUILD — restarts_ok, recovered, cache_bad, proxy_bad, both
# traffic floors, live_at_stop, both runtimes still in 'ps', that the daemon
# still serves a runtime created after the load, and the descriptor count.
# Those are what running this file under a sanitizer is FOR, and all of them
# passed under ASan in the run above (descriptors: delta=2 of a tolerance of 6;
# cache_bad=0 proxy_bad=0 over 33311 and 15594 healthy round trips, so the
# traffic floors are nowhere near the sanitizer's clock here).
#
# THE DAEMON BEING GONE IS STILL A FAILURE, in every build.  'unreadable' is
# rejected before the exemption below is ever reached: "this build cannot answer
# the question" and "there was no daemon left to ask" are different statements
# and only the first one is excused here.
#
# NOT ASSERTED IS NOT `NOT MEASURABLE`.  This file already carries herr() below,
# from d1fa885, for a claim this RUN could not put and might put next time.  This
# is the other thing: this BUILD cannot answer this question and never will, so
# retrying changes nothing.  They are counted in separate columns, and only
# herr() ends the run non-zero — a job that is red every single night for a
# reason nobody can act on gets ignored, which is the same end state as a check
# that cannot fail.
#
# Detected from the binary rather than from an environment variable, using the
# idiom the nightly's own "Verify the build" step uses: a build that lost its
# sanitizer flags must not be able to claim this exemption.  A stripped Release
# binary yields nothing and is treated as not sanitized, which is the safe way
# round — unknown keeps the strict bound.
#
# NOT `grep -q`.  This file runs under `set -euo pipefail`, and `grep -q` exits
# the moment it matches, which hands `nm` a SIGPIPE; with pipefail the pipeline
# then reports 141 and the `if` takes the branch for "no match" precisely when
# there was one.  grep without -q reads its input to the end, so the pipeline's
# status is grep's.  (The same idiom in the nightly's "Verify the build" step is
# safe only because GitHub Actions does not set pipefail; it is not safe here.)
SANITIZED=""
if nm -C "$BIN" 2>/dev/null | grep '__tsan_' >/dev/null 2>&1; then
    SANITIZED="TSan"
elif nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null 2>&1; then
    SANITIZED="ASan"
fi

PASS=0; FAIL=0; HERR=0; SKIP=0; TOTAL=0

# herr LABEL REASON [DETAIL...]
#
# A claim this run was unable to put the question to.  Kept apart from a failure
# on purpose, and deliberately in the words test_proxy_group_keepalive_load.sh
# already uses for it rather than a third vocabulary: an empty measurement
# window and a broken build used to print the same sentence here, and the run
# that printed it was read as a product defect.
#
# Both still end the run non-zero — an assertion that was never evaluated has
# not passed — but only one of them is about the build, and the summary line
# counts them separately so that is visible without reading the log.
herr() {
    local label=$1 reason=$2; shift 2
    TOTAL=$((TOTAL+1)); HERR=$((HERR+1))
    echo "  NOT MEASURABLE [$label]: $reason"
    local line
    for line in "$@"; do echo "        $line"; done
}

# not_asserted LABEL REASON
#
# A claim this BUILD cannot answer, as opposed to one this RUN could not put.
# See the long note at RSS_BOUND_KB: herr() above is for a window that did not
# open and might next time, and it ends the run non-zero; this one is for a
# number that belongs to the sanitizer and will belong to it every night for
# ever, and it does not.  Two columns, deliberately, so the summary line says
# which of the two happened without anyone reading the log.
#
# The vocabulary is test_abrupt_client_abort.sh's, from 4414780, and not a third
# one invented here.
not_asserted() {  # label reason
    TOTAL=$((TOTAL+1)); SKIP=$((SKIP+1))
    echo "  NOT ASSERTED [$1]: $2"
    echo "        sanitized build ($SANITIZED) — this measures the sanitizer, not the daemon"
}

cleanup() {
    [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null || true
    # Wait for the daemon to actually go.  A plain kill returns immediately, and
    # a daemon still holding connections stays bound long enough for the next
    # test in the suite to collide with it.
    if [ -n "$DPID" ]; then
        kill "$DPID" 2>/dev/null || true
        for _ in $(seq 1 50); do
            kill -0 "$DPID" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
    # Kill by socket, not only by pid.  A CLI command run against a daemon that
    # is not up yet — or not up any more — starts one of its own, detached from
    # this shell; killing $DPID would leave that one running for good, holding
    # this test's ports.  The socket path comes from mktemp, so this can only
    # ever hit daemons belonging to this run.
    #
    # This was an inline `pgrep -f 'socketley daemon'` loop.  `-f` matches the
    # whole command line, so the pattern also matches any shell whose own
    # command line happens to carry that string — including the runner invoking
    # this file — and an -f match one character too broad kills the run doing
    # the killing, which has happened twice in this project.  The environ check
    # underneath made it safe in practice, but the shape is the one lib_daemon.sh
    # exists to delete, and a safe instance of a dangerous shape is still a copy
    # of it for the next file to imitate.  daemon_sweep asks the socket who is
    # serving it instead, and matches nothing by name.
    daemon_sweep "$SOCKETLEY_SOCKET"
    rm -rf "$TMPDIR_T"
}
trap cleanup EXIT

echo "=== Integration: restart under load ==="

# ── Resource sampling ───────────────────────────────────────────────────────
# Both readers return the literal string 'unreadable' rather than an empty
# string, and every assertion rejects it before comparing anything.  An empty
# value compares equal to another empty value, and a "before == after" that
# holds only because the daemon died and neither sample could be taken is a
# pass for the wrong reason — this suite has produced exactly that before.
fd_count() {
    local n
    n=$(ls -1 "/proc/$DPID/fd" 2>/dev/null | wc -l 2>/dev/null) || n=""
    n=$(printf '%s' "$n" | tr -d '[:space:]')
    case "$n" in
        ''|0|*[!0-9]*) echo "unreadable" ;;   # a live process always has 0,1,2
        *)             echo "$n" ;;
    esac
}

rss_kb() {
    local n
    n=$(awk '/^VmRSS:/{print $2; exit}' "/proc/$DPID/status" 2>/dev/null) || n=""
    n=$(printf '%s' "$n" | tr -d '[:space:]')
    case "$n" in
        ''|*[!0-9]*) echo "unreadable" ;;
        *)           echo "$n" ;;
    esac
}

assert_fds_returned() {   # base final tolerance
    local base="$1" final="$2" tol="$3" delta
    TOTAL=$((TOTAL+1))
    if [ "$base" = "unreadable" ] || [ "$final" = "unreadable" ]; then
        FAIL=$((FAIL+1))
        echo "  FAIL [descriptors returned]: /proc/$DPID/fd unreadable (base=$base final=$final)"
        echo "        the daemon is gone — that is a failure, not a clean run"
        return
    fi
    delta=$((final - base))
    echo "  fds:  base=$base final=$final delta=$delta tolerance=$tol"
    if [ "$delta" -le "$tol" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [descriptors returned]: $delta descriptors were never given back"
    fi
}

assert_rss_bounded() {    # base final bound_kb
    local base="$1" final="$2" bound="$3" delta
    TOTAL=$((TOTAL+1))
    if [ "$base" = "unreadable" ] || [ "$final" = "unreadable" ]; then
        FAIL=$((FAIL+1))
        echo "  FAIL [memory bounded]: /proc/$DPID/status unreadable (base=$base final=$final)"
        echo "        the daemon is gone — that is a failure, not a clean run"
        return
    fi
    delta=$((final - base))
    echo "  rss:  base=${base}kB final=${final}kB growth=${delta}kB bound=${bound}kB"
    if [ -n "$SANITIZED" ]; then
        TOTAL=$((TOTAL-1))   # not_asserted takes its own
        not_asserted "memory bounded" \
            "RSS grew ${delta}kB from a base of ${base}kB; the ${bound}kB bound is a Release figure"
        return
    fi
    if [ "$delta" -le "$bound" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [memory bounded]: RSS grew ${delta}kB over the run, bound is ${bound}kB"
    fi
}

# ── Harness ────────────────────────────────────────────────────────────────
H="$TMPDIR_T/harness.py"
cat >"$H" <<'PYEOF'
"""Modes: waitport | waitsock | warmup | load | probe.

Every mode prints one machine-readable line and nothing else that matters.  The
shell reads named fields out of that line; a field that is absent must make the
shell fail, never compare equal to an absent expectation.
"""
import socket
import subprocess
import sys
import threading
import time

mode = sys.argv[1]


def connect_ok(port, deadline):
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.4).close()
            return True
        except OSError:
            time.sleep(0.02)
    return False


if mode == "waitport":
    sys.exit(0 if connect_ok(int(sys.argv[2]), time.time() + float(sys.argv[3])) else 1)


if mode == "waitsock":
    # Wait for the daemon's IPC socket without going through the CLI: every CLI
    # command starts a daemon of its own when the socket does not answer, which
    # is exactly what must not happen while ours is still coming up.
    path = sys.argv[2]
    end = time.time() + float(sys.argv[3])
    while time.time() < end:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.settimeout(0.4)
            s.connect(path)
            s.close()
            sys.exit(0)
        except OSError:
            time.sleep(0.02)
        finally:
            try:
                s.close()
            except OSError:
                pass
    sys.exit(1)


if mode == "serve":
    # One verified cache round trip against an arbitrary port.  Prints a marker
    # on success and nothing on failure, so the shell asserts the presence of
    # 'SERVES_OK' rather than comparing two strings that could both be empty.
    try:
        s = socket.create_connection(("127.0.0.1", int(sys.argv[2])), timeout=3)
        s.settimeout(3)
        s.sendall(b"set fk fv\nget fk\n")
        buf = b""
        while buf.count(b"\n") < 2:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        s.close()
        if buf.split(b"\n")[:2] == [b"ok", b"fv"]:
            print("SERVES_OK")
    except OSError:
        pass
    sys.exit(0)

BIN         = sys.argv[2]
CACHE_NAME  = sys.argv[3]
PROXY_NAME  = sys.argv[4]
CACHE_PORT  = int(sys.argv[5])
PROXY_PORT  = int(sys.argv[6])
CYCLES      = int(sys.argv[7]) if len(sys.argv) > 7 else 0

PAD = "p" * 200
OPS_PER_CONN = 4
CACHE_THREADS = 3
PROXY_THREADS = 3

lock = threading.Lock()
stop_evt = threading.Event()
c = {"cache_ops": 0, "cache_ok": 0, "cache_bad": 0, "cache_err": 0,
     "proxy_ops": 0, "proxy_ok": 0, "proxy_bad": 0, "proxy_err": 0}


def bump(k):
    with lock:
        c[k] += 1


def ok_of(kind):
    with lock:
        return c[kind + "_ok"]


def wait_progress(kind, base, timeout):
    """True once this runtime's success counter moves past `base`.

    Waiting rather than sampling a fixed slice on purpose: on a loaded machine a
    60ms window can legitimately contain no completions and the assertion built
    on this would flake.  Half a second of no progress at all, with six threads
    hammering, means the traffic is not running — which is the thing worth
    failing on.
    """
    end = time.time() + timeout
    while time.time() < end:
        if ok_of(kind) > base:
            return True
        time.sleep(0.01)
    return False


def recv_lines(s, n):
    """Exactly n newline-terminated lines, or None.

    None means the peer went away or stalled.  During a restart window that is
    expected, so it is counted as an error and never as a wrong answer — only a
    reply whose content is wrong counts as '_bad', and that is the number this
    test actually argues about.
    """
    buf = b""
    out = []
    while len(out) < n:
        try:
            chunk = s.recv(65536)
        except OSError:          # includes socket timeouts
            return None
        if not chunk:
            return None
        buf += chunk
        while b"\n" in buf and len(out) < n:
            line, buf = buf.split(b"\n", 1)
            out.append(line.rstrip(b"\r"))
    return out


def cache_roundtrip(s, key, val):
    s.sendall(("set %s %s\nget %s\n" % (key, val, key)).encode())
    lines = recv_lines(s, 2)
    if lines is None:
        return None
    return lines[0] == b"ok" and lines[1] == val.encode()


def proxy_roundtrip(s, payload):
    s.sendall((payload + "\n").encode())
    lines = recv_lines(s, 1)
    if lines is None:
        return None
    return lines[0] == payload.encode()


def cache_worker(tid):
    seq = 0
    while not stop_evt.is_set():
        try:
            s = socket.create_connection(("127.0.0.1", CACHE_PORT), timeout=1.0)
            s.settimeout(1.0)
        except OSError:
            bump("cache_err")
            time.sleep(0.01)
            continue
        try:
            for _ in range(OPS_PER_CONN):
                if stop_evt.is_set():
                    break
                seq += 1
                # The key space is deliberately small and per-thread: values are
                # unique per operation, so a stale answer is still caught, but
                # the store does not grow with the op count.  Unique keys would
                # add megabytes of entirely legitimate cache content to the
                # daemon's RSS and make the memory bound below meaningless.
                key = "rk%d_%d" % (tid, seq % 64)
                val = "rv%d_%d_%s" % (tid, seq, PAD)
                bump("cache_ops")
                r = cache_roundtrip(s, key, val)
                if r is None:
                    bump("cache_err")
                    break
                bump("cache_ok" if r else "cache_bad")
        except OSError:
            bump("cache_err")
        try:
            s.close()
        except OSError:
            pass


def proxy_worker(tid):
    seq = 0
    while not stop_evt.is_set():
        try:
            s = socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=1.0)
            s.settimeout(1.0)
        except OSError:
            bump("proxy_err")
            time.sleep(0.01)
            continue
        try:
            for _ in range(OPS_PER_CONN):
                if stop_evt.is_set():
                    break
                seq += 1
                bump("proxy_ops")
                r = proxy_roundtrip(s, "px%d-%06d:%s" % (tid, seq, PAD))
                if r is None:
                    bump("proxy_err")
                    break
                bump("proxy_ok" if r else "proxy_bad")
        except OSError:
            bump("proxy_err")
        try:
            s.close()
        except OSError:
            pass


def probe_cache(tag):
    try:
        s = socket.create_connection(("127.0.0.1", CACHE_PORT), timeout=2.0)
        s.settimeout(2.0)
    except OSError:
        return False
    try:
        return cache_roundtrip(s, "__probe", "pv-%s" % tag) is True
    except OSError:
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass


def probe_proxy(tag):
    try:
        s = socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=2.0)
        s.settimeout(2.0)
    except OSError:
        return False
    try:
        return proxy_roundtrip(s, "probe-%s" % tag) is True
    except OSError:
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass


if mode == "warmup":
    # Runs before the resource baseline is taken, so that everything the daemon
    # allocates once — buffer pools, backend pool entries, the state file — is
    # already in the baseline and does not read as growth later.
    cok = sum(1 for i in range(5) if probe_cache("w%d" % i))
    pok = sum(1 for i in range(5) if probe_proxy("w%d" % i))
    print("WARMUP cache_ok=%d proxy_ok=%d" % (cok, pok))
    sys.exit(0)

if mode == "probe":
    print("PROBE cache_ok=%d proxy_ok=%d"
          % (1 if probe_cache("final") else 0, 1 if probe_proxy("final") else 0))
    sys.exit(0)


def run_cli(*args):
    try:
        r = subprocess.run([BIN] + list(args), stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=20)
        return r.returncode
    except Exception:
        return -1


threads = []
for i in range(CACHE_THREADS):
    threads.append(threading.Thread(target=cache_worker, args=(i,), daemon=True))
for i in range(PROXY_THREADS):
    threads.append(threading.Thread(target=proxy_worker, args=(i,), daemon=True))
for t in threads:
    t.start()

restarts_ok = 0
live_at_stop = 0
live_missed = []          # cycles whose window could not be proved open
recovered = 0

for i in range(CYCLES):
    if i % 2 == 0:
        kind, name, port, probe = "cache", CACHE_NAME, CACHE_PORT, probe_cache
    else:
        kind, name, port, probe = "proxy", PROXY_NAME, PROXY_PORT, probe_proxy

    time.sleep(0.12)                     # let traffic build against this runtime
    # Proof that the failure window is actually open: the counter for the
    # runtime about to be stopped has to still be moving, checked immediately
    # before the stop.  A test that restarts an idle runtime looks identical
    # from the outside and proves nothing.
    if wait_progress(kind, ok_of(kind), 0.5):
        live_at_stop += 1
    else:
        # Which cycle and which runtime, not just how many.  A shortfall that
        # names 'the third cycle, the proxy' can be argued with; a bare count
        # cannot, and this one is reported even when the run passes.
        live_missed.append("%d:%s" % (i, kind))

    rc_stop = run_cli("stop", name)
    time.sleep(0.08)                     # requests land on a runtime that is gone
    rc_start = run_cli("start", name)
    up = connect_ok(port, time.time() + 5.0)
    if rc_stop == 0 and rc_start == 0 and up:
        restarts_ok += 1
    if probe("c%d" % i):
        recovered += 1

time.sleep(0.3)                          # traffic against the restarted runtimes
stop_evt.set()
for t in threads:
    t.join(15)

with lock:
    print("TOTALS cycles=%d restarts_ok=%d live_at_stop=%d live_missed=%s recovered=%d "
          "cache_ops=%d cache_ok=%d cache_bad=%d cache_err=%d "
          "proxy_ops=%d proxy_ok=%d proxy_bad=%d proxy_err=%d"
          % (CYCLES, restarts_ok, live_at_stop, ",".join(live_missed) or "-", recovered,
             c["cache_ops"], c["cache_ok"], c["cache_bad"], c["cache_err"],
             c["proxy_ops"], c["proxy_ok"], c["proxy_bad"], c["proxy_err"]))
PYEOF

wait_port() {   # port seconds
    python3 "$H" waitport "$1" "$2"
}

# ── Echo backend for the proxy ─────────────────────────────────────────────
# Whatever a connection sends comes back on that same connection: the backend
# has to be trivially correct so that a wrong reply can only have come from the
# proxy.
python3 - "$BE_PORT" >"$TMPDIR_T/backend.log" 2>&1 <<'PYEOF' &
import socket, sys, threading

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1])))
srv.listen(256)


def handle(conn):
    conn.settimeout(30)
    try:
        while True:
            data = conn.recv(65536)
            if not data:
                return
            conn.sendall(data)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


while True:
    try:
        cl, _ = srv.accept()
    except OSError:
        break
    threading.Thread(target=handle, args=(cl,), daemon=True).start()
PYEOF
BEPID=$!

SOCKETLEY_DLOG="$TMPDIR_T/daemon.log"
"$BIN" daemon >"$TMPDIR_T/daemon.log" 2>&1 &
DPID=$!
# Wait on the IPC socket itself, never by polling with a CLI command.  Every CLI
# command auto-starts a daemon when the socket does not answer yet — cli.cpp's
# ensure_daemon() forks, setsids and re-execs 'socketley daemon' — so polling
# 'ps' against the daemon this test has just launched races it and spawns a
# second, orphaned one.  Whichever loses the bind exits, and when the loser is
# $DPID the pid this test watches becomes a zombie while an orphan serves the
# run: /proc/$DPID/fd is then empty and every resource sample below reads
# 'unreadable'.  Measured at 2 spawned orphans in 30 startups of this sequence.
python3 "$H" waitsock "$SOCKETLEY_SOCKET" 8 || true

TOTAL=$((TOTAL+1))
if "$BIN" ps >/dev/null 2>&1; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the daemon never became reachable — everything below is meaningless"
fi

# ...and the daemon answering is the one this test launched.  A zombie $DPID
# reads 'unreadable' in every /proc sample, so without this the run would report
# its confusion at the very end, in the descriptor and memory checks, rather
# than here where it happened.
TOTAL=$((TOTAL+1))
if [ "$(fd_count)" != "unreadable" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: pid $DPID is not a live process — the daemon that answers"
    echo "        is not the one this test launched, so every /proc sample below is a corpse's"
fi

TOTAL=$((TOTAL+1))
if wait_port "$BE_PORT" 5; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the echo backend never came up on $BE_PORT"
fi

create_ok "cache under test created" "$BIN" create cache "$CACHE_NAME" -p "$CACHE_PORT" -s
create_ok "proxy under test created" "$BIN" create proxy "$PROXY_NAME" -p "$PROXY_PORT" \
    --backend "127.0.0.1:$BE_PORT" --protocol tcp -s
wait_port "$CACHE_PORT" 5 || true
wait_port "$PROXY_PORT" 5 || true

WARM=$(python3 "$H" warmup "$BIN" "$CACHE_NAME" "$PROXY_NAME" \
        "$CACHE_PORT" "$PROXY_PORT" 2>&1 | grep '^WARMUP ' | head -1 || true)

# Assert the success marker, not a comparison: 'WARMUP cache_ok=5 proxy_ok=5'
# has to be present.  If the warm-up did not run there is no line at all, and
# that must fail here rather than silently move the resource baseline.
TOTAL=$((TOTAL+1))
if [ "$WARM" = "WARMUP cache_ok=5 proxy_ok=5" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: warm-up did not serve both runtimes: '${WARM:-<no WARMUP line>}'"
fi

# Baseline with both runtimes created but stopped, so the final sample can be
# taken in exactly the same state — no listener, no pooled backend connections
# in either, and every one-time allocation already made.
"$BIN" stop "$CACHE_NAME" >/dev/null 2>&1 || true
"$BIN" stop "$PROXY_NAME" >/dev/null 2>&1 || true
sleep 0.6
BASE_FD=$(fd_count)
BASE_RSS=$(rss_kb)

"$BIN" start "$CACHE_NAME" >/dev/null 2>&1 || true
"$BIN" start "$PROXY_NAME" >/dev/null 2>&1 || true
wait_port "$CACHE_PORT" 5 || true
wait_port "$PROXY_PORT" 5 || true

OUT="$TMPDIR_T/harness.out"
python3 "$H" load "$BIN" "$CACHE_NAME" "$PROXY_NAME" \
    "$CACHE_PORT" "$PROXY_PORT" "$CYCLES" >"$OUT" 2>&1 || true
TOTALS=$(grep '^TOTALS ' "$OUT" 2>/dev/null | head -1 || true)

# Every number below is read out of that one line.  A missing field leaves the
# value unset, and an unset value must fail loudly rather than compare equal to
# an equally unset expectation.
field() {
    printf '%s\n' "$TOTALS" | grep -o "\b$1=[0-9]\+" | cut -d= -f2 | head -1 || true
}

# The same, for a field that is not a number.  'live_missed' is a list of
# cycle:kind pairs, or '-' when every window opened; it is diagnostic only, so
# an empty reading of it degrades the message and never the verdict.
field_raw() {
    printf '%s\n' "$TOTALS" | grep -o "\b$1=[^ ]\+" | cut -d= -f2- | head -1 || true
}

assert_field_eq() {   # name expected label
    local n
    TOTAL=$((TOTAL+1))
    n=$(field "$1")
    if [ -z "$n" ]; then
        FAIL=$((FAIL+1))
        echo "  FAIL [$3]: no '$1' in the harness result — the harness did not finish"
        return
    fi
    if [ "$n" -eq "$2" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$3]: $1=$n, wanted $2"
    fi
}

assert_field_min() {  # name minimum label
    local n
    TOTAL=$((TOTAL+1))
    n=$(field "$1")
    if [ -z "$n" ]; then
        FAIL=$((FAIL+1))
        echo "  FAIL [$3]: no '$1' in the harness result — the harness did not finish"
        return
    fi
    if [ "$n" -ge "$2" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$3]: $1=$n, wanted at least $2"
    fi
}

TOTAL=$((TOTAL+1))
if [ -n "$TOTALS" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [harness ran]: no TOTALS line; raw output:"
    grep -v '^$' "$OUT" 2>/dev/null | head -8 | sed 's/^/        /' || true
fi

# ── The failure window really opened ───────────────────────────────────────
#
# Traffic was demonstrably still moving against each runtime at the moment it
# was stopped.  This is a claim about the HARNESS — whether it managed to ask
# the question — and not about the build, and it is the only assertion in this
# file of that kind.
#
# It used to be `assert_field_eq live_at_stop "$CYCLES"`, so a run that missed
# one window printed
#
#     FAIL [traffic in flight at every stop]: live_at_stop=5, wanted 6
#
# in the same voice as a use-after-free.  That happened once, at 18/19, in a
# full-suite run whose own numbers said nothing was wrong: cycles=6
# restarts_ok=6 recovered=6 cache_bad=0 proxy_bad=0, over 52502 cache and 13669
# proxy operations.  Re-run alone on a quiet box: 19/19, four times out of four.
# What the harness could not do was GUARANTEE the window was open in one cycle
# of six while the whole suite was competing for the machine.
#
# THE FLOOR IS FIVE OF SIX, and the missing one is named rather than waved
# through.  The argument: three threads per runtime complete thousands of
# operations a second, so a 0.5s window containing not one completion is a
# scheduling artifact of a loaded box rather than a signal about anything.  Two
# such windows in six cycles is no longer explicable that way — at that point
# the traffic is genuinely intermittent, the restarts it is being paired with
# are not reliably adversarial, and the run should say the question could not be
# put.  That is NOT MEASURABLE, in the words test_proxy_group_keepalive_load.sh
# already uses, and it still ends the run non-zero.
#
# Zero is different in kind and stays a failure.  No window open at any stop
# means the traffic never ran at all, every restart was of an idle runtime, and
# nothing this file reports means anything — which is precisely the case the
# guard was written for, and the one it must never call merely unmeasurable.
#
# TOTAL is counted inside each branch rather than once above them, because the
# last branch counts its own: herr() takes a TOTAL of its own the way bad() and
# ok() do, so a pre-increment here would charge this one assertion twice.  It
# did, in the first draft — a NOT MEASURABLE run printed `18/20 passed (0
# failed, 1 not measurable)`, which adds up to nineteen of twenty and is the
# same species of arithmetic this file is being repaired for.
LIVE=$(field live_at_stop)
LIVE_MISSED=$(field_raw live_missed)
if [ -z "$LIVE" ]; then
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [traffic in flight at every stop]: no 'live_at_stop' in the harness"
    echo "        result — the harness did not finish"
elif [ "$LIVE" -eq "$CYCLES" ]; then
    TOTAL=$((TOTAL+1)); PASS=$((PASS+1))
elif [ "$LIVE" -eq 0 ]; then
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [traffic in flight at every stop]: live_at_stop=0 — not one of the"
    echo "        $CYCLES stops had traffic moving against the runtime it was stopping."
    echo "        Every restart here was of an idle runtime, which looks identical from"
    echo "        the outside and proves nothing, so the passes above are empty."
elif [ "$LIVE" -ge "$MIN_LIVE" ]; then
    TOTAL=$((TOTAL+1)); PASS=$((PASS+1))
    echo "  note: live_at_stop=$LIVE of $CYCLES — no completion landed in the 0.5s before"
    echo "        the stop at cycle ${LIVE_MISSED:-?}, so that one restart is not evidence."
    echo "        The other $LIVE are, which is the floor this test accepts; the build is"
    echo "        judged by restarts_ok, recovered and the *_bad counts below."
else
    herr "traffic in flight at every stop" \
        "live_at_stop=$LIVE of $CYCLES (missed ${LIVE_MISSED:-?}), floor is $MIN_LIVE" \
        "The traffic driver was too intermittent to guarantee the failure window" \
        "was open, so the restarts it was paired with are not evidence either way." \
        "Nothing here says the build misbehaved — restarts_ok, recovered and the" \
        "*_bad counts are what answer that — only that this run could not put the" \
        "question.  On a quiet machine it does; check what else was running."
fi

# The restart itself completed: both CLI commands succeeded and the port came
# back.  A runtime lost to a bad setup() lands here.
assert_field_eq restarts_ok "$CYCLES" "every restart completed"

# The success marker that matters: a connection made *after* each restart got a
# correct answer.  A dead daemon cannot satisfy this.
assert_field_eq recovered "$CYCLES" "the runtime served correctly after every restart"

# Wrong content is the signature of state carried across a restart that should
# not have been.  Dropped connections during the stop window are expected and
# are counted as errors instead, deliberately not asserted on.
assert_field_eq cache_bad 0 "cache answered with the wrong value"
assert_field_eq proxy_bad 0 "proxy answered with the wrong payload"

# A run that barely managed any traffic has not exercised anything, and its
# zeroes above would be worthless.
assert_field_min cache_ok "$MIN_OK" "enough cache traffic to mean something"
assert_field_min proxy_ok "$MIN_OK" "enough proxy traffic to mean something"

# Both runtimes are still running — 'ps' only lists running ones.
PS_OUT=$("$BIN" ps 2>&1 || true)
for n in "$CACHE_NAME" "$PROXY_NAME"; do
    TOTAL=$((TOTAL+1))
    if grep -q "$n" <<<"$PS_OUT"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [runtime still running]: '$n' is not in ps after the restarts"
    fi
done

# The daemon is not merely alive, it still does its job: create a runtime that
# never existed during the load, serve a verified round trip on it, remove it.
# Deliberately not create_ok.  Here the create is not setup, it is the
# measurement — "the daemon still creates a runtime and serves it" is one claim
# and the round trip below is the oracle for all of it, so counting the create
# separately would report one defect as two.  What the create said is kept, so
# the failure can say whether the runtime was ever made.
FINAL_CRC=0
FINAL_CREATE=$("$BIN" create cache rl_final -p "$FINAL_PORT" -s 2>&1) || FINAL_CRC=$?
# Wait for the success signal — a completed round trip — and not for a deadline.
# 'wait_port' alone proves nothing here: it returns as soon as the kernel accepts
# a connection out of the listen backlog, which is true from the instant listen()
# ran, while an event loop still winding down six restarts' worth of connections
# may not reach the new runtime's first read for a while.  Trying once after that
# wait was a timing assumption; retrying until it answers is not, and a wedged or
# dead daemon never answers and still fails, only later.
FINAL_RT=""
for _ in $(seq 1 60); do
    FINAL_RT=$(python3 "$H" serve "$FINAL_PORT" 2>/dev/null || true)
    [ "$FINAL_RT" = "SERVES_OK" ] && break
    sleep 0.5
done
TOTAL=$((TOTAL+1))
if grep -q '^SERVES_OK$' <<<"$FINAL_RT"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [daemon still serves]: a freshly created runtime did not answer correctly"
    if [ "$FINAL_CRC" -ne 0 ]; then
        echo "        and it was never created: create exited $FINAL_CRC saying"
        echo "        '${FINAL_CREATE:-<nothing>}' — the daemon refused before anything could serve"
    fi
    tail -5 "$TMPDIR_T/daemon.log" 2>/dev/null | sed 's/^/        daemon: /' || true
fi
"$BIN" remove rl_final >/dev/null 2>&1 || true

# Back to the same lifecycle state the baseline was taken in.
"$BIN" stop "$CACHE_NAME" >/dev/null 2>&1 || true
"$BIN" stop "$PROXY_NAME" >/dev/null 2>&1 || true
sleep 0.8
assert_fds_returned "$BASE_FD" "$(fd_count)" "$FD_TOLERANCE"
assert_rss_bounded  "$BASE_RSS" "$(rss_kb)"  "$RSS_BOUND_KB"

# Every assertion is accounted for in exactly one column.  Cheap, and it caught
# the draft of the branch above charging one assertion to TOTAL twice — a
# summary that does not add up cannot be acted on, and the arithmetic that
# produces it is not the sort of thing anyone re-checks by eye.
if [ "$((PASS+FAIL+HERR+SKIP))" -ne "$TOTAL" ]; then
    echo "  FAIL [counters]: $PASS passed + $FAIL failed + $HERR not measurable"
    echo "        + $SKIP not asserted does not equal $TOTAL counted — this summary"
    echo "        is wrong, not just the run"
    FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1))
fi

if [ "$FAIL" -gt 0 ] || [ "$HERR" -gt 0 ] || [ "$SKIP" -gt 0 ]; then
    echo "  ${TOTALS:-<no TOTALS line>}"
fi

# SKIP is reported but never changes the verdict or the exit status: a claim
# this build cannot answer is not a claim that failed.  HERR still does.
if [ "$SKIP" -gt 0 ]; then
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $HERR not measurable, $SKIP not asserted under $SANITIZED)"
else
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $HERR not measurable)"
fi
if [ "$FAIL" -eq 0 ] && [ "$HERR" -eq 0 ]; then echo "  OK"
elif [ "$FAIL" -eq 0 ]; then echo "  NOT MEASURABLE -- this run could not put the question, see above"
else echo "  FAILED"; fi
exit $((FAIL+HERR))
