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
# runtime is still moving, and the assertion below requires that to have held
# for every cycle.  If a future change makes the traffic threads stall, this
# test fails on that assertion instead of quietly restarting an idle runtime and
# reporting a pass.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

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

CACHE_PORT=19500
PROXY_PORT=19501
BE_PORT=19502
FINAL_PORT=19503
CACHE_NAME=rl_cache
PROXY_NAME=rl_proxy
CYCLES=6            # restarts; alternates cache, proxy, cache, ...
MIN_OK=40           # per runtime: below this the load was too thin to mean much

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
# assume a value that has never fired is correct.
RSS_BOUND_KB=24576

PASS=0; FAIL=0; TOTAL=0

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
"""Modes: waitport | warmup | load | probe.

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
    print("TOTALS cycles=%d restarts_ok=%d live_at_stop=%d recovered=%d "
          "cache_ops=%d cache_ok=%d cache_bad=%d cache_err=%d "
          "proxy_ops=%d proxy_ok=%d proxy_bad=%d proxy_err=%d"
          % (CYCLES, restarts_ok, live_at_stop, recovered,
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

"$BIN" daemon >"$TMPDIR_T/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 60); do "$BIN" ps >/dev/null 2>&1 && break; sleep 0.1; done

TOTAL=$((TOTAL+1))
if "$BIN" ps >/dev/null 2>&1; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the daemon never became reachable — everything below is meaningless"
fi

TOTAL=$((TOTAL+1))
if wait_port "$BE_PORT" 5; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the echo backend never came up on $BE_PORT"
fi

"$BIN" create cache "$CACHE_NAME" -p "$CACHE_PORT" -s 2>&1 || true
"$BIN" create proxy "$PROXY_NAME" -p "$PROXY_PORT" \
    --backend "127.0.0.1:$BE_PORT" --protocol tcp -s 2>&1 || true
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

# The failure window really opened: traffic was demonstrably still moving
# against each runtime at the moment it was stopped.
assert_field_eq live_at_stop "$CYCLES" "traffic in flight at every stop"

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
    if printf '%s\n' "$PS_OUT" | grep -q "$n"; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [runtime still running]: '$n' is not in ps after the restarts"
    fi
done

# The daemon is not merely alive, it still does its job: create a runtime that
# never existed during the load, serve a verified round trip on it, remove it.
"$BIN" create cache rl_final -p "$FINAL_PORT" -s >/dev/null 2>&1 || true
wait_port "$FINAL_PORT" 5 || true
FINAL_RT=$(python3 "$H" serve "$FINAL_PORT" 2>/dev/null || true)
TOTAL=$((TOTAL+1))
if printf '%s\n' "$FINAL_RT" | grep -q '^SERVES_OK$'; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [daemon still serves]: a freshly created runtime did not answer correctly"
fi
"$BIN" remove rl_final >/dev/null 2>&1 || true

# Back to the same lifecycle state the baseline was taken in.
"$BIN" stop "$CACHE_NAME" >/dev/null 2>&1 || true
"$BIN" stop "$PROXY_NAME" >/dev/null 2>&1 || true
sleep 0.8
assert_fds_returned "$BASE_FD" "$(fd_count)" "$FD_TOLERANCE"
assert_rss_bounded  "$BASE_RSS" "$(rss_kb)"  "$RSS_BOUND_KB"

if [ "$FAIL" -gt 0 ]; then
    echo "  ${TOTALS:-<no TOTALS line>}"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
