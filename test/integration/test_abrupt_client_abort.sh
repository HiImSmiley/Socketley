#!/usr/bin/env bash
# Integration test: a client that vanishes with a reply still owed is torn down.
#
# The read path of every runtime here is written around "a completion is still
# owed, so the teardown will run when it lands".  That reasoning fails the
# moment the last operation has already finished: the connection is marked
# closing, nothing is in flight to wake it, and it sits holding its descriptor
# and its subscriptions until the runtime stops.  The cache's own read handler
# carries a comment saying exactly that, and the proxy has been fixed twice for
# the same shape — a peer that vanished while its counterpart still owed it
# data.
#
# The provocation is a client that dies by RST with the answer still on its way:
#   - against the proxy, the payload is marked so the backend sits on it for
#     150ms; the client is already gone by the time the echo comes back
#   - against the cache, a pipeline of several hundred reads of a 2 KB value is
#     sent and the socket is reset immediately, so hundreds of KiB of reply are
#     queued for a peer that no longer exists
# SO_LINGER is set to (on, 0) so the close is an RST and not a FIN: the client's
# descriptor is gone at once and its number is immediately available for reuse.
# Verifying connections run against both runtimes throughout, so a healthy
# connection is always present to be damaged.
#
# WHAT IT CATCHES
#   - a connection that is never reaped: 'connections' from 'stats' has to fall
#     back to 0 on both runtimes after the storm.  A connection with nothing
#     left to wake it keeps that number above zero forever, and this is the
#     sharpest assertion in the file
#   - descriptors held past the connection: the count is compared against a
#     baseline taken in the same lifecycle state
#   - collateral damage: '*_bad' is a healthy connection given the wrong bytes,
#     '*_reset' is a healthy connection closed by the runtime.  Both are zero in
#     a correct build; both are what a recycled descriptor number looks like
#     from the victim's side
#   - a daemon left wedged rather than crashed: after the storm a runtime that
#     never existed during it is created and has to serve a real round trip.
#     This waits for that success signal rather than for a deadline, so it fails
#     only when the answer never comes at all, or comes back wrong
#
# WHAT IT DOES NOT CATCH
#   - anything that needs the peer to vanish during a *write* the kernel has
#     already accepted; this drives the read and reply paths
#   - WebSocket, TLS, UDP or Lua paths — plain TCP cache and proxy only
#   - a leak of one connection in a thousand.  The 'connections' check is exact,
#     but only a connection still held *after the drain deadline* counts, so a
#     runtime that reaps late rather than never passes
#
# HONEST ABOUT TIMING — whether an individual abort lands inside the narrow
# window is luck; the 150ms backend delay and the size of the cache pipeline are
# there to widen it, not to close it. What is not luck is the volume: the
# assertion on 'aborted_*' below requires a real number of aborts to have
# happened, so a run that finished before the window ever opened fails there
# rather than reporting a pass. When hunting this class deliberately, loop:
#   for i in $(seq 20); do bash test/integration/test_abrupt_client_abort.sh || break; done
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# shellcheck source=lib_create.sh
. "$(dirname "$0")/lib_create.sh"

if ! command -v python3 >/dev/null 2>&1; then
    echo "=== Integration: abrupt client aborts ==="
    echo "  SKIP: python3 not available"
    exit 0
fi

# Own daemon, socket and state directory: against the shared daemon auto-restart
# puts a crashed runtime straight back, and a runtime that was restarted has by
# definition dropped every connection it was holding — the check that matters
# here would pass over the corpse.
TMPDIR_T=$(mktemp -d /tmp/socketley-abort-XXXXXX)
export HOME="$TMPDIR_T/home"
export SOCKETLEY_SOCKET="$TMPDIR_T/daemon.sock"
mkdir -p "$HOME"
DPID=""
BEPID=""

CACHE_PORT=19520
PROXY_PORT=19521
BE_PORT=19522
FINAL_PORT=19523
CACHE_NAME=ab_cache
PROXY_NAME=ab_proxy
LOAD_SECS=1.5       # almost all of this test's runtime
# Floors, not targets.  Against a stand-in server this window produced roughly
# 1200 aborts and 1500 verified round trips per runtime; these are set an order
# of magnitude below that so a busy machine does not fail the test, while a run
# that never really got going still does.
MIN_ABORTS=100      # per runtime: fewer than this and the storm never happened
MIN_OK=60           # per runtime: fewer than this and the zeroes prove nothing
DRAIN_SECS=8        # how long a runtime may take to reap its dead connections
# Budget for the post-storm runtime to serve its first request.  This is a
# ceiling on patience, not a wait: the check returns the instant a round trip
# succeeds, so a healthy daemon spends milliseconds here and only a wedged or
# dead one spends the whole budget — and then still fails.  It is generous
# because the daemon may legitimately still be reaping the storm's connections
# when the new runtime is created, and "the event loop is busy" must not read as
# "the daemon is broken".
FINAL_SERVE_SECS=30

# See the note in test_restart_under_load.sh.  Both samples are taken with both
# runtimes created but stopped, so no listener and no pooled backend connection
# is present in either — the proxy legitimately keeps up to 32 idle backend
# descriptors per backend for a minute after load, which would swamp any
# tolerance if the sample were taken while it was running.
FD_TOLERANCE=6

# GUESSED, NOT MEASURED.  Written without a run; a ceiling against gross
# leakage, not a certified profile.  Aborted connections queue hundreds of KiB
# of undeliverable reply each, so some transient growth is expected and only
# growth that survives the settle is measured.  The real number is printed every
# run — tighten this from data rather than trusting a bound that has never
# fired.
RSS_BOUND_KB=24576

PASS=0; FAIL=0; TOTAL=0; SKIP=0

# ─── THREE CHECKS THAT MEASURE THE SANITIZER, NOT THE PRODUCT ───────────────
#
# This file runs in the nightly under TSan as well as under Release, and under
# ASan+UBSan once that job builds again.  Three of its assertions have no
# defined meaning in a sanitized build:
#
#   * RSS_BOUND_KB.  24 MB of growth, against a Release daemon whose baseline
#     is about 7 MB.  TSan's baseline is 88-100 MB before a byte of traffic and
#     its shadow memory grows with every word the program touches.  Measured on
#     the same commit, the same test, in nightly run 30719890629: the
#     non-sanitized invariants job grew 5724 kB and passed; the TSan job grew
#     1818092 kB.  Reproduced here on 2026-08-02 with a local tsan_x64 build:
#     base 88316 kB, growth 1653100 kB.  A factor of roughly three hundred, in
#     both places.  That number is TSan's, not the daemon's.
#
#   * MIN_OK, twice.  A floor on healthy round trips completed inside a fixed
#     1.5 s window, set an order of magnitude below the ~1500 a Release build
#     manages.  TSan is several times slower, so the same window yields tens:
#     19 and 3 on the runner, 30 and 13 here.  That is the sanitizer's clock.
#
# They are printed and not asserted in a sanitized build, loudly, with the
# numbers, so nobody reads a quiet log as a checked one.  Everything else stays
# asserted in every build -- cache_bad, proxy_bad, the resets, the abort floors,
# the drain, the descriptors, and that the daemon still serves a fresh runtime.
# Those are what running this file under TSan is FOR, and all of them passed
# under TSan in both runs above.
#
# ZERO IS STILL A FAILURE, in every build.  "Barely any traffic got through
# because the sanitizer is slow" and "no traffic got through at all" are not the
# same statement, and only the first one is excused here.
#
# Detected from the binary rather than from an environment variable, using the
# idiom the nightly's own "Verify the build" step uses: a build that lost its
# sanitizer flags must not be able to claim this exemption.  A stripped Release
# binary yields nothing and is treated as not sanitized, which is the safe way
# round -- unknown keeps the strict bounds.
#
# NOT `grep -q`.  This file runs under `set -euo pipefail`, and `grep -q` exits
# the moment it matches, which hands `nm` a SIGPIPE; with pipefail the pipeline
# then reports 141 and the `if` takes the branch for "no match" precisely when
# there was one.  The first draft of this detection did exactly that and every
# assertion below stayed armed under TSan.  grep without -q reads its input to
# the end, so the pipeline's status is grep's.  (The same idiom in the nightly's
# "Verify the build" step is safe only because GitHub Actions does not set
# pipefail; it is not safe here.)
SANITIZED=""
if nm -C "$BIN" 2>/dev/null | grep '__tsan_' >/dev/null 2>&1; then
    SANITIZED="TSan"
elif nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null 2>&1; then
    SANITIZED="ASan"
fi

# Printed, counted in its own column, and deliberately NOT added to FAIL: unlike
# NOT MEASURABLE in test_restart_under_load.sh, which means "this run could not
# put the question and might next time", this means "this build cannot answer
# this question and never will".  A job that is red every single night for a
# reason nobody can act on gets ignored, which is the same end state as a check
# that cannot fail.
not_asserted() {  # label reason
    TOTAL=$((TOTAL+1)); SKIP=$((SKIP+1))
    echo "  NOT ASSERTED [$1]: $2"
    echo "        sanitized build ($SANITIZED) — this measures the sanitizer, not the daemon"
}

cleanup() {
    [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null || true
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
    # this test's ports.  The socket path comes from mktemp, so matching on it
    # can only ever hit daemons belonging to this run.
    for p in $(pgrep -f 'socketley daemon' 2>/dev/null || true); do
        if grep -qx "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" \
                < <(tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null); then
            kill -9 "$p" 2>/dev/null || true
        fi
    done
    rm -rf "$TMPDIR_T"
}
trap cleanup EXIT

echo "=== Integration: abrupt client aborts ==="

# ── Resource sampling ───────────────────────────────────────────────────────
# Both readers return the literal string 'unreadable' rather than an empty
# string, and every assertion rejects it before comparing anything.  Two empty
# values compare equal, so a daemon that died would otherwise satisfy
# "before == after" and be reported as a clean run.
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
        echo "  FAIL [descriptors returned]: $delta descriptors survived the abort storm"
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
        not_asserted "memory bounded" "RSS grew ${delta}kB; the ${bound}kB bound is a Release figure"
        return
    fi
    if [ "$delta" -le "$bound" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [memory bounded]: RSS grew ${delta}kB over the run, bound is ${bound}kB"
    fi
}

# Poll 'stats' until the runtime reports no live connections.  Prints '0' on
# success, the last value seen otherwise, or 'unreadable' when the field could
# not be read at all — which must fail rather than silently look like a match.
wait_conns_zero() {   # name seconds
    local name="$1" secs="$2" end v="unreadable"
    end=$(( $(date +%s) + secs ))
    while :; do
        v=$("$BIN" stats "$name" 2>/dev/null | grep -m1 '^connections:' \
            | cut -d: -f2 | tr -d '[:space:]' || true)
        case "$v" in
            ''|*[!0-9]*) v="unreadable" ;;
            0)           echo 0; return ;;
        esac
        [ "$(date +%s)" -ge "$end" ] && break
        sleep 0.2
    done
    echo "$v"
}

assert_drained() {    # name
    local name="$1" v
    TOTAL=$((TOTAL+1))
    v=$(wait_conns_zero "$name" "$DRAIN_SECS")
    if [ "$v" = "0" ]; then
        PASS=$((PASS+1))
        return
    fi
    FAIL=$((FAIL+1))
    if [ "$v" = "unreadable" ]; then
        echo "  FAIL [connections reaped: $name]: 'stats' has no readable 'connections' field"
        echo "        the runtime or the daemon is gone — that is a failure, not a drained run"
    else
        echo "  FAIL [connections reaped: $name]: still $v live connections ${DRAIN_SECS}s after"
        echo "        the last client went away — nothing will ever wake them"
    fi
}

# ── Harness ────────────────────────────────────────────────────────────────
H="$TMPDIR_T/harness.py"
cat >"$H" <<'PYEOF'
"""Modes: waitport | serve | prime | storm.

Each mode prints one machine-readable line.  A field the shell asks for and does
not find must make the shell fail loudly — never compare equal to an equally
missing expectation.
"""
import socket
import struct
import sys
import threading
import time

mode = sys.argv[1]

BIG = "b" * 2000          # the cache value the aborters ask for, hundreds of times


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


def recv_lines(s, n):
    """Exactly n newline-terminated lines, or a reason.

    Returns (lines, None) on success, (None, 'reset') when the peer closed with
    a reply still owed, (None, 'timeout') when nothing arrived in time.  The two
    are kept apart on purpose: a peer-initiated close of a healthy connection is
    a defect, a timeout on a loaded machine is usually scheduling.
    """
    buf = b""
    out = []
    while len(out) < n:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            return None, "timeout"
        except OSError:
            return None, "reset"
        if not chunk:
            return None, "reset"
        buf += chunk
        while b"\n" in buf and len(out) < n:
            line, buf = buf.split(b"\n", 1)
            out.append(line.rstrip(b"\r"))
    return out, None


def rt_cache(s, key, val):
    s.sendall(("set %s %s\nget %s\n" % (key, val, key)).encode())
    lines, why = recv_lines(s, 2)
    if lines is None:
        return why
    return "ok" if (lines[0] == b"ok" and lines[1] == val.encode()) else "bad"


def rt_proxy(s, payload):
    s.sendall((payload + "\n").encode())
    lines, why = recv_lines(s, 1)
    if lines is None:
        return why
    return "ok" if lines[0] == payload.encode() else "bad"


if mode == "prime":
    # The aborters' pipeline is only worth anything if the reply is large, so a
    # 2 KB value has to be in the cache before the storm starts.
    try:
        s = socket.create_connection(("127.0.0.1", int(sys.argv[2])), timeout=3)
        s.settimeout(3)
        if rt_cache(s, "bigk", BIG) == "ok":
            print("PRIMED")
        s.close()
    except OSError:
        pass
    sys.exit(0)

if mode == "serve":
    # One verified cache round trip against an arbitrary port.  Prints a marker
    # on success and nothing at all on failure, so the shell asserts a marker's
    # presence instead of comparing two possibly-empty strings.
    try:
        s = socket.create_connection(("127.0.0.1", int(sys.argv[2])), timeout=3)
        s.settimeout(3)
        if rt_cache(s, "fk", "fv") == "ok":
            print("SERVES_OK")
        s.close()
    except OSError:
        pass
    sys.exit(0)


def serve_probe(port):
    """One full cache round trip.  Returns (status, detail).

    status is one of: ok, wrong, connect, reset, timeout.  'wrong' is kept
    apart from every other outcome because it is the only one that is a defect
    on its own — the runtime spoke, and said something else than the value just
    written.  Everything else means it has not answered *yet*.
    """
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=2)
    except OSError as e:
        return "connect", "errno=%s" % (e.errno,)
    try:
        s.settimeout(3)
        s.sendall(b"set fk fv\nget fk\n")
        lines, why = recv_lines(s, 2)
        if lines is None:
            return why, ""
        if lines[0] == b"ok" and lines[1] == b"fv":
            return "ok", ""
        return "wrong", "set->%r get->%r" % (lines[0][:60], lines[1][:60])
    except OSError as e:
        return "reset", "errno=%s" % (e.errno,)
    finally:
        try:
            s.close()
        except OSError:
            pass


if mode == "servewait":
    # Wait for a *success signal*, not for a deadline: retry a complete set/get
    # round trip until one lands or the budget is spent.  A connect proves
    # nothing here — the kernel completes handshakes out of the listen backlog
    # on its own, so a socket accepts from the instant listen() ran, while an
    # event loop still reaping a storm of aborted connections may not reach the
    # new runtime's first read for a while.  Only a returned value proves the
    # daemon serves.
    #
    # Every line printed starts with a marker the shell dispatches on, so an
    # empty capture (python itself failed) can never be mistaken for a pass.
    port = int(sys.argv[2])
    budget = float(sys.argv[3])
    started = time.time()
    end = started + budget
    attempts = 0
    last = "none"
    while True:
        attempts += 1
        status, detail = serve_probe(port)
        waited = time.time() - started
        if status == "ok":
            print("SERVES_OK attempts=%d waited=%.2fs" % (attempts, waited))
            sys.exit(0)
        if status == "wrong":
            # It answered.  Retrying would only hide it.
            print("SERVES_WRONG attempts=%d waited=%.2fs %s"
                  % (attempts, waited, detail))
            sys.exit(2)
        last = status + ("(" + detail + ")" if detail else "")
        if time.time() >= end:
            break
        time.sleep(0.05)
    print("SERVES_NEVER attempts=%d waited=%.2fs last=%s"
          % (attempts, time.time() - started, last))
    sys.exit(1)

CACHE_PORT = int(sys.argv[2])
PROXY_PORT = int(sys.argv[3])
LOAD_SECS  = float(sys.argv[4])

PAD = "v" * 200
CACHE_PIPELINE = 150      # 'get bigk' repeats per aborted cache connection
ABORT_THREADS = 3         # per runtime
VERIFY_THREADS = 3        # per runtime
OPS_PER_CONN = 4
# Pause between aborts.  This is not about being gentle to the daemon — it is
# about this process.  Aborting is cheap and verifying is not, so unthrottled
# aborter threads hold Python's interpreter lock almost continuously and starve
# the verifying threads in the same process to a trickle; the run then asserts
# its zeroes over almost no healthy traffic.  Measured against a stand-in
# server, 2ms restores the verifiers to a useful rate while still leaving room
# for many hundreds of aborts in the window.
ABORT_PAUSE = 0.002
# Verifying connections close cleanly and each leaves a TIME_WAIT behind.  A
# fast machine would open tens of thousands in the window and walk into
# ephemeral port exhaustion, which would fail this test for a reason that has
# nothing to do with the runtimes.  Aborted connections are RST and cost nothing.
MAX_VERIFY_CONNS = 800

lock = threading.Lock()
c = {"cache_ok": 0, "cache_bad": 0, "cache_reset": 0, "cache_timeout": 0,
     "proxy_ok": 0, "proxy_bad": 0, "proxy_reset": 0, "proxy_timeout": 0,
     "aborted_cache": 0, "aborted_proxy": 0,
     "connfail": 0, "verify_conns": 0}


def bump(k):
    with lock:
        c[k] += 1


def verify_budget_left():
    with lock:
        return c["verify_conns"] < MAX_VERIFY_CONNS


def rst_socket(s):
    """close() that sends RST instead of FIN: the client is gone at once and its
    descriptor number is immediately available to the next accept."""
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass


def cache_aborter(deadline):
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", CACHE_PORT), timeout=2)
        except OSError:
            time.sleep(0.005)
            continue
        try:
            # ~600 KiB of reply owed to a peer that is about to stop existing.
            s.sendall(b"get bigk\n" * CACHE_PIPELINE)
            bump("aborted_cache")
        except OSError:
            pass
        rst_socket(s)
        time.sleep(ABORT_PAUSE)


def proxy_aborter(deadline):
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=2)
        except OSError:
            time.sleep(0.005)
            continue
        try:
            # 'SLOW' makes the backend sit on this for 150ms, so the echo is
            # still in flight long after the client has gone.
            s.sendall(("SLOW-abort:%s\n" % PAD).encode())
            bump("aborted_proxy")
        except OSError:
            pass
        rst_socket(s)
        time.sleep(ABORT_PAUSE)


def cache_verifier(tid, deadline):
    seq = 0
    while time.time() < deadline and verify_budget_left():
        try:
            s = socket.create_connection(("127.0.0.1", CACHE_PORT), timeout=3)
            s.settimeout(3)
        except OSError:
            bump("connfail")
            time.sleep(0.01)
            continue
        bump("verify_conns")
        try:
            for _ in range(OPS_PER_CONN):
                if time.time() >= deadline:
                    break
                seq += 1
                # Small per-thread key space: values stay unique per operation
                # so a stale answer is still caught, but the store does not grow
                # with the op count.  Unique keys would add entirely legitimate
                # cache content to the daemon's RSS and make the memory bound
                # below measure the wrong thing.
                key = "ak%d_%d" % (tid, seq % 64)
                val = "av%d_%d_%s" % (tid, seq, PAD)
                r = rt_cache(s, key, val)
                bump("cache_" + r)
                if r in ("reset", "timeout"):
                    break
        except OSError:
            bump("cache_reset")
        try:
            s.close()
        except OSError:
            pass


def proxy_verifier(tid, deadline):
    seq = 0
    while time.time() < deadline and verify_budget_left():
        try:
            s = socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=3)
            s.settimeout(3)
        except OSError:
            bump("connfail")
            time.sleep(0.01)
            continue
        bump("verify_conns")
        try:
            for _ in range(OPS_PER_CONN):
                if time.time() >= deadline:
                    break
                seq += 1
                r = rt_proxy(s, "ap%d-%06d:%s" % (tid, seq, PAD))
                bump("proxy_" + r)
                if r in ("reset", "timeout"):
                    break
        except OSError:
            bump("proxy_reset")
        try:
            s.close()
        except OSError:
            pass


deadline = time.time() + LOAD_SECS
threads = []
for i in range(ABORT_THREADS):
    threads.append(threading.Thread(target=cache_aborter, args=(deadline,), daemon=True))
    threads.append(threading.Thread(target=proxy_aborter, args=(deadline,), daemon=True))
for i in range(VERIFY_THREADS):
    threads.append(threading.Thread(target=cache_verifier, args=(i, deadline), daemon=True))
    threads.append(threading.Thread(target=proxy_verifier, args=(i, deadline), daemon=True))
for t in threads:
    t.start()
for t in threads:
    t.join(30)

with lock:
    print("TOTALS aborted_cache=%d aborted_proxy=%d "
          "cache_ok=%d cache_bad=%d cache_reset=%d cache_timeout=%d "
          "proxy_ok=%d proxy_bad=%d proxy_reset=%d proxy_timeout=%d "
          "connfail=%d verify_conns=%d"
          % (c["aborted_cache"], c["aborted_proxy"],
             c["cache_ok"], c["cache_bad"], c["cache_reset"], c["cache_timeout"],
             c["proxy_ok"], c["proxy_bad"], c["proxy_reset"], c["proxy_timeout"],
             c["connfail"], c["verify_conns"]))
PYEOF

wait_port() {   # port seconds
    python3 "$H" waitport "$1" "$2"
}

# ── Echo backend, with a deliberate delay for aborted requests ─────────────
# Payloads beginning with 'SLOW' are held for 150ms before being echoed, which
# is what guarantees the reply is still owed when the client's RST arrives.
# Everything else is echoed at once, so the verifying connections are not slowed
# down by the provocation aimed at their neighbours.
python3 - "$BE_PORT" >"$TMPDIR_T/backend.log" 2>&1 <<'PYEOF' &
import socket, sys, threading, time

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
            if data.startswith(b"SLOW"):
                time.sleep(0.15)
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
SOCKETLEY_DLOG="$TMPDIR_T/daemon.log"
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

# Warm both runtimes before the baseline is taken, so that everything the daemon
# allocates once is already inside it and does not read as growth later.  Not
# asserted here: the priming that matters is the one after the restart below.
python3 "$H" prime "$CACHE_PORT" >/dev/null 2>&1 || true
python3 "$H" serve "$PROXY_PORT" >/dev/null 2>&1 || true

# Baseline with both runtimes created but stopped, so the final sample can be
# taken in exactly the same state — no listener and no pooled backend
# connections in either, every one-time allocation already made.
"$BIN" stop "$CACHE_NAME" >/dev/null 2>&1 || true
"$BIN" stop "$PROXY_NAME" >/dev/null 2>&1 || true
sleep 0.6
BASE_FD=$(fd_count)
BASE_RSS=$(rss_kb)

"$BIN" start "$CACHE_NAME" >/dev/null 2>&1 || true
"$BIN" start "$PROXY_NAME" >/dev/null 2>&1 || true
wait_port "$CACHE_PORT" 5 || true
wait_port "$PROXY_PORT" 5 || true
# 'start' ran a fresh setup(), so the big value has to be put back for this run.
# This one is asserted: without it every aborted cache connection is owed four
# bytes of 'nil' instead of hundreds of KiB, the provocation quietly stops being
# a provocation, and the zeroes below would be measuring nothing.
TOTAL=$((TOTAL+1))
if [ "$(python3 "$H" prime "$CACHE_PORT" 2>/dev/null || true)" = "PRIMED" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: could not store the 2 KB value the aborters read back"
    echo "        without it the cache aborts owe almost no reply and prove little"
fi

# ── The storm ──────────────────────────────────────────────────────────────
OUT="$TMPDIR_T/harness.out"
python3 "$H" storm "$CACHE_PORT" "$PROXY_PORT" "$LOAD_SECS" >"$OUT" 2>&1 || true
TOTALS=$(grep '^TOTALS ' "$OUT" 2>/dev/null | head -1 || true)

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

# A sufficiency floor whose number is a throughput figure: how much healthy
# traffic the window produced.  Same as assert_field_min in a normal build; in a
# sanitized one the floor is not asserted, because the window is measuring the
# sanitizer's clock.  Zero still fails either way -- nothing got through at all
# is a defect in any build, and it is the case the floor was written for.
assert_field_min_throughput() {  # name minimum label
    local n
    n=$(field "$1")
    if [ -z "$n" ] || [ -z "$SANITIZED" ]; then
        assert_field_min "$@"
        return
    fi
    TOTAL=$((TOTAL+1))
    if [ "$n" -eq 0 ]; then
        FAIL=$((FAIL+1))
        echo "  FAIL [$3]: $1=$n — not one healthy round trip completed, so every zero above is meaningless"
        return
    fi
    TOTAL=$((TOTAL-1))       # not_asserted takes its own
    not_asserted "$3" "$1=$n against a floor of $2 calibrated on a Release build"
}

TOTAL=$((TOTAL+1))
if [ -n "$TOTALS" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [harness ran]: no TOTALS line; raw output:"
    grep -v '^$' "$OUT" 2>/dev/null | head -8 | sed 's/^/        /' || true
fi

# The failure window actually opened: a real number of clients died owing a
# reply.  A run that finished before the storm started fails here.
assert_field_min aborted_cache "$MIN_ABORTS" "enough cache clients died mid-reply"
assert_field_min aborted_proxy "$MIN_ABORTS" "enough proxy clients died mid-reply"

# Collateral damage on the healthy connections running alongside.  Wrong bytes
# and a peer-initiated close are both defects; timeouts are reported but not
# asserted on, because on a loaded machine a timeout is usually scheduling and
# would make this test flaky for a reason it is not about.
assert_field_eq cache_bad   0 "cache answered a healthy client with the wrong value"
assert_field_eq proxy_bad   0 "proxy answered a healthy client with the wrong payload"
assert_field_eq cache_reset 0 "cache closed a healthy connection"
assert_field_eq proxy_reset 0 "proxy closed a healthy connection"

# Zeroes above are worthless if barely any healthy traffic got through.
assert_field_min_throughput cache_ok "$MIN_OK" "enough healthy cache traffic to mean something"
assert_field_min_throughput proxy_ok "$MIN_OK" "enough healthy proxy traffic to mean something"

# ── The point of the test ──────────────────────────────────────────────────
# Every client is gone. A connection that nothing will ever wake keeps this
# number above zero for as long as the runtime lives.
assert_drained "$CACHE_NAME"
assert_drained "$PROXY_NAME"

# The daemon is not merely alive: it still creates and serves a runtime that
# never existed during the storm.
#
# The wait here is on the success signal — a completed set/get against the new
# runtime — and not on a deadline.  'wait_port' is deliberately not used: it
# returns as soon as the kernel accepts a connection out of the listen backlog,
# which happens the moment listen() ran and says nothing about whether the event
# loop has got round to serving.  Creating a runtime immediately after 1.5s of
# RST churn and giving it one 3s attempt was a timing assumption, and it lost
# roughly one run in five.  The assertion is not weakened by this: a daemon that
# is wedged or dead never produces the signal and still fails, only later.
CREATE_LOG="$TMPDIR_T/ab_final.create"
"$BIN" create cache ab_final -p "$FINAL_PORT" -s >"$CREATE_LOG" 2>&1 \
    || echo "(create exited $?)" >>"$CREATE_LOG"

# Everything known about the daemon at the moment the check gave up, printed
# only on failure: whether the process is still there, what it thinks it is
# running, and what it says about the runtime that would not answer.
diagnose_final() {
    local out
    if kill -0 "$DPID" 2>/dev/null; then
        echo "        daemon pid $DPID: alive"
    else
        echo "        daemon pid $DPID: GONE — it did not survive the storm"
    fi
    out=$(cat "$CREATE_LOG" 2>/dev/null || true)
    echo "        create ab_final said: ${out:-<nothing, which is success>}"
    out=$("$BIN" ls 2>&1 || true)
    printf '%s\n' "        --- ls ---"
    printf '%s\n' "${out:-<no output>}" | sed 's/^/        /'
    out=$("$BIN" stats ab_final 2>&1 || true)
    printf '%s\n' "        --- stats ab_final ---"
    printf '%s\n' "${out:-<no output>}" | sed 's/^/        /'
    out=$(tail -n 8 "$TMPDIR_T/daemon.log" 2>/dev/null || true)
    printf '%s\n' "        --- daemon.log (tail) ---"
    printf '%s\n' "${out:-<empty>}" | sed 's/^/        /'
}

FINAL_SERVE=$(python3 "$H" servewait "$FINAL_PORT" "$FINAL_SERVE_SECS" 2>&1 || true)
# Sampled at the moment of judgement: 'create' is a CLI command, so if the storm
# killed the daemon the create itself started a fresh one and the answer below
# would come from a daemon that never saw the abuse.  A live $DPID is what makes
# the round trip mean 'it survived' rather than 'something is listening'.
FINAL_ALIVE=$(fd_count)
# Dispatch on the marker line, not on the whole capture: stderr is merged in so
# that a probe that died has something to show, and a stray warning ahead of the
# marker must not turn a served round trip into 'never answered'.  No marker at
# all falls through to the failure branch, which is the only safe direction.
FINAL_MARK=$(printf '%s\n' "$FINAL_SERVE" | grep -m1 '^SERVES_' || true)
TOTAL=$((TOTAL+1))
case "$FINAL_MARK" in
    SERVES_OK*)
        if [ "$FINAL_ALIVE" = "unreadable" ]; then
            FAIL=$((FAIL+1))
            echo "  FAIL [daemon still serves]: the answer was correct, but pid $DPID is gone —"
            echo "        it came from a replacement daemon a CLI command started, not from the"
            echo "        daemon that went through the storm"
            diagnose_final
        else
            PASS=$((PASS+1))
            echo "  final runtime: $FINAL_MARK"
        fi
        ;;
    SERVES_WRONG*)
        FAIL=$((FAIL+1))
        echo "  FAIL [daemon still serves]: a freshly created runtime answered, but wrongly"
        echo "        $FINAL_SERVE"
        diagnose_final
        ;;
    *)
        FAIL=$((FAIL+1))
        echo "  FAIL [daemon still serves]: a freshly created runtime never answered"
        echo "        within ${FINAL_SERVE_SECS}s — the daemon no longer serves what it creates"
        echo "        ${FINAL_SERVE:-<no marker at all: the probe itself did not run>}"
        diagnose_final
        ;;
esac
"$BIN" remove ab_final >/dev/null 2>&1 || true

# Back to the baseline's lifecycle state.
"$BIN" stop "$CACHE_NAME" >/dev/null 2>&1 || true
"$BIN" stop "$PROXY_NAME" >/dev/null 2>&1 || true
sleep 0.8
assert_fds_returned "$BASE_FD" "$(fd_count)" "$FD_TOLERANCE"
assert_rss_bounded  "$BASE_RSS" "$(rss_kb)"  "$RSS_BOUND_KB"

if [ "$FAIL" -gt 0 ] || [ "$SKIP" -gt 0 ]; then
    echo "  ${TOTALS:-<no TOTALS line>}"
fi

# The summary has to add up, or it cannot be acted on and nobody re-checks the
# arithmetic by eye.  Same guard as test_restart_under_load.sh.
if [ "$((PASS+FAIL+SKIP))" -ne "$TOTAL" ]; then
    echo "  FAIL [counters]: $PASS passed + $FAIL failed + $SKIP not asserted"
    echo "        does not equal $TOTAL counted — this summary is wrong, not just the run"
    FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1))
fi

if [ "$SKIP" -gt 0 ]; then
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $SKIP not asserted under $SANITIZED)"
else
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
fi
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
