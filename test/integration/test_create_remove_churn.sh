#!/usr/bin/env bash
# Integration test: creating and removing runtimes in a loop gives everything back.
#
# A runtime is not just an object in a map — it owns a listener descriptor, a
# set of io_uring registrations, a provided-buffer ring, preallocated connection
# structs, and a state file.  'remove' has to unwind all of it, and it does so
# through a deferred delete that holds the object alive for one event loop tick
# because in-flight completions still point into it.  Anything that path forgets
# does not fail once: it accumulates, and the suite's other tests each create
# one or two runtimes and never notice.
#
# So: forty-five create/serve/remove cycles over three runtime types, all on the
# same port, with real concurrent traffic in each cycle.  The port is
# deliberately reused.  Listeners are bound with SO_REUSEPORT, so a listener
# that outlived its runtime does not fail to bind — it stays in the kernel's
# balancing set and silently takes a share of the next runtime's connections.
# Reusing the port is what turns that leak into a visible wrong answer instead
# of a slow drift.
#
# WHAT IT CATCHES
#   - a listener, io_uring registration or connection descriptor that 'remove'
#     never releases: the descriptor count is compared against a baseline taken
#     after a warm-up round, so one leaked descriptor per cycle is 45 against a
#     tolerance of 6
#   - one whole leaked runtime instance per cycle.  See the sizing note below:
#     that is ~226 MB against a bound of 12 MB
#   - a removed runtime that keeps accepting: 'closed' counts cycles where the
#     port actually stopped answering afterwards
#   - a removed runtime still listed by 'ls'
#   - the daemon under test dying and being silently replaced.  Any CLI call
#     fork+execs a fresh daemon when the socket does not answer (cli.cpp,
#     ensure_daemon), so a daemon that crashes mid-churn is replaced between two
#     cycles and every counter below still reads perfect.  The identity check
#     compares the pid and its /proc start time across the whole run
#   - both removal paths: even cycles call 'remove' on a running runtime (which
#     stops it itself), odd cycles 'stop' first and then 'remove'
#
# SIZING THE MEMORY BOUND
#   A leaked instance only costs RSS for the pages something actually touched,
#   so the traffic below exists to make that footprint real: each cycle drives
#   8 concurrent connections carrying 2 KB payloads, which faults in the buffer
#   ring and grows the connection pool past its initial reservation.  With the
#   single sequential 8-byte exchange this test used to drive, a leaked cache
#   instance was worth 258 kB; with the traffic below it is worth 466 kB, and
#   that is the difference between hiding inside the noise and not.
#
#   What one live instance holds, measured on this build at exactly the traffic
#   below by creating instances and never removing them — which is what the leak
#   looks like to the allocator:
#
#       cache   466 kB     server  8849 kB     proxy  6089 kB
#
#   Fifteen cycles of each is 15 * (466 + 8849 + 6089) = 231060 kB.  So a leak
#   of one whole runtime instance per cycle shows up here as ~226 MB of growth.
#   A leak confined to one type is 132 MB (server), 91 MB (proxy) or 6.8 MB
#   (cache).
#
#   Healthy growth is what this script itself printed over 22 consecutive clean
#   runs: 2756, 2840, 2844, 2864, 2884, 2892, 2956, 4640, 4672, 4688, 4692,
#   4696, 4696, 4700, 4712, 4716, 4716, 4716, 4728, 4732, 4752 kB and one run at
#   64 kB.  It is bimodal — one cluster near 2.9 MB and one near 4.7 MB, each
#   only ~100 kB wide — which is allocator retention differing by which arena
#   the run happened to reuse, not a leak; it does not grow with repetition.
#
#   The bound is 12288 kB.  That is 2.6x the worst healthy observation, so
#   normal variation would have to be more than half again as large as anything
#   yet seen to reach it, and 18x below the 226 MB a per-cycle instance leak
#   produces.  The two constraints are "at least ~2.5x the worst healthy run"
#   (11.9 MB) and "no more than a tenth of the leak it must catch" (22.6 MB);
#   12 MB is the low end of that window, which is where a leak detector belongs
#   — the cost of being slightly too tight is a rerun, the cost of being too
#   loose is a leak that ships.
#
# WHAT IT DOES NOT CATCH
#   - a leak much smaller than one instance per cycle.  Healthy growth is about
#     100 kB per cycle, so anything under that per-cycle scale is invisible to
#     RSS here; the descriptor check is the sharp instrument for small leaks
#   - a leak of *only* cache instances, which is 6.8 MB and sits under the
#     bound.  Raising the payload past the cache's 4 KB buffer would lift it,
#     at the cost of a bound that no longer has 2.6x headroom
#   - anything about removing a runtime that is *busy*: traffic here is finished
#     before the remove.  Removal under concurrent load is the restart test's
#     territory
#   - Lua, TLS, UDP and cluster runtimes: three plain TCP types are created
#
# The 'both empty' trap is guarded explicitly: a sentinel runtime is created up
# front and never removed, and the final 'ls' check requires the sentinel to be
# present *and* the churn names to be absent.  An 'ls' that returned nothing at
# all — because the daemon died — fails the first half instead of passing the
# second.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# shellcheck source=lib_create.sh
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

if ! command -v python3 >/dev/null 2>&1; then
    echo "=== Integration: create/remove churn ==="
    echo "  SKIP: python3 not available"
    exit 0
fi

# Own daemon, socket and state directory: against the shared daemon a leftover
# runtime from an earlier test answers on the churn port before this test ever
# creates anything, and auto-restart puts back whatever the churn kills.
TMPDIR_T=$(mktemp -d /tmp/socketley-churn-XXXXXX)
export HOME="$TMPDIR_T/home"
export SOCKETLEY_SOCKET="$TMPDIR_T/daemon.sock"
mkdir -p "$HOME"
DPID=""
BEPID=""

CHURN_PORT=$((SL_PORT_BASE+510))    # every created runtime binds this one, on purpose
BE_PORT=$((SL_PORT_BASE+511))       # echo backend behind the proxy cycles
SENTINEL_PORT=$((SL_PORT_BASE+512))
FINAL_PORT=$((SL_PORT_BASE+513))
CYCLES=45           # 15 each of cache, server, proxy
WARM_CYCLES=3       # one of each, before the resource baseline is taken
ROUNDTRIPS=3        # verified exchanges per connection per cycle
CONNS=8             # concurrent connections per cycle
PAYLOAD=2048        # bytes per exchange; see the sizing note above

# See the long note in test_restart_under_load.sh: both samples are taken at the
# same point in the lifecycle (no churn runtime existing, after a settle), so
# only transient descriptors — the IPC connection serving the sampling command,
# a state file being rewritten — can differ.  A leak here is one per cycle.
FD_TOLERANCE=6

# Measured, not guessed.  See SIZING THE MEMORY BOUND above: healthy runs land
# at 2.8-4.8 MB, a per-cycle instance leak at ~226 MB.  Release figures — see
# the sanitizer note below for why this bound is not asserted in an instrumented
# build.
RSS_BOUND_KB=12288

# ─── ONE CHECK THAT MEASURES THE SANITIZER, NOT THE PRODUCT ─────────────────
#
# This file runs in the nightly under ASan+UBSan as well as under Release, and
# RSS_BOUND_KB has no defined meaning in an instrumented build.
#
# Every number in SIZING THE MEMORY BOUND above — the 466/8849/6089 kB an
# instance holds, the 2.8-4.8 MB a healthy run grows, the 226 MB a per-cycle
# leak produces — was measured against a daemon with no sanitizer in it.  An
# ASan daemon keeps eight bytes of shadow for every byte of application memory
# and a redzone around every allocation, so it starts an order of magnitude
# higher and every page the churn faults in costs its shadow as well:
#
#     Release   base 18216 kB   growth   2804 kB   (2026-08-02, this machine)
#     ASan      base 96424 kB   growth 313448 kB   (2026-08-02, this machine)
#
# The base alone is five times the whole Release run, and the growth is
# twenty-five times a bound that was chosen to sit an order of magnitude BELOW
# the leak it catches.  The nightly's first ASan run in five weeks, on the same
# commit, reported base 95772 kB and growth 313576 kB — the two agree to within
# a tenth of a percent, which is what a sanitizer's fixed overhead looks like
# and not what a leak looks like.  Widening the bound to cover it would put it
# above the 226 MB it exists to catch, i.e. it would stop bounding anything.
#
# So it is printed and not asserted in a sanitized build, loudly, with the
# numbers, so nobody reads a quiet log as a checked one.  EVERYTHING ELSE STAYS
# ASSERTED IN EVERY BUILD — created, served, ops, removed, closed, the daemon
# identity check, the 'ls' pair, that the daemon still serves a fresh runtime,
# and the descriptor count.  Those are what running this file under ASan is FOR,
# and all of them passed under ASan in the run above (descriptors: delta=0).
#
# THE DAEMON BEING GONE IS STILL A FAILURE, in every build.  'unreadable' is
# rejected before the exemption below is ever reached: "this build cannot answer
# the question" and "there was no daemon left to ask" are different statements
# and only the first one is excused here.
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

PASS=0; FAIL=0; SKIP=0; TOTAL=0
SUBPID=""
DAEMON_SURVIVED=0   # set once the identity check confirms it lived through the churn

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
    fi
    # Kill by socket, not only by pid.  A CLI command run against a daemon that
    # is not up yet — or not up any more — starts one of its own, detached from
    # this shell; killing $DPID would leave that one running for good, holding
    # this test's ports.  The socket path comes from mktemp, so matching on it
    # can only ever hit daemons belonging to this run.
    # Matched by exact process name, never by a command-line pattern.  `pgrep -f
    # 'socketley daemon'` also matches a shell whose own command line merely
    # carries that string — a test runner, or this file — and the environ check
    # below cannot rule it out, because such a shell exports the very
    # SOCKETLEY_SOCKET being matched on.  The two tests together are what make
    # this reach daemons of this run and nothing else.
    for p in $(pgrep -x socketley 2>/dev/null || true); do
        case "$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null)" in
            *" daemon "*|*" daemon") ;;
            *) continue ;;
        esac
        if grep -qx "SOCKETLEY_SOCKET=$SOCKETLEY_SOCKET" \
                < <(tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null); then
            kill -9 "$p" 2>/dev/null || true
        fi
    done
    # The reaping subshell (see below) exits normally, so waiting on it prints
    # nothing.  Its recorded status is how a signal death gets reported here —
    # in words, after the verdict.
    [ -n "$SUBPID" ] && wait "$SUBPID" 2>/dev/null || true
    local st
    st=$(cat "$TMPDIR_T/daemon.status" 2>/dev/null || true)
    case "$st" in
        ''|*[!0-9]*) ;;
        *)
            # 143 = our SIGTERM, 137 = our SIGKILL.  Anything else above 128 is
            # the daemon dying of its own accord while being shut down.
            # Only worth saying when the daemon was still alive at the last
            # assertion.  If it died during the churn the identity check has
            # already reported that, in more detail, and repeating it here as a
            # shutdown problem would misdescribe when it happened.
            if [ "$st" -gt 128 ] && [ "$st" -ne 143 ] && [ "$st" -ne 137 ] \
               && [ "$DAEMON_SURVIVED" = 1 ]; then
                echo "  NOTE: the daemon survived the churn but died of signal"
                echo "        $((st - 128)) when asked to shut down.  Every assertion above was"
                echo "        evaluated against a live daemon, so the results stand — but"
                echo "        a crash on shutdown is a defect in its own right."
            fi
            ;;
    esac
    rm -rf "$TMPDIR_T"
}
trap cleanup EXIT

echo "=== Integration: create/remove churn ==="

# ── Resource sampling ───────────────────────────────────────────────────────
# Every reader returns the literal string 'unreadable'/'gone' rather than an
# empty string, and every assertion rejects it before comparing anything.  Two
# empty values compare equal, so a dead daemon would otherwise satisfy
# "before == after" and report a clean run.
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

# pid plus the kernel's start time for that pid.  The start time is what makes
# this an identity and not just a liveness check: pids get reused, and the CLI
# spawns replacement daemons on its own, so "a daemon is running" proves
# nothing about it being *the* daemon whose memory we sampled.
daemon_ident() {
    local st
    st=$(sed 's/.*) //' "/proc/$DPID/stat" 2>/dev/null | awk '{print $20}') || st=""
    st=$(printf '%s' "$st" | tr -d '[:space:]')
    case "$st" in
        ''|*[!0-9]*) echo "gone" ;;
        *)           echo "$DPID:$st" ;;
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
        echo "  FAIL [descriptors returned]: $delta descriptors survived $CYCLES create/remove cycles"
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
        echo "  FAIL [memory bounded]: RSS grew ${delta}kB over $CYCLES cycles, bound is ${bound}kB"
        echo "        one leaked runtime instance per cycle is ~226MB here; see the header"
    fi
}

# ── Harness ────────────────────────────────────────────────────────────────
H="$TMPDIR_T/harness.py"
cat >"$H" <<'PYEOF'
"""Modes: waitport | waitsock | serve | churn.

Each mode prints one machine-readable line.  A field the shell asks for and does
not find must make the shell fail loudly — never compare equal to an equally
missing expectation.
"""
import socket
import subprocess
import sys
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


def connect_refused(port, deadline):
    """True once the port stops accepting.

    A listener that outlived its runtime keeps accepting — with SO_REUSEPORT it
    does not even have to be the only one — which is exactly the leak this loop
    is looking for.
    """
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.4).close()
            time.sleep(0.01)
        except OSError:
            return True
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
    buf = b""
    out = []
    while len(out) < n:
        try:
            chunk = s.recv(262144)
        except OSError:          # includes socket timeouts
            return None
        if not chunk:
            return None
        buf += chunk
        while b"\n" in buf and len(out) < n:
            line, buf = buf.split(b"\n", 1)
            out.append(line.rstrip(b"\r"))
    return out


def shut(*socks):
    for s in socks:
        try:
            s.close()
        except OSError:
            pass


if mode == "serve":
    # One cache round trip against an already-running runtime.  Prints
    # SERVES_OK only when the reply carries back the value just written, so a
    # port that accepts and then says nothing does not count as serving.
    probe_port = int(sys.argv[2])
    try:
        ps = socket.create_connection(("127.0.0.1", probe_port), timeout=3)
        ps.settimeout(3)
    except OSError:
        sys.exit(1)
    try:
        ps.sendall(b"set churn_probe probe_value\nget churn_probe\n")
        got = recv_lines(ps, 2)
        if got == [b"ok", b"probe_value"]:
            print("SERVES_OK")
    except OSError:
        pass
    shut(ps)
    sys.exit(0)


def open_conns(port, k):
    """k concurrent connections.  Concurrency is not decoration: it is what
    forces the connection pool past its initial reservation and faults in more
    than one buffer of the provided-buffer ring, which is most of what a leaked
    instance would be holding on to."""
    out = []
    for _ in range(k):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            s.settimeout(3)
            out.append(s)
        except OSError:
            pass
    return out


def rt_cache(port, n, k, pay):
    """set/get round trips: the reply has to carry back the value just written.

    All k requests are sent before any reply is read, so k of them are in
    flight at once rather than k sequential conversations."""
    socks = open_conns(port, k)
    ok = 0
    val = "v" * pay
    for i in range(n):
        for j, s in enumerate(socks):
            try:
                s.sendall(("set ck%d_%d %s\nget ck%d_%d\n" % (j, i, val, j, i)).encode())
            except OSError:
                pass
        for s in socks:
            lines = recv_lines(s, 2)
            if lines and lines[0] == b"ok" and lines[1] == val.encode():
                ok += 1
    shut(*socks)
    return ok


def rt_proxy(port, n, k, pay):
    """Echo through the backend: the exact payload has to come back, on the
    connection that sent it — k in flight at once."""
    socks = open_conns(port, k)
    ok = 0
    for i in range(n):
        sent = []
        for j, s in enumerate(socks):
            msg = "px-%d-%d-%s" % (j, i, "y" * pay)
            sent.append(msg)
            try:
                s.sendall((msg + "\n").encode())
            except OSError:
                pass
        for j, s in enumerate(socks):
            lines = recv_lines(s, 1)
            if lines and lines[0] == sent[j].encode():
                ok += 1
    shut(*socks)
    return ok


def rt_server(port, n, k, pay):
    """A bare server consumes what it is sent: no echo to the sender, no relay
    to the other clients — verified against both the current build and 14c432b,
    so this is what the runtime does, not a regression.  There is therefore no
    round trip to check here.  What this still proves is the part the test is
    about: the listener of *this* cycle is the one answering, on a port every
    cycle reuses, and it takes k concurrent conversations without dropping
    them.  A leaked listener from an earlier cycle would take a share of these
    connections under SO_REUSEPORT and the sends would break."""
    socks = open_conns(port, k)
    ok = 0
    for i in range(n):
        for j, s in enumerate(socks):
            try:
                s.sendall(("consume-%d-%d-%s\n" % (j, i, "z" * pay)).encode())
                ok += 1
            except OSError:
                pass
    shut(*socks)
    return ok


# churn <bin> <port> <backend-port> <cycles> <roundtrips> <conns> <payload> <prefix>
BIN     = sys.argv[2]
PORT    = int(sys.argv[3])
BE_PORT = int(sys.argv[4])
CYCLES  = int(sys.argv[5])
RTS     = int(sys.argv[6])
CONNS   = int(sys.argv[7])
PAYLOAD = int(sys.argv[8])
PREFIX  = sys.argv[9]

# Every cycle reuses the same port on purpose: listeners set SO_REUSEPORT, so a
# leaked one does not fail to bind — it quietly takes a share of the next
# runtime's connections, and only reusing the port turns that into a visible
# wrong answer.
KINDS  = ["cache", "server", "proxy"]
VERIFY = {"cache": rt_cache, "server": rt_server, "proxy": rt_proxy}


def run_cli(*args):
    try:
        r = subprocess.run([BIN] + list(args), stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=20)
        return r.returncode
    except Exception:
        return -1


created = served = removed = closed = ops = 0
expect = RTS * CONNS

for i in range(CYCLES):
    kind = KINDS[i % len(KINDS)]
    name = "%s%02d" % (PREFIX, i)

    args = ["create", kind, name, "-p", str(PORT)]
    if kind == "proxy":
        args += ["--backend", "127.0.0.1:%d" % BE_PORT, "--protocol", "tcp"]
    args.append("-s")

    rc = run_cli(*args)
    if rc == 0 and connect_ok(PORT, time.time() + 5.0):
        created += 1

    got = VERIFY[kind](PORT, RTS, CONNS, PAYLOAD)
    ops += got
    if got == expect:
        served += 1

    # Alternate the two teardown paths.  'remove' on a running runtime stops it
    # itself; stopping first reaches teardown through the other branch, and the
    # two have not always agreed about what they release.
    if i % 2 == 1:
        run_cli("stop", name)
        time.sleep(0.05)
    if run_cli("remove", name) == 0:
        removed += 1

    if connect_refused(PORT, time.time() + 3.0):
        closed += 1

print("TOTALS cycles=%d created=%d served=%d removed=%d closed=%d ops=%d"
      % (CYCLES, created, served, removed, closed, ops))
PYEOF

wait_port() {   # port seconds
    python3 "$H" waitport "$1" "$2"
}

churn() {       # port cycles prefix outfile
    python3 "$H" churn "$BIN" "$1" "$BE_PORT" "$2" "$ROUNDTRIPS" "$CONNS" \
        "$PAYLOAD" "$3" >"$4" 2>&1 || true
}

# ── Echo backend for the proxy cycles ──────────────────────────────────────
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
            data = conn.recv(262144)
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

# The daemon is started inside a subshell that reaps it, with that subshell's
# stderr discarded.  Job control announces a child that dies by a signal, and a
# bare "Segmentation fault" printed across the results reads like the test
# harness broke rather than the thing under test; cleanup() reports the same
# fact deliberately instead.  The pid is published through a file because $! in
# here would name the subshell, and every /proc sample below needs the daemon.
(
    # set +e matters: 'wait' reports the daemon's death as a non-zero status,
    # and under the script's errexit that would kill this subshell before it
    # ever recorded what the status was.
    set +e
    "$BIN" daemon >"$TMPDIR_T/daemon.log" 2>&1 &
    echo $! >"$TMPDIR_T/daemon.pid"
    wait $!
    echo $? >"$TMPDIR_T/daemon.status"
) 2>/dev/null &
SUBPID=$!
# Set in this shell rather than in the subshell above: create_ok prints the tail
# of it when a create is refused, and the CLI's own message is only `could not
# start runtime` whenever the reason was found on the daemon side.
SOCKETLEY_DLOG="$TMPDIR_T/daemon.log"
for _ in $(seq 1 100); do [ -s "$TMPDIR_T/daemon.pid" ] && break; sleep 0.02; done
DPID=$(tr -d '[:space:]' <"$TMPDIR_T/daemon.pid" 2>/dev/null || true)
if [ -z "$DPID" ]; then
    echo "  FAIL [setup]: the daemon process never reported a pid"
    echo "  Results: 0/1 passed (1 failed)"
    echo "  FAILED"
    exit 1
fi
# Wait on the IPC socket itself, never by polling with a CLI command.  Every CLI
# command auto-starts a daemon when the socket does not answer yet — cli.cpp's
# ensure_daemon() forks, setsids and re-execs 'socketley daemon' — so polling
# 'ps' against the daemon this test has just launched races it and spawns a
# second, orphaned one.  Whichever loses the bind exits, and when the loser is
# $DPID the pid this test watches becomes a zombie while an orphan serves the
# run: BASE_IDENT is then taken from a corpse and every /proc sample below reads
# 'unreadable'.  Measured at 2 spawned orphans in 30 startups of this sequence.
python3 "$H" waitsock "$SOCKETLEY_SOCKET" 8 || true
BASE_IDENT=$(daemon_ident)

TOTAL=$((TOTAL+1))
if "$BIN" ps >/dev/null 2>&1; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the daemon never became reachable — everything below is meaningless"
fi

# ...and the daemon answering is the one this test launched.  Without this a
# zombie $DPID is only noticed at the very end, by the identity check and the
# resource samples, which would describe it as "the daemon died during the
# churn" when in fact it never survived its own startup.
TOTAL=$((TOTAL+1))
if [ "$BASE_IDENT" != "gone" ]; then
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

# The sentinel is created once and never removed.  It is what stops the final
# 'ls' assertion from passing because 'ls' printed nothing at all.
create_ok "sentinel created" "$BIN" create cache sentinel_keep -p "$SENTINEL_PORT" -s
wait_port "$SENTINEL_PORT" 5 || true
TOTAL=$((TOTAL+1))
if [ "$(python3 "$H" serve "$SENTINEL_PORT" 2>/dev/null || true)" = "SERVES_OK" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the sentinel runtime never served — the 'ls' check below cannot discriminate"
fi

# ── Warm-up: one cycle of each type before the baseline ────────────────────
# Everything the daemon allocates once — buffer pools, the state file, the
# io_uring registrations a first runtime forces — must be inside the baseline,
# or it reads as growth later.
WARM_OUT="$TMPDIR_T/warmup.out"
churn "$CHURN_PORT" "$WARM_CYCLES" churn_w "$WARM_OUT"
TOTAL=$((TOTAL+1))
if grep -q "^TOTALS .* served=$WARM_CYCLES " "$WARM_OUT" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the warm-up round did not serve all $WARM_CYCLES runtime types:"
    grep -v '^$' "$WARM_OUT" 2>/dev/null | head -5 | sed 's/^/        /' || true
fi

sleep 0.6
BASE_FD=$(fd_count)
BASE_RSS=$(rss_kb)

# ── The churn ──────────────────────────────────────────────────────────────
OUT="$TMPDIR_T/harness.out"
churn "$CHURN_PORT" "$CYCLES" churn_c "$OUT"
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

TOTAL=$((TOTAL+1))
if [ -n "$TOTALS" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [harness ran]: no TOTALS line; raw output:"
    grep -v '^$' "$OUT" 2>/dev/null | head -8 | sed 's/^/        /' || true
fi

assert_field_eq created "$CYCLES"                             "every runtime came up on the shared port"
assert_field_eq served  "$CYCLES"                             "every runtime served correctly before removal"
assert_field_eq ops     "$((CYCLES * ROUNDTRIPS * CONNS))"    "every round trip on every connection came back right"
assert_field_eq removed "$CYCLES"                             "every remove reported success"
assert_field_eq closed  "$CYCLES"                             "the port stopped answering after every remove"

# ── The daemon we measured is the daemon we started ────────────────────────
# This has to be asserted, not assumed.  Every CLI call fork+execs a fresh
# daemon when the socket does not answer (cli.cpp, ensure_daemon), so a daemon
# that crashes in the middle of the churn is replaced before the next 'create'
# and all five counters above still come out perfect against a process that has
# only existed for a few milliseconds.
NOW_IDENT=$(daemon_ident)
TOTAL=$((TOTAL+1))
if [ "$BASE_IDENT" != "gone" ] && [ "$NOW_IDENT" = "$BASE_IDENT" ]; then
    PASS=$((PASS+1))
    DAEMON_SURVIVED=1
else
    FAIL=$((FAIL+1))
    echo "  FAIL [same daemon throughout]: the daemon under test did not survive the churn"
    echo "        started as '$BASE_IDENT', now '$NOW_IDENT'"
    echo "        a CLI call silently starts a replacement, so the counters above"
    echo "        describe a daemon that was not running when the baseline was taken"
    echo "        (observed trigger: churning 'server' runtimes across two ports —"
    echo "         SIGSEGV, no traffic required, cache and proxy do not reproduce)"
    grep -v '^$' "$TMPDIR_T/daemon.log" 2>/dev/null | tail -3 | sed 's/^/        /' || true
fi

# ── Nothing left behind ────────────────────────────────────────────────────
LS_OUT=$("$BIN" ls 2>&1 || true)

TOTAL=$((TOTAL+1))
if grep -q 'sentinel_keep' <<<"$LS_OUT"; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [ls is answering]: the sentinel runtime is missing from 'ls', so an empty"
    echo "        listing below would prove nothing"
fi

TOTAL=$((TOTAL+1))
if grep -q 'churn_' <<<"$LS_OUT"; then
    FAIL=$((FAIL+1))
    echo "  FAIL [nothing left behind]: removed runtimes are still listed:"
    printf '%s\n' "$LS_OUT" | grep 'churn_' | head -5 | sed 's/^/        /' || true
else
    PASS=$((PASS+1))
fi

# The daemon is not merely alive: it still creates and serves a runtime that
# never existed during the churn.
# Deliberately not create_ok.  Here the create is not setup, it is the
# measurement: the claim is that the daemon still creates *and serves* after the
# churn, and the round trip below is the oracle for both halves.  Counting the
# create separately would report one defect as two.  What the create said is
# kept, so that when the round trip fails the report can say whether the runtime
# was ever made.
FINAL_CRC=0
FINAL_CREATE=$("$BIN" create cache final_probe -p "$FINAL_PORT" -s 2>&1) || FINAL_CRC=$?
# Wait for the success signal — a completed round trip — and not for a deadline.
# 'wait_port' alone proves nothing here: it returns as soon as the kernel accepts
# a connection out of the listen backlog, which is true from the instant listen()
# ran, while an event loop still winding down 45 cycles' worth of teardown may
# not reach the new runtime's first read for a while.  Trying once after that
# wait was a timing assumption; retrying until it answers is not, and a wedged or
# dead daemon never answers and still fails, only later.
FINAL_RT=""
for _ in $(seq 1 60); do
    FINAL_RT=$(python3 "$H" serve "$FINAL_PORT" 2>/dev/null || true)
    [ "$FINAL_RT" = "SERVES_OK" ] && break
    sleep 0.5
done
TOTAL=$((TOTAL+1))
if [ "$FINAL_RT" = "SERVES_OK" ]; then
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
"$BIN" remove final_probe >/dev/null 2>&1 || true

# Back to the baseline's lifecycle state: no churn runtime exists, only the
# sentinel, which was already there when the baseline was taken.
sleep 0.8
assert_fds_returned "$BASE_FD" "$(fd_count)" "$FD_TOLERANCE"
assert_rss_bounded  "$BASE_RSS" "$(rss_kb)"  "$RSS_BOUND_KB"

if [ "$FAIL" -gt 0 ] || [ "$SKIP" -gt 0 ]; then
    echo "  ${TOTALS:-<no TOTALS line>}"
fi

# Every assertion is accounted for in exactly one column, or the summary cannot
# be acted on and nobody re-checks the arithmetic by eye.  Same guard as
# test_restart_under_load.sh and test_abrupt_client_abort.sh.
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
