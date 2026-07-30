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

PASS=0; FAIL=0; TOTAL=0

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
assert_field_min cache_ok "$MIN_OK" "enough healthy cache traffic to mean something"
assert_field_min proxy_ok "$MIN_OK" "enough healthy proxy traffic to mean something"

# ── The point of the test ──────────────────────────────────────────────────
# Every client is gone. A connection that nothing will ever wake keeps this
# number above zero for as long as the runtime lives.
assert_drained "$CACHE_NAME"
assert_drained "$PROXY_NAME"

# The daemon is not merely alive: it still creates and serves a runtime that
# never existed during the storm.
"$BIN" create cache ab_final -p "$FINAL_PORT" -s >/dev/null 2>&1 || true
wait_port "$FINAL_PORT" 5 || true
TOTAL=$((TOTAL+1))
if [ "$(python3 "$H" serve "$FINAL_PORT" 2>/dev/null || true)" = "SERVES_OK" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [daemon still serves]: a freshly created runtime did not answer correctly"
fi
"$BIN" remove ab_final >/dev/null 2>&1 || true

# Back to the baseline's lifecycle state.
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
