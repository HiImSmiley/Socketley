#!/usr/bin/env bash
# A runtime restarted with traffic in flight comes back whole, which is the
# only moment a fresh setup() runs over state a teardown() decided to keep --
# catching a lost runtime, one answering wrongly, and descriptors or memory
# never given back, while proving nothing about Lua, TLS, UDP or a
# single-restart race, and guarding against an empty measurement window with
# live_at_stop.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# shellcheck source=lib_create.sh
. "$(dirname "$0")/lib_create.sh"
# For daemon_sweep in cleanup, sourced because that defines functions without
# running anything.
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

if ! command -v python3 >/dev/null 2>&1; then
    echo "=== Integration: restart under load ==="
    echo "  SKIP: python3 not available"
    exit 0
fi

# Own daemon, socket and state directory, because against the shared daemon
# auto-restart puts a crashed runtime back and the probe passes over the
# corpse.
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

# Tolerance for the descriptor check, where both samples are taken at the same
# point in the lifecycle so only transients differ, and a real leak in this
# family is hundreds rather than six.
FD_TOLERANCE=6

# An RSS ceiling that is guessed rather than measured, so treat it as catching
# gross leakage and tighten it from the numbers this run prints on every pass.
RSS_BOUND_KB=24576

# RSS is printed and not asserted in a sanitized build, because ASan's fixed
# overhead is seventeen times the Release growth against a bound eleven times
# it and no number bounds both -- detected from the binary rather than an
# environment variable, counted in its own column because a nightly that is red
# for an unactionable reason gets ignored, and with the daemon being gone still
# a failure in every build.
SANITIZED=""
if nm -C "$BIN" 2>/dev/null | grep '__tsan_' >/dev/null 2>&1; then
    SANITIZED="TSan"
elif nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null 2>&1; then
    SANITIZED="ASan"
fi

PASS=0; FAIL=0; HERR=0; SKIP=0; TOTAL=0

# A claim this run was unable to put the question to, in the words another test
# already uses, counted separately from a failure although both end the run
# non-zero.
herr() {
    local label=$1 reason=$2; shift 2
    TOTAL=$((TOTAL+1)); HERR=$((HERR+1))
    echo "  NOT MEASURABLE [$label]: $reason"
    local line
    for line in "$@"; do echo "        $line"; done
}

# A claim this build cannot answer, as opposed to one this run could not put,
# which does not end the run non-zero because retrying changes nothing.
not_asserted() {  # label reason
    TOTAL=$((TOTAL+1)); SKIP=$((SKIP+1))
    echo "  NOT ASSERTED [$1]: $2"
    echo "        sanitized build ($SANITIZED) — this measures the sanitizer, not the daemon"
}

cleanup() {
    [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null || true
    # Wait for the daemon to actually go, because a plain kill returns
    # immediately and a daemon holding connections stays bound long enough for
    # the next test to collide.
    if [ -n "$DPID" ]; then
        kill "$DPID" 2>/dev/null || true
        for _ in $(seq 1 50); do
            kill -0 "$DPID" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
    # Killed through daemon_sweep, which asks the socket who is serving it,
    # because a `pgrep -f` pattern one character too broad kills the run doing
    # the killing -- which has happened twice in this project.
    daemon_sweep "$SOCKETLEY_SOCKET"
    rm -rf "$TMPDIR_T"
}
trap cleanup EXIT

echo "=== Integration: restart under load ==="

# ── Resource sampling ───────────────────────────────────────────────────────
# Both readers return the literal 'unreadable' rather than an empty string,
# because two empty samples compare equal and a before==after that holds only
# because the daemon died is a pass for the wrong reason.
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
# Wait on the IPC socket itself, never by polling with a CLI command, because
# polling auto-starts a second daemon and when the loser is $DPID every /proc
# sample reads 'unreadable' -- measured at 2 orphans in 30 startups.
python3 "$H" waitsock "$SOCKETLEY_SOCKET" 8 || true

TOTAL=$((TOTAL+1))
if "$BIN" ps >/dev/null 2>&1; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the daemon never became reachable — everything below is meaningless"
fi

# And the daemon answering is the one this test launched, or the run reports
# its confusion at the very end rather than here where it happened.
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

# Assert the success marker rather than a comparison, because a warm-up that
# did not run leaves no line at all and must fail here rather than move the
# baseline.
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

# Every number is read out of that one line, and a missing field must fail
# loudly rather than compare equal to an equally unset expectation.
field() {
    printf '%s\n' "$TOTALS" | grep -o "\b$1=[0-9]\+" | cut -d= -f2 | head -1 || true
}

# The same for a field that is not a number, which is diagnostic only, so an
# empty reading degrades the message and never the verdict.
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
# Traffic was still moving at every stop, which is a claim about the harness
# rather than the build, so five of six is not measurable and named rather than
# failed -- while zero is a failure in kind, because it means every restart was
# of an idle runtime; TOTAL is counted inside each branch, since herr() takes
# one of its own.
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

# The restart itself completed -- both commands succeeded and the port came
# back -- which is where a runtime lost to a bad setup() lands.
assert_field_eq restarts_ok "$CYCLES" "every restart completed"

# The marker that matters: a connection made after each restart got a correct
# answer, which a dead daemon cannot satisfy.
assert_field_eq recovered "$CYCLES" "the runtime served correctly after every restart"

# Wrong content is the signature of state carried across a restart, while
# dropped connections during the stop window are expected and counted as errors
# instead.
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

# The daemon still does its job -- create, serve a verified round trip, remove
# -- as one claim with the round trip its oracle, so counting the create
# separately would report one defect as two.
FINAL_CRC=0
FINAL_CREATE=$("$BIN" create cache rl_final -p "$FINAL_PORT" -s 2>&1) || FINAL_CRC=$?
# Wait for a completed round trip rather than a deadline, because wait_port
# returns from the instant listen() ran while the event loop may not reach the
# new runtime's first read for a while.
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

# Every assertion is accounted for in exactly one column, which caught a draft
# charging one assertion to TOTAL twice.
if [ "$((PASS+FAIL+HERR+SKIP))" -ne "$TOTAL" ]; then
    echo "  FAIL [counters]: $PASS passed + $FAIL failed + $HERR not measurable"
    echo "        + $SKIP not asserted does not equal $TOTAL counted — this summary"
    echo "        is wrong, not just the run"
    FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1))
fi

if [ "$FAIL" -gt 0 ] || [ "$HERR" -gt 0 ] || [ "$SKIP" -gt 0 ]; then
    echo "  ${TOTALS:-<no TOTALS line>}"
fi

# SKIP is reported but never changes the verdict, because a claim this build
# cannot answer is not a claim that failed; HERR still does.
if [ "$SKIP" -gt 0 ]; then
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $HERR not measurable, $SKIP not asserted under $SANITIZED)"
else
    echo "  Results: $PASS/$TOTAL passed ($FAIL failed, $HERR not measurable)"
fi
if [ "$FAIL" -eq 0 ] && [ "$HERR" -eq 0 ]; then echo "  OK"
elif [ "$FAIL" -eq 0 ]; then echo "  NOT MEASURABLE -- this run could not put the question, see above"
else echo "  FAILED"; fi
exit $((FAIL+HERR))
