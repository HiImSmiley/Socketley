#!/usr/bin/env bash
# A client that vanishes by RST with a reply still owed must be torn down,
# provoked against a slow-echoing proxy and a cache pipelining hundreds of KiB
# -- catching a connection never reaped, descriptors held past it, collateral
# damage to healthy neighbours and a wedged daemon, while proving nothing about
# writes, TLS, UDP, Lua or a leak of one connection in a thousand, and
# requiring a real number of aborts so a run that never opened the window fails
# rather than passing.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# shellcheck source=lib_create.sh
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

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

CACHE_PORT=$((SL_PORT_BASE+520))
PROXY_PORT=$((SL_PORT_BASE+521))
BE_PORT=$((SL_PORT_BASE+522))
FINAL_PORT=$((SL_PORT_BASE+523))
CACHE_NAME=ab_cache
PROXY_NAME=ab_proxy
LOAD_SECS=1.5       # almost all of this test's runtime
# Floors rather than targets, an order of magnitude below what a stand-in
# server produced, so a busy machine does not fail while a run that never got
# going still does.
MIN_ABORTS=100      # per runtime: fewer than this and the storm never happened
MIN_OK=60           # per runtime: fewer than this and the zeroes prove nothing
DRAIN_SECS=8        # how long a runtime may take to reap its dead connections
# A ceiling on patience rather than a wait, generous because the daemon may
# still be reaping the storm and "the event loop is busy" must not read as "the
# daemon is broken".
FINAL_SERVE_SECS=30

# Both samples are taken with both runtimes created but stopped, because the
# proxy keeps up to 32 idle backend descriptors for a minute and would swamp
# any tolerance.
FD_TOLERANCE=6

# Guessed rather than measured, a ceiling against gross leakage, with the real
# number printed every run so it can be tightened from data.
RSS_BOUND_KB=24576

PASS=0; FAIL=0; TOTAL=0; SKIP=0

# Three assertions have no defined meaning in a sanitized build -- TSan grew
# 1.8 GB against Release's 5.7 MB and its clock turns the throughput floors
# into tens -- so they are printed loudly rather than asserted, with zero still
# a failure, detection taken from the binary and grep without -q, because -q
# plus pipefail reports a match as no match.
SANITIZED=""
if nm -C "$BIN" 2>/dev/null | grep '__tsan_' >/dev/null 2>&1; then
    SANITIZED="TSan"
elif nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null 2>&1; then
    SANITIZED="ASan"
fi

# Counted in its own column and not added to FAIL, because this build can never
# answer the question and a nightly that is red for an unactionable reason gets
# ignored.
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
    # Killed by socket and by exact process name, because a CLI command against
    # an absent daemon starts a detached one and `-f` matches any shell whose
    # command line carries the string.
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
    rm -rf "$TMPDIR_T"
}
trap cleanup EXIT

echo "=== Integration: abrupt client aborts ==="

# ── Resource sampling ───────────────────────────────────────────────────────
# Both readers return the literal 'unreadable' rather than an empty string,
# because two empty values compare equal and a dead daemon would satisfy
# before==after.
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

# Poll `stats` until the runtime reports no live connections, printing the last
# value seen or 'unreadable', which must fail rather than look like a match.
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

# Payloads beginning with SLOW are held 150 ms before being echoed, which is
# what guarantees the reply is still owed when the RST arrives, while
# everything else is echoed at once.
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

# Warm both runtimes before the baseline, so what the daemon allocates once is
# inside it rather than reading as growth later.
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
# The big value has to be put back after `start` ran a fresh setup(), asserted
# because without it every aborted connection is owed four bytes and the zeroes
# below measure nothing.
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

# A sufficiency floor on healthy traffic, not asserted in a sanitized build
# because the window measures the sanitizer's clock, though zero still fails
# either way.
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

# The failure window actually opened, so a run that finished before the storm
# started fails here.
assert_field_min aborted_cache "$MIN_ABORTS" "enough cache clients died mid-reply"
assert_field_min aborted_proxy "$MIN_ABORTS" "enough proxy clients died mid-reply"

# Collateral damage on healthy neighbours, with timeouts reported but not
# asserted on, because on a loaded machine a timeout is usually scheduling.
assert_field_eq cache_bad   0 "cache answered a healthy client with the wrong value"
assert_field_eq proxy_bad   0 "proxy answered a healthy client with the wrong payload"
assert_field_eq cache_reset 0 "cache closed a healthy connection"
assert_field_eq proxy_reset 0 "proxy closed a healthy connection"

# Zeroes above are worthless if barely any healthy traffic got through.
assert_field_min_throughput cache_ok "$MIN_OK" "enough healthy cache traffic to mean something"
assert_field_min_throughput proxy_ok "$MIN_OK" "enough healthy proxy traffic to mean something"

# ── The point of the test ──────────────────────────────────────────────────
# Every client is gone, because a connection nothing will ever wake keeps this
# number above zero for the life of the runtime.
assert_drained "$CACHE_NAME"
assert_drained "$PROXY_NAME"

# The daemon still creates and serves a runtime that never existed during the
# storm, waiting on the round trip rather than a deadline, because wait_port
# returns from the moment listen() ran and a one-attempt assumption lost one
# run in five.
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
# Sampled at the moment of judgement, because `create` would start a fresh
# daemon that never saw the abuse and a live $DPID is what makes the round trip
# mean it survived.
FINAL_ALIVE=$(fd_count)
# Dispatch on the marker line rather than the whole capture, because stderr is
# merged in and a stray warning must not turn a served round trip into never
# answered.
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
# arithmetic by eye.
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
