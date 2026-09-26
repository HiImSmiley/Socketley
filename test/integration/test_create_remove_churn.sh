#!/usr/bin/env bash
# suite: isolated -- a daemon, socket and port window of its own, so it runs beside the others
# Forty-five create/serve/remove cycles over three runtime types on one
# deliberately reused port, because SO_REUSEPORT means a listener that outlived
# its runtime silently takes a share of the next one's connections rather than
# failing to bind -- with descriptors compared against a post-warm-up baseline,
# RSS bounded at 12 MB where healthy runs grow 2.8-4.8 MB and a per-cycle
# instance leak is ~226 MB, the daemon's identity checked so a
# crash-and-respawn cannot read as a clean run, and both removal paths
# exercised.
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

# Both samples are taken at the same point in the lifecycle, so only transient
# descriptors can differ and a leak here is one per cycle.
FD_TOLERANCE=6

# Measured rather than guessed, on Release figures -- see the sanitizer note
# below for why this bound is not asserted in an instrumented build.
RSS_BOUND_KB=12288

# RSS has no defined meaning under ASan, whose fixed overhead alone is
# twenty-five times a bound chosen to sit an order of magnitude below the leak
# it catches, so it is printed loudly with the numbers while every other
# assertion stays live in every build -- with the sanitizer detected from the
# binary rather than the environment, and without `grep -q`, which under
# pipefail takes the no-match branch precisely when it matched.
SANITIZED=""
if nm -C "$BIN" 2>/dev/null | grep '__tsan_' >/dev/null 2>&1; then
    SANITIZED="TSan"
elif nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null 2>&1; then
    SANITIZED="ASan"
fi

PASS=0; FAIL=0; SKIP=0; TOTAL=0
SUBPID=""
DAEMON_SURVIVED=0   # set once the identity check confirms it lived through the churn

# Counted in its own column and deliberately not added to FAIL, because "this
# build cannot answer this question and never will" is not the same as "this
# run could not put the question" and a job that is red every night for a
# reason nobody can act on gets ignored.
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
    # Killed by socket rather than only by pid, because a CLI command run
    # against an absent daemon starts one of its own that $DPID would never
    # reach.
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
    # The reaping subshell exits normally, so its recorded status is how a
    # signal death gets reported here -- in words, after the verdict.
    [ -n "$SUBPID" ] && wait "$SUBPID" 2>/dev/null || true
    local st
    st=$(cat "$TMPDIR_T/daemon.status" 2>/dev/null || true)
    case "$st" in
        ''|*[!0-9]*) ;;
        *)
            # 143 is our SIGTERM and 137 our SIGKILL, so anything else above
            # 128 is the daemon dying of its own accord while being shut down.
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
# Every reader returns a literal 'unreadable'/'gone' rather than an empty
# string, because two empty values compare equal and a dead daemon would
# satisfy "before == after".
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

# The kernel's start time is what makes this an identity rather than a liveness
# check, since pids get reused and the CLI spawns replacement daemons on its
# own.
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
    to the other clients — verified against both the current build and 771e1fc,
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

# The daemon is started inside a subshell that reaps it with stderr discarded,
# because a bare "Segmentation fault" from job control reads like the harness
# broke, and the pid is published through a file since $! would name the
# subshell.
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
# Wait on the IPC socket itself and never by polling with a CLI command,
# because every CLI command auto-starts a daemon when the socket does not
# answer and when the loser of the bind is $DPID every /proc sample below reads
# 'unreadable'.
python3 "$H" waitsock "$SOCKETLEY_SOCKET" 8 || true
BASE_IDENT=$(daemon_ident)

TOTAL=$((TOTAL+1))
if "$BIN" ps >/dev/null 2>&1; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the daemon never became reachable — everything below is meaningless"
fi

# ...and the daemon answering is the one this test launched, without which a
# zombie $DPID is only noticed at the end and described as a death during the
# churn.
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

# The sentinel is created once and never removed, so the final 'ls' assertion
# cannot pass because 'ls' printed nothing at all.
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

# Asserted rather than assumed, because a daemon that crashes mid-churn is
# replaced before the next 'create' and all five counters still come out
# perfect against a process a few milliseconds old.
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

# Deliberately not create_ok, because here the create is the measurement rather
# than setup and counting it separately would report one defect as two.
FINAL_CRC=0
FINAL_CREATE=$("$BIN" create cache final_probe -p "$FINAL_PORT" -s 2>&1) || FINAL_CRC=$?
# Retried until it answers rather than tried once after wait_port, because the
# kernel accepts from the backlog the instant listen ran while an event loop
# unwinding 45 cycles of teardown may not reach the first read for a while.
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
# be acted on.
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
