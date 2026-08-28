#!/usr/bin/env bash
# A write that takes ECONNRESET marks the connection closing, declines to
# finish it because a read is armed, and hands the teardown to an operation
# whose only trigger it has already consumed -- so a pipeline of GETs for a 4
# MB file closed with SO_LINGER (on, 0) strands connections at about 15% a
# round, which is why several rounds run and one assertion at the end says
# whether `connections` fell back to 0, with healthy clients alongside to catch
# a recycled descriptor number and a fresh runtime afterwards to catch a wedged
# daemon; there is deliberately no fd assertion, because teardown closes every
# client socket it still holds.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
# shellcheck source=lib_daemon.sh
. "$(dirname "$0")/lib_daemon.sh"
# shellcheck source=lib_create.sh
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

echo "=== Integration: abrupt HTTP client aborts (server) ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not available"
    exit 0
fi

# Own daemon, socket and state directory, because against the shared daemon
# auto-restart puts a crashed runtime straight back and the check that matters
# would pass over the corpse -- through daemon_isolate, which run_group.sh
# reads as this file's declaration that it shares nothing, with the daemon
# still started here because the assertions need its pid.
daemon_isolate srvabort
TMPDIR_T="$SOCKETLEY_TMPD"
mkdir -p "$TMPDIR_T/www"
DPID=""

PORT=$((SL_PORT_BASE+560))
FINAL_PORT=$((SL_PORT_BASE+561))
NAME=sab_srv
ROUNDS=8            # see "HONEST ABOUT THE RATE" above
LOAD_SECS=1.2       # per round
PIPELINE=20         # GETs for the big file per aborted connection
# One definition, at 4 MB so that a pipeline of 20 owes 80 MB and a write is
# certain to be in flight when the reset lands.
BIG_BYTES=$((4 * 1024 * 1024))
ABORT_THREADS=3
VERIFY_THREADS=2
DRAIN_SECS=10       # how long the runtime may take to reap its dead connections
FINAL_SERVE_SECS=30
# Floors rather than targets, set well below what this box produces so a busy
# machine does not fail the test while a run that never got going still does.
MIN_ABORTS=$((ROUNDS * 40))
MIN_OK=$((ROUNDS * 8))

PASS=0; FAIL=0; TOTAL=0; SKIP=0

# Detected from the binary rather than from an environment variable, using the
# idiom test_abrupt_client_abort.sh explains at length: a build that lost its
# sanitizer flags must not be able to claim the exemption, and `grep -q` must
# not be used because SIGPIPE plus pipefail inverts the answer.
SANITIZED=""
if nm -C "$BIN" 2>/dev/null | grep '__tsan_' >/dev/null 2>&1; then
    SANITIZED="TSan"
elif nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null 2>&1; then
    SANITIZED="ASan"
fi

not_asserted() {  # label reason
    TOTAL=$((TOTAL+1)); SKIP=$((SKIP+1))
    echo "  NOT ASSERTED [$1]: $2"
    echo "        sanitized build ($SANITIZED) — this measures the sanitizer, not the daemon"
}

cleanup() {
    if [ -n "$DPID" ]; then
        kill "$DPID" 2>/dev/null || true
        for _ in $(seq 1 50); do
            kill -0 "$DPID" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "$DPID" 2>/dev/null || true
        wait "$DPID" 2>/dev/null || true
    fi
    # By socket as well as by pid and by exact process name, because a CLI
    # command run while the daemon is down starts a detached one and `pgrep -f`
    # also matches the shell carrying the string.
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

# ── The document under load ────────────────────────────────────────────────
# 4 MB so a pipeline of 20 owes 80 MB, with fixed content the verifiers check,
# so a wrong answer is distinguishable from no answer.
python3 - "$TMPDIR_T/www" "$BIG_BYTES" <<'PYEOF'
import sys, os
d = sys.argv[1]
with open(os.path.join(d, "big.txt"), "wb") as f:
    f.write(b"B" * int(sys.argv[2]))
with open(os.path.join(d, "small.txt"), "wb") as f:
    f.write(b"SMALL-OK\n")
PYEOF

H="$TMPDIR_T/harness.py"
cat >"$H" <<'PYEOF'
"""Modes: waitsock | waitport | serve | servewait | storm.

Every mode prints one machine-readable line whose first token is a marker the
shell dispatches on, so an empty capture — python itself failed — can never be
mistaken for a pass.
"""
import socket
import struct
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
    # The IPC socket directly, never by polling with a CLI command: every CLI
    # command auto-starts a daemon when the socket does not answer, which races
    # the one this test just launched and orphans one of the two.
    path = sys.argv[2]
    end = time.time() + float(sys.argv[3])
    while time.time() < end:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.settimeout(0.4)
            s.connect(path)
            sys.exit(0)
        except OSError:
            time.sleep(0.02)
        finally:
            try:
                s.close()
            except OSError:
                pass
    sys.exit(1)


def http_get(s, path, expect):
    """One HTTP round trip.  Returns 'ok', 'wrong', 'reset' or 'timeout'.

    'wrong' is kept apart from everything else because it is the only outcome
    that is a defect on its own: the runtime spoke, and said something other
    than the file's contents.  Everything else means it has not answered yet.
    """
    try:
        s.sendall(("GET %s HTTP/1.1\r\nHost: x\r\n\r\n" % path).encode())
    except OSError:
        return "reset"
    buf = b""
    while b"\r\n\r\n" not in buf:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            return "timeout"
        except OSError:
            return "reset"
        if not chunk:
            return "reset"
        buf += chunk
    head, body = buf.split(b"\r\n\r\n", 1)
    if b" 200 " not in head.split(b"\r\n")[0]:
        return "wrong"
    clen = None
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                clen = int(line.split(b":", 1)[1])
            except ValueError:
                return "wrong"
    if clen is None:
        return "wrong"
    while len(body) < clen:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            return "timeout"
        except OSError:
            return "reset"
        if not chunk:
            return "reset"
        body += chunk
    return "ok" if body[:clen] == expect else "wrong"


def serve_probe(port):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=2)
    except OSError as e:
        return "connect", "errno=%s" % (e.errno,)
    try:
        s.settimeout(3)
        return http_get(s, "/small.txt", b"SMALL-OK\n"), ""
    finally:
        try:
            s.close()
        except OSError:
            pass


if mode == "primed":
    # The document the ABORTERS request, fetched whole and checked by length.
    #
    # servewait below asks for /small.txt, and a check on /small.txt cannot see
    # the one setup failure that would quietly empty this test: a missing or
    # truncated /big.txt makes every aborted connection owe a 404 instead of
    # 80 MB, so no write is ever in flight when the reset lands, the provocation
    # stops being one, and every zero this file asserts would be measuring
    # nothing while still passing.  That is the shape an assertion has to be
    # able to fail against, so it is asserted separately and on the real file.
    port = int(sys.argv[2])
    want = int(sys.argv[3])
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.settimeout(20)
        r = http_get(s, "/big.txt", b"B" * want)
        print("PRIMED status=%s want=%d" % (r, want))
        s.close()
    except OSError as e:
        print("PRIMED status=connect errno=%s" % (e.errno,))
    sys.exit(0)


if mode == "servewait":
    # Wait for a success signal, not for a deadline: a connect proves nothing
    # here, because the kernel completes handshakes out of the listen backlog on
    # its own from the instant listen() ran, while an event loop still reaping a
    # storm may not reach the new runtime's first read for a while.
    port = int(sys.argv[2])
    end = time.time() + float(sys.argv[3])
    started = time.time()
    attempts = 0
    last = "none"
    while True:
        attempts += 1
        status, detail = serve_probe(port)
        if status == "ok":
            print("SERVES_OK attempts=%d waited=%.2fs" % (attempts, time.time() - started))
            sys.exit(0)
        if status == "wrong":
            print("SERVES_WRONG attempts=%d %s" % (attempts, detail))
            sys.exit(2)
        last = status + (("(" + detail + ")") if detail else "")
        if time.time() >= end:
            break
        time.sleep(0.05)
    print("SERVES_NEVER attempts=%d waited=%.2fs last=%s"
          % (attempts, time.time() - started, last))
    sys.exit(1)


# ── storm ──────────────────────────────────────────────────────────────────
PORT = int(sys.argv[2])
SECS = float(sys.argv[3])
PIPELINE = int(sys.argv[4])
ABORT_THREADS = int(sys.argv[5])
VERIFY_THREADS = int(sys.argv[6])

BIG_REQ = ("GET /big.txt HTTP/1.1\r\nHost: x\r\n\r\n" * PIPELINE).encode()
SMALL = b"SMALL-OK\n"

lock = threading.Lock()
c = {"aborted": 0, "ok": 0, "wrong": 0, "reset": 0, "timeout": 0,
     "connfail": 0, "verify_conns": 0}


def bump(k):
    with lock:
        c[k] += 1


# Verifying connections close cleanly and each leaves a TIME_WAIT behind, so a
# fast machine would walk into ephemeral port exhaustion and fail this test for
# a reason that has nothing to do with the runtime.  Aborted connections are RST
# and cost nothing.
MAX_VERIFY_CONNS = 600


def verify_budget_left():
    with lock:
        return c["verify_conns"] < MAX_VERIFY_CONNS


def aborter(deadline):
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=2)
        except OSError:
            time.sleep(0.005)
            continue
        try:
            s.sendall(BIG_REQ)
            bump("aborted")
        except OSError:
            pass
        # close() that sends RST instead of FIN: the client is gone at once and
        # its descriptor number is immediately available to the next accept.
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        except OSError:
            pass
        try:
            s.close()
        except OSError:
            pass
        # Aborting is cheap and verifying is not.  Unthrottled aborter threads
        # hold the interpreter lock almost continuously and starve the verifying
        # threads in this same process, and the run then asserts its zeroes over
        # almost no healthy traffic.
        time.sleep(0.002)


def verifier(deadline):
    while time.time() < deadline and verify_budget_left():
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=3)
            s.settimeout(3)
        except OSError:
            bump("connfail")
            time.sleep(0.01)
            continue
        bump("verify_conns")
        try:
            for _ in range(3):
                if time.time() >= deadline:
                    break
                r = http_get(s, "/small.txt", SMALL)
                bump(r)
                if r in ("reset", "timeout"):
                    break
        except OSError:
            bump("reset")
        try:
            s.close()
        except OSError:
            pass


deadline = time.time() + SECS
threads = [threading.Thread(target=aborter, args=(deadline,), daemon=True)
           for _ in range(ABORT_THREADS)]
threads += [threading.Thread(target=verifier, args=(deadline,), daemon=True)
            for _ in range(VERIFY_THREADS)]
for t in threads:
    t.start()
for t in threads:
    t.join(60)

with lock:
    print("TOTALS aborted=%d ok=%d wrong=%d reset=%d timeout=%d connfail=%d verify_conns=%d"
          % (c["aborted"], c["ok"], c["wrong"], c["reset"], c["timeout"],
             c["connfail"], c["verify_conns"]))
PYEOF

# ── Bring the daemon up ────────────────────────────────────────────────────
"$BIN" daemon >"$TMPDIR_T/daemon.log" 2>&1 &
DPID=$!
python3 "$H" waitsock "$SOCKETLEY_SOCKET" 8 || true

TOTAL=$((TOTAL+1))
if "$BIN" ps >/dev/null 2>&1; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the daemon never became reachable — everything below is meaningless"
fi

# ...and the daemon answering is the one this test launched, without which a
# zombie $DPID would be reported at the very end rather than here.
TOTAL=$((TOTAL+1))
if [ -d "/proc/$DPID/fd" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: pid $DPID is not a live process — the daemon that answers is not"
    echo "        the one this test launched"
fi

create_ok "server under test created" "$BIN" create server "$NAME" -p "$PORT" \
    --http "$TMPDIR_T/www" --http-cache -s
python3 "$H" waitport "$PORT" 5 || true

# A real round trip before the storm: the server is up and answering at all.
TOTAL=$((TOTAL+1))
if [ "$(python3 "$H" servewait "$PORT" 10 2>&1 | grep -c '^SERVES_OK')" = "1" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the server never answered a request at all"
fi

# It serves the file the aborters ask for, whole, because a missing or
# truncated /big.txt answers every aborted connection with a 404 and leaves no
# write in flight -- so every zero below would pass while measuring nothing.
TOTAL=$((TOTAL+1))
PRIMED=$(python3 "$H" primed "$PORT" "$BIG_BYTES" 2>&1 || true)
if [ "$PRIMED" = "PRIMED status=ok want=$BIG_BYTES" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the server did not serve /big.txt whole — the aborters"
    echo "        would owe a 404 rather than ${BIG_BYTES} bytes, and every zero below"
    echo "        would be measuring nothing.  probe said: ${PRIMED:-<no output>}"
fi

# ── The storm, several rounds ──────────────────────────────────────────────
# Rounds rather than one long window because a stranded connection never goes
# away: the count accumulates, so N rounds and one assertion detects the defect
# far more often than one round would, at the cost of N storms.
T_AB=0; T_OK=0; T_WRONG=0; T_RESET=0; T_TIMEOUT=0; ROUNDS_RAN=0
for r in $(seq 1 "$ROUNDS"); do
    OUT="$TMPDIR_T/storm.$r"
    python3 "$H" storm "$PORT" "$LOAD_SECS" "$PIPELINE" "$ABORT_THREADS" \
        "$VERIFY_THREADS" >"$OUT" 2>&1 || true
    LINE=$(grep '^TOTALS ' "$OUT" 2>/dev/null | head -1 || true)
    if [ -z "$LINE" ]; then
        # Named and dumped here rather than lumped together at the end: a round
        # that produced nothing is the only thing in this file that can go wrong
        # without saying why, and "7 of 8" on its own sends the next reader
        # looking through eight files for the empty one.
        echo "  round $r produced no TOTALS line; its raw output was:"
        sed -n '1,12p' "$OUT" 2>/dev/null | sed 's/^/        /'
        [ -s "$OUT" ] || echo "        <empty: python3 wrote nothing at all>"
        continue
    fi
    ROUNDS_RAN=$((ROUNDS_RAN+1))
    f() { printf '%s\n' "$LINE" | grep -o "\b$1=[0-9]\+" | cut -d= -f2 | head -1; }
    T_AB=$((T_AB + $(f aborted)))
    T_OK=$((T_OK + $(f ok)))
    T_WRONG=$((T_WRONG + $(f wrong)))
    T_RESET=$((T_RESET + $(f reset)))
    T_TIMEOUT=$((T_TIMEOUT + $(f timeout)))
done

echo "  storm: rounds=$ROUNDS_RAN/$ROUNDS aborted=$T_AB ok=$T_OK wrong=$T_WRONG" \
     "reset=$T_RESET timeout=$T_TIMEOUT"

TOTAL=$((TOTAL+1))
if [ "$ROUNDS_RAN" -eq "$ROUNDS" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [harness ran]: only $ROUNDS_RAN of $ROUNDS rounds produced a TOTALS line"
    echo "        the round that failed printed its own output above"
fi

assert_min() {   # value minimum label
    TOTAL=$((TOTAL+1))
    if [ "$1" -ge "$2" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$3]: $1, wanted at least $2"
    fi
}

assert_zero() {  # value label
    TOTAL=$((TOTAL+1))
    if [ "$1" -eq 0 ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$2]: $1"
    fi
}

# The failure window actually opened: this counts clients that got a full
# pipeline onto the wire and were then reset, so a run that finished before the
# storm started fails here rather than passing.
assert_min "$T_AB" "$MIN_ABORTS" "enough clients sent a full pipeline and were reset"

# Timeouts are printed but not asserted on, because on a loaded machine a
# timeout is usually scheduling and asserting it would make this flaky for a
# reason it is not about.
assert_zero "$T_WRONG" "the server answered a healthy client with the wrong bytes"
assert_zero "$T_RESET" "the server closed a healthy connection"

# Zeroes above are worthless if barely any healthy traffic got through, and
# zero still fails in every build -- "the sanitizer is slow" and "nothing got
# through" are not the same statement.
if [ -n "$SANITIZED" ] && [ "$T_OK" -gt 0 ]; then
    not_asserted "enough healthy traffic to mean something" \
        "ok=$T_OK against a floor of $MIN_OK calibrated on a Release build"
else
    assert_min "$T_OK" "$MIN_OK" "enough healthy traffic to mean something"
fi

# ── The point of the test ──────────────────────────────────────────────────
# Every client is gone, because a connection nothing will ever wake keeps this
# number above zero for as long as the runtime lives.
wait_conns_zero() {   # seconds
    local end v="unreadable"
    end=$(( $(date +%s) + $1 ))
    while :; do
        v=$("$BIN" stats "$NAME" 2>/dev/null | grep -m1 '^connections:' \
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

TOTAL=$((TOTAL+1))
DRAINED=$(wait_conns_zero "$DRAIN_SECS")
if [ "$DRAINED" = "0" ]; then
    PASS=$((PASS+1))
elif [ "$DRAINED" = "unreadable" ]; then
    FAIL=$((FAIL+1))
    echo "  FAIL [connections reaped]: 'stats' has no readable 'connections' field —"
    echo "        the runtime or the daemon is gone, which is a failure and not a drained run"
else
    FAIL=$((FAIL+1))
    echo "  FAIL [connections reaped]: still $DRAINED live connections ${DRAIN_SECS}s after"
    echo "        the last client went away — nothing will ever wake them"
fi

# The daemon is not merely alive: it still creates and serves a runtime that
# never existed during the storm.
CREATE_LOG="$TMPDIR_T/final.create"
"$BIN" create server sab_final -p "$FINAL_PORT" --http "$TMPDIR_T/www" -s \
    >"$CREATE_LOG" 2>&1 || echo "(create exited $?)" >>"$CREATE_LOG"

FINAL=$(python3 "$H" servewait "$FINAL_PORT" "$FINAL_SERVE_SECS" 2>&1 || true)
FINAL_MARK=$(printf '%s\n' "$FINAL" | grep -m1 '^SERVES_' || true)
TOTAL=$((TOTAL+1))
case "$FINAL_MARK" in
    SERVES_OK*)
        if [ -d "/proc/$DPID/fd" ]; then
            PASS=$((PASS+1))
            echo "  final runtime: $FINAL_MARK"
        else
            FAIL=$((FAIL+1))
            echo "  FAIL [daemon still serves]: the answer was correct, but pid $DPID is gone —"
            echo "        it came from a replacement daemon a CLI command started"
        fi
        ;;
    *)
        FAIL=$((FAIL+1))
        echo "  FAIL [daemon still serves]: a freshly created runtime never answered correctly"
        echo "        ${FINAL:-<no marker at all: the probe itself did not run>}"
        echo "        create said: $(cat "$CREATE_LOG" 2>/dev/null || true)"
        tail -n 8 "$TMPDIR_T/daemon.log" 2>/dev/null | sed 's/^/        /' || true
        ;;
esac

echo "=== Results: $PASS/$TOTAL passed, $FAIL failed, $SKIP not asserted ==="
[ "$FAIL" -eq 0 ]
