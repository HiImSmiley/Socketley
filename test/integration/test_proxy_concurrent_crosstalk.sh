#!/usr/bin/env bash
# Integration test: under concurrency, nobody receives another connection's data.
#
# Tearing a backend down clears the client's backend_fd, but a client that died
# first left a deferred backend still holding client_fd.  That descriptor number
# is reused by the next accept within microseconds, and the stale backend then
# spliced its data into a stranger's socket and took that healthy connection
# down with it on EOF — no error recorded anywhere.  The fix clears the
# back-reference and makes both forwarding paths verify that the pairing is
# mutual, because a descriptor number does not prove identity once numbers are
# reused.
#
# For a second and a half two kinds of connection run against each other: ones
# that connect, exchange tagged messages and verify them, and ones that connect,
# push data and then die by RST with the reply still owed to them.  The second
# kind is what frees a descriptor number, the first kind is what keeps taking
# fresh ones, and the collision between the two is the defect.  Every message is
# tagged '<connection>-<sequence>' with an id unique for the whole run, so a
# line from a connection that closed a second ago is still recognisable as
# foreign rather than merely unexpected, and the report separates missing, out
# of order, foreign and scrambled — "foreign" is the signature that matters, the
# others are ordinary breakage.
#
# HONEST LIMIT — the crossed-delivery half of this is probabilistic, not a
# deterministic check.  The other failure kinds it asserts are not: the same fix
# also stopped the splice pipeline from starting while the ordinary write queue
# still held data for that backend, and stopped teardown from discarding queued
# and in-pipe bytes.  Those showed up in 87% of measured rounds before the fix,
# so a regression of either lands on the 'missing' or 'scrambled' assertion
# almost every run.  It is specifically the stale-descriptor race that needs
# luck.
#
# The bug needs a descriptor to be recycled into a live connection inside the
# window in which the dead peer's backend still owes it data.  One run is at
# most 1500 verifying connections and 18000 messages against several thousand
# RST'd ones, in a little over two seconds; the original diagnosis ran 240000
# messages per path over repeated passes on a quiet machine.  A green run here
# therefore means "not observed", not "cannot happen", and a reintroduced
# regression can survive a fair number of runs before this catches it — treat a
# single pass as weak evidence.  What it buys the suite is a cheap standing
# chance of noticing, and, when it does fire, a message that names the failure
# kind instead of an unexplained hang.  When deliberately hunting this class of
# defect, loop it:
#   for i in $(seq 30); do bash test/integration/test_proxy_concurrent_crosstalk.sh || break; done
# The classifier itself is not probabilistic and was checked against relays that
# deliberately mis-deliver and truncate; it is only the *provocation* that is a
# matter of luck.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")

# Own daemon, socket and state directory: against the shared one this test does
# not discriminate — auto-restart hides a crash, and a leftover runtime from an
# earlier run answers on the port before this test ever creates its own.
TMPDIR_T=$(mktemp -d /tmp/socketley-crosstalk-XXXXXX)
export HOME="$TMPDIR_T/home"
export SOCKETLEY_SOCKET="$TMPDIR_T/daemon.sock"
mkdir -p "$HOME"
DPID=""
BEPID=""

BE_PORT=19430
PX_PORT=19431
PX_NAME=xtalk_px
# Load knobs.  These are the dials to turn if this test ever becomes slow or
# flaky on a loaded machine: LOAD_SECS is almost all of the runtime, and
# CHURNERS is almost all of the pressure on the proxy's accept path.
LOAD_SECS=1.5      # how long the two kinds of connection run against each other
VERIFIERS=8        # threads opening verifying connections back to back
CHURNERS=8         # threads opening connections that die with data still owed
MSGS=12            # tagged messages per verifying connection
MIN_CONNS=30       # below this the run was too thin to have proved anything
OUT="$TMPDIR_T/harness.out"
PASS=0; FAIL=0; TOTAL=0

cleanup() {
    [ -n "$BEPID" ] && kill "$BEPID" 2>/dev/null || true
    [ -n "$DPID" ] && kill "$DPID" 2>/dev/null || true
    rm -rf "$TMPDIR_T"
}
trap cleanup EXIT

echo "=== Integration: no crossed delivery through the proxy under load ==="

# Threaded TCP echo backend.  Whatever a connection sends must come back on that
# same connection and nowhere else — that is the invariant under test, so the
# backend has to be trivially correct about it.
python3 - "$BE_PORT" >"$TMPDIR_T/backend.log" 2>&1 <<'PYEOF' &
import socket, sys, threading

port = int(sys.argv[1])
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(256)


def handle(c):
    c.settimeout(20)
    try:
        while True:
            data = c.recv(65536)
            if not data:
                return
            c.sendall(data)
    except OSError:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


while True:
    try:
        conn, _ = srv.accept()
    except OSError:
        break
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PYEOF
BEPID=$!

"$BIN" daemon >"$TMPDIR_T/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 60); do "$BIN" ps >/dev/null 2>&1 && break; sleep 0.1; done

for _ in $(seq 1 50); do nc -z 127.0.0.1 "$BE_PORT" 2>/dev/null && break; sleep 0.1; done

TOTAL=$((TOTAL+1))
if nc -z 127.0.0.1 "$BE_PORT" 2>/dev/null; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the echo backend never came up on $BE_PORT"
fi

"$BIN" create proxy "$PX_NAME" -p "$PX_PORT" \
    --backend "127.0.0.1:$BE_PORT" --protocol tcp -s 2>&1 || true
for _ in $(seq 1 50); do nc -z 127.0.0.1 "$PX_PORT" 2>/dev/null && break; sleep 0.1; done
sleep 0.3

TOTAL=$((TOTAL+1))
if "$BIN" stats "$PX_NAME" >/dev/null 2>&1; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [setup]: the proxy runtime is not up — everything below is meaningless"
fi

python3 - "$PX_PORT" "$LOAD_SECS" "$VERIFIERS" "$CHURNERS" "$MSGS" >"$OUT" 2>&1 <<'PYEOF' || true
import socket, struct, sys, threading, time

port = int(sys.argv[1])
load_secs = float(sys.argv[2])
n_verify = int(sys.argv[3])
n_churn = int(sys.argv[4])
msgs = int(sys.argv[5])

PAD = "x" * 480          # ~512 bytes per message, enough to be worth splicing
ADDR = ("127.0.0.1", port)
# A ceiling on verifying connections.  They are closed cleanly, so each one
# leaves a TIME_WAIT behind; without a cap a fast machine opens tens of
# thousands in the window and a suite run in a loop walks into ephemeral port
# exhaustion, which would fail this test for a reason that has nothing to do
# with the proxy.  Churn connections are RST-closed and cost nothing here.
MAX_CONNS = 1500

lock = threading.Lock()
results = []
counter = [0]
connfail = [0]


def next_cid():
    with lock:
        counter[0] += 1
        return "c%05d" % counter[0]


def verifier():
    """One connection: send msgs tagged '<cid>-<seq>', then classify everything
    that comes back.  The connection id is unique for the whole run, so a line
    from a connection that closed a moment ago is still recognisable as foreign
    rather than merely unexpected."""
    cid = next_cid()
    r = {"cid": cid, "ok": 0, "missing": msgs, "outoforder": 0,
         "foreign": 0, "corrupt": 0, "reset": 0, "note": "-"}
    try:
        s = socket.create_connection(ADDR, timeout=5)
    except OSError:
        # A connection that was never established says nothing about delivery,
        # and the churn threads are deliberately hammering the accept path.
        # Counted and reported, but not folded into the delivery figures — a
        # proxy that refuses everything still fails, on the connection floor.
        with lock:
            connfail[0] += 1
        return
    s.settimeout(5)
    try:
        for i in range(1, msgs + 1):
            s.sendall(("%s-%04d:%s\n" % (cid, i, PAD)).encode())
    except OSError as e:
        r["note"] = "send:%s" % type(e).__name__

    buf = b""
    lines = []
    try:
        while len(lines) < msgs:
            chunk = s.recv(65536)
            if not chunk:
                # A healthy connection is never closed by the peer here.  This
                # is what the defect looked like from the victim's side.
                r["reset"] = 1
                if r["note"] == "-":
                    r["note"] = "peer-closed"
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                lines.append(line)
    except socket.timeout:
        if r["note"] == "-":
            r["note"] = "timeout"
    except OSError as e:
        r["reset"] = 1
        if r["note"] == "-":
            r["note"] = "recv:%s" % type(e).__name__

    expect = 1
    for line in lines:
        try:
            tag = line.decode("latin1").split(":", 1)[0]
            who, seq = tag.split("-")
            seq = int(seq)
            if len(who) != len(cid):
                raise ValueError("tag length")
        except Exception:
            # Neither ours nor anybody's: the stream itself was scrambled.
            r["corrupt"] += 1
            continue
        if who != cid:
            r["foreign"] += 1
        elif seq != expect:
            r["outoforder"] += 1
            expect = seq + 1
        else:
            r["ok"] += 1
            expect += 1
    if buf:
        # A trailing partial line is a truncated stream, not a delivered message.
        r["corrupt"] += 1
    r["missing"] = max(0, msgs - r["ok"] - r["outoforder"])
    try:
        s.close()
    except OSError:
        pass
    with lock:
        results.append(r)


def churner(deadline):
    """Connections that die with the backend's echo still owed to them.  RST
    rather than a clean close, so the client is gone before the reply lands and
    its descriptor number is immediately available to the next accept."""
    while time.time() < deadline:
        try:
            s = socket.create_connection(ADDR, timeout=2)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                         struct.pack("ii", 1, 0))
            s.sendall(b"z" * 8192)
            s.close()
        except OSError:
            pass


def verify_loop(deadline):
    """Verifying connections are opened back to back for the whole window, not
    once at the start: the descriptor a dying peer left behind has to be handed
    to a connection that is still alive, so new accepts have to keep coming
    while the churn is running."""
    while time.time() < deadline:
        with lock:
            if counter[0] >= MAX_CONNS:
                return
        verifier()


threads = []
deadline = time.time() + load_secs
for _ in range(n_churn):
    threads.append(threading.Thread(target=churner, args=(deadline,), daemon=True))
for _ in range(n_verify):
    threads.append(threading.Thread(target=verify_loop, args=(deadline,), daemon=True))
for t in threads:
    t.start()
for t in threads:
    t.join(20)

expected = len(results) * msgs
agg = {k: 0 for k in ("ok", "missing", "outoforder", "foreign", "corrupt", "reset")}
for r in results:
    for k in agg:
        agg[k] += r[k]

for r in sorted(results, key=lambda x: x["cid"]):
    if r["ok"] != msgs or any(r[k] for k in ("missing", "outoforder", "foreign", "corrupt", "reset")):
        print("CONN %s ok=%d missing=%d outoforder=%d foreign=%d corrupt=%d "
              "reset=%d note=%s" % (r["cid"], r["ok"], r["missing"], r["outoforder"],
                                    r["foreign"], r["corrupt"], r["reset"], r["note"]))

print("TOTALS conns=%d expected=%d ok=%d missing=%d outoforder=%d foreign=%d "
      "corrupt=%d reset=%d connfail=%d" % (len(results), expected, agg["ok"],
                                           agg["missing"], agg["outoforder"],
                                           agg["foreign"], agg["corrupt"],
                                           agg["reset"], connfail[0]))
PYEOF

TOTALS=$(grep '^TOTALS ' "$OUT" 2>/dev/null | head -1 || true)

# Every check below reads its number out of that one line.  If the line is not
# there the number is unset, and an unset number must fail loudly instead of
# comparing equal to an equally unset expectation — that mistake has produced a
# green run against a broken build in this project before.
assert_zero() {
    local field="$1" what="$2" n
    TOTAL=$((TOTAL+1))
    # The trailing '|| true' is load bearing under `set -o pipefail`: without it
    # a missing field aborts the script instead of failing this assertion.
    n=$(printf '%s\n' "$TOTALS" | grep -o "\b$field=[0-9]\+" | cut -d= -f2 | head -1 || true)
    if [ -z "$n" ]; then
        FAIL=$((FAIL+1))
        echo "  FAIL [$what]: no '$field' in the harness result — the harness did not finish"
        return
    fi
    if [ "$n" -eq 0 ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$what]: $n"
    fi
}

TOTAL=$((TOTAL+1))
if [ -n "$TOTALS" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [harness ran]: no TOTALS line; raw output:"
    grep -v '^$' "$OUT" 2>/dev/null | head -5 | sed 's/^/        /' || true
fi

# This is the one that matters.  Missing and misordered data can come from any
# number of ordinary problems; a message carrying somebody else's connection id
# can only mean the proxy wrote it into the wrong socket.
assert_zero foreign     "messages delivered on the wrong connection"
assert_zero corrupt     "scrambled or truncated stream"
assert_zero outoforder  "messages delivered out of order"
assert_zero missing     "messages never delivered"
assert_zero reset       "healthy connections torn down by the proxy"

# A run that only managed a handful of connections has not exercised anything,
# and its zeroes above are worthless.  Assert the load actually happened rather
# than let an empty run report success.
CONNS=$(printf '%s\n' "$TOTALS" | grep -o "\bconns=[0-9]\+" | cut -d= -f2 | head -1 || true)
TOTAL=$((TOTAL+1))
if [ -n "$CONNS" ] && [ "$CONNS" -ge "$MIN_CONNS" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [load actually ran]: only ${CONNS:-<none>} verifying connections, wanted >= $MIN_CONNS"
fi

EXPECTED=$(printf '%s\n' "$TOTALS" | grep -o "\bexpected=[0-9]\+" | cut -d= -f2 | head -1 || true)
GOT_OK=$(printf '%s\n' "$TOTALS" | grep -o "\bok=[0-9]\+" | cut -d= -f2 | head -1 || true)
TOTAL=$((TOTAL+1))
if [ -n "$EXPECTED" ] && [ -n "$GOT_OK" ] && [ "$EXPECTED" -gt 0 ] && [ "$GOT_OK" -eq "$EXPECTED" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [every message came back correctly]: ${GOT_OK:-<none>} of ${EXPECTED:-<none>}"
fi

if [ "$FAIL" -gt 0 ]; then
    echo "  ${TOTALS:-<no TOTALS line>}"
    echo "  Affected connections (first 10):"
    grep '^CONN ' "$OUT" 2>/dev/null | head -10 | sed 's/^/        /' || true
fi

# Churn plus crossed delivery used to be a way to lose the runtime entirely.
TOTAL=$((TOTAL+1))
if "$BIN" stats "$PX_NAME" >/dev/null 2>&1; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [runtime alive]: the proxy did not survive the concurrent load"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
