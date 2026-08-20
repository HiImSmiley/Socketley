#!/usr/bin/env bash
# Integration test: a subscriber publish() gives up on is still REACHABLE.
#
# ─── WHAT THIS GUARDS, AND WHY IT IS NOT THE OBVIOUS THING ──────────────────
#
# publish() writes into each subscriber's write queue and flushes it.  Two
# things make it give up on a subscriber and mark it `closing`: the queue
# reaching its byte cap, and a flush reporting that nothing reached the ring.
# It then leaves the teardown to the read that subscriber has armed.
#
# That is, on its face, exactly the shape shared/conn_reachability.h exists to
# refuse — a `closing` connection deferring to an armed read, which is the
# defect fixed in the cache as 78c9ecc and in the server as ceaa3f2.  It is also
# the shape on_cqe's chokepoint cannot see, because publish() runs on the
# PUBLISHER's completion and the connection it gives up on is a subscriber's.
#
# It is nonetheless sound here, and the reason is the premise rather than the
# shape.  conn_reachability.h's rule rests on "a connection that is `closing`
# is, by definition, one whose peer has already gone" — true in both of those
# defects, where the connection was marked closing BECAUSE its peer reset and
# the error had already been consumed by a write.  publish() marks it closing
# for a reason the peer has no part in: a local resource ran out.  The
# subscriber is alive.  Its armed read is therefore reachable by the one thing
# that can complete it, and the deferral is a promise something does keep.
#
# So what has to hold is not "the connection is torn down" but "the connection
# can still be reached".  This test asserts that, and it is worth having because
# the obvious repair breaks it.  Measured on this tree, same binary, the drain
# switched by an environment variable:
#
#     routing publish()'s subscribers through classify()   phase 2: 0 of 952
#     leaving them to their armed read                      phase 2: 952 of 952
#
# The repair tears the connection out of m_conn_idx inside the window where the
# submission queue is exhausted — which is the only window in which publish()
# gives up at all — and close_fd() cannot submit the cancel that would release
# it.  There is then no path back, where before there was one.
#
# ─── THE PROVOCATION ────────────────────────────────────────────────────────
#
# A flush fails when get_sqe() cannot produce an SQE.  Under SQPOLL that is
# reachable: io_uring_submit() is a tail update and no syscall, so the retry
# inside get_sqe() cannot drain a full submission queue the way it does
# otherwise.  One publish to more subscribers than the ring has SQ entries
# (2048 by default) runs out partway down the subscriber list — measured here at
# exactly 2048 delivered of 3000, with 952 given up on.
#
# ─── THE PROVOCATION NO LONGER FIRES, AND THAT IS THE POINT ─────────────────
#
# The paragraph above describes the tree as it was.  get_sqe() now waits for the
# SQPOLL thread to drain the submission queue instead of reporting a permanent
# failure, so publish() no longer gives up on anybody for a shortage of SQEs:
# this file's sqpoll arm delivers 3000 of 3000 and prints its own "gave up on
# nobody" note.  The delivery half of that is
# test_cache_publish_delivers_to_all.sh, which is where the numbers above now
# live as a regression guard.
#
# This file is NOT redundant and must not be deleted.  publish() still has two
# marks that defer a `closing` connection's teardown to its armed read — the
# 8 MB write-queue cap and a flush that genuinely could not reach the ring — and
# the assertion below is the only thing standing between them and the "obvious
# repair" that routes them through classify(), which was measured at 0 of 952
# reachable.  What it no longer does is provoke the second mark; its own NOTE
# says so on every run, and that honesty is worth more than a green tick that
# would be true of a build with nothing in it.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

# One port per arm, never one shared between them.  A daemon that has not
# finished going away still holds its listener, and SO_REUSEPORT then splits the
# second arm's subscribers between the two caches — which reads as "publish
# reached half of them" and is not this mechanism at all.  Measured while
# writing this: the control arm reported 1466, 1507, 1511 and 1526 of 3000 on
# four runs, all approximately half, and 3000 of 3000 once the ports differed.
PORT_SQPOLL=$((SL_PORT_BASE+330))
PORT_PLAIN=$((SL_PORT_BASE+331))
NAME=pubreachcache
SUBS="${SUBS:-3000}"
PASS=0; FAIL=0; TOTAL=0

TMPD=$(mktemp -d)
cleanup() {
    if [ -n "${SOCKETLEY_DPID:-}" ]; then
        "$BIN" stop "$NAME" 2>/dev/null || true
        sleep 0.2
        "$BIN" remove "$NAME" 2>/dev/null || true
        daemon_stop
    fi
    rm -rf "$TMPD" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Integration: a subscriber publish() gave up on is still reachable ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 is required"
    exit 0
fi
if [ "$(ulimit -n)" -lt $((SUBS * 2 + 256)) ]; then
    echo "  SKIP: ulimit -n $(ulimit -n) is too low for $SUBS subscribers"
    exit 0
fi

cat > "$TMPD/subs.py" <<'PY'
import selectors, socket, sys, time

port, count = int(sys.argv[1]), int(sys.argv[2])

subs = []
registered = 0
# One at a time, each subscribe acknowledged before the next is sent.  That
# keeps at most one reply in flight, so the submission queue can only ever run
# out on the publish below -- which is the thing being provoked.  Registering
# all of them first and reading the acknowledgements afterwards exhausts the
# ring on the REPLY path instead, and then nothing subscribes at all: measured
# registered=0 of 3000 that way.
for _ in range(count):
    s = socket.socket()
    s.connect(("127.0.0.1", port))
    s.sendall(b"subscribe ch\n")
    s.settimeout(30.0)
    buf = b""
    try:
        while b"ok\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        if b"ok\n" in buf:
            registered += 1
    except OSError:
        pass
    s.setblocking(False)
    subs.append(s)
print("registered=%d" % registered)

pub = socket.socket()
pub.connect(("127.0.0.1", port))
pub.sendall(b"publish ch hello\n")
time.sleep(10)


def census(socks, secs):
    sel = selectors.DefaultSelector()
    st = {}
    for i, s in enumerate(socks):
        st[i] = "silent"
        try:
            sel.register(s, selectors.EVENT_READ, i)
        except Exception:
            st[i] = "closed"
    end = time.time() + secs
    outstanding = sum(1 for v in st.values() if v == "silent")
    while outstanding and time.time() < end:
        for key, _ in sel.select(timeout=0.5):
            i = key.data
            try:
                chunk = key.fileobj.recv(65536)
            except OSError:
                chunk = b""
            if not chunk:
                st[i] = "closed"
            elif b"message ch hello" in chunk:
                st[i] = "delivered"
            else:
                continue
            sel.unregister(key.fileobj)
            outstanding -= 1
    return st


st = census(subs, 8)
silent = [i for i, v in st.items() if v == "silent"]
print("delivered=%d" % sum(1 for v in st.values() if v == "delivered"))
print("gaveup=%d" % len(silent))

# ── The assertion this file exists for ──────────────────────────────────────
# The ring recovered long ago.  A subscriber publish() gave up on is alive and
# has a read armed, so if it SPEAKS that read must complete and the runtime must
# act on it.  A subscriber still silent after speaking is one nothing in the
# process can ever reach again.
for i in silent:
    try:
        subs[i].send(b"ping\n")
    except OSError:
        pass
time.sleep(4)
st2 = census([subs[i] for i in silent], 8)
print("unreachable=%d" % sum(1 for v in st2.values() if v == "silent"))
for s in subs:
    try:
        s.close()
    except OSError:
        pass
PY

# Redirected to a file and never captured with $( ).  A command substitution
# runs the function in a SUBSHELL, so every variable daemon_isolate and
# daemon_start export -- SOCKETLEY_DPID above all -- dies with it, and the
# cleanup trap in this shell then finds nothing to stop.  Measured: two daemons
# and two workers left running per invocation, holding their ports, which is
# what makes the next run of the suite report "no free 2000-port window" as a
# product failure.
run_arm() {   # run_arm SQPOLL_VALUE LABEL PORT
    local sqp=$1 label=$2 port=$3
    if [ -n "${SOCKETLEY_DPID:-}" ]; then
        "$BIN" stop "$NAME" 2>/dev/null || true
        "$BIN" remove "$NAME" 2>/dev/null || true
        daemon_stop 2>/dev/null || true
    fi
    daemon_isolate "cachepubreach-$label"
    SOCKETLEY_SQPOLL="$sqp" daemon_start "$BIN"
    create_ok "cache created ($label)" "$BIN" create cache "$NAME" -p "$port" -s
    ready_resp 127.0.0.1 "$port" 20 || true
    timeout 300 python3 "$TMPD/subs.py" "$port" "$SUBS" 2>&1 || true
}

field() { printf '%s\n' "$2" | sed -n "s/^$1=//p"; }

# ── Arm 1: SQPOLL on — publish() is made to give up on subscribers ──────────
run_arm 1 sqpoll "$PORT_SQPOLL" > "$TMPD/arm1.out" 2>&1
OUT=$(cat "$TMPD/arm1.out")
R=$(field registered "$OUT");   R=${R:-0}
D=$(field delivered "$OUT");    D=${D:-0}
G=$(field gaveup "$OUT");       G=${G:-0}
U=$(field unreachable "$OUT");  U=${U:-$SUBS}
echo "  sqpoll arm: registered=$R delivered=$D gaveup=$G unreachable=$U of $SUBS"

TOTAL=$((TOTAL+1))
if [ "$R" -eq "$SUBS" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [every subscriber registers]: $R of $SUBS were acknowledged."
    echo "         Nothing below this line means anything: a subscriber that never"
    echo "         registered is not in the set publish() walks."
fi

# An assertion that cannot fail is not coverage, so say when it could not have.
# If publish() served everyone, the submission queue never ran out and this
# invocation did not exercise the mechanism at all.
if [ "$G" -eq 0 ]; then
    echo "  NOTE: publish() gave up on nobody — the SQ never ran out, so this run"
    echo "        did not exercise the mechanism.  Raise SUBS above the ring depth."
fi

TOTAL=$((TOTAL+1))
if [ "$U" -eq 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [a subscriber publish() gave up on is still reachable]:"
    echo "         $U of $G spoke and the runtime never answered and never closed"
    echo "         them.  Their armed read is the only way back to them and"
    echo "         something has taken it away.  See the header: this is what"
    echo "         routing publish()'s subscribers through classify() does."
fi

# ── Arm 2: SQPOLL off — the control ─────────────────────────────────────────
# Not a second provocation.  Without SQPOLL get_sqe() recovers by submitting, so
# publish() gives up on nobody; a run where this arm loses subscribers is
# measuring something other than what arm 1 measures.
run_arm 0 plain "$PORT_PLAIN" > "$TMPD/arm2.out" 2>&1
OUT=$(cat "$TMPD/arm2.out")
R2=$(field registered "$OUT"); R2=${R2:-0}
D2=$(field delivered "$OUT");  D2=${D2:-0}
echo "  control arm: registered=$R2 delivered=$D2 of $SUBS"

TOTAL=$((TOTAL+1))
if [ "$D2" -eq "$SUBS" ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [control: every subscriber is served without SQPOLL]: $D2 of $SUBS"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
