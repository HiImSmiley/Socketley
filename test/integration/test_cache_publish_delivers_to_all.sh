#!/usr/bin/env bash
# Integration test: every subscriber gets the message, and every subscribe is
# answered — even when the fan-out is wider than the submission queue is deep.
#
# ─── WHAT THIS GUARDS ───────────────────────────────────────────────────────
#
# This is the delivery half of the pair.  Its sibling,
# test_cache_publish_subscriber_reachable.sh, asserts that a subscriber
# publish() gave up on can still be REACHED — that its armed read still has
# something that can complete it.  That property held while the message it was
# supposed to receive was thrown away, and the two are genuinely different
# claims: a connection can be perfectly healthy and still never be told the
# thing it subscribed for.
#
# The mechanism is one line in shared/event_loop.cpp.  get_sqe() recovered from
# a full submission queue by calling io_uring_submit() and retrying once; under
# IORING_SETUP_SQPOLL that call is a store to the ring tail and NOT a syscall,
# so it frees no slot and the retry cannot succeed.  Every submit_* helper then
# reported "this never reached the ring", and each runtime's flush path read
# that transient local shortage as a permanent per-connection failure: the bytes
# were dropped, the connection was marked `closing`, and nobody was told.
#
# Measured on this tree before the fix, SQPOLL on, 3000 subscribers, a 2048-entry
# ring, one publish:
#
#     delivered  2048 of 3000     (exactly the ring depth)
#     gave up     952             silently — never retried, never reported
#
# and, sending every subscribe before reading any acknowledgement, so the queue
# runs out on the REPLY path instead:
#
#     registered  2750 of 3000 and 2996 of 3000 on two runs
#
# A client that asked to subscribe got silence and was not subscribed.
#
# ─── WHY EACH ASSERTION CAN FAIL ────────────────────────────────────────────
#
#   sqpoll thread present  — the whole provocation rests on SQPOLL.  Without it
#       get_sqe() recovers by submitting and nothing is ever dropped: measured
#       3000 of 3000 in both modes with SOCKETLEY_SQPOLL=0.  An arm that
#       quietly loses SQPOLL therefore LOOKS like a fix, so it is checked
#       positively — the kernel poller is a thread named iou-sqp-<pid> inside
#       the process that owns the ring, and it is either there or it is not.
#   the ring ran out       — after the fix nothing is dropped, so no client-side
#       count can say whether the mechanism was exercised at all.  The loop logs
#       the first time it has to wait for the poller; that line is the proof
#       this run provoked the thing it claims to test.  Without it, delivered ==
#       SUBS is true of a run that never filled the queue.
#   delivered == SUBS      — fails at 2048 of 3000 on the unfixed tree.
#   registered == SUBS     — fails at 2750-2996 of 3000 on the unfixed tree,
#       on the reply path rather than the publish path.
#   control delivered      — SQPOLL off.  Not a second provocation: it is what
#       says the harness can tell a delivered message from an undelivered one.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

# One port per arm, never one shared between them.  A daemon that has not
# finished going away still holds its listener, and SO_REUSEPORT then splits the
# next arm's subscribers between the two caches — which reads as "publish
# reached half of them" and is not this mechanism at all.
PORT_FANOUT=$((SL_PORT_BASE+344))
PORT_REPLY=$((SL_PORT_BASE+345))
PORT_PLAIN=$((SL_PORT_BASE+346))
NAME=pubdelivercache
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

echo "=== Integration: a publish wider than the submission queue still reaches everyone ==="

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

port  = int(sys.argv[1])
count = int(sys.argv[2])
mode  = sys.argv[3]           # "serial" | "batch"

subs = []
registered = 0

if mode == "serial":
    # One at a time, each acknowledgement read before the next subscribe is
    # sent.  At most one reply is ever in flight, so the submission queue can
    # only run out on the publish below -- which is the fan-out arm's subject.
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
else:
    # Every subscribe sent before any acknowledgement is read, so the queue runs
    # out on the REPLY path.  This is the arm where a client that asked to
    # subscribe got silence and was not subscribed.
    for _ in range(count):
        s = socket.socket()
        s.connect(("127.0.0.1", port))
        s.sendall(b"subscribe ch\n")
        s.setblocking(False)
        subs.append(s)
    sel = selectors.DefaultSelector()
    seen = {}
    for i, s in enumerate(subs):
        seen[i] = b""
        sel.register(s, selectors.EVENT_READ, i)
    end = time.time() + 30
    outstanding = len(subs)
    while outstanding and time.time() < end:
        for key, _ in sel.select(timeout=0.5):
            i = key.data
            try:
                chunk = key.fileobj.recv(65536)
            except OSError:
                chunk = b""
            if not chunk:
                sel.unregister(key.fileobj); outstanding -= 1; continue
            seen[i] += chunk
            if b"ok\n" in seen[i]:
                registered += 1
                sel.unregister(key.fileobj); outstanding -= 1
    sel.close()

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
    sel.close()
    return st


st = census(subs, 10)
print("delivered=%d" % sum(1 for v in st.values() if v == "delivered"))
print("closed=%d"    % sum(1 for v in st.values() if v == "closed"))
print("silent=%d"    % sum(1 for v in st.values() if v == "silent"))
for s in subs:
    try:
        s.close()
    except OSError:
        pass
PY

# SQPOLL, checked positively rather than assumed.  The kernel poller is a thread
# named iou-sqp-<pid> in the process that owns the ring; this counts them across
# the processes belonging to THIS daemon only.  pgrep -x, never -f: -f matches
# the whole command line and so matches the shell doing the matching.
count_sqpoll_threads() {
    local n=0 p
    for p in $(pgrep -x socketley 2>/dev/null); do
        grep -qs -- "$SOCKETLEY_SOCKET" "/proc/$p/environ" 2>/dev/null || continue
        n=$((n + $(grep -l "^iou-sqp" /proc/"$p"/task/*/comm 2>/dev/null | wc -l)))
    done
    printf '%s\n' "$n"
}

# Redirected to a file and never captured with $( ).  A command substitution
# runs the function in a SUBSHELL, so every variable daemon_isolate and
# daemon_start export -- SOCKETLEY_DPID above all -- dies with it, and the
# cleanup trap in this shell then finds nothing to stop: two daemons and two
# workers left running per invocation, holding their ports.
run_arm() {   # run_arm SQPOLL_VALUE LABEL PORT MODE
    local sqp=$1 label=$2 port=$3 mode=$4
    if [ -n "${SOCKETLEY_DPID:-}" ]; then
        "$BIN" stop "$NAME" 2>/dev/null || true
        "$BIN" remove "$NAME" 2>/dev/null || true
        daemon_stop 2>/dev/null || true
    fi
    daemon_isolate "cachepubdeliver-$label"
    SOCKETLEY_SQPOLL="$sqp" daemon_start "$BIN"
    create_ok "cache created ($label)" "$BIN" create cache "$NAME" -p "$port" -s
    ready_resp 127.0.0.1 "$port" 20 || true
    echo "sqpollthreads=$(count_sqpoll_threads)"
    timeout 300 python3 "$TMPD/subs.py" "$port" "$SUBS" "$mode" 2>&1 || true
    # The loop says once, per ring, that it had to wait for the poller.  That is
    # the only outside evidence the submission queue actually ran out.
    local nfull
    nfull=$(grep -c 'submission queue was full' "$SOCKETLEY_DLOG" 2>/dev/null) || nfull=0
    echo "sqfull=$nfull"
}

field() { printf '%s\n' "$2" | sed -n "s/^$1=//p"; }

check() {   # check LABEL GOT WANT EXPLANATION
    TOTAL=$((TOTAL+1))
    if [ "$2" = "$3" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        echo "  FAIL [$1]: got $2, expected $3"
        # `[ -n x ] && echo` as the last statement of a function returns the
        # test's own status, and under `set -e` an empty explanation then kills
        # the script before the remaining arms have run.
        if [ -n "${4:-}" ]; then
            echo "         $4"
        fi
    fi
    return 0
}

# ── Arm 1: the fan-out.  The queue runs out while publish() walks subscribers ──
run_arm 1 fanout "$PORT_FANOUT" serial > "$TMPD/arm1.out" 2>&1
OUT=$(cat "$TMPD/arm1.out")
T=$(field sqpollthreads "$OUT"); T=${T:-0}
R=$(field registered "$OUT");    R=${R:-0}
D=$(field delivered "$OUT");     D=${D:-0}
S=$(field silent "$OUT");        S=${S:-0}
F=$(field sqfull "$OUT");        F=${F:-0}
echo "  fanout arm: sqpoll_threads=$T registered=$R delivered=$D silent=$S sqfull_lines=$F"

TOTAL=$((TOTAL+1))
if [ "$T" -gt 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [the SQPOLL arm actually has a submission poller]: 0 iou-sqp threads."
    echo "         Nothing below this line means anything: without SQPOLL the queue"
    echo "         never runs out and every count below is trivially correct."
fi

check "every subscriber registers (fanout)" "$R" "$SUBS" \
      "A subscriber that never registered is not in the set publish() walks."

TOTAL=$((TOTAL+1))
if [ "$F" -gt 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [the submission queue actually ran out]: the loop never logged a"
    echo "         full queue, so this run did not exercise the mechanism and the"
    echo "         delivery count below proves nothing.  Raise SUBS above the ring"
    echo "         depth, or the ring grew."
fi

check "every subscriber is delivered to" "$D" "$SUBS" \
      "publish() gave up on $S of them without retrying and without telling anyone."

# ── Arm 2: the reply path.  The queue runs out on the subscribe acks ──────────
run_arm 1 reply "$PORT_REPLY" batch > "$TMPD/arm2.out" 2>&1
OUT=$(cat "$TMPD/arm2.out")
T2=$(field sqpollthreads "$OUT"); T2=${T2:-0}
R2=$(field registered "$OUT");    R2=${R2:-0}
D2=$(field delivered "$OUT");     D2=${D2:-0}
echo "  reply arm:  sqpoll_threads=$T2 registered=$R2 delivered=$D2"

TOTAL=$((TOTAL+1))
if [ "$T2" -gt 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [the reply arm actually has a submission poller]: 0 iou-sqp threads."
fi

check "every subscribe is answered" "$R2" "$SUBS" \
      "A client that asked to subscribe got silence and is not subscribed."
check "every subscriber is delivered to (reply arm)" "$D2" "$SUBS" ""

# ── Control: SQPOLL off ──────────────────────────────────────────────────────
# Not a third provocation.  Without SQPOLL get_sqe() recovers by submitting, so
# nothing is ever dropped; a run where this arm loses subscribers is measuring
# something other than what the two arms above measure.
run_arm 0 plain "$PORT_PLAIN" serial > "$TMPD/arm3.out" 2>&1
OUT=$(cat "$TMPD/arm3.out")
T3=$(field sqpollthreads "$OUT"); T3=${T3:-0}
R3=$(field registered "$OUT");    R3=${R3:-0}
D3=$(field delivered "$OUT");     D3=${D3:-0}
echo "  control arm: sqpoll_threads=$T3 registered=$R3 delivered=$D3 of $SUBS"

TOTAL=$((TOTAL+1))
if [ "$T3" -eq 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [the control has no submission poller]: $T3 iou-sqp threads with"
    echo "         SOCKETLEY_SQPOLL=0.  The control is then a second provocation."
fi

check "control: every subscriber is served without SQPOLL" "$D3" "$SUBS" ""

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
