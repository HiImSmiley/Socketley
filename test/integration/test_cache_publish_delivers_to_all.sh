#!/usr/bin/env bash
# Integration test: every subscriber gets the message, and every subscribe is
# answered, at a fan-out of 3000.
#
# ─── WHAT THIS COVERS NOW, AND WHAT IT USED TO ──────────────────────────────
#
# This file was a three-armed test for a defect that only occurred under SQPOLL.
# get_sqe() recovered from a full submission queue by calling io_uring_submit()
# and retrying once; under IORING_SETUP_SQPOLL that call was a store to the ring
# tail and NOT a syscall, so it freed no slot and the retry could not succeed.
# Each runtime's flush path then read a transient local shortage as a permanent
# per-connection failure: bytes dropped, connection marked `closing`, nobody
# told.  Measured then, 3000 subscribers against a 2048-entry ring:
#
#     delivered  2048 of 3000     (exactly the ring depth)
#     gave up     952             silently -- never retried, never reported
#     registered  2750 and 2996 of 3000, sending every subscribe before reading
#
# With SQPOLL off the same runs delivered 3000 of 3000, which is what the third
# arm existed to say.
#
# SQPOLL is gone from this build, so the provocation cannot be arranged and the
# defect cannot recur.  What is left is the arm that always passed, in both of
# its shapes, because it is not vacuous on its own: 3000 subscribers registered
# and delivered to, once walking the fan-out and once with every subscribe sent
# before any acknowledgement is read.  It no longer guards get_sqe(), and
# nothing in this tree does -- said here rather than left to be inferred from a
# file that still looks like a regression test.
#
# ─── WHY EACH ASSERTION CAN FAIL ────────────────────────────────────────────
#
#   registered == SUBS   — a subscriber that never registered is not in the set
#       publish() walks, so its absence would read as a delivery failure.
#   delivered == SUBS    — one short is one connection that subscribed and was
#       never told the message existed.
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

echo "=== Integration: a publish reaches every one of 3000 subscribers ==="

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

# Redirected to a file and never captured with $( ).  A command substitution
# runs the function in a SUBSHELL, so every variable daemon_isolate and
# daemon_start export -- SOCKETLEY_DPID above all -- dies with it, and the
# cleanup trap in this shell then finds nothing to stop: two daemons and two
# workers left running per invocation, holding their ports.
run_arm() {   # run_arm LABEL PORT MODE
    local label=$1 port=$2 mode=$3
    if [ -n "${SOCKETLEY_DPID:-}" ]; then
        "$BIN" stop "$NAME" 2>/dev/null || true
        "$BIN" remove "$NAME" 2>/dev/null || true
        daemon_stop 2>/dev/null || true
    fi
    daemon_isolate "cachepubdeliver-$label"
    daemon_start "$BIN"
    create_ok "cache created ($label)" "$BIN" create cache "$NAME" -p "$port" -s
    ready_resp 127.0.0.1 "$port" 20 || true
    timeout 300 python3 "$TMPD/subs.py" "$port" "$SUBS" "$mode" 2>&1 || true
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

# ── The fan-out: publish() walks every subscriber ───────────────────────────
run_arm fanout "$PORT_FANOUT" serial > "$TMPD/arm1.out" 2>&1
OUT=$(cat "$TMPD/arm1.out")
R=$(field registered "$OUT");    R=${R:-0}
D=$(field delivered "$OUT");     D=${D:-0}
S=$(field silent "$OUT");        S=${S:-0}
echo "  fanout arm: registered=$R delivered=$D silent=$S"

check "every subscriber registers (fanout)" "$R" "$SUBS" \
      "A subscriber that never registered is not in the set publish() walks."
check "every subscriber is delivered to" "$D" "$SUBS" \
      "publish() gave up on $S of them without retrying and without telling anyone."

# ── The reply path: every subscribe sent before any ack is read ─────────────
run_arm reply "$PORT_REPLY" batch > "$TMPD/arm2.out" 2>&1
OUT=$(cat "$TMPD/arm2.out")
R2=$(field registered "$OUT");    R2=${R2:-0}
D2=$(field delivered "$OUT");     D2=${D2:-0}
echo "  reply arm:  registered=$R2 delivered=$D2"

check "every subscribe is answered" "$R2" "$SUBS" \
      "A client that asked to subscribe got silence and is not subscribed."
check "every subscriber is delivered to (reply arm)" "$D2" "$SUBS" ""

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
