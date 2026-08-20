#!/usr/bin/env bash
# Integration test: a master's broadcast reaches every client, even when there
# are more of them than the submission queue is deep.
#
# ─── WHY THIS EXISTS SEPARATELY FROM THE CACHE TEST ─────────────────────────
#
# test_cache_publish_delivers_to_all.sh covers the same defect in
# cache_instance::publish().  This is the second runtime that has it, and it was
# found by asking the question that file's fix raised rather than by a report:
# get_sqe() is in shared/, so any path that submits more operations in one
# non-yielding pass than the ring holds has it.  There are two such paths in the
# tree — publish() and server_instance::broadcast() — and they lose exactly the
# same way.
#
# Measured on this tree, SQPOLL on, 3000 connected clients, a 2048-entry ring,
# one broadcast from an authenticated master:
#
#     before   got 2048 of 3000   (exactly the ring depth), 952 never told
#     after    got 3000 of 3000
#     SQPOLL off, before          3000 of 3000
#
# The 952 are not disconnected and not told: broadcast() marks them `closing`
# and moves on, so the client sits on a connection it believes is fine and never
# learns the message existed.
#
# ─── WHY EACH ASSERTION CAN FAIL ────────────────────────────────────────────
#
#   sqpoll thread present — without SQPOLL, io_uring_submit() is a real syscall
#       that drains the queue, so nothing is ever dropped and every count below
#       is trivially correct.  An arm that quietly loses SQPOLL therefore LOOKS
#       like a fix.  Checked positively: the kernel poller is a thread named
#       iou-sqp-<pid> in the process that owns the ring.
#   the ring ran out      — after the fix nothing is dropped, so no client-side
#       count can say the mechanism was exercised.  The loop logs the first time
#       it has to wait for the poller; without that line "got == CLIENTS" is
#       also true of a run that never filled the queue.
#   master: ok            — a broadcast that was never authorised reaches nobody
#       for a reason that has nothing to do with this defect.
#   got == CLIENTS        — fails at 2048 of 3000 on the unfixed tree.
#   control               — SQPOLL off; what says the harness can tell a
#       delivered broadcast from an undelivered one.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_ready.sh"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"

# One port per arm.  A daemon that has not finished going away still holds its
# listener, and SO_REUSEPORT then splits the next arm's clients between the two
# servers — which reads as "the broadcast reached half of them".
PORT_BCAST=$((SL_PORT_BASE+347))
PORT_PLAIN=$((SL_PORT_BASE+348))
NAME=bcastsrv
PW=s3cret
CLIENTS="${CLIENTS:-3000}"
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

echo "=== Integration: a broadcast wider than the submission queue still reaches everyone ==="

if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 is required"
    exit 0
fi
if [ "$(ulimit -n)" -lt $((CLIENTS * 2 + 256)) ]; then
    echo "  SKIP: ulimit -n $(ulimit -n) is too low for $CLIENTS clients"
    exit 0
fi

cat > "$TMPD/bcast.py" <<'PY'
import selectors, socket, sys, time

port, count = int(sys.argv[1]), int(sys.argv[2])
pw = sys.argv[3]

socks = []
for _ in range(count):
    s = socket.socket()
    try:
        s.connect(("127.0.0.1", port))
    except OSError:
        continue
    s.setblocking(False)
    socks.append(s)
print("connected=%d" % len(socks))
time.sleep(2)

# The master is the LAST connection, so every client above it is already in
# m_active_fds when the broadcast walks it.
m = socket.socket()
m.connect(("127.0.0.1", port))
m.sendall(("master %s\n" % pw).encode())
m.settimeout(15.0)
try:
    ack = m.recv(256)
except OSError:
    ack = b""
print("master_ack=%s" % ack.decode(errors="replace").strip())
time.sleep(1)

m.sendall(b"HELLO-EVERYONE\n")
time.sleep(8)

sel = selectors.DefaultSelector()
st = {}
for i, s in enumerate(socks):
    st[i] = "silent"
    try:
        sel.register(s, selectors.EVENT_READ, i)
    except Exception:
        st[i] = "closed"
end = time.time() + 12
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
        elif b"HELLO-EVERYONE" in chunk:
            st[i] = "got"
        else:
            continue
        sel.unregister(key.fileobj)
        outstanding -= 1
sel.close()

print("got=%d"    % sum(1 for v in st.values() if v == "got"))
print("closed=%d" % sum(1 for v in st.values() if v == "closed"))
print("silent=%d" % sum(1 for v in st.values() if v == "silent"))
for s in socks + [m]:
    try:
        s.close()
    except OSError:
        pass
PY

# pgrep -x, never -f: -f matches the whole command line and so matches the shell
# doing the matching.  Counted only across the processes of THIS daemon.
count_sqpoll_threads() {
    local n=0 p
    for p in $(pgrep -x "$(basename "$BIN")" 2>/dev/null); do
        grep -qs -- "$SOCKETLEY_SOCKET" "/proc/$p/environ" 2>/dev/null || continue
        n=$((n + $(grep -l "^iou-sqp" /proc/"$p"/task/*/comm 2>/dev/null | wc -l)))
    done
    printf '%s\n' "$n"
}

# Redirected to a file, never captured with $( ): a command substitution runs the
# function in a subshell, and SOCKETLEY_DPID set inside one never reaches the
# cleanup trap — two daemons left holding their ports per invocation.
run_arm() {   # run_arm SQPOLL_VALUE LABEL PORT
    local sqp=$1 label=$2 port=$3
    if [ -n "${SOCKETLEY_DPID:-}" ]; then
        "$BIN" stop "$NAME" 2>/dev/null || true
        "$BIN" remove "$NAME" 2>/dev/null || true
        daemon_stop 2>/dev/null || true
    fi
    daemon_isolate "srvbcast-$label"
    SOCKETLEY_SQPOLL="$sqp" daemon_start "$BIN"
    create_ok "server created ($label)" "$BIN" create server "$NAME" -p "$port" \
        --mode master --master-pw "$PW" -s
    ready_tcp 127.0.0.1 "$port" 20 || true
    echo "sqpollthreads=$(count_sqpoll_threads)"
    timeout 300 python3 "$TMPD/bcast.py" "$port" "$CLIENTS" "$PW" 2>&1 || true
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
        # test's own status, and under `set -e` an empty explanation would then
        # kill the script before the remaining arms had run.
        if [ -n "${4:-}" ]; then
            echo "         $4"
        fi
    fi
    return 0
}

# ── Arm 1: SQPOLL on.  The broadcast is wider than the ring ──────────────────
run_arm 1 bcast "$PORT_BCAST" > "$TMPD/arm1.out" 2>&1
OUT=$(cat "$TMPD/arm1.out")
T=$(field sqpollthreads "$OUT"); T=${T:-0}
C=$(field connected "$OUT");     C=${C:-0}
A=$(field master_ack "$OUT");    A=${A:-none}
G=$(field got "$OUT");           G=${G:-0}
S=$(field silent "$OUT");        S=${S:-0}
F=$(field sqfull "$OUT");        F=${F:-0}
echo "  broadcast arm: sqpoll_threads=$T connected=$C ack='$A' got=$G silent=$S sqfull_lines=$F"

TOTAL=$((TOTAL+1))
if [ "$T" -gt 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [the arm actually has a submission poller]: 0 iou-sqp threads."
    echo "         Nothing below this line means anything: without SQPOLL the"
    echo "         queue never runs out and every count below is trivially right."
fi

check "every client connects" "$C" "$CLIENTS" \
      "A client that never connected is not in the set broadcast() walks."
check "the master authenticated" "$A" "master: ok" \
      "An unauthorised sender's line is dropped, not broadcast."

TOTAL=$((TOTAL+1))
if [ "$F" -gt 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [the submission queue actually ran out]: the loop never logged a"
    echo "         full queue, so this run did not exercise the mechanism and the"
    echo "         count below proves nothing.  Raise CLIENTS above the ring depth."
fi

check "every client gets the broadcast" "$G" "$CLIENTS" \
      "$S of them were marked closing and never told the message existed."

# ── Control: SQPOLL off ──────────────────────────────────────────────────────
run_arm 0 plain "$PORT_PLAIN" > "$TMPD/arm2.out" 2>&1
OUT=$(cat "$TMPD/arm2.out")
T2=$(field sqpollthreads "$OUT"); T2=${T2:-0}
G2=$(field got "$OUT");           G2=${G2:-0}
echo "  control arm: sqpoll_threads=$T2 got=$G2 of $CLIENTS"

TOTAL=$((TOTAL+1))
if [ "$T2" -eq 0 ]; then
    PASS=$((PASS+1))
else
    FAIL=$((FAIL+1))
    echo "  FAIL [the control has no submission poller]: $T2 iou-sqp threads with"
    echo "         SOCKETLEY_SQPOLL=0.  The control is then a second provocation."
fi

check "control: every client gets the broadcast without SQPOLL" "$G2" "$CLIENTS" ""

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
