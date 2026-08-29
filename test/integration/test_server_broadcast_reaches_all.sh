#!/usr/bin/env bash
# Integration test: a master's broadcast reaches every one of 3000 clients.
#
# ─── WHAT THIS COVERS NOW, AND WHAT IT USED TO ──────────────────────────────
#
# This file was a two-armed test for a defect that only occurred under SQPOLL:
# io_uring_submit() was a store to the ring tail rather than a syscall, so
# broadcast() could submit more operations in one non-yielding pass than the
# ring held, mark the remainder `closing` and move on.  Measured then, 3000
# clients against a 2048-entry ring: 2048 delivered, 952 never told the message
# existed.  With SQPOLL off the same run delivered 3000 of 3000, which is why
# the second arm existed.
#
# SQPOLL is gone from this build, so the provocation cannot be arranged and the
# defect cannot recur.  What is left is the arm that always passed, kept because
# it is not vacuous on its own: a fan-out to 3000 connected clients, from an
# authenticated master, delivered to all of them.  It no longer guards
# get_sqe(), and nothing in this tree does -- said here rather than left to be
# inferred from a file that looks like a regression test.
#
# ─── WHY EACH ASSERTION CAN FAIL ────────────────────────────────────────────
#
#   every client connects — a client that never connected is not in the set
#       broadcast() walks, so its absence would read as a delivery failure.
#   master: ok            — a broadcast that was never authorised reaches nobody
#       for a reason that has nothing to do with the fan-out.
#   got == CLIENTS        — one client short is one connection told nothing.
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

echo "=== Integration: a broadcast reaches every one of 3000 clients ==="

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

# Redirected to a file, never captured with $( ): a command substitution runs the
# function in a subshell, and SOCKETLEY_DPID set inside one never reaches the
# cleanup trap — two daemons left holding their ports per invocation.
run_arm() {   # run_arm LABEL PORT
    local label=$1 port=$2
    daemon_isolate "srvbcast-$label"
    daemon_start "$BIN"
    create_ok "server created ($label)" "$BIN" create server "$NAME" -p "$port" \
        --mode master --master-pw "$PW" -s
    ready_tcp 127.0.0.1 "$port" 20 || true
    timeout 300 python3 "$TMPD/bcast.py" "$port" "$CLIENTS" "$PW" 2>&1 || true
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

# ── The fan-out ─────────────────────────────────────────────────────────────
run_arm bcast "$PORT_BCAST" > "$TMPD/arm1.out" 2>&1
OUT=$(cat "$TMPD/arm1.out")
C=$(field connected "$OUT");     C=${C:-0}
A=$(field master_ack "$OUT");    A=${A:-none}
G=$(field got "$OUT");           G=${G:-0}
S=$(field silent "$OUT");        S=${S:-0}
echo "  broadcast: connected=$C ack='$A' got=$G silent=$S"

check "every client connects" "$C" "$CLIENTS" \
      "A client that never connected is not in the set broadcast() walks."
check "the master authenticated" "$A" "master: ok" \
      "An unauthorised sender's line is dropped, not broadcast."
check "every client gets the broadcast" "$G" "$CLIENTS" \
      "$S of them were marked closing and never told the message existed."

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
