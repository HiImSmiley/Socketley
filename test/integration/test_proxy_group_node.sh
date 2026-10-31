#!/usr/bin/env bash
# suite: host -- like test_cluster, a group's remote member is not reached over TCP inside a network namespace, not yet understood
# Integration test: a proxy naming a group takes each local member's node.
#
# ─── WHAT THIS EXISTS TO CATCH ─────────────────────────────────────────────
#
# `--backend s` took the node beside s's port and `--backend @g` with s as its
# member went over loopback TCP, because the group entry was published without
# the path: the addressing form alone chose the transport, 17.93 us against
# 9.83.  An answer is the same over either, so what is asserted here is the
# sockets themselves, sampled while requests are held open -- AF_UNIX to each
# member's node, and none to its port.
#
# And the boundary that makes this more than one field: a group may hold a
# member that publishes no node -- a proxy, or a runtime on another daemon --
# and that one is dialled by address, in the same group, on the same
# selection.  A path means nothing off this box, so a remote member with one
# would be a backend that is simply down.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
. "$(dirname "$0")/lib_ports.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"

echo "=== Integration: a proxy naming a group takes each member's node ==="

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); [ -n "${1:-}" ] && echo "  PASS: $1"; }
bad() {
    TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1))
    echo "  FAIL [$1]: $2"
    local line
    for line in "${@:3}"; do echo "        $line"; done
}

PORT=$((SL_PORT_BASE+1350))
PA=$PORT; PB=$((PORT+1)); PP=$((PORT+2)); PQ=$((PORT+3))
PC=$((PORT+4)); PR=$((PORT+6)); PM=$((PORT+7))
daemon_isolate groupnode
RTDIR="$SOCKETLEY_SOCKET.rt"

# The second daemon of section 7, on its own socket and state directory,
# cleaned up before the first because daemon_stop deletes the directory both
# live in.
SOCK2="$SOCKETLEY_TMPD/two.sock"
HOME2="$SOCKETLEY_TMPD/home2"
D2PID=""
two() { HOME="$HOME2" SOCKETLEY_SOCKET="$SOCK2" "$BIN" "$@"; }
stop_two() {
    [ -n "$D2PID" ] && kill "$D2PID" 2>/dev/null
    daemon_sweep "$SOCK2"
}
trap 'stop_two; daemon_stop 2>/dev/null || true' EXIT
daemon_start "$BIN"

WWW="$SOCKETLEY_TMPD/www"; mkdir -p "$WWW"
printf 'over-either\n' > "$WWW/index.html"

"$BIN" create server gn_a -p "$PA" --group gn_g --http "$WWW" -s >/dev/null 2>&1
"$BIN" create server gn_b -p "$PB" --group gn_g --http "$WWW" -s >/dev/null 2>&1
sleep 1
"$BIN" create proxy gn_p -p "$PP" --backend @gn_g -s >/dev/null 2>&1
"$BIN" create proxy gn_q -p "$PQ" --backend gn_a   -s >/dev/null 2>&1
sleep 1.5

# N requests at once through PORT under /NAME/, each held open for HOLD
# seconds after its answer so the backend leg is there for ss to see, printing
# how many answered with the document.  Backgrounded; HELD_PID is what to wait
# on, and never a bare `wait`, which would also wait on the daemon.
held() {   # held PORT NAME N HOLD OUTFILE
    python3 - "$1" "$2" "$3" "$4" >"$5" <<'PY' &
import socket, sys, threading, time
port, name, n, hold = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
got = [0] * n
def one(i):
    try:
        s = socket.create_connection(('127.0.0.1', port), timeout=5)
        s.sendall(('GET /%s/ HTTP/1.1\r\nHost: x\r\n\r\n' % name).encode())
        d = s.recv(600)
        got[i] = 1 if b'over-either' in d else 0
        time.sleep(hold)
        s.close()
    except Exception:
        pass
ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
for t in ts: t.start()
for t in ts: t.join()
print(sum(got))
PY
    HELD_PID=$!
}
# Legs to a node: one row per accepted connection, the path in its local field.
node_legs() { ss -xn state established 2>/dev/null | grep -cF "$1"; }
# Legs to a port: the dialling side's rows only.
port_legs() { ss -Htn state established "( dport = :$1 )" 2>/dev/null | wc -l; }

# ── 1. Both members have a node ────────────────────────────────────────────
if [ -S "$RTDIR/gn_a.sock" ] && [ -S "$RTDIR/gn_b.sock" ]; then ok "both members have a node"
else bad "both members have a node" "$(ls "$RTDIR" 2>/dev/null | tr '\n' ' ')"; fi

# ── 2. The group proxy's legs are AF_UNIX, and none of them is TCP ─────────
OUT="$SOCKETLEY_TMPD/held.txt"
held "$PP" gn_p 8 2.5 "$OUT"
sleep 1.2
A_LEGS=$(node_legs "$RTDIR/gn_a.sock"); B_LEGS=$(node_legs "$RTDIR/gn_b.sock")
A_TCP=$(port_legs "$PA"); B_TCP=$(port_legs "$PB")
wait "$HELD_PID"; ANSWERED=$(cat "$OUT")
if [ "$ANSWERED" = "8" ]; then ok "8 of 8 through @gn_g answered with the document"
else bad "8 of 8 through @gn_g answered with the document" "answered: '$ANSWERED'"; fi
if [ "$A_LEGS" -ge 1 ] && [ "$B_LEGS" -ge 1 ] && [ "$A_TCP" -eq 0 ] && [ "$B_TCP" -eq 0 ]; then
    ok "every leg is AF_UNIX: a.sock $A_LEGS, b.sock $B_LEGS, TCP to either port 0"
else
    bad "every leg is AF_UNIX" \
        "a.sock $A_LEGS, b.sock $B_LEGS, TCP to :$PA $A_TCP, to :$PB $B_TCP;" \
        "a member with a node reached over its port is the addressing form" \
        "choosing the transport, which is what this file exists to catch"
fi

# ── 3. Said in the log, per member ─────────────────────────────────────────
SAID_A=$(grep -c "@gn_g member 127.0.0.1:$PA is reached over $RTDIR/gn_a.sock" "$SOCKETLEY_DLOG" 2>/dev/null || true)
SAID_B=$(grep -c "@gn_g member 127.0.0.1:$PB is reached over $RTDIR/gn_b.sock" "$SOCKETLEY_DLOG" 2>/dev/null || true)
SAID_Q=$(grep -c "\"gn_a\" is reached over $RTDIR/gn_a.sock" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "${SAID_A:-0}" -ge 1 ] && [ "${SAID_B:-0}" -ge 1 ]; then
    ok "the log names both members' nodes"
else
    bad "the log names both members' nodes" \
        "a: $SAID_A line(s), b: $SAID_B line(s); a transport tcpdump cannot see" \
        "has to be said somewhere"
fi
if [ "${SAID_Q:-0}" -ge 1 ]; then ok "and the name form still says its own"
else bad "and the name form still says its own" "$SAID_Q line(s) for \"gn_a\""; fi

# ── 4. A republish keeps the pooled node legs ──────────────────────────────
#
# The pool and the breakers are pruned against the membership on every
# snapshot, by the key a member is dialled under; a prune that compared a path
# against the member's port would empty the pool on every control action.
# Paired with section 7, where a member that really left must go.
POOLED_BEFORE=$(( $(node_legs "$RTDIR/gn_a.sock") + $(node_legs "$RTDIR/gn_b.sock") ))
# A third member with no node of its own -- a TCP proxy in front of gn_a --
# which is also the republish.
"$BIN" create proxy gn_c -p "$PC" --group gn_g --backend gn_a --protocol tcp -s >/dev/null 2>&1
sleep 1.5
POOLED_AFTER=$(( $(node_legs "$RTDIR/gn_a.sock") + $(node_legs "$RTDIR/gn_b.sock") ))
if [ "$POOLED_BEFORE" -ge 1 ] && [ "$POOLED_AFTER" -ge 1 ]; then
    ok "pooled node legs survive a republish ($POOLED_BEFORE before, $POOLED_AFTER after)"
else
    bad "pooled node legs survive a republish" \
        "$POOLED_BEFORE pooled before the republish, $POOLED_AFTER after;" \
        "0 before means the pool is not what was measured"
fi

# ── 5. A member without a node is dialled by address, in the same group ────
held "$PP" gn_p 12 2.5 "$OUT"
sleep 1.2
# b.sock is the witness for the node here and below, because gn_c and gn_q
# name gn_a and take its node themselves, so a.sock counts their legs too.
C_TCP=$(port_legs "$PC"); B_LEGS=$(node_legs "$RTDIR/gn_b.sock")
wait "$HELD_PID"; ANSWERED=$(cat "$OUT")
SAID_C=$(grep -c "member 127.0.0.1:$PC is reached over" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "$ANSWERED" = "12" ] && [ "$C_TCP" -ge 1 ] && [ "$B_LEGS" -ge 1 ] && [ "${SAID_C:-0}" -eq 0 ]; then
    ok "a member with no node stays TCP beside one with: :$PC $C_TCP leg(s), b.sock $B_LEGS"
else
    bad "a member with no node stays TCP beside one with" \
        "answered $ANSWERED of 12, TCP to :$PC $C_TCP, b.sock $B_LEGS," \
        "log claimed a node for :$PC $SAID_C time(s)"
fi

# ── 6. A remote member gets no path ────────────────────────────────────────
#
# A second daemon on this box joins the same cluster directory and puts a
# member of gn_g on its own socket, which is how a member of another daemon
# arrives in this one's table: by host and port, from a scan.  Its node is
# real and in the other daemon's directory, and this proxy must never dial it.
CDIR="$SOCKETLEY_TMPD/cluster"; mkdir -p "$CDIR" "$HOME2"
HOME="$HOME2" SOCKETLEY_SOCKET="$SOCK2" "$BIN" daemon >>"$SOCKETLEY_TMPD/two.log" 2>&1 &
D2PID=$!
for _ in $(seq 1 100); do grep -q "daemon started" "$SOCKETLEY_TMPD/two.log" 2>/dev/null && break; sleep 0.1; done
"$BIN" daemon --name gnode1 --cluster "$CDIR" >/dev/null 2>&1
two    daemon --name gnode2 --cluster "$CDIR" >/dev/null 2>&1
two    create server gn_r -p "$PR" --group gn_g --http "$WWW" -s >/dev/null 2>&1
sleep 3.5
"$BIN" create proxy gn_m -p "$PM" --backend @gn_g -s >/dev/null 2>&1
sleep 1.5
GROUP=$("$BIN" cluster group gn_g 2>&1)
if grep -q "$PR" <<<"$GROUP"; then ok "the remote member is in this daemon's view of the group"
else bad "the remote member is in this daemon's view of the group" "cluster group gn_g said:" "$GROUP"; fi

held "$PM" gn_m 12 2.5 "$OUT"
sleep 1.2
R_TCP=$(port_legs "$PR"); R_NODE=$(node_legs "$SOCK2.rt/gn_r.sock"); B_LEGS=$(node_legs "$RTDIR/gn_b.sock")
wait "$HELD_PID"; ANSWERED=$(cat "$OUT")
SAID_R=$(grep -c "is reached over $SOCK2.rt/gn_r.sock" "$SOCKETLEY_DLOG" 2>/dev/null || true)
if [ "$ANSWERED" = "12" ] && [ "$R_TCP" -ge 1 ] && [ "$R_NODE" -eq 0 ] && [ "$B_LEGS" -ge 1 ] && [ "${SAID_R:-0}" -eq 0 ]; then
    ok "the remote member is reached over TCP (:$PR $R_TCP leg(s)) beside a local one over its node (b.sock $B_LEGS)"
else
    bad "the remote member is reached over TCP beside a local one over its node" \
        "answered $ANSWERED of 12, TCP to :$PR $R_TCP, legs on its node $R_NODE," \
        "b.sock $B_LEGS, log claimed its node $SAID_R time(s);" \
        "a path published for a member on another daemon is a backend that is down"
fi


# ── 7. A member that stops leaves the pool; the others keep theirs ─────────
"$BIN" stop gn_b >/dev/null 2>&1
sleep 1.5
B_LEFT=$(node_legs "$RTDIR/gn_b.sock"); A_KEPT=$(node_legs "$RTDIR/gn_a.sock")
held "$PP" gn_p 8 0.2 "$OUT"; wait "$HELD_PID"; ANSWERED=$(cat "$OUT")
if [ "$B_LEFT" -eq 0 ] && [ "$A_KEPT" -ge 1 ] && [ "$ANSWERED" = "8" ]; then
    ok "a stopped member is gone from the pool and the group still answers"
else
    bad "a stopped member is gone from the pool and the group still answers" \
        "b.sock legs $B_LEFT, a.sock legs $A_KEPT, answered $ANSWERED of 8"
fi

two stop gn_r >/dev/null 2>&1
for rt in gn_m gn_q gn_p gn_c gn_a; do "$BIN" stop "$rt" >/dev/null 2>&1; done
stop_two
daemon_stop
trap - EXIT

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
