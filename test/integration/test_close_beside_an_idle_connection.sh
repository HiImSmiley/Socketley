#!/usr/bin/env bash
# ─── WHAT WENT WRONG ────────────────────────────────────────────────────────
#
# A cache leader with a replica attached stopped closing its clients on an
# aarch64 Jetson running kernel 6.8: `printf 'get a\r\n' | nc -q 1` had its
# answer and then hung, with the server's side in CLOSE-WAIT, one more per
# request.  The follower was not the cause, only the first long-lived
# connection: any idle client did the same, and every CLOSE-WAIT cleared the
# moment that idle connection went.
#
# The runtimes register each accepted socket in io_uring's fixed file table,
# and a kernel before the per-resource node rework frees the nodes a removed
# file waits on in order, so a recv armed on one idle slot holds back the put
# of every socket closed after it.  strace showed close() and the slot's
# unregister both made at once; the kernel simply did not drop the file.  On
# kernel 7.2 the same build closes at once, which is why this is green there
# with or without the fix.
#
# ─── WHAT IS ASSERTED ───────────────────────────────────────────────────────
#
# With one connection held open and silent, a client that sends one line and
# half-closes gets its answer and the server's FIN within two seconds, three
# times in a row, against:
#
#   * a cache with no follower, the case the follower only exposed
#   * a cache leader with a follower attached, the case that was reported
#   * a server, the other runtime that registers its clients, which in inout
#     mode answers the sender nothing, so only its FIN is asserted
#
# and afterwards no socket on any of the ports is left in CLOSE-WAIT.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${BIN:-$HERE/../../bin/Release/socketley}"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
daemon_isolate idleclose
P=$((SL_PORT_BASE + 1022))
PASS=0; FAIL=0; TOTAL=0
HOLDERS=()
cleanup() {
    local h
    for h in "${HOLDERS[@]}"; do kill "$h" 2>/dev/null; done
    daemon_stop
}
trap cleanup EXIT

pass() { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
fail() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

# One line, then a half-close, then the time until the server's FIN, or
# "timeout" when it has not come within the deadline.
ask_and_wait_close() {
    python3 -I - "$1" "$2" <<'EOF'
import socket, sys, time
port, line = int(sys.argv[1]), sys.argv[2]
s = socket.create_connection(("127.0.0.1", port), timeout=2)
s.sendall(line.encode() + b"\r\n")
s.shutdown(socket.SHUT_WR)
start, got = time.monotonic(), b""
try:
    while True:
        chunk = s.recv(4096)
        if not chunk:
            print("closed %.2f %d" % (time.monotonic() - start, len(got)))
            break
        got += chunk
except socket.timeout:
    print("timeout %d" % len(got))
EOF
}

wait_listen() {
    local _
    for _ in $(seq 1 50); do
        ss -ltnH "sport = :$1" | grep -q LISTEN && return 0
        sleep 0.1
    done
    return 1
}

# A connection that never speaks, held for as long as this test runs.
hold_idle() {
    python3 -I "$HERE/lib_idle_conn.py" hold 127.0.0.1 "$1" 60 >/dev/null &
    HOLDERS+=($!)
    sleep 0.3
}

# The fourth argument is the fewest answer bytes the line must get back before the FIN.
check_port() {
    local name=$1 port=$2 line=$3 least=$4 i r
    for i in 1 2 3; do
        r=$(ask_and_wait_close "$port" "$line")
        case "$r" in
            closed*) [ "${r##* }" -ge "$least" ] && pass || fail "$name/$i" "closed without an answer: $r" ;;
            *)       fail "$name/$i" "no FIN within 2s of the half-close beside an idle connection: $r" ;;
        esac
    done
    local cw
    cw=$(ss -tnH "( sport = :$port )" | grep -c CLOSE-WAIT || true)
    [ "$cw" = 0 ] && pass || fail "$name/close-wait" "$cw socket(s) left in CLOSE-WAIT"
}

echo "=== Integration: a client is closed while another connection sits idle ==="

daemon_start "$BIN"

"$BIN" create cache ic_plain -p "$P" -s >/dev/null 2>&1
wait_listen "$P" || fail "cache/listen" "port $P never listened"
hold_idle "$P"
check_port "cache" "$P" "get a" 1

"$BIN" create cache ic_leader -p $((P + 1)) -s >/dev/null 2>&1
wait_listen $((P + 1)) || fail "leader/listen" "port $((P + 1)) never listened"
printf 'set seed v\r\n' | timeout 5 nc -q 1 127.0.0.1 $((P + 1)) >/dev/null 2>&1
"$BIN" create cache ic_follower -p $((P + 2)) --replicate "127.0.0.1:$((P + 1))" -s >/dev/null 2>&1
synced=0
for _ in $(seq 1 50); do
    [ "$(printf 'get seed\r\n' | timeout 3 nc -q 1 127.0.0.1 $((P + 2)) 2>/dev/null | tr -d '\r')" = v ] && { synced=1; break; }
    sleep 0.2
done
[ "$synced" = 1 ] && pass || fail "leader/sync" "the follower never answered the seeded key"
check_port "leader-with-follower" $((P + 1)) "get seed" 1

"$BIN" create server ic_server -p $((P + 3)) --mode inout -s >/dev/null 2>&1
wait_listen $((P + 3)) || fail "server/listen" "port $((P + 3)) never listened"
hold_idle $((P + 3))
check_port "server" $((P + 3)) "hello" 0

echo ""
echo "  Results: $PASS/$TOTAL passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
