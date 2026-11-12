#!/usr/bin/env bash
# suite: isolated -- its own network and mount namespace, daemon, socket and port window, so it runs beside the others
# Integration test: in TCP mode --backend-timeout bounds the connect to a backend.
#
# A backend address that has gone silent -- a container restarted onto a new address, its old one answering nothing
# -- held every client a TCP proxy sent there for the kernel's two minutes of SYN retries, since TCP mode had no
# deadline at all. The connect is bounded by --backend-timeout now, as HTTP's wait for the first byte is: a connect
# not done within it is a failed attempt, the breaker is charged and, as --retry allows, the next backend is dialled.
# 0 keeps it unbounded.
#
# What each part would catch:
#   * a connect with no bound: with --retry 1, a client routed to the silent address first is not answered inside
#     the deadline and a margin, by the backend that answers
#   * a bound that holds the client anyway: without --retry, the clients routed to silence are not let go inside it
#   * a bound where 0 says none: with --backend-timeout 0 the client routed there is still waiting
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
if [ -z "${SL_IN_NETNS:-}" ]; then
    if ! unshare -rnm true 2>/dev/null; then
        echo "=== Integration: in TCP mode --backend-timeout bounds the connect to a backend ==="
        echo "  SKIP: no unprivileged network and mount namespace here"
        exit 0
    fi
    exec unshare -rnm env SL_IN_NETNS=1 BIN="$BIN" bash "$0" "$@"
fi
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: in TCP mode --backend-timeout bounds the connect to a backend ==="
ip link set lo up
# 10.255.255.0/24 goes into a dummy device, which drops it: a SYN there is never answered, not even refused.
ip link add slcd0 type dummy && ip link set slcd0 up && ip route add 10.255.255.0/24 dev slcd0 \
    || { echo "  SKIP: no dummy device in this namespace"; exit 0; }
daemon_isolate tcpdeadline
T=$SOCKETLEY_TMPD
PE=$((SL_PORT_BASE + 1971)); PB=$((SL_PORT_BASE + 1972)); PZ=$((SL_PORT_BASE + 1973)); PN=$((SL_PORT_BASE + 1974))

python3 -c '
import socket, sys, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(64)
def echo(c):
    with c:
        while (d := c.recv(4096)):
            c.sendall(d)
while True:
    threading.Thread(target=echo, args=(s.accept()[0],), daemon=True).start()' "$PE" &
ECHO_PID=$!
trap 'kill $ECHO_PID 2>/dev/null; daemon_stop' EXIT
daemon_start "$BIN"

# The silent address first and the answering one second, round robin, so every other client is sent to silence.
"$BIN" create proxy cd_b -p "$PB" --protocol tcp --backend "10.255.255.1:$PE,127.0.0.1:$PE" --strategy round-robin \
    --backend-timeout 1 --retry 1 -s >/dev/null 2>&1
"$BIN" create proxy cd_n -p "$PN" --protocol tcp --backend "10.255.255.1:$PE,127.0.0.1:$PE" --strategy round-robin \
    --backend-timeout 1 -s >/dev/null 2>&1
"$BIN" create proxy cd_z -p "$PZ" --protocol tcp --backend "10.255.255.1:$PE,127.0.0.1:$PE" --strategy round-robin \
    --backend-timeout 0 --retry 1 -s >/dev/null 2>&1
for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$PB") 2>/dev/null && break; sleep 0.1; done

ask() {   # port timeout_s -> the echo of one line through the proxy, or nothing
    python3 -c '
import socket, sys
c = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=float(sys.argv[2]))
c.settimeout(float(sys.argv[2])); c.sendall(b"ping\n")
try: print(c.recv(64).decode().strip())
except Exception: print("")' "$1" "$2" 2>/dev/null
}

six() {   # port -> "answered slowest_ms" for six clients one after another, three of them sent to silence first
    local answered=0 slowest=0 t0 got ms
    for _ in 1 2 3 4 5 6; do
        t0=$(date +%s%N); got=$(ask "$1" 6); ms=$(( ($(date +%s%N) - t0) / 1000000 ))
        [ "$got" = ping ] && answered=$((answered + 1))
        [ "$ms" -gt "$slowest" ] && slowest=$ms
    done
    echo "$answered $slowest"
}

# A deadline of 1 s, a dial of the next backend and an echo; the kernel's own bound is two minutes.
read -r answered slowest < <(six "$PB")
[ "$answered" -eq 6 ] && [ "$slowest" -lt 2500 ] \
    && ok "with --retry 1, all six answered, the slowest in ${slowest} ms" \
    || bad "with --retry 1, all six answered inside the 1 s deadline and a margin" "$answered of 6, slowest ${slowest} ms"
read -r answered slowest < <(six "$PN")
[ "$answered" -eq 3 ] && [ "$slowest" -lt 2500 ] \
    && ok "without --retry, the three sent to silence are let go at the deadline, the slowest in ${slowest} ms" \
    || bad "without --retry, the three sent to silence are let go at the deadline" "$answered of 6 answered, slowest ${slowest} ms"

# --backend-timeout 0: the client that meets the silent address is still waiting when this one gives up.
waited=0
for _ in 1 2; do [ -z "$(ask "$PZ" 3)" ] && waited=$((waited + 1)); done
[ "$waited" -ge 1 ] && ok "with --backend-timeout 0 the connect is not bounded" \
    || bad "with --backend-timeout 0 the connect is not bounded" "both clients answered within 3 s"

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] || exit 1
