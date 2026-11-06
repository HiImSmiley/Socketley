#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# UDP through a tunnel: a port on the edge whose datagrams an agent carries to a service at home and back, each
# visitor a flow of its own.
#
# What each part would catch:
#   * a datagram not carried there and back, or one visitor given another's answer
#   * datagrams lost on loopback when many come at once, or a large one cut
#   * a TCP and a UDP service of one port number taken for a clash
#   * a datagram carried, or a port kept, while the agent is away or the service is gone
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: UDP through a tunnel ==="
daemon_isolate tunneludp
PE=$((SL_PORT_BASE + 1990))
PG=$((SL_PORT_BASE + 1991))
PU=$((SL_PORT_BASE + 1992))
PT=$((SL_PORT_BASE + 1993))
PM=$((SL_PORT_BASE + 1994))
unset SOCKETLEY_CONFIG
mkdir -p "$HOME/.config/socketley"
printf 'config = {\n    metrics_port = %s\n}\n' "$PM" > "$HOME/.config/socketley/config.lua"
# The service at home: each datagram answered with "echo " before it.
python3 - "$PU" "$PT" <<'PY' &
import socket, sys, threading
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("127.0.0.1", int(sys.argv[1])))
t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); t.bind(("127.0.0.1", int(sys.argv[2]))); t.listen()
def tcp():
    while True:
        c, _ = t.accept(); c.sendall(b"tcp " + c.recv(100)); c.close()
threading.Thread(target=tcp, daemon=True).start()
while True:
    d, a = u.recvfrom(65536)
    u.sendto(b"echo " + d, a)
PY
HOMESVC=$!
trap 'kill $HOMESVC 2>/dev/null; daemon_stop' EXIT
daemon_start "$BIN"

"$BIN" create tunnel t --mode edge -p "$PE" -s >/dev/null 2>&1 || bad "an edge is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do ss -ltn "sport = :$PE" | grep -q LISTEN && break; sleep 0.1; done
INV=$("$BIN" tunnel t invite pi --udp "game:127.0.0.1:$PG" --tcp "chat:127.0.0.1:$PG" 2>&1)
case "$INV" in pi.*) ok ;; *) bad "a UDP and a TCP service of one port number are invited together" "$INV" ;; esac
"$BIN" tunnel t list | grep -q "game:127.0.0.1:$PG/udp" && ok || bad "list says the UDP service" "$("$BIN" tunnel t list)"
"$BIN" create tunnel home --mode agent --to "http://127.0.0.1:$PE" --join "$INV" \
    --offer "game=127.0.0.1:$PU,chat=127.0.0.1:$PT" -s >/dev/null 2>&1 || bad "an agent is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do [ "$("$BIN" stats t 2>/dev/null | sed -n 's/^links://p')" = 1 ] && break; sleep 0.1; done
for _ in $(seq 1 30); do ss -Hlun "sport = :$PG" | grep -q . && break; sleep 0.1; done
[ "$(ss -Hlun "sport = :$PG" | awk '{print $4}')" = "127.0.0.1:$PG" ] && ok || bad "the edge opens the UDP port, on the address given" "$(ss -Hlun "sport = :$PG")"

out=$(python3 - "$PG" <<'PY'
import socket, sys
port = int(sys.argv[1])
def ask(s, payload, tries=20):
    s.settimeout(0.3)
    for _ in range(tries):
        s.sendto(payload, ("127.0.0.1", port))
        try:
            return s.recvfrom(65536)[0]
        except socket.timeout:
            pass
    return b"(nothing)"
a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print("one", ask(a, b"from a").decode())
print("two", ask(b, b"from b").decode(), ask(a, b"a again").decode())
big = bytes(range(256)) * 31 + b"end"   # 7939 bytes
print("big", len(ask(a, big)) == len(big) + 5)
# A burst, counted as it comes back.
a.settimeout(2)
for i in range(200):
    a.sendto(b"n%d" % i, ("127.0.0.1", port))
got = set()
try:
    while len(got) < 200:
        got.add(a.recvfrom(100)[0])
except socket.timeout:
    pass
print("burst", len(got))
PY
)
echo "$out" | grep -qx "one echo from a" && ok || bad "a datagram is carried to the service at home and its answer back" "$out"
echo "$out" | grep -qx "two echo from b echo a again" && ok || bad "each visitor gets its own answers" "$out"
echo "$out" | grep -qx "big True" && ok || bad "a datagram of eight thousand bytes is carried whole" "$out"
n=$(echo "$out" | sed -n 's/^burst //p')
[ "${n:-0}" -ge 190 ] && ok || bad "two hundred at once come back, on loopback all but a few" "$n of 200"
[ "$(python3 -c "
import socket; s = socket.create_connection(('127.0.0.1', $PG), timeout=5); s.sendall(b'hi'); print(s.recv(100).decode())" 2>&1)" = "tcp hi" ] \
    && ok || bad "the TCP service of the same port number is carried beside it" "$(tail -2 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do [ "$("$BIN" stats t | sed -n 's/^flows://p')" -ge 2 ] && break; sleep 0.2; done
[ "$("$BIN" stats t | sed -n 's/^flows://p')" -ge 2 ] && ok || bad "the edge counts its flows" "$("$BIN" stats t | grep -E 'flows|datagrams')"

ask_once() { python3 -c "
import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1)
s.sendto(b'$1', ('127.0.0.1', $PG))
try: print(s.recvfrom(100)[0].decode())
except Exception: print('(nothing)')"; }
# The agent away: nothing is answered, and what was not carried is counted.
"$BIN" stop home >/dev/null 2>&1
for _ in $(seq 1 30); do [ "$("$BIN" stats t 2>/dev/null | sed -n 's/^links://p')" = 0 ] && break; sleep 0.2; done
before=$("$BIN" stats t | sed -n 's/^datagrams_dropped://p')
[ "$(ask_once away)" = "(nothing)" ] && ok || bad "with the agent away nothing answers" "$(ask_once away)"
for _ in $(seq 1 50); do [ "$("$BIN" stats t | sed -n 's/^datagrams_dropped://p')" -gt "$before" ] && break; sleep 0.2; done
[ "$("$BIN" stats t | sed -n 's/^datagrams_dropped://p')" -gt "$before" ] && ok || bad "and the datagram is counted as dropped" "$("$BIN" stats t | grep datagrams)"
"$BIN" start home >/dev/null 2>&1
for _ in $(seq 1 50); do [ "$(ask_once back)" = "echo back" ] && break; sleep 0.2; done
[ "$(ask_once back)" = "echo back" ] && ok || bad "and once it is back the service answers again" "$(ask_once back)"

# The metrics say what was carried and what was dropped.
for _ in $(seq 1 50); do curl -s "http://127.0.0.1:$PM/metrics" | grep -q '^socketley_tunnel_datagrams_dropped_total{name="t"} [1-9]' && break; sleep 0.2; done
M=$(curl -s "http://127.0.0.1:$PM/metrics")
grep -q '^socketley_tunnel_datagrams_total{name="t"} [1-9]' <<<"$M" && grep -q '^socketley_tunnel_datagrams_dropped_total{name="t"} [1-9]' <<<"$M" \
    && ok || bad "the metrics count datagrams carried and dropped" "$(echo "$M" | grep -E 'tunnel_(datagrams|flows)' | head -4)"

# The service taken away closes its port.
"$BIN" tunnel t set pi --tcp "chat:127.0.0.1:$PG" >/dev/null 2>&1 || bad "set takes the UDP service away" "rc $?"
for _ in $(seq 1 30); do ss -Hlun "sport = :$PG" | grep -q . || break; sleep 0.1; done
[ -z "$(ss -Hlun "sport = :$PG")" ] && ok || bad "and its port is closed" "$(ss -Hlun "sport = :$PG")"

echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
