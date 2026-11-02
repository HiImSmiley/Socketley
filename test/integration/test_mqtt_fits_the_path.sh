#!/usr/bin/env bash
# suite: isolated -- its own network namespace, daemon, socket and port window, so it runs beside the others
# Integration test: an mqtt subscriber on a slow path with a round trip gets its PINGRESP ahead of the PUBLISHes it
# has not read yet, so a busy topic does not make it look dead.
#
# What each part would catch:
#   * a PINGRESP queued behind every PUBLISH owed: over 4 Mbit/s with 20 ms of round trip a subscriber flooded with
#     QoS 0 waited more than 7.5 s for it, where it now waits 0.86 s, most of it the path's own queue
#   * the flood itself lost: the subscriber reads none of it
# A delay on loopback needs a network namespace of its own, which an unprivileged user namespace gives.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
if [ -z "${SL_IN_NETNS:-}" ]; then
    if ! unshare -rn true 2>/dev/null; then
        echo "=== Integration: an mqtt subscriber's PINGRESP fits the path ==="
        echo "  SKIP: no unprivileged network namespace here"
        exit 0
    fi
    exec unshare -rn env SL_IN_NETNS=1 BIN="$BIN" bash "$0" "$@"
fi
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: an mqtt subscriber's PINGRESP fits the path ==="
# A path's own packets, not loopback's 64 KiB ones.
ip link set lo up; ip link set dev lo mtu 1500
command -v tc >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 || { echo "  SKIP: tc and python3 are required"; exit 0; }
sanitized=0
nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null && sanitized=1
daemon_isolate mqttpath
P=$((SL_PORT_BASE + 1935))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"
"$BIN" create mqtt m -p "$P" --anonymous -s >/dev/null 2>&1
for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$P") 2>/dev/null && break; sleep 0.1; done
# What the broker sends: 4 Mbit/s, 10 ms each way, a bottleneck queue of about 30 ms.
tc qdisc add dev lo root handle 1: prio bands 3 priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
tc qdisc add dev lo parent 1:3 handle 30: netem delay 10ms rate 4mbit limit 100
tc filter add dev lo parent 1: protocol ip u32 match ip sport "$P" 0xffff flowid 1:3
tc filter add dev lo parent 1: protocol ip u32 match ip dport "$P" 0xffff flowid 1:3

out=$(PYTHONPATH="$HERE" timeout 240 python3 - "$P" <<'PY'
import socket, sys, threading, time
from lib_mqtt import Client
port = int(sys.argv[1])
sub = Client(port, timeout=30); sub.connect("sub", keepalive=60); sub.subscribe(("t", 0))
s = sub.sock; s.settimeout(5)
stop = [False]
def flood():
    pub = Client(port, timeout=30); pub.connect("pub")
    body = b"x" * 1000
    while not stop[0]:
        for _ in range(200):
            pub.publish("t", body, qos=0, wait=False)
        time.sleep(0.05)
threading.Thread(target=flood, daemon=True).start()
time.sleep(4)
waits, got = [], 0
for _ in range(8):
    t = time.perf_counter(); s.sendall(b"\xc0\x00")
    # Read until the PINGRESP's two bytes, which a payload of x and a topic of t never hold, even across two reads;
    # a wait past 20 s is counted as 20 s, so a broker that holds it that long still gives a number.
    tail = b""
    while time.perf_counter() - t < 20:
        d = s.recv(1 << 16)
        if not d:
            break
        got += len(d)
        if b"\xd0\x00" in tail + d:
            break
        tail = d[-1:]
    waits.append(min(20000, (time.perf_counter() - t) * 1000))
    time.sleep(0.3)
stop[0] = True
waits.sort()
print("%.0f %.0f %d" % (waits[len(waits) // 2], waits[-1], got))
PY
)
read -r p50 worst got <<<"$out"
echo "  PINGRESP on a flooded 4 Mbit/s path: ${p50:-?} ms at the median, ${worst:-?} ms at worst, ${got:-0} bytes read meanwhile"
[ "${got:-0}" -gt 100000 ] && ok || bad "the subscriber reads the flood" "$out"
if [ "$sanitized" = 1 ]; then echo "  SKIP [wait]: milliseconds measure the sanitizer, not the queue"
elif [ "${p50:-99999}" -lt 2000 ]; then ok
else bad "its PINGRESP comes ahead of what it has not read" "${p50:-none} ms at the median"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
