#!/usr/bin/env bash
# suite: isolated -- its own network namespace, daemon, socket and port window, so it runs beside the others
# Integration test: a tunnel link with a round trip keeps the stream data it sends short, so a stream opened beside
# bulk ones is answered within a round trip or two, and one without keeps the kernel's buffer whole.
#
# What each part would catch:
#   * the link's data unbounded: over a 40 Mbit/s path with 20 ms of round trip, a new stream beside six downloads
#     was answered after 0.8 to 1.3 s, behind every stream's window and the kernel's buffer
#   * the bound paid for in rate: the downloads below the path's rate
#   * the setting made on every link, which on a LAN only caps the rate: read back from the agent's socket, since how
#     much stays unsent there is set by whichever of the six readers and the two loops a busy box starves most
# A delay on loopback needs a network namespace of its own, which an unprivileged user namespace gives.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
if [ -z "${SL_IN_NETNS:-}" ]; then
    if ! unshare -rn true 2>/dev/null; then
        echo "=== Integration: a tunnel link fits the path ==="
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

echo "=== Integration: a tunnel link fits the path ==="
ip link set lo up
command -v tc >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 || { echo "  SKIP: tc and python3 are required"; exit 0; }
# Under the sanitizer every row runs but the ones that time something.
sanitized=0
nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null && sanitized=1
daemon_isolate tunnelpath
PE=$((SL_PORT_BASE + 1990)); PT=$((SL_PORT_BASE + 1991)); PU=$((SL_PORT_BASE + 1992))
PX=$((SL_PORT_BASE + 1993)); PB=$((SL_PORT_BASE + 1994))
unset SOCKETLEY_CONFIG
python3 - "$PX" "$PB" <<'PY' &
import socketserver, sys, threading
px, pb = int(sys.argv[1]), int(sys.argv[2])
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            d = self.request.recv(65536)
            if not d: break
            self.request.sendall(d)
class Bulk(socketserver.BaseRequestHandler):
    def handle(self):
        b = b"z" * 65536
        try:
            while True: self.request.sendall(b)
        except OSError: pass
class S(socketserver.ThreadingTCPServer):
    daemon_threads = True; allow_reuse_address = True
threading.Thread(target=S(("127.0.0.1", pb), Bulk).serve_forever, daemon=True).start()
S(("127.0.0.1", px), Echo).serve_forever()
PY
BACKENDS=$!
trap 'kill $BACKENDS 2>/dev/null; daemon_stop' EXIT
daemon_start "$BIN"
"$BIN" create tunnel t --mode edge -p "$PE" -s >/dev/null 2>&1
INV=$("$BIN" tunnel t invite pi --tcp "echo:$PT,bulk:$PU" 2>&1)
"$BIN" create tunnel home --mode agent --to "http://127.0.0.1:$PE" --join "$INV" \
    --offer "echo=127.0.0.1:$PX,bulk=127.0.0.1:$PB" -s >/dev/null 2>&1
joined() { for _ in $(seq 1 100); do "$BIN" tunnel t list | grep -q joined && return 0; sleep 0.1; done; return 1; }
joined || { echo "  FATAL: the agent never joined: $(tail -3 "$SOCKETLEY_DLOG")"; echo "=== Results: 0 passed, 1 failed ==="; exit 1; }

# Six downloads through the tunnel for `secs` seconds; while they run, the most the agent's link holds unsent in the
# kernel, and with `echoes` the time a new stream beside them takes to answer.
load() {   # secs echoes
    python3 - "$PT" "$PU" "$PE" "$1" "$2" <<'PY'
import socket, subprocess, sys, threading, time
pt, pu, pe, secs, echoes = (int(a) for a in sys.argv[1:6])
got = [0]; stop = [False]; peak = [0]
def bulk():
    s = socket.create_connection(("127.0.0.1", pu)); s.settimeout(30)
    while not stop[0]:
        d = s.recv(1 << 20)
        if not d: break
        got[0] += len(d)
def watch():
    while not stop[0]:
        out = subprocess.run(["ss", "-tinH", "state", "established", "( dport = :%d )" % pe], capture_output=True, text=True).stdout
        for w in out.split():
            if w.startswith("notsent:"): peak[0] = max(peak[0], int(w[8:]))
        time.sleep(0.1)
ts = [threading.Thread(target=bulk, daemon=True) for _ in range(6)] + [threading.Thread(target=watch, daemon=True)]
for t in ts: t.start()
time.sleep(2)
lat = []; t0 = time.time(); g0 = got[0]
while time.time() - t0 < secs or len(lat) < echoes:
    if len(lat) < echoes:
        t = time.perf_counter()
        s = socket.create_connection(("127.0.0.1", pt)); s.settimeout(30)
        s.sendall(b"ping\n"); s.recv(64); s.close()
        lat.append((time.perf_counter() - t) * 1000)
    time.sleep(0.15)
rate = (got[0] - g0) / (time.time() - t0) / 1e6
stop[0] = True
lat.sort()
print("%d %.0f %.2f" % (peak[0], lat[len(lat) // 2] if lat else 0, rate))
PY
}

# The TCP_NOTSENT_LOWAT the agent put on its link, from a copy of the socket (pidfd_getfd, which the test may as root of
# its own user namespace): 16384 where it fitted the link to the path, 0 where it left the kernel's buffer whole.
lowat() {
    python3 - "$PE" <<'PY'
import ctypes, os, re, socket, subprocess, sys
out = subprocess.run(["ss", "-tnpH", "state", "established", "( dport = :%s )" % sys.argv[1]], capture_output=True, text=True).stdout
m = re.search(r"127\.0\.0\.1:(\d+) .*pid=(\d+),fd=(\d+)", out)
fd = ctypes.CDLL(None).syscall(438, os.pidfd_open(int(m[2])), int(m[3]), 0) if m else -1
if fd < 0: print("none none"); sys.exit()
with socket.socket(fileno=fd) as s: print(m[1], s.getsockopt(socket.IPPROTO_TCP, 25))
PY
}
# The agent dialling again, and its new link up.
redial() {
    local was=$1 port v
    "$BIN" stop home >/dev/null 2>&1; "$BIN" start home >/dev/null 2>&1
    for _ in $(seq 1 100); do read -r port v < <(lowat); [ "$port" != none ] && [ "$port" != "$was" ] && return 0; sleep 0.1; done
}

read -r lan_unsent _ _ < <(load 4 0)
# The kernel's round trip when the link is made decides, and a handshake on a starved host can measure a millisecond on
# loopback, so a link made again settles it: one that fits every link fits all three.
lan_lowat=() port=none
for try in 1 2 3; do
    read -r port v < <(lowat)
    lan_lowat+=("$v")
    [ "$v" = 0 ] && break
    [ "$try" = 3 ] || redial "$port"
done

# A 20 ms round trip and 40 Mbit/s from the agent to the edge, with a bottleneck queue of 30 ms, and the agent
# dialling again so its link is made on that path.
ip link set dev lo mtu 1500
tc qdisc del dev lo root 2>/dev/null
tc qdisc add dev lo root handle 1: prio bands 3 priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
tc qdisc add dev lo parent 1:3 handle 30: netem delay 10ms rate 40mbit limit 100
tc filter add dev lo parent 1: protocol ip u32 match ip sport "$PE" 0xffff flowid 1:3
tc filter add dev lo parent 1: protocol ip u32 match ip dport "$PE" 0xffff flowid 1:3
redial "$port"
read -r wan_unsent echo_ms rate < <(load 6 30)
read -r _ wan_lowat < <(lowat)
echo "  unsent at most: ${lan_unsent} bytes on loopback, ${wan_unsent} on the path;" \
     "a new stream beside six downloads answered in ${echo_ms} ms, the downloads at ${rate} MB/s;" \
     "the link's TCP_NOTSENT_LOWAT ${lan_lowat[*]} on loopback, ${wan_lowat} on the path"
if [ "$sanitized" = 1 ]; then echo "  SKIP [timing]: a rate and a latency in milliseconds measure the sanitizer, not the link"
elif awk -v e="${echo_ms:-99999}" 'BEGIN{exit !(e > 0 && e < 400)}'; then ok
else bad "a new stream beside bulk ones is answered within a few round trips" "${echo_ms} ms at the median"; fi
if [ "$sanitized" = 1 ]; then echo "  SKIP [timing]: a rate and a latency in milliseconds measure the sanitizer, not the link"
elif awk -v r="${rate:-0}" 'BEGIN{exit !(r >= 4.2)}'; then ok
else bad "and the downloads still fill the path's 4.7 MB/s" "${rate} MB/s"; fi
if [ "${wan_unsent:-999999999}" -le $((512 << 10)) ] && [ "$wan_lowat" = 16384 ]; then ok
else bad "over a round trip the kernel holds little of the link's data" \
    "$wan_unsent bytes unsent, TCP_NOTSENT_LOWAT $wan_lowat"; fi
if [ "${lan_lowat[-1]}" = 0 ]; then ok
else bad "and on loopback the buffer is left whole, which would otherwise cap the rate" \
    "TCP_NOTSENT_LOWAT ${lan_lowat[*]} on three links, $lan_unsent bytes unsent at most"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
