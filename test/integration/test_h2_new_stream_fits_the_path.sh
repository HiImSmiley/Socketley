#!/usr/bin/env bash
# suite: isolated -- its own network namespace, daemon, socket and port window, so it runs beside the others
# Integration test: on a TLS HTTP/2 entrance with a round trip, a stream opened beside a download is answered behind
# little of it.
#
# What each part would catch:
#   * an entrance that frames 256 KiB ahead on a fitted connection: over 4 Mbit/s with 20 ms of round trip a small
#     answer on a new stream waited 1.2 to 1.8 s behind a download, where 64 KiB ahead it waits 0.6 to 0.9
#   * a new stream not answered at all beside the download
# A delay on loopback needs a network namespace of its own, which an unprivileged user namespace gives.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
if [ -z "${SL_IN_NETNS:-}" ]; then
    if ! unshare -rn true 2>/dev/null; then
        echo "=== Integration: a new HTTP/2 stream fits the path ==="
        echo "  SKIP: no unprivileged network namespace here"
        exit 0
    fi
    exec unshare -rn env SL_IN_NETNS=1 BIN="$BIN" bash "$0" "$@"
fi
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a new HTTP/2 stream fits the path ==="
ip link set lo up; ip link set dev lo mtu 1500
command -v tc >/dev/null 2>&1 || { echo "  SKIP: tc is required"; exit 0; }
python3 -c "import h2" 2>/dev/null || { echo "  SKIP: the python h2 library is required"; exit 0; }
sanitized=0
nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null && sanitized=1
daemon_isolate h2stream
T=$SOCKETLEY_TMPD
S=$((SL_PORT_BASE + 1937)); E=$((SL_PORT_BASE + 1938))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
mkdir -p "$T/www"; head -c $((64 << 20)) /dev/urandom > "$T/www/big.bin"; echo small > "$T/www/small.txt"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=files.example.com \
    -addext "subjectAltName=DNS:files.example.com" -keyout "$T/e.key" -out "$T/e.pem" >/dev/null 2>&1
daemon_start "$BIN"
"$BIN" create server web -p "$S" --http "$T/www" --domain files.example.com -s >/dev/null 2>&1
"$BIN" create proxy ent -p "$E" --tls --cert "$T/e.pem" --key "$T/e.key" -s >/dev/null 2>&1
for _ in $(seq 1 60); do f=$(find "$T" -name 'routes-ent' | head -1); [ -n "$f" ] && grep -q files.example.com "$f" && break; sleep 0.2; done
# 4 Mbit/s, 10 ms each way, a bottleneck queue of about 30 ms, before the connection, so it is fitted to the path.
tc qdisc add dev lo root handle 1: prio bands 3 priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
tc qdisc add dev lo parent 1:3 handle 30: netem delay 10ms rate 4mbit limit 100
tc filter add dev lo parent 1: protocol ip u32 match ip sport "$E" 0xffff flowid 1:3
tc filter add dev lo parent 1: protocol ip u32 match ip dport "$E" 0xffff flowid 1:3

out=$(timeout 120 python3 - "$E" "$T/e.pem" <<'PY'
import os, socket, ssl, sys, time, h2.connection, h2.events, h2.config
port, ca = int(sys.argv[1]), sys.argv[2]
ctx = ssl.create_default_context(cafile=ca); ctx.set_alpn_protocols(["h2"])
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname="files.example.com"); s.settimeout(5)
c = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True)); c.initiate_connection()
c.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 16 << 20}); c.increment_flow_control_window(64 << 20)
s.sendall(c.data_to_send())
def req(path):
    sid = c.get_next_available_stream_id()
    c.send_headers(sid, [(":method", "GET"), (":scheme", "https"), (":authority", "files.example.com"), (":path", path)], end_stream=True)
    s.sendall(c.data_to_send()); return sid
big = req("/big.bin"); got = {}; start = time.time(); small = None; asked = None; waits = []; next_at = start + 3; big_done = None
while time.time() - start < 40 and len(waits) < 7:
    if small is None and time.time() >= next_at:
        small = req("/small.txt"); asked = time.perf_counter()
    try:
        d = s.recv(1 << 16)
    except socket.timeout:
        break
    if not d: break
    for e in c.receive_data(d):
        if isinstance(e, h2.events.DataReceived):
            got[e.stream_id] = got.get(e.stream_id, 0) + len(e.data)
            c.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
        if isinstance(e, h2.events.StreamEnded) and e.stream_id == big:
            big_done = time.time() - start
        if isinstance(e, h2.events.StreamEnded) and e.stream_id == small:
            waits.append((time.perf_counter() - asked) * 1000); small = None; next_at = time.time() + 1
    s.sendall(c.data_to_send())
waits.sort()
print("%.0f %.0f %d" % (waits[len(waits) // 2], waits[-1], len(waits)) if waits else "none none 0")
PY
)
read -r p50 worst n <<<"$out"
echo "  a small answer on a new stream beside a download over 4 Mbit/s: ${p50:-?} ms at the median, ${worst:-?} ms at worst"
[ "${n:-0}" -ge 5 ] && ok || bad "a new stream beside the download is answered" "$out"
if [ "$sanitized" = 1 ]; then echo "  SKIP [wait]: milliseconds measure the sanitizer, not the queue"
elif [ "${p50:-99999}" -lt 1100 ]; then ok
else bad "behind little of the download" "${p50:-none} ms at the median"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
