#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a persistent mqtt broker with many retained messages writes its snapshot without holding its loop,
# and a restart gives every one of them back.
#
# What each part would catch:
#   * the snapshot encoded on the loop and copied once more into its frame: at 60 MB every packet waited about 70 ms
#     behind each interval's write
#   * a snapshot whose frame is written wrong, its length or the routes after it: a restart that keeps nothing
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: an mqtt broker writes a large snapshot off its loop ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
if nm -C "$BIN" 2>/dev/null | grep -q '__asan_'; then
    echo "  SKIP: a stall in milliseconds measures the sanitizer, not the snapshot"; exit 0
fi
daemon_isolate mqttsnap
P=$((SL_PORT_BASE + 1946))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
daemon_start "$BIN"
"$BIN" create mqtt m -p "$P" --anonymous --persistent on -s >/dev/null 2>&1
for _ in $(seq 1 50); do (exec 3<>"/dev/tcp/127.0.0.1/$P") 2>/dev/null && break; sleep 0.1; done

out=$(PYTHONPATH="$HERE" timeout 180 python3 - "$P" <<'PY'
import sys, time
from lib_mqtt import Client
p = int(sys.argv[1])
pub = Client(p, timeout=30); pub.connect("pub")
body = b"x" * 2000
for i in range(30000):
    pub.publish("t/%d" % i, body, qos=0, retain=True, wait=False)
pub.ping()
time.sleep(1.5)
probe = Client(p); probe.connect("probe")
worst = 0.0; k = 0
end = time.time() + 5
while time.time() < end:
    # A retained message replaced now and then, so every interval has a snapshot to write.
    if k % 200 == 0:
        pub.publish("t/0", body, qos=0, retain=True, wait=False)
    t = time.perf_counter(); probe.ping(); worst = max(worst, (time.perf_counter() - t) * 1000); k += 1
    time.sleep(0.002)
print("worst %.1f" % worst)
PY
)
echo "  the worst PINGREQ beside a 60 MB snapshot each second: $out"
w=$(sed -n 's/^worst \([0-9.]*\)$/\1/p' <<<"$out")
if awk -v w="${w:-999}" 'BEGIN{exit !(w < 30)}'; then ok
else bad "a packet never waits behind the snapshot" "$out"; fi

"$BIN" stop m >/dev/null 2>&1; "$BIN" start m >/dev/null 2>&1
kept=""
for _ in $(seq 1 100); do
    kept=$(grep -o 'session(s) and [0-9]* retained message(s) kept' "$SOCKETLEY_DLOG" | tail -1 | awk '{print $3}')
    [ "$(grep -c 'retained message(s) kept' "$SOCKETLEY_DLOG")" -ge 2 ] && break
    sleep 0.1
done
if [ "$kept" = 30000 ]; then ok; else bad "a restart gives back every retained message" "${kept:-none} of 30000"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
