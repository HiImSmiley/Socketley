#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a persistent mqtt broker with many retained messages writes its snapshot without holding its loop,
# and a restart gives every one of them back.
#
# What each part would catch:
#   * the snapshot encoded on the loop and copied once more into its frame: at 60 MB every packet waited about 70 ms
#     behind each interval's write
#   * a snapshot whose frame is written wrong, its length or the routes after it: a restart that keeps nothing
#   * every session encoded again each interval: 1000 offline sessions holding 1M messages held the loop 90-350 ms
#   * a session's bytes kept from an earlier snapshot after it changed: a restart without what was queued since
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
# Under the sanitizer every row runs but the ones that time something.
sanitized=0
nm -C "$BIN" 2>/dev/null | grep '__asan_' >/dev/null && sanitized=1
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
if [ "$sanitized" = 1 ]; then echo "  SKIP [stall]: a stall in milliseconds measures the sanitizer, not the snapshot"
elif awk -v w="${w:-999}" 'BEGIN{exit !(w < 30)}'; then ok
else bad "a packet never waits behind the snapshot" "$out"; fi

# Offline sessions with deep queues, and one of them given more after a snapshot has written its bytes.
out=$(PYTHONPATH="$HERE" timeout 300 python3 - "$P" <<'PY'
import sys, time
from lib_mqtt import *
p = int(sys.argv[1])
for i in range(1000):
    c = connected(p, "off-%d" % i, props={SESSION_EXPIRY: 3600}); c.subscribe(("deep/#", 1)); c.disconnect()
pub = Client(p, timeout=60); pub.connect("deep-pub")
for k in range(300):
    pub.publish("deep/x", b"y" * 100, qos=1)
c = connected(p, "later", props={SESSION_EXPIRY: 3600}); c.subscribe(("later/#", 1)); c.disconnect()
pub.publish("later/x", "first", qos=1)
time.sleep(2.5)
probe = Client(p); probe.connect("probe")
worst = 0.0; k = 0; sent = 1
end = time.time() + 4
while time.time() < end:
    if k % 100 == 0:
        pub.publish("later/x", "more-%d" % k, qos=1)
        sent += 1
    t = time.perf_counter(); probe.ping(); worst = max(worst, (time.perf_counter() - t) * 1000); k += 1
    time.sleep(0.002)
print("worst %.1f" % worst)
print("sent %d" % sent)
PY
)
echo "  the worst PINGREQ beside 1000 offline sessions holding 300k messages: $out"
w=$(sed -n 's/^worst \([0-9.]*\)$/\1/p' <<<"$out")
sent=$(sed -n 's/^sent \([0-9]*\)$/\1/p' <<<"$out")
if [ "$sanitized" = 1 ]; then echo "  SKIP [stall]: a stall in milliseconds measures the sanitizer, not the snapshot"
elif awk -v w="${w:-999}" 'BEGIN{exit !(w < 30)}'; then ok
else bad "a packet never waits behind the sessions a snapshot holds" "$out"; fi

"$BIN" stop m >/dev/null 2>&1; "$BIN" start m >/dev/null 2>&1
kept=""
for _ in $(seq 1 600); do
    kept=$(grep -o 'session(s) and [0-9]* retained message(s) kept' "$SOCKETLEY_DLOG" | tail -1 | awk '{print $3}')
    [ "$(grep -c 'retained message(s) kept' "$SOCKETLEY_DLOG")" -ge 2 ] && break
    sleep 0.1
done
if [ "$kept" = 30000 ]; then ok; else bad "a restart gives back every retained message" "${kept:-none} of 30000"; fi
got=$(PYTHONPATH="$HERE" timeout 60 python3 - "$P" <<'PY'
import sys
from lib_mqtt import *
p = int(sys.argv[1])
c = Client(p); present, _, _ = c.connect("later", clean=False, props={SESSION_EXPIRY: 3600})
ms = [m.payload.decode() for m in c.messages(100, 3)]
d = Client(p); d.connect("off-7", clean=False, props={SESSION_EXPIRY: 3600})
print(present, ms[0] if ms else None, len(ms), len(d.messages(400, 5)))
PY
)
read -r present first n deep <<<"$got"
if [ "$present" = True ] && [ "$first" = first ] && [ "${n:-0}" = "${sent:-none}" ] && [ "${deep:-0}" = 300 ]; then ok
else bad "a restart gives back what an offline session was given after a snapshot had written it" "$got of $sent"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
