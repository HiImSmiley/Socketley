#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: a dns runtime reads a changed large zone off its loop, and answers from the one before meanwhile.
#
# What each part would catch:
#   * a zone read, checked and freed on the loop: at 300,000 records every query waited 250 ms behind each
#     reload, and at a million over a second
#   * a reload that is read and never served, or served and never looked at again: the last edit not answered
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: a dns runtime reloads a large zone off its loop ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
if nm -C "$BIN" 2>/dev/null | grep -q '__asan_'; then
    echo "  SKIP: a stall in milliseconds measures the sanitizer, not the reload"; exit 0
fi
daemon_isolate dnsreload
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1929))
unset SOCKETLEY_CONFIG
trap 'daemon_stop' EXIT
python3 - "$T/big.zone" <<'PY'
import sys
with open(sys.argv[1], "w") as f:
    f.write("$ORIGIN big.test.\n$TTL 60\n@ SOA ns host 1 1 1 1 1\n@ NS ns\nns A 192.0.2.1\n")
    for i in range(300000):
        f.write("h%d A 10.%d.%d.%d\n" % (i, (i >> 16) & 255, (i >> 8) & 255, i & 255))
PY
daemon_start "$BIN"
"$BIN" create dns ns -p "$P" --bind 127.0.0.1 --zone "$T/big.zone" --rrl 0 --proxy none -s >/dev/null 2>&1

out=$(timeout 120 python3 - "$P" "$T/big.zone" <<'PY'
import re, socket, struct, sys, threading, time
port, path = int(sys.argv[1]), sys.argv[2]
def query(s, name, qid):
    s.sendto(struct.pack("!HHHHHH", qid, 0, 1, 0, 0, 0) +
             b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0" + struct.pack("!HH", 1, 1),
             ("127.0.0.1", port))
    return struct.unpack("!H", s.recv(512)[6:8])[0]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
for _ in range(300):
    try:
        if query(s, "ns.big.test", 1) == 1: break
    except OSError: pass
    time.sleep(0.1)
worst = [0.0]; stop = [False]
def edit():
    # Three edits, each a new serial and a name the one before did not have.
    for k in range(3):
        time.sleep(1.5)
        t = re.sub(r"SOA ns host (\d+)", lambda m: "SOA ns host %d" % (int(m.group(1)) + 1), open(path).read(), count=1)
        open(path, "w").write(t + "e%d A 192.0.2.9\n" % k)
    time.sleep(3); stop[0] = True
th = threading.Thread(target=edit); th.start()
while not stop[0]:
    t = time.perf_counter(); query(s, "ns.big.test", 2); worst[0] = max(worst[0], (time.perf_counter() - t) * 1000)
    time.sleep(0.0005)
th.join()
served = False
for _ in range(100):
    if query(s, "e2.big.test", 3) == 1:
        served = True; break
    time.sleep(0.1)
print("worst %.1f served %s" % (worst[0], served))
PY
)
echo "  the worst query across three reloads of 300,000 records: $out"
w=$(sed -n 's/^worst \([0-9.]*\) .*/\1/p' <<<"$out")
if awk -v w="${w:-999}" 'BEGIN{exit !(w < 40)}'; then ok
else bad "a query never waits behind a reload" "$out"; fi
case "$out" in *"served True") ok ;; *) bad "and the last edit is served" "$out" ;; esac
reloads=$("$BIN" stats ns 2>/dev/null | awk -F: '$1=="zone_reloads" {print $2}')
if [ "${reloads:-0}" -ge 2 ]; then ok; else bad "the edits were taken as reloads" "zone_reloads ${reloads:-none}"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
