#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# An mqtt runtime's topic rules into a storage and a server: messages gathered into one NDJSON object a minute,
# and every client of a server handed each message as a line.
#
# What each part would catch:
#   * a storage object written per message instead of per batch, or one a stop loses
#   * a batch cut at stop not kept across the restart, or written twice after it
#   * a server rule's line in another shape than documented
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
. "$HERE/lib_ready.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
. "$HERE/lib_verdicts.sh"

echo "=== Integration: an mqtt runtime's topic rules write a storage's objects and a server's lines ==="
daemon_isolate mqttbatch
T=$SOCKETLEY_TMPD
PT=$((SL_PORT_BASE + 1942))
PV=$((SL_PORT_BASE + 1943))
PE=$((SL_PORT_BASE + 1944))
trap 'daemon_stop' EXIT
daemon_start "$BIN"

"$BIN" create storage raw -p "$PT" --dir "$T/raw" --anonymous -s >/dev/null 2>&1 \
    || bad "a storage is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create server chat -p "$PV" -s >/dev/null 2>&1 || bad "a server is made" "$(tail -3 "$SOCKETLEY_DLOG")"
cat > "$T/routes" <<'EOF'
log/#             storage://raw/logs/%Y/
chat/#            server://chat
EOF
"$BIN" create mqtt edge -p "$PE" --anonymous --routes "$T/routes" --persistent on -s >/dev/null 2>&1 \
    && ok || bad "a broker with topic rules is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for p in "$PT" "$PV" "$PE"; do ready_tcp 127.0.0.1 "$p" || bad "port $p listens" "$(tail -5 "$SOCKETLEY_DLOG")"; done
curl -s -o /dev/null -X PUT "http://127.0.0.1:$PT/logs"

run() {
    PYTHONPATH="$HERE" python3 - "$1" "$PT" "$PV" "$PE" "$BIN" 2>&1 <<'PY'
import json, sys, time, urllib.request
from lib_mqtt import *
phase = sys.argv[1]
pt, pv, pe = (int(x) for x in sys.argv[2:5])
binary = sys.argv[5]

def keys(bucket):
    with urllib.request.urlopen("http://127.0.0.1:%d/%s?list-type=2" % (pt, bucket)) as r:
        x = r.read().decode()
    return [k.split("</Key>")[0] for k in x.split("<Key>")[1:]]

if phase == "rules":
    def rules():
        pub = connected(pe, "edge-pub")
        chat = line_client(pv)
        chat.sendall(b"hello\n")
        time.sleep(0.4)
        pub.publish("chat/room1", "hi room", qos=1)
        got = read_until(chat, b"hi room")
        truth("a server rule hands every client of the server the message as a JSON line",
              b'{"topic":"chat/room1","payload":"hi room"}' in got, got)
        for i in range(3):
            pub.publish("log/app", "line %d" % i, qos=1)
        time.sleep(0.5)
        check("a storage rule writes nothing until its batch is cut", keys("logs"), [])
        pub.disconnect()
        chat.close()
        time.sleep(1.2)
    guarded("rules", rules)

if phase == "batched":
    def batched():
        end = time.time() + 15
        ks = []
        while time.time() < end:
            ks = keys("logs")
            if ks:
                break
            time.sleep(0.3)
        truth("a stop cuts the batch into one object, kept across the restart and written after it",
              len(ks) == 1 and ks[0].startswith(time.strftime("%Y/", time.gmtime())) and ks[0].endswith(".ndjson"), ks)
        if ks:
            with urllib.request.urlopen("http://127.0.0.1:%d/logs/%s" % (pt, ks[0])) as r:
                body = r.read().decode()
            lines = [json.loads(l) for l in body.splitlines()]
            check("holding one JSON line a message, in order", [l["payload"] for l in lines],
                  ["line 0", "line 1", "line 2"])
            truth("each with its topic and time", all(l["topic"] == "log/app" and l["at"] > 0 for l in lines), lines)
        end = time.time() + 15
        while time.time() < end and stat_sum(binary, "edge", "rule_0_delivered") != 1:
            time.sleep(0.2)
        check("the batch is the storage rule's one delivery", stat_sum(binary, "edge", "rule_0_delivered"), 1)
        time.sleep(1.5)
        check("and is not written twice", len(keys("logs")), 1)
    guarded("batched", batched)
PY
}

tally < <(run rules)
"$BIN" stop edge >/dev/null 2>&1
"$BIN" start edge >/dev/null 2>&1
ready_tcp 127.0.0.1 "$PE" || bad "the broker with rules starts again" "$(tail -5 "$SOCKETLEY_DLOG")"
tally < <(run batched)

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
