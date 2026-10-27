#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# An mqtt runtime's topic rules into a cache and a db, and back into a broker: every message its rules match goes
# to the target beside the broker's own subscribers, and waits for a target that is down.
#
# What each part would catch:
#   * a rule's target missing a message, getting it twice, or getting it in another shape than documented
#   * a %1 or %t placeholder filled wrong
#   * messages for a target that is down lost, reordered or sent twice when it is back
#   * what was delivered before a restart sent again after it
#   * a rule that does not read taken, or refused without naming its line
#   * a webhook rule's message lost when the hook fails for a while, sent twice, reordered, or sent again when the
#     hook refused it
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

echo "=== Integration: an mqtt runtime's topic rules hand messages to a cache, a db and a broker ==="
daemon_isolate mqttroutes
T=$SOCKETLEY_TMPD
PK=$((SL_PORT_BASE + 1940))
PD=$((SL_PORT_BASE + 1941))
PE=$((SL_PORT_BASE + 1944))
PH=$((SL_PORT_BASE + 1945))
HOOK_PID=""
trap '[ -n "$HOOK_PID" ] && kill "$HOOK_PID" 2>/dev/null; daemon_stop' EXIT
daemon_start "$BIN"

printf 'devices private\n' > "$T/schema"
printf 'backend dbbackendsecret0123456789\n' > "$T/keys"
chmod 600 "$T/keys"
"$BIN" create cache kv -p "$PK" -s >/dev/null 2>&1 || bad "a cache is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create db fleet -p "$PD" --schema "$T/schema" --keys "$T/keys" -s >/dev/null 2>&1 \
    || bad "a db is made" "$(tail -3 "$SOCKETLEY_DLOG")"

# Rules that do not read stop the start and say which line.
printf 'sensor/# cache://kv/stack/x\n' > "$T/badroutes"
out=$("$BIN" create mqtt x1 -p "$PE" --anonymous --routes "$T/badroutes" -s 2>&1)
case "$(tail -5 "$SOCKETLEY_DLOG")" in *"line 1: a cache target is"*) ok ;; *) bad "a rule that does not read stops the start and says which" "$out" ;; esac
"$BIN" remove x1 >/dev/null 2>&1

cat > "$T/routes" <<'EOF'
# filter          target
sensor/+/temp     cache://kv/stream/temps-%1
alarm/#           cache://kv/channel/alarms
device/+/state    db://fleet/devices/%1
fwd/#             mqtt://edge/from-edge/%t     # back into the broker, under another topic
EOF
printf 'web/#             http://127.0.0.1:%s/in\nnope/#            http://127.0.0.1:%s/bad\n' "$PH" "$PH" >> "$T/routes"
# A webhook that fails its first two messages, as one that is restarting does, and refuses every one at /bad.
python3 - "$PH" "$T/hook.log" <<'PY' &
import http.server, sys
out, fails = open(sys.argv[2], "a"), {"n": 0}
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        b = self.rfile.read(int(self.headers.get("content-length", 0)))
        if self.path == "/bad":
            self.send_response(400); self.end_headers(); return
        if fails["n"] < 2:
            fails["n"] += 1
            self.send_response(500); self.end_headers(); return
        out.write(self.path + " " + b.decode() + "\n"); out.flush()
        self.send_response(204); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
HOOK_PID=$!
export HOOKLOG="$T/hook.log"
"$BIN" create mqtt edge -p "$PE" --anonymous --routes "$T/routes" --persistent on -s >/dev/null 2>&1 \
    && ok || bad "a broker with topic rules is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for p in "$PK" "$PD" "$PE"; do ready_tcp 127.0.0.1 "$p" || bad "port $p listens" "$(tail -5 "$SOCKETLEY_DLOG")"; done

run() {
    PYTHONPATH="$HERE" python3 - "$1" "$PK" "$PD" "$PE" "$BIN" 2>&1 <<'PY'
import json, os, subprocess, sys, time, urllib.request, urllib.error
from lib_mqtt import *
phase = sys.argv[1]
pk, pd, pe = (int(x) for x in sys.argv[2:5])
binary = sys.argv[5]

def cache(cmd, until=b"\n", timeout=3):
    s = line_client(pk)
    s.sendall(cmd.encode() + b"\n")
    out = read_until(s, until, timeout)
    s.close()
    return out.decode(errors="replace")

def xrange(key, want, timeout=6):
    end = time.time() + timeout
    out = ""
    while time.time() < end:
        out = cache("xrange %s - +" % key, b"end\n", 1)
        if want in out:
            return out
        time.sleep(0.2)
    return out

def doc(path):
    r = urllib.request.Request("http://127.0.0.1:%d%s" % (pd, path),
                               headers={"Authorization": "Bearer dbbackendsecret0123456789"})
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, None

def until_doc(path, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        st, d = doc(path)
        if st == 200:
            return d
        time.sleep(0.2)
    return None

if phase == "rules":
    def rules():
        pub = connected(pe, "edge-pub")
        chan = line_client(pk)
        chan.sendall(b"subscribe alarms\n")
        back = connected(pe, "back-sub")
        back.subscribe(("from-edge/#", 1))
        time.sleep(0.4)

        pub.publish("sensor/k1/temp", "21.5", qos=1)
        pub.publish("sensor/k1/temp", "21.7", qos=1)
        out = xrange("temps-k1", "21.7")
        truth("a cache stream rule adds an entry a message, %1 the level '+' matched",
              "21.5" in out and "21.7" in out and out.index("21.5") < out.index("21.7"), out)
        truth("each entry naming the topic, the payload, the QoS and the client",
              "topic sensor/k1/temp" in out and "payload 21.5" in out and "qos 1" in out and "client edge-pub" in out, out)

        pub.publish("alarm/fire/hall", "smoke", qos=1)
        got = read_until(chan, b"smoke")
        truth("a cache channel rule publishes the payload to the channel's subscribers", b"smoke" in got, got)

        pub.publish("device/d1/state", json.dumps({"on": True, "level": 3}), qos=1)
        d = until_doc("/c/devices/d1")
        truth("a db rule puts a JSON payload as the document, %1 its id",
              d is not None and d.get("on") is True and d.get("level") == 3, d)
        pub.publish("device/d2/state", "not json", qos=1)
        d = until_doc("/c/devices/d2")
        truth("and wraps any other payload with its topic", d is not None and d.get("payload") == "not json" and
              d.get("topic") == "device/d2/state", d)
        pub.publish("device/d1/state", json.dumps({"on": False}), qos=1)
        end = time.time() + 5
        while time.time() < end and (doc("/c/devices/d1")[1] or {}).get("on") is not False:
            time.sleep(0.2)
        check("and a later message replaces the document", (doc("/c/devices/d1")[1] or {}).get("on"), False)

        pub.publish("fwd/a/b", "carried", qos=1)
        m = back.message(3)
        check("an mqtt rule publishes on a broker, %t the whole topic",
              (m.topic, m.payload) if m else None, ("from-edge/fwd/a/b", b"carried"))

        # A target that is down holds its messages until it is back.
        subprocess.run([binary, "stop", "kv"], capture_output=True, timeout=30)
        for i in range(5):
            pub.publish("sensor/k2/temp", "held-%d" % i, qos=1)
        end = time.time() + 10
        while time.time() < end and stat_sum(binary, "edge", "rule_0_queued") < 1:
            time.sleep(0.2)
        truth("messages for a stopped target are kept", stat_sum(binary, "edge", "rule_0_queued") >= 1,
              stat_sum(binary, "edge", "rule_0_queued"))
        subprocess.run([binary, "start", "kv"], capture_output=True, timeout=30)
        xrange("temps-k2", "held-4", 30)
        time.sleep(0.5)
        out = xrange("temps-k2", "held-4", 2)
        got = [w for l in out.splitlines() for w in l.split() if w.startswith("held-")]
        check("and all of them reach it once it is back, once each and in order", got,
              ["held-%d" % i for i in range(5)])

        # A webhook rule: every message, in order and once, though the hook answered the first two with a 500.
        for i in range(3):
            pub.publish("web/a/b", "w%d" % i, qos=1)
        end = time.time() + 20
        lines = []
        while time.time() < end and len(lines) < 3:
            try:
                lines = [l for l in open(os.environ["HOOKLOG"]).read().splitlines() if l.startswith("/in ")]
            except OSError:
                pass
            time.sleep(0.2)
        bodies = [json.loads(l.split(" ", 1)[1]) for l in lines]
        check("a webhook rule POSTs each message as JSON, in order and once, though the hook failed twice",
              [(b.get("topic"), b.get("payload"), b.get("qos"), b.get("client")) for b in bodies],
              [("web/a/b", "w%d" % i, 1, "edge-pub") for i in range(3)])
        # The hook logs a body before its answer is read and the count pushed, so the count is waited for.
        end = time.time() + 20
        while time.time() < end and stat_sum(binary, "edge", "rule_4_delivered") < 3:
            time.sleep(0.2)
        check("and counts them delivered", stat_sum(binary, "edge", "rule_4_delivered"), 3)
        pub.publish("nope/x", "no", qos=1)
        end = time.time() + 10
        while time.time() < end and stat_sum(binary, "edge", "rule_5_failed") < 1:
            time.sleep(0.2)
        check("a message the hook refuses with a 400 is counted failed and not sent again",
              (stat_sum(binary, "edge", "rule_5_failed"), stat_sum(binary, "edge", "rule_5_queued")), (1, 0))

        # Past what a rule holds for a target that is down the oldest go, and the log says so once and then how
        # many, where the broken build only counted them.
        dlog = os.environ.get("SOCKETLEY_DLOG", "")

        def said(text):
            try:
                return open(dlog, errors="replace").read().count(text)
            except OSError:
                return -1
        subprocess.run([binary, "stop", "kv"], capture_output=True, timeout=30)
        # Past the queue's bound and the rule's window of 64 in flight, which a loaded machine keeps fuller.
        limit, window, over = 100000, 64, 10
        total = limit + window + over
        body = s("alarm/flood") + b"\x00" + b"f"   # 5.0: no properties
        pub.sock.sendall((bytes([PUBLISH << 4]) + varint(len(body)) + body) * total)
        end = time.time() + 60
        while time.time() < end and stat_sum(binary, "edge", "received_qos0") < total:
            time.sleep(0.2)
        dropped = stat_sum(binary, "edge", "rule_1_dropped")
        held = stat_sum(binary, "edge", "rule_1_queued")
        truth("a rule holding as much as it may for a stopped target drops the oldest, counted",
              dropped >= over and dropped + held == total, "dropped %d held %d of %d" % (dropped, held, total))
        check("and says so in the log once", said("mqtt: the rule for alarm/# holds 100000 requests"), 1)
        subprocess.run([binary, "start", "kv"], capture_output=True, timeout=30)
        end = time.time() + 120
        while time.time() < end and stat_sum(binary, "edge", "rule_1_queued") > limit // 2:
            time.sleep(0.2)
        pub.publish("alarm/after", "x", qos=1)
        end = time.time() + 10
        while time.time() < end and said("%d mqtt rule request(s) were dropped while it was full" % dropped) < 1:
            time.sleep(0.2)
        check("and how many, once it has room again",
              said("%d mqtt rule request(s) were dropped while it was full" % dropped), 1)
        pub.disconnect()
        back.disconnect()
    guarded("rules", rules)

if phase == "after":
    def after():
        pub = connected(pe, "edge-pub2")
        pub.publish("device/d3/state", "{}", qos=1)
        # The daemon's figures are the worker's last report, which follows the restart within a second or so.
        end = time.time() + 15
        while time.time() < end and stat_sum(binary, "edge", "rule_2_delivered") != 1:
            time.sleep(0.2)
        check("after a restart the rules count afresh", stat_sum(binary, "edge", "rule_2_delivered"), 1)
        check("and what was delivered before the stop is not sent again", stat_sum(binary, "edge", "rule_0_delivered"), 0)
        pub.disconnect()
    guarded("after", after)
PY
}

export SOCKETLEY_DLOG
tally < <(run rules)
"$BIN" stop edge >/dev/null 2>&1
"$BIN" start edge >/dev/null 2>&1
ready_tcp 127.0.0.1 "$PE" || bad "the broker with rules starts again" "$(tail -5 "$SOCKETLEY_DLOG")"
tally < <(run after)

st=$("$BIN" stats edge 2>&1)
case "$st" in *"rule_0_target:sensor/+/temp cache://kv/stream/temps-%1"*"rule_3_target:fwd/# mqtt://edge/from-edge/%t"*) ok ;;
    *) bad "stats name each rule and its target" "$st" ;; esac

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
