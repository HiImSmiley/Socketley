#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Clients other people wrote, against an mqtt runtime: the Mosquitto command-line clients and Eclipse Paho, over
# MQTT 3.1.1 and 5.0, TCP, TLS and WebSocket.
#
#   mosquitto_pub / mosquitto_sub  passwords, QoS 0-2, retained, wills, -C counts, 3.1.1 and 5.0, TLS
#   mosquitto_rr                   request and response through a 5.0 response topic and correlation data
#   paho-mqtt (python)             a persistent session across a reconnect, QoS 2, a will, WebSocket, TLS
#
# A client that is not on PATH, or paho not importable, is skipped and said so.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
. "$HERE/lib_ready.sh"

PASS=0; FAIL=0; SKIPPED=0
pass() { PASS=$((PASS + 1)); }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL [$1]: ${2:-}"; }
skip() { SKIPPED=$((SKIPPED + 1)); echo "  SKIP: $1"; }
expect() { [ "$2" = "$3" ] && pass || fail "$1" "got '$2', want '$3'"; }

echo "=== Integration: the Mosquitto clients and Paho against an mqtt runtime ==="
daemon_isolate mqttclients
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1960))
PW=$((SL_PORT_BASE + 1961))
PT=$((SL_PORT_BASE + 1962))
trap 'daemon_stop' EXIT
daemon_start "$BIN"

printf 'devpass1\n' | "$BIN" mqtt-passwd "$T/users" dev >/dev/null 2>&1
(
    cd "$T"
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=test-ca" -keyout ca.key -out ca.pem
    openssl req -newkey rsa:2048 -nodes -subj "/CN=127.0.0.1" -keyout srv.key -out srv.csr
    printf 'subjectAltName=IP:127.0.0.1\n' > srv.ext
    openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile srv.ext -out srv.pem
) >/dev/null 2>&1
"$BIN" create mqtt b -p "$P" --users "$T/users" --ws "$PW" -s >/dev/null 2>&1 \
    || fail "a broker is made" "$(tail -3 "$SOCKETLEY_DLOG")"
"$BIN" create mqtt bt -p "$PT" --tls --cert "$T/srv.pem" --key "$T/srv.key" --users "$T/users" -s >/dev/null 2>&1 \
    || fail "a TLS broker is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for p in "$P" "$PW" "$PT"; do ready_tcp 127.0.0.1 "$p" || fail "port $p listens" "$(tail -5 "$SOCKETLEY_DLOG")"; done
A=(-h 127.0.0.1 -p "$P" -u dev -P devpass1)

if command -v mosquitto_sub >/dev/null 2>&1 && command -v mosquitto_pub >/dev/null 2>&1; then
    for v in mqttv311 mqttv5; do
        mosquitto_sub "${A[@]}" -V "$v" -t "m/$v/#" -q 2 -C 3 -W 10 -v > "$T/sub.$v" 2>&1 &
        sp=$!
        sleep 0.5
        mosquitto_pub "${A[@]}" -V "$v" -t "m/$v/a" -m zero -q 0
        mosquitto_pub "${A[@]}" -V "$v" -t "m/$v/b" -m one -q 1
        mosquitto_pub "${A[@]}" -V "$v" -t "m/$v/c" -m two -q 2
        wait "$sp"; rc=$?
        expect "mosquitto_sub $v hears QoS 0, 1 and 2 from mosquitto_pub" "$rc:$(sort "$T/sub.$v" | tr '\n' '|')" \
            "0:m/$v/a zero|m/$v/b one|m/$v/c two|"
    done
    mosquitto_pub "${A[@]}" -t m/kept -m retained-value -r -q 1
    got=$(mosquitto_sub "${A[@]}" -t m/kept -C 1 -W 5 -F '%r %p' 2>&1)
    expect "a retained message is handed to a later mosquitto_sub, flagged" "$got" "1 retained-value"
    mosquitto_pub "${A[@]}" -t m/kept -r -n
    got=$(mosquitto_sub "${A[@]}" -t m/kept -C 1 -W 2 2>&1); rc=$?
    expect "mosquitto_pub -r -n clears it" "$rc:$got" "27:Timed out"
    out=$(mosquitto_pub -h 127.0.0.1 -p "$P" -u dev -P wrong -t x -m y 2>&1); rc=$?
    case "$out" in *"ad user name or password"*) [ "$rc" -ne 0 ] && pass || fail "a wrong password exits non-zero" "rc $rc" ;;
        *) fail "a wrong password is refused, as mosquitto_pub reports it" "rc $rc: $out" ;; esac
    # A will: a subscriber that stays, and a client killed while holding one.
    mosquitto_sub "${A[@]}" -t m/will -C 1 -W 10 > "$T/will" 2>&1 &
    sp=$!
    sleep 0.4
    mosquitto_sub "${A[@]}" -i will-holder -t nothing --will-topic m/will --will-payload "holder died" --will-qos 1 >/dev/null 2>&1 &
    hp=$!
    sleep 0.6
    kill -9 "$hp" 2>/dev/null
    wait "$hp" 2>/dev/null
    wait "$sp"
    expect "a client killed with a will set gets its will sent" "$(cat "$T/will")" "holder died"
    # A persistent session: -c with an id, the messages published while it was away delivered when it is back.
    mosquitto_sub "${A[@]}" -i away -c -t m/away -q 1 -C 1 -W 3 >/dev/null 2>&1 &
    sleep 0.5; kill "$!" 2>/dev/null; wait "$!" 2>/dev/null
    for i in 1 2 3; do mosquitto_pub "${A[@]}" -t m/away -m "while away $i" -q 1; done
    got=$(mosquitto_sub "${A[@]}" -i away -c -t m/away -q 1 -C 3 -W 5 2>&1 | tr '\n' '|')
    expect "mosquitto_sub -c gets what was published while it was away" "$got" "while away 1|while away 2|while away 3|"
    got=$(mosquitto_sub "${A[@]}" -t '$SYS/broker/version' -C 1 -W 5 2>&1)
    case "$got" in "socketley "*) pass ;; *) fail "\$SYS/broker/version says the broker" "$got" ;; esac
    mosquitto_sub -h 127.0.0.1 -p "$PT" --cafile "$T/ca.pem" -u dev -P devpass1 -t m/tls -C 1 -W 10 > "$T/tls" 2>&1 &
    sp=$!
    sleep 0.6
    mosquitto_pub -h 127.0.0.1 -p "$PT" --cafile "$T/ca.pem" -u dev -P devpass1 -t m/tls -m "over tls" -q 1
    wait "$sp"
    expect "mosquitto_pub and mosquitto_sub speak over TLS" "$(cat "$T/tls")" "over tls"
    head -c 200000 /dev/urandom > "$T/big.in"
    mosquitto_sub "${A[@]}" -t m/big -C 1 -W 10 -N > "$T/big" 2>/dev/null &
    sp=$!
    sleep 0.4
    mosquitto_pub "${A[@]}" -t m/big -f "$T/big.in" -q 1
    wait "$sp"
    expect "a 200 KB binary message arrives whole" "$(md5sum < "$T/big" | cut -c1-32)" "$(md5sum < "$T/big.in" | cut -c1-32)"
else
    skip "mosquitto_pub and mosquitto_sub are not on PATH"
fi

if command -v mosquitto_rr >/dev/null 2>&1; then
    PYTHONPATH="$HERE" python3 - "$P" > "$T/responder" 2>&1 <<'PY' &
import sys
from lib_mqtt import *
c = connected(int(sys.argv[1]), "responder", username="dev", password="devpass1")
c.subscribe(("rpc/time", 1))
m = c.message(10)
if m:
    back = {CORRELATION: m.props[CORRELATION]} if CORRELATION in m.props else None
    c.publish(m.props[RESPONSE_TOPIC], b"pong:" + m.payload + b":" + m.props.get(CORRELATION, b"-"), qos=1, props=back)
    print("answered")
c.disconnect()
PY
    rp=$!
    sleep 0.6
    got=$(mosquitto_rr "${A[@]}" -t rpc/time -e rpc/reply/me -D publish correlation-data req-42 -m ping -W 5 2>&1)
    wait "$rp"
    expect "mosquitto_rr gets the answer to its request through the response topic, its correlation data with it" \
        "$got" "pong:ping:req-42"
else
    skip "mosquitto_rr is not on PATH"
fi

if python3 -c 'import paho.mqtt.client' 2>/dev/null; then
    cat > "$T/paho_check.py" <<'PY'
import ssl, sys, threading, time
import paho.mqtt.client as mqtt
port, wsport, tport, tmpd = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]

def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))

class Box:
    def __init__(self):
        self.msgs, self.ev, self.rc = [], threading.Event(), None

def client(cid, proto, transport="tcp", clean=True, will=None, tls=False):
    kw = {"client_id": cid, "protocol": proto, "transport": transport}
    if proto != mqtt.MQTTv5:
        kw["clean_session"] = clean
    c = mqtt.Client(**kw)
    box = Box()
    c.username_pw_set("dev", "devpass1")
    if will:
        c.will_set(*will)
    if tls:
        c.tls_set(ca_certs=tmpd + "/ca.pem")
    if transport == "websockets":
        c.ws_set_options(path="/mqtt")
    def on_connect(cl, ud, flags, rc, props=None):
        code = rc.value if hasattr(rc, "value") else int(rc)
        box.rc = (flags.get("session present") if isinstance(flags, dict) else flags.session_present, code)
        box.ev.set()
    def on_message(cl, ud, msg):
        box.msgs.append((msg.topic, msg.payload, msg.qos))
    c.on_connect = on_connect
    c.on_message = on_message
    return c, box

def up(c, box, p, **kw):
    box.ev.clear()
    c.connect("127.0.0.1", p, keepalive=30, **kw)
    c.loop_start()
    box.ev.wait(5)

def wait_for(box, n, t=5):
    end = time.time() + t
    while len(box.msgs) < n and time.time() < end:
        time.sleep(0.05)

for name, proto in (("3.1.1", mqtt.MQTTv311), ("5.0", mqtt.MQTTv5)):
    s, sb = client("paho-sub-" + name, proto)
    up(s, sb, port)
    s.subscribe("p/" + name + "/#", qos=2)
    time.sleep(0.4)
    p, pb = client("paho-pub-" + name, proto)
    up(p, pb, port)
    for q in (0, 1, 2):
        p.publish("p/%s/q%d" % (name, q), b"payload-%d" % q, qos=q).wait_for_publish(5)
    wait_for(sb, 3)
    check("paho %s: QoS 0, 1 and 2 arrive at their QoS" % name, sorted(sb.msgs),
          [("p/%s/q%d" % (name, q), b"payload-%d" % q, q) for q in (0, 1, 2)])
    p.loop_stop(); p.disconnect(); s.loop_stop(); s.disconnect()

# A persistent 3.1.1 session: away, then back with what it missed.
s, sb = client("paho-keep", mqtt.MQTTv311, clean=False)
up(s, sb, port)
s.subscribe("p/keep", qos=1)
time.sleep(0.3)
s.loop_stop(); s.disconnect()
p, pb = client("paho-keeper-pub", mqtt.MQTTv311)
up(p, pb, port)
for i in range(3):
    p.publish("p/keep", b"missed-%d" % i, qos=1).wait_for_publish(5)
s, sb = client("paho-keep", mqtt.MQTTv311, clean=False)
up(s, sb, port)
wait_for(sb, 3)
check("paho: a clean_session=False client is told its session is there", sb.rc, (1, 0))
check("and gets what it missed, in order", [m[1] for m in sb.msgs], [b"missed-0", b"missed-1", b"missed-2"])
s.loop_stop(); s.disconnect()

# WebSocket, as a browser's paho does it.
w, wb = client("paho-ws", mqtt.MQTTv311, transport="websockets")
up(w, wb, wsport)
check("paho over WebSocket connects", wb.rc, (0, 0))
w.subscribe("p/ws", qos=1)
time.sleep(0.3)
p.publish("p/ws", b"to the browser", qos=1).wait_for_publish(5)
wait_for(wb, 1)
check("and receives", [m[1] for m in wb.msgs], [b"to the browser"])
w.loop_stop(); w.disconnect()

# TLS.
t, tb = client("paho-tls", mqtt.MQTTv5, tls=True)
up(t, tb, tport)
check("paho over TLS connects", tb.rc[1] if tb.rc else None, 0)
t.subscribe("p/tls", qos=1)
time.sleep(0.3)
t.publish("p/tls", b"secure", qos=1).wait_for_publish(5)
wait_for(tb, 1)
check("and hears its own message", [m[1] for m in tb.msgs], [b"secure"])
t.loop_stop(); t.disconnect()

# A will left by a client whose socket is cut.
s, sb = client("paho-will-sub", mqtt.MQTTv311)
up(s, sb, port)
s.subscribe("p/will", qos=1)
time.sleep(0.3)
d, db = client("paho-dies", mqtt.MQTTv311, will=("p/will", b"paho died", 1, False))
up(d, db, port)
d.loop_stop()
d.socket().close()
wait_for(sb, 1)
check("paho: a will is sent when its socket is cut", [m[1] for m in sb.msgs], [b"paho died"])
s.loop_stop(); s.disconnect()
p.loop_stop(); p.disconnect()
PY
    while IFS= read -r l; do
        case "$l" in ok\ *) pass ;; bad\ *) fail "${l#bad }" ;; *) echo "  $l" ;; esac
    done < <(python3 "$T/paho_check.py" "$P" "$PW" "$PT" "$T" 2>&1)
else
    skip "paho-mqtt is not importable"
fi

echo "  Results: $PASS passed, $FAIL failed, $SKIPPED clients skipped"
[ "$FAIL" -eq 0 ] || { echo "  FAILED"; exit 1; }
[ "$PASS" -gt 0 ] || { echo "  SKIPPED: no MQTT client ran, nothing was asserted"; exit 0; }
echo "  OK"
exit 0
