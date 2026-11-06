#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: an mqtt runtime over TLS hands a subscriber's send key to the kernel for a large payload, and only
# then.
#
# What each part would catch:
#   * plaintext reaching the socket before the key update OpenSSL encrypted has gone, or what was sent meanwhile put
#     ahead of it: a subscriber that cannot read its messages
#   * a connection switched for small packets, which costs it more than the records encrypted here
#   * the messages after a switch -- small and large, QoS 0 and 1, to many subscribers at once -- sent the wrong way
#   * a key update after the switch, the client's own and one it asks for, which the kernel must take or the
#     connection must end
#   * SOCKETLEY_KERNEL_TLS=0 not keeping every record in user space
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

echo "=== Integration: an mqtt runtime over TLS moves a subscriber's send key to the kernel for a large payload ==="
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }
[ -r /proc/net/tls_stat ] || { echo "  SKIP: the kernel has no TLS layer here (modprobe tls)"; exit 0; }
daemon_isolate mqttktls
P=$((SL_PORT_BASE + 1971))
T=$(mktemp -d /tmp/socketley-mktls-XXXXXX)
trap 'daemon_stop; rm -rf "$T"' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=127.0.0.1 \
    -keyout "$T/k.pem" -out "$T/c.pem" >/dev/null 2>&1
start_broker() {
    "$BIN" create mqtt mk -p "$P" --anonymous --max-packet 16M --tls --cert "$T/c.pem" --key "$T/k.pem" -s \
        >/dev/null 2>&1 && ok || bad "a broker over TLS taking large packets is made" "$(tail -3 "$SOCKETLEY_DLOG")"
    ready_tcp 127.0.0.1 "$P" || bad "port $P listens" "$(tail -5 "$SOCKETLEY_DLOG")"
}

cat > "$T/run.py" <<'PY'
import os, ssl, subprocess, sys
from lib_mqtt import *
port, part = int(sys.argv[1]), sys.argv[2]

def ctx():
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    c.minimum_version = ssl.TLSVersion.TLSv1_3
    return c

def kernel(cl):
    # This client's connection at the broker's end, as ss shows it: its send key in the kernel or not.
    me = cl.sock.getsockname()[1]
    out = subprocess.run(["ss", "-tniH", "state", "established", "( sport = :%d and dport = :%d )" % (port, me)],
                         capture_output=True, text=True).stdout
    return "txconf: sw" in out or "tx: sw" in out

def payload(i, n):
    return ((b"%d-" % i) * (n // len(b"%d-" % i) + 1))[:n]

def whole(got, want):
    return [len(m.payload) if m.payload == w else "cut at %d" % len(m.payload) for m, w in zip(got, want)] + \
           ["missing"] * (len(want) - len(got))

def sub(name):
    c = Client(port, tls=ctx(), timeout=30)
    c.connect(name)
    c.subscribe(("k/#", 1))
    return c

if part == "moved":
    s = sub("one")
    pub = Client(port, tls=ctx(), timeout=30)
    pub.connect("pub")
    small = [payload(i, n) for i, n in enumerate([16 << 10, 100, 200 << 10])]
    for p in small:
        pub.publish("k/t", p, qos=1)
    check("small payloads alone come whole", whole(s.messages(len(small), 20), small), [len(p) for p in small])
    truth("and leave the subscriber's connection in user space", not kernel(s))
    # A large one, then every size and QoS after it, on the one connection.
    sizes = [(1 << 20, 0), (100, 0), (3 << 20, 1), (16 << 10, 1), (300 << 10, 0), (8 << 20, 1), (5, 0), (2 << 20, 0)]
    want = [payload(10 + i, n) for i, (n, _) in enumerate(sizes)]
    # Each read before the next goes, since a subscriber this far behind may be dropped a QoS 0 message.
    got = []
    for (n, q), p in zip(sizes, want):
        pub.publish("k/t", p, qos=q)
        got += s.messages(1, 30)
    check("a large payload moves its subscriber, and every message after it comes whole and in order",
          whole(got, want), [n for n, _ in sizes])
    truth("the subscriber's connection sends through kernel TLS", kernel(s))
    # The publisher's own connection carried acks only, so it stays as it was.
    truth("the publisher's connection, sent nothing large, is not moved", not kernel(pub))
elif part == "many":
    subs = [sub("m%d" % i) for i in range(8)]
    pub = Client(port, tls=ctx(), timeout=30)
    pub.connect("pub2")
    want = [payload(30, 2 << 20), payload(31, 700), payload(32, 1 << 20)]
    for i, p in enumerate(want):
        pub.publish("k/t", p, qos=i % 2)
    good = sum(whole(c.messages(len(want), 30), want) == [len(p) for p in want] for c in subs)
    check("eight subscribers each get three messages whole, the large ones through kernel TLS", good, len(subs))
    truth("all eight were moved", all(kernel(c) for c in subs), [kernel(c) for c in subs])
elif part == "off":
    s = sub("off")
    pub = Client(port, tls=ctx(), timeout=30)
    pub.connect("pub3")
    want = [payload(40, 3 << 20), payload(41, 10)]
    for p in want:
        pub.publish("k/t", p, qos=1)
    check("with SOCKETLEY_KERNEL_TLS=0 a large payload comes whole", whole(s.messages(2, 30), want), [len(p) for p in want])
    truth("and its subscriber's connection stays in user space", not kernel(s))
elif part == "publish":
    pub = Client(port, tls=ctx(), timeout=30)
    pub.connect("pub-" + sys.argv[3])
    pub.publish("k/t", sys.argv[3].encode() * (int(sys.argv[4]) // len(sys.argv[3])), qos=1)
    pub.disconnect()
PY
py() { PYTHONPATH="$HERE" python3 "$T/run.py" "$P" "$@" 2>&1; }

daemon_start "$BIN"
start_broker
tally < <(py moved)
tally < <(py many)

# Key updates after the switch, the client's own and one it asks the broker for: openssl's client subscribes, a large
# payload moves its connection, then the update, then a small payload.  Not -ign_eof, which turns s_client's command
# letters off.
for cmd in k K; do
    { printf '\x10\x0e\x00\x04MQTT\x04\x02\x00\x3c\x00\x02k%s' "$cmd"; sleep 0.5
      printf '\x82\x08\x00\x01\x00\x03k/t\x00'; sleep 1
      py publish BIGPAYLOAD $((1 << 20)) >/dev/null; sleep 1.5
      printf '%s\n' "$cmd"; sleep 1
      py publish AFTERUPDATE 1100 >/dev/null; sleep 1.5; } |
        timeout 20 openssl s_client -connect "127.0.0.1:$P" -tls1_3 > "$T/ku$cmd" 2>&1
    big=$(grep -ao 'BIGPAYLOAD' "$T/ku$cmd" | wc -l); after=$(grep -ao 'AFTERUPDATE' "$T/ku$cmd" | wc -l)
    broken=$(grep -acE 'bad record mac|decryption failed|wrong version number|record layer failure' "$T/ku$cmd")
    if [ "$broken" = 0 ] && [ "$big" -ge $(( (1 << 20) / 10 )) ] && [ "$after" = 100 ]; then ok
    elif [ "$cmd" = K ] && [ "$broken" = 0 ] && [ "$big" -ge $(( (1 << 20) / 10 )) ]; then
        echo "  note: this kernel takes no second send key, so the connection ended at the asked-for update"; ok
    else bad "a key update ('$cmd') after the switch is followed by the next message" \
        "big $big, after $after, $broken record errors: $(grep -aE 'error|alert' "$T/ku$cmd" | head -2 | tr '\n' ' ')"; fi
done
daemon_stop

# SOCKETLEY_KERNEL_TLS=0: large payloads are encrypted here, and whole.
daemon_isolate mqttktls-off
SOCKETLEY_KERNEL_TLS=0 daemon_start "$BIN"
start_broker
tally < <(py off)

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
