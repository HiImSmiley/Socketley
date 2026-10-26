#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# The mqtt runtime as a broker: MQTT 3.1, 3.1.1 and 5.0, its sessions, its CLI, and what survives a restart.
#
# What each part would catch:
#   * a QoS 1 or 2 message lost, delivered twice, or acknowledged before the broker holds it
#   * a session that forgets its subscriptions or its queued messages across a disconnect, a stop or a kill -9
#   * a will sent on a clean disconnect, not sent on a lost one, or sent before its delay
#   * a wildcard that matches $SYS, a retained message that is not replaced or not cleared
#   * a client that breaks the protocol -- a packet too large, a topic alias out of range -- kept connected
#   * a 5.0 property dropped on the way: expiry, response topic, correlation data, user properties
#   * mqtt-pub, mqtt-sub, mqtt-sessions, mqtt-kick and mqtt-retained answering wrong or not at all
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
tally() { while IFS= read -r line; do case "$line" in ok\ *) ok ;; bad\ *) bad "${line#bad }" "" ;; *) echo "  $line" ;; esac; done; }
expect() { [ "$2" = "$3" ] && ok || bad "$1" "got '$2', want '$3'"; }

echo "=== Integration: the mqtt runtime is a broker whose sessions outlive their connections ==="
daemon_isolate mqtt
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 1930))
trap 'daemon_stop' EXIT
daemon_start "$BIN"

# ── refusals ────────────────────────────────────────────────────────────────
out=$("$BIN" create mqtt x1 -p "$P" 2>&1); rc=$?
case "$out" in *"say who may connect"*) [ "$rc" -eq 1 ] && ok || bad "a broker nobody may connect to is refused with exit 1" "rc $rc" ;;
    *) bad "a broker without --users, --idp, --ca or --anonymous is refused" "rc $rc: $out" ;; esac
"$BIN" remove x1 >/dev/null 2>&1
out=$("$BIN" create mqtt x2 -p "$P" --anonymous --ws "$P" 2>&1); rc=$?
case "$out" in *"--ws needs a port of its own"*) ok ;; *) bad "a WebSocket port equal to the MQTT port is refused" "rc $rc: $out" ;; esac
"$BIN" remove x2 >/dev/null 2>&1
out=$("$BIN" create mqtt x3 -p "$P" --anonymous --max-packet 10 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok || bad "a --max-packet below 64 bytes is refused" "rc $rc: $out"
"$BIN" remove x3 >/dev/null 2>&1
out=$("$BIN" create mqtt x4 -p "$P" --anonymous --ca "$T/none.pem" 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok || bad "--ca without --tls is refused" "rc $rc: $out"
"$BIN" remove x4 >/dev/null 2>&1
out=$("$BIN" create mqtt x5 -p "$P" --anonymous --listen unix:/tmp/x.sock 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok || bad "--listen unix: is refused" "rc $rc: $out"
"$BIN" remove x5 >/dev/null 2>&1

"$BIN" create mqtt m -p "$P" --anonymous --persistent on --max-packet 64K --session-expiry 1h -s >/dev/null 2>&1 \
    && ok || bad "a broker is made and started" "$(tail -3 "$SOCKETLEY_DLOG")"
ready_tcp 127.0.0.1 "$P" || bad "the broker listens" "$(tail -5 "$SOCKETLEY_DLOG")"

run() {
    PYTHONPATH="$HERE" python3 - "$1" "$P" "$BIN" "$T" 2>&1 <<'PY'
import os, socket, struct, subprocess, sys, threading, time
from lib_mqtt import *
phase, port, binary, tmpd = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]

def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))

def truth(name, cond, detail=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + str(detail)))

def cli(*args, stdin=None):
    r = subprocess.run([binary] + list(args), input=stdin, capture_output=True, timeout=30)
    return r.returncode, r.stdout.decode(errors="replace")

def guarded(name, fn):
    try:
        fn()
    except Exception as e:
        print("bad %s: %s %s" % (name, type(e).__name__, e))

if phase == "main":
    # ── connecting ──────────────────────────────────────────────────────────
    def connecting():
        c = Client(port)
        present, code, pr = c.connect("", props={SESSION_EXPIRY: 0})
        check("a 5.0 client without an id is let in", code, 0)
        truth("and is told the id it was given", ASSIGNED_ID in pr and len(pr[ASSIGNED_ID]) > 8, pr)
        check("the receive maximum is said", pr.get(RECEIVE_MAX), 1024)
        check("the largest packet is said", pr.get(MAX_PACKET), 64 * 1024)
        truth("a topic alias maximum is said", pr.get(ALIAS_MAX, 0) > 0, pr)
        truth("and PINGREQ is answered", c.ping())
        c.disconnect()

        c = Client(port, version=4)
        present, code, _ = c.connect("", clean=False)
        check("a 3.1.1 client without an id keeping its session is refused", code, 0x02)
        c.close()
        c = Client(port, version=4)
        check("a 3.1.1 client without an id on a clean session is let in", c.connect("")[1], 0)
        c.disconnect()
        c = Client(port, version=3)
        check("a 3.1 client is let in", c.connect("old-client")[1], 0)
        truth("and speaks", c.ping())
        c.disconnect()

        c = Client(port, version=4)
        c.send_raw(bytes([0x10]) + varint(12) + s("MQTT") + bytes([9, 2]) + struct.pack(">H", 60) + s(""))
        p = c.read(3)
        check("a version it does not speak is answered unacceptable protocol version",
              (p.kind, p.body[1]) if p else None, (CONNACK, 0x01))
        c.close()

        c = Client(port)
        c.send_raw(b"\x30\x05\x00\x01a\x00\x00")
        truth("a PUBLISH before CONNECT is closed on", c.closed_within(3))
        c = Client(port)
        c.send_raw(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        truth("an HTTP request on the MQTT port is closed on at once", c.closed_within(1))
        c = Client(port)
        c.send_raw(b"\x10\xff\xff\xff\xff\x7f")
        truth("a remaining length of five bytes is closed on", c.closed_within(2))
        c = Client(port)
        truth("a connection that never sends CONNECT is closed within the handshake deadline",
              c.closed_within(13))
    guarded("connecting", connecting)

    # ── delivery ────────────────────────────────────────────────────────────
    def delivery():
        sub = connected(port, "sub-1")
        check("a subscription at each QoS is granted it", sub.subscribe(("d/0", 0), ("d/1", 1), ("d/2", 2)), [0, 1, 2])
        pub = connected(port, "pub-1")
        pub.publish("d/0", "zero")
        check("a QoS 1 publish is acknowledged with success", pub.publish("d/1", "one", qos=1), 0)
        check("a QoS 2 publish is carried through PUBREC, PUBREL and PUBCOMP", pub.publish("d/2", "two", qos=2), 0)
        got = sub.messages(3)
        check("each arrives once, at the QoS of its subscription",
              sorted((m.topic, m.payload, m.qos) for m in got),
              [("d/0", b"zero", 0), ("d/1", b"one", 1), ("d/2", b"two", 2)])
        truth("and nothing more", sub.quiet(0.4))

        # The lower of the publish's and the subscription's QoS.
        sub.subscribe(("low/#", 0))
        pub.publish("low/x", "x", qos=2)
        m = sub.message()
        check("a QoS 2 message to a QoS 0 subscription goes at QoS 0", (m.qos if m else None), 0)

        # A QoS 2 publish sent again before PUBREL is one message, not two.
        pid = pub.pid()
        pub.publish("d/2", "once", qos=2, pid=pid, wait=False)
        rec = pub.expect(PUBREC)
        pub.publish("d/2", "once", qos=2, pid=pid, dup=True, wait=False)
        rec2 = pub.expect(PUBREC)
        pub.send(PUBREL, 2, struct.pack(">H", pid))
        pub.expect(PUBCOMP)
        truth("a QoS 2 publish sent twice is answered PUBREC twice", rec is not None and rec2 is not None)
        got = sub.messages(2, 1.0)
        check("and delivered once", [m.payload for m in got], [b"once"])

        # Order: a thousand QoS 1 messages arrive as they were sent.
        sub.subscribe(("seq", 1))
        for i in range(1000):
            pub.publish("seq", str(i), qos=1, wait=False)
        acks = 0
        while acks < 1000:
            p = pub.expect(PUBACK, 5)
            if p is None:
                break
            acks += 1
        check("a thousand QoS 1 publishes are each acknowledged", acks, 1000)
        got = sub.messages(1000, 10)
        check("and arrive in order", [m.payload for m in got], [str(i).encode() for i in range(1000)])

        # Wildcards, and $SYS kept out of them.
        w = connected(port, "wild")
        w.subscribe(("w/+/t", 0), ("w/a/#", 0), ("#", 0))
        pub.publish("w/a/t", "1")
        got = w.messages(3, 1.0)
        truth("a topic several filters match reaches the client", len(got) >= 1, got)
        w.disconnect()
        w = connected(port, "wild2")
        w.subscribe(("#", 0))
        time.sleep(0.2)
        truth("# matches no $SYS topic", all(not m.topic.startswith("$") for m in w.messages(50, 0.5)))
        w.disconnect()
        w = connected(port, "sys")
        w.subscribe(("$SYS/broker/#", 0))
        got = w.messages(5, 2)
        truth("$SYS/broker/# hands the broker's figures retained",
              any(m.topic.startswith("$SYS/broker/") and m.retain for m in got), got)
        w.disconnect()

        # Unsubscribing.
        check("UNSUBACK says each filter was there", sub.unsubscribe("d/0", "never/subscribed"), [0x00, 0x11])
        pub.publish("d/0", "after")
        truth("and an unsubscribed filter delivers nothing", sub.quiet(0.4))

        # Fan out: fifty subscribers hear one publish.
        many = [connected(port, "fan-%d" % i) for i in range(50)]
        for c in many:
            c.subscribe(("fan", 1))
        pub.publish("fan", "all", qos=1)
        heard = sum(1 for c in many if (c.message(3) or Message("", b"", 0, 0, 0, 0, {})).payload == b"all")
        check("fifty subscribers each hear one publish", heard, 50)
        for c in many:
            c.disconnect()
        sub.disconnect()
        pub.disconnect()
    guarded("delivery", delivery)

    # ── retained messages ───────────────────────────────────────────────────
    def retained():
        pub = connected(port, "ret-pub")
        pub.publish("r/a", "first", qos=1, retain=True)
        pub.publish("r/a", "second", qos=1, retain=True)
        pub.publish("r/b", "bee", qos=1, retain=True)
        sub = connected(port, "ret-sub")
        sub.subscribe(("r/+", 1))
        got = sorted((m.topic, m.payload, m.retain) for m in sub.messages(2))
        check("a new subscription gets the last retained message of each topic, flagged retained",
              got, [("r/a", b"second", True), ("r/b", b"bee", True)])
        pub.publish("r/a", "live", qos=1, retain=True)
        m = sub.message()
        check("a retained publish to an existing subscription is not flagged retained", (m.payload, m.retain) if m else None,
              (b"live", False))
        pub.publish("r/b", "", qos=1, retain=True)
        sub.message(1)
        s2 = connected(port, "ret-sub2")
        s2.subscribe(("r/+", 1))
        got = [m.topic for m in s2.messages(3, 1.0)]
        check("an empty retained payload clears the topic", got, ["r/a"])
        # Retain handling 2: none on subscribing; 1: only for a new subscription.
        s3 = connected(port, "ret-sub3")
        s3.subscribe(("r/a", 1 | (2 << 4)))
        truth("retain handling 2 sends nothing on subscribing", s3.quiet(0.5))
        s3.subscribe(("r/+", 1 | (1 << 4)))
        check("retain handling 1 sends them for a new subscription", len(s3.messages(1, 1.0)), 1)
        s3.subscribe(("r/+", 1 | (1 << 4)))
        truth("and not for one it already had", s3.quiet(0.5))
        # Retain as published.
        s3.subscribe(("rap", 1 | 8))
        pub.publish("rap", "kept", qos=1, retain=True)
        m = s3.message()
        check("retain as published keeps the flag on a live message", m.retain if m else None, True)
        for c in (pub, sub, s2, s3):
            c.disconnect()
    guarded("retained", retained)

    # ── 5.0 options and properties ──────────────────────────────────────────
    def options():
        a = connected(port, "nl")
        a.subscribe(("nl/t", 1 | 4))
        a.publish("nl/t", "mine", qos=1)
        truth("no local keeps a client's own message from it", a.quiet(0.5))
        a.disconnect()

        sub = connected(port, "props-sub")
        sub.subscribe(("pr/#", 1), props={SUB_ID: 42})
        pub = connected(port, "props-pub")
        pub.publish("pr/x", b"\x00\x01binary", qos=1, props={
            RESPONSE_TOPIC: "pr/reply", CORRELATION: b"corr-7", CONTENT_TYPE: "application/octet-stream",
            USER_PROPERTY: [("k", "v"), ("k", "w")], PAYLOAD_FORMAT: 0, MESSAGE_EXPIRY: 300})
        m = sub.message()
        truth("a message arrives with its properties", m is not None)
        if m:
            check("the response topic goes with it", m.props.get(RESPONSE_TOPIC), "pr/reply")
            check("so does the correlation data", m.props.get(CORRELATION), b"corr-7")
            check("and the content type", m.props.get(CONTENT_TYPE), "application/octet-stream")
            check("and every user property, in order", m.props.get(USER_PROPERTY), [("k", "v"), ("k", "w")])
            check("and the subscription identifier", m.props.get(SUB_ID), [42])
            truth("and what is left of its expiry", 295 <= m.props.get(MESSAGE_EXPIRY, 0) <= 300, m.props)
            check("and the payload, bytes as they were", m.payload, b"\x00\x01binary")

        # A topic alias set once and used alone after.
        pub.publish("pr/alias/long/topic", "one", props={ALIAS: 1})
        pub.publish("", "two", props={ALIAS: 1})
        got = [(m.topic, m.payload) for m in sub.messages(2)]
        check("a topic alias stands for its topic", got, [("pr/alias/long/topic", b"one"), ("pr/alias/long/topic", b"two")])
        pub.publish("", "three", props={ALIAS: 2})
        truth("an alias never set is a protocol error that closes the connection", pub.closed_within(2))
        check("and the DISCONNECT says why", pub.disconnect_packet.body[0] if pub.disconnect_packet else None, 0x82)

        bad = connected(port, "alias-big")
        bad.publish("x", "y", props={ALIAS: 65000})
        truth("an alias above the maximum closes the connection", bad.closed_within(2))
        check("with topic alias invalid", bad.disconnect_packet.body[0] if bad.disconnect_packet else None, 0x94)

        big = connected(port, "too-big")
        big.publish("big", b"x" * (70 * 1024))
        truth("a packet larger than the broker's maximum closes the connection", big.closed_within(3))
        check("with packet too large", big.disconnect_packet.body[0] if big.disconnect_packet else None, 0x95)

        wc = connected(port, "wild-pub")
        wc.publish("a/+/b", "no", qos=1, wait=False)
        truth("a publish to a wildcard topic closes the connection", wc.closed_within(3))
        c = connected(port, "bad-filter")
        check("a filter # does not end is refused in its SUBACK", c.subscribe("a/#/b"), [0x8F])
        c.disconnect()
        c = Client(port, version=4)
        c.connect("bad-filter-3")
        c.send(SUBSCRIBE, 2, struct.pack(">H", 1) + s("a/#/b") + b"\x00")
        try:
            p = c.read(2)
            answered = p is not None and p.kind == SUBACK and p.body[-1] == 0x80
        except Closed:
            p, answered = None, True
        truth("and a 3.1.1 client sending it is answered 0x80 or closed", answered, p)
        c.close()

        # A client's receive maximum holds the broker's QoS 1 messages back.
        slow = connected(port, "slow", props={RECEIVE_MAX: 2})
        slow.subscribe(("rm", 1))
        slow.auto_ack = False
        p3 = connected(port, "rm-pub")
        for i in range(6):
            p3.publish("rm", str(i), qos=1)
        first = slow.messages(6, 1.0)
        check("no more QoS 1 messages are in flight than the client's receive maximum", len(first), 2)
        for m in first:
            slow.ack(m)
        rest = slow.messages(6, 2.0)
        for m in rest:
            slow.ack(m)
        more = slow.messages(6, 2.0)
        check("and the rest follow as they are acknowledged", len(first) + len(rest) + len(more), 6)
        for c in (sub, slow, p3):
            c.disconnect()

        # Shared subscriptions split the messages over the group.
        g1 = connected(port, "g1")
        g2 = connected(port, "g2")
        g1.subscribe(("$share/grp/sh/t", 1))
        g2.subscribe(("$share/grp/sh/t", 1))
        p4 = connected(port, "sh-pub")
        p4.publish("sh/t", "kept", qos=1, retain=True)
        for i in range(20):
            p4.publish("sh/t", str(i), qos=1)
        a, b = g1.messages(20, 1.5), g2.messages(20, 1.5)
        check("a shared subscription delivers each message to one member", len(a) + len(b), 21)
        truth("and to each member some", len(a) > 0 and len(b) > 0, (len(a), len(b)))
        g3 = connected(port, "g3")
        g3.subscribe(("$share/grp2/sh/t", 1))
        truth("a shared subscription gets no retained message on subscribing", g3.quiet(0.5))
        for c in (g1, g2, g3, p4):
            c.disconnect()
        a2 = connected(port, "clear-rap")
        a2.publish("rap", "", qos=1, retain=True)
        a2.publish("sh/t", "", qos=1, retain=True)
        a2.disconnect()
    guarded("options", options)

    # ── sessions ────────────────────────────────────────────────────────────
    def sessions():
        c = connected(port, "keep", clean=True, props={SESSION_EXPIRY: 600})
        c.subscribe(("q/#", 1))
        c.disconnect()
        pub = connected(port, "q-pub")
        for i in range(3):
            pub.publish("q/%d" % i, "queued-%d" % i, qos=1)
        pub.publish("q/exp", "expires", qos=1, props={MESSAGE_EXPIRY: 1})
        time.sleep(1.6)
        c = Client(port)
        present, code, _ = c.connect("keep", clean=False, props={SESSION_EXPIRY: 600})
        check("a client coming back finds its session", present, True)
        got = [m.payload for m in c.messages(4, 2)]
        check("with what was queued for it, in order, and not what expired", got,
              [b"queued-0", b"queued-1", b"queued-2"])
        c.disconnect()
        c = Client(port)
        present, _, _ = c.connect("keep", clean=True)
        check("a clean start finds none", present, False)
        c.disconnect()

        c = connected(port, "short", props={SESSION_EXPIRY: 1})
        c.subscribe(("short", 1))
        c.disconnect()
        # Sooner than the once-a-second sweep is sure to have come by, which the connect does not wait for.
        time.sleep(1.3)
        c = Client(port)
        present, _, _ = c.connect("short", clean=False, props={SESSION_EXPIRY: 1})
        check("a session ends once its expiry has passed", present, False)
        c.disconnect()

        # 3.1.1: clean session false keeps it.
        c = Client(port, version=4)
        c.connect("v3-keep", clean=False)
        c.subscribe(("v3/q", 1))
        c.disconnect()
        pub.publish("v3/q", "for-v3", qos=1)
        c = Client(port, version=4)
        present, _, _ = c.connect("v3-keep", clean=False)
        m = c.message(2)
        check("a 3.1.1 session kept by clean session 0 gets what it missed", (present, m.payload if m else None),
              (True, b"for-v3"))
        c.disconnect()

        # A second connection with the same id takes the session over.
        first = connected(port, "twin", props={SESSION_EXPIRY: 60})
        second = connected(port, "twin", clean=False, props={SESSION_EXPIRY: 60})
        truth("the first connection of a client id taken over is closed", first.closed_within(2))
        check("and told it was taken over", first.disconnect_packet.body[0] if first.disconnect_packet else None, 0x8E)
        truth("while the second goes on", second.ping())
        second.disconnect()

        # Keep alive: a client silent for one and a half times it is let go.
        k = connected(port, "sleepy", keepalive=1)
        t0 = time.time()
        closed = k.closed_within(4)
        truth("a client that says nothing past its keep alive is closed", closed and time.time() - t0 < 3.2,
              time.time() - t0)
        pub.disconnect()
    guarded("sessions", sessions)

    # ── wills ───────────────────────────────────────────────────────────────
    def wills():
        sub = connected(port, "will-sub")
        sub.subscribe(("will/#", 1))
        a = connected(port, "w-lost", will=("will/a", "a died", 1, False))
        a.close()
        m = sub.message(3)
        check("a will is sent when the connection is lost", m.payload if m else None, b"a died")
        b = connected(port, "w-clean", will=("will/b", "b died", 1, False))
        b.disconnect()
        truth("and not when the client disconnects", sub.quiet(0.8))
        c = connected(port, "w-asked", will=("will/c", "c asked", 1, False))
        c.disconnect(reason=0x04)
        m = sub.message(2)
        check("unless it disconnects asking for its will", m.payload if m else None, b"c asked")
        d = connected(port, "w-delay", will=("will/d", "d late", 1, False, {WILL_DELAY: 2}),
                      props={SESSION_EXPIRY: 30})
        d.close()
        t0 = time.time()
        m = sub.message(4)
        took = time.time() - t0
        truth("a will with a delay is sent after it", m is not None and m.payload == b"d late" and took >= 1.5,
              (m, took))
        e = connected(port, "w-back", will=("will/e", "e late", 1, False, {WILL_DELAY: 2}),
                      props={SESSION_EXPIRY: 30})
        e.close()
        time.sleep(0.5)
        e = connected(port, "w-back", clean=False, props={SESSION_EXPIRY: 30})
        truth("and not when the client comes back within it", sub.quiet(2.5))
        e.disconnect()
        r = connected(port, "w-retain", will=("will/r", "gone", 1, True))
        r.close()
        sub.message(2)
        late = connected(port, "will-late")
        late.subscribe(("will/r", 1))
        m = late.message(2)
        check("a retained will is kept retained", (m.payload, m.retain) if m else None, (b"gone", True))
        late.publish("will/r", "", qos=1, retain=True)
        late.disconnect()
        sub.disconnect()
    guarded("wills", wills)

    # ── the CLI ─────────────────────────────────────────────────────────────
    def commands():
        sub = connected(port, "cli-sub")
        sub.subscribe(("cli/#", 2))
        rc, out = cli("mqtt-pub", "m", "cli/plain", "hello", "world")
        check("mqtt-pub succeeds silently", (rc, out), (0, ""))
        rc, out = cli("mqtt-pub", "m", "--qos", "2", "--retain", "cli/kept", stdin=b"line one\n\tline two  \x00end\n")
        check("mqtt-pub takes its payload from a pipe", rc, 0)
        got = sorted((m.topic, m.payload, m.qos) for m in sub.messages(2))
        check("both reach a subscriber, the piped payload byte for byte", got,
              [("cli/kept", b"line one\n\tline two  \x00end", 2), ("cli/plain", b"hello world", 0)])
        rc, out = cli("mqtt-retained", "m", "cli/#")
        truth("mqtt-retained lists what is retained", rc == 0 and '"topic":"cli/kept"' in out, out)
        rc, out = cli("mqtt-retained", "m", "--clear", "cli/kept")
        check("mqtt-retained --clear clears it", (rc, out), (0, ""))
        rc, out = cli("mqtt-retained", "m", "cli/#")
        check("and it is gone", out.strip(), "[]")
        rc, out = cli("mqtt-pub", "m", "a/+/b", "x")
        truth("mqtt-pub to a wildcard is refused with exit 1", rc == 1 and "is not a topic" in out, (rc, out))
        rc, out = cli("mqtt-pub", "nosuch", "t", "x")
        truth("mqtt-pub to no broker is refused", rc == 1 and "no mqtt runtime" in out, (rc, out))

        k = connected(port, "cli-held", props={SESSION_EXPIRY: 600})
        k.subscribe(("held/#", 1))
        rc, out = cli("mqtt-sessions", "m")
        truth("mqtt-sessions lists the connected client with its subscription",
              rc == 0 and '"client":"cli-held"' in out and '"held/#"' in out and '"connected":true' in out, out)
        rc, out = cli("mqtt-kick", "m", "cli-held")
        check("mqtt-kick disconnects it", (rc, out), (0, ""))
        truth("the kicked client is closed", k.closed_within(2))
        rc, out = cli("mqtt-sessions", "m")
        truth("and its session stays, not connected", '"client":"cli-held"' in out and
              '"connected":false' in out.split('"client":"cli-held"')[1].split("}")[0], out)
        rc, out = cli("mqtt-kick", "m", "cli-held", "--end")
        check("mqtt-kick --end ends the session too", rc, 0)
        rc, out = cli("mqtt-sessions", "m")
        truth("and it is gone", '"cli-held"' not in out, out)
        rc, out = cli("mqtt-kick", "m", "nobody")
        check("kicking nobody says so", (rc, out.strip()), (1, "no session of nobody"))

        # mqtt-sub prints what arrives, as JSON lines, and stops after --count.
        proc = subprocess.Popen([binary, "mqtt-sub", "m", "tap/#", "--count", "2"], stdout=subprocess.PIPE)
        time.sleep(0.6)
        p = connected(port, "tap-pub")
        p.publish("tap/one", "1")
        p.publish("other", "x")
        p.publish("tap/two", "two", qos=1)
        try:
            out, _ = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
        lines = out.decode().strip().splitlines()
        check("mqtt-sub prints the matching messages and stops after --count", proc.returncode, 0)
        truth("as a JSON line each", len(lines) == 2 and '"topic":"tap/one"' in lines[0] and
              '"payload":"two"' in lines[1], lines)
        p.disconnect()
        sub.disconnect()
        rc, out = cli("mqtt-pub", "--help")
        truth("mqtt-pub --help answers its usage", "usage: mqtt-pub" in out or "usage: mqtt-pub" in str(rc), out)
    guarded("commands", commands)

    # ── what is kept ────────────────────────────────────────────────────────
    def before_restart():
        c = connected(port, "durable", props={SESSION_EXPIRY: 3600})
        c.subscribe(("dur/#", 1), ("$share/dg/shr/s", 1))
        c.disconnect()
        p = connected(port, "dur-pub")
        p.publish("dur/kept", "retained-across", qos=1, retain=True)
        for i in range(5):
            p.publish("dur/q", "q%d" % i, qos=1)
        p.disconnect()
        time.sleep(1.5)
    guarded("before restart", before_restart)

if phase == "after":
    def after_restart():
        c = Client(port)
        present, code, _ = c.connect("durable", clean=False, props={SESSION_EXPIRY: 3600})
        check("a session is there after the restart", (present, code), (True, 0))
        got = [(m.topic, m.payload) for m in c.messages(6, 3)]
        check("with its queued messages", [x for x in got if x[0] == "dur/q"],
              [("dur/q", b"q%d" % i) for i in range(5)])
        p = connected(port, "dur-pub2")
        p.publish("shr/s", "shared", qos=1)
        m = c.message(2)
        check("and its subscriptions, shared ones too", m.payload if m else None, b"shared")
        s2 = connected(port, "dur-reader")
        s2.subscribe(("dur/kept", 1))
        m = s2.message(2)
        check("a retained message is there after the restart", m.payload if m else None, b"retained-across")
        c.subscribe(("dur/more", 1))
        c.disconnect()
        p.publish("dur/more", "for-next", qos=1)
        p.disconnect()
        s2.disconnect()
        time.sleep(1.6)
    guarded("after restart", after_restart)

if phase == "killed":
    def after_kill():
        c = Client(port)
        present, code, _ = c.connect("durable", clean=False, props={SESSION_EXPIRY: 3600})
        check("a session is there after its worker was killed", present, True)
        # A kill may come before the last snapshot of the answers to what was sent: those go again, marked DUP, as QoS 1
        # allows after a crash, and the message queued since is there behind them.
        got = []
        end = time.time() + 5
        while time.time() < end and b"for-next" not in [x.payload for x in got]:
            m = c.message(1)
            if m is not None:
                got.append(m)
        check("with the message queued a second before", b"for-next" in [x.payload for x in got], True)
        check("and before it only what went before, again and marked so",
              [x.payload for x in got if x.payload != b"for-next" and not x.dup], [])
        c.disconnect(reason=0)
        e = Client(port)
        e.connect("durable", clean=True)
        e.disconnect()
    guarded("after kill", after_kill)
PY
}

tally < <(run main)

st=$("$BIN" stats m 2>&1)
case "$st" in *"sessions:"*"retained:"*"received_qos1:"*"sent_qos2:"*"connects:"*) ok ;; *) bad "stats name the sessions, the retained messages and the flows" "$st" ;; esac
cfg=$("$BIN" show m 2>&1)
case "$cfg" in *'"anonymous": true'*'"max_packet": 65536'*'"session_expiry": 3600'*'"persistent_path": "on"'*) ok ;;
    *) bad "show carries the broker's settings" "$cfg" ;; esac
out=$("$BIN" edit m --max-sessions 5 2>&1); rc=$?
case "$out" in *"cannot be changed with \`edit\`"*"import"*"--restart"*) [ "$rc" -eq 1 ] && ok || bad "edit refuses a broker's own flag with exit 1" "rc $rc" ;;
    *) bad "edit sends a broker's own flag to import" "rc $rc: $out" ;; esac
[ -s "$HOME/.local/share/socketley/mqtt/m.snapshot" ] || [ -n "$(find "$HOME" -name m.snapshot -size +0 2>/dev/null)" ] \
    && ok || bad "--persistent on keeps the snapshot under the state directory" "$(find "$HOME" -name '*.snapshot')"

# Stopped and started: sessions, queues and retained messages come back from the snapshot.
"$BIN" stop m >/dev/null 2>&1 && "$BIN" start m >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P" || bad "the broker listens after a start" "$(tail -5 "$SOCKETLEY_DLOG")"
tally < <(run after)

# The worker killed outright: what the last snapshot held, a second's worth at most behind.
wpid=$(ss -ltnpH "sport = :$P" 2>/dev/null | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1)
if [ -n "$wpid" ]; then
    # The kill comes once a snapshot holds every change, which a disk busy with other writes can take seconds to finish.
    for _ in $(seq 1 100); do
        case "$("$BIN" stats m 2>&1)" in *"snapshot_unsaved:0"*) break ;; esac
        sleep 0.1
    done
    kill -9 "$wpid"
    for _ in $(seq 1 100); do
        sleep 0.2
        ss -ltnH "sport = :$P" 2>/dev/null | grep -q . && break
    done
    ready_tcp 127.0.0.1 "$P" 15 && ok || bad "the killed worker is started again" "$(tail -5 "$SOCKETLEY_DLOG")"
    tally < <(run killed)
else
    bad "the broker's worker is found" "no process listens on $P"
fi

# The daemon restarted with its state directory: the broker comes back running.
kill "$SOCKETLEY_DPID" 2>/dev/null
wait "$SOCKETLEY_DPID" 2>/dev/null
daemon_start "$BIN"
ready_tcp 127.0.0.1 "$P" 15 && ok || bad "the broker comes back with the daemon" "$(tail -5 "$SOCKETLEY_DLOG")"
st=$("$BIN" ls 2>&1 | awk '$2=="m"')
case "$st" in *" Up "*) ok ;; *) bad "and is listed running" "$st" ;; esac

# Removed and made again under its name: a broker that kept its state under the state directory starts empty.
PYTHONPATH="$HERE" python3 - "$P" <<'PY' >/dev/null 2>&1
import sys, time
from lib_mqtt import *
c = connected(int(sys.argv[1]), "left-behind", props={SESSION_EXPIRY: 3600})
c.subscribe(("lb/#", 1))
c.publish("lb/kept", "old", qos=1, retain=True)
c.disconnect()
time.sleep(1.5)
PY
"$BIN" remove m >/dev/null 2>&1
# The files go once the worker has written its last snapshot and is gone, which a busy disk can make seconds.
for _ in $(seq 1 100); do
    left=$(find "$HOME" -name 'm.snapshot*' 2>/dev/null)
    [ -z "$left" ] && break
    sleep 0.1
done
[ -z "$left" ] && ok || bad "remove takes the broker's snapshot under the state directory with it" "$left"
"$BIN" create mqtt m -p "$P" --anonymous --persistent on -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P" || bad "a broker of the same name is made again" "$(tail -3 "$SOCKETLEY_DLOG")"
got=$(PYTHONPATH="$HERE" python3 - "$P" <<'PY' 2>&1
import sys
from lib_mqtt import *
c = Client(int(sys.argv[1]))
present, _, _ = c.connect("left-behind", clean=False, props={SESSION_EXPIRY: 3600})
c.subscribe(("lb/#", 1))
m = c.message(1)
print(present, m.payload if m else None)
PY
)
expect "and starts without the sessions and retained messages of the one removed" "$got" "False None"

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
