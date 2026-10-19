#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# An mqtt runtime of several shards: one broker to its clients whichever process the kernel gave each connection.
#
# What each part would catch:
#   * a message published on one shard missing the subscribers on another, or reaching one twice
#   * a retained message kept only by the shard it was published on
#   * a session that does not follow its client to another shard, or two shards both holding it
#   * a shared subscription's message delivered once per shard instead of once per group
#   * mqtt-sessions, mqtt-kick or mqtt-sub seeing one shard only
#   * a shard's sessions lost across a restart because the shards share one snapshot
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

echo "=== Integration: an mqtt runtime of several shards is one broker ==="
daemon_isolate mqttshards
P=$((SL_PORT_BASE + 1950))
trap 'daemon_stop' EXIT
daemon_start "$BIN"

"$BIN" create mqtt sh -p "$P" --anonymous --shards 3 --persistent on -s >/dev/null 2>&1 \
    && ok || bad "a broker of three shards is made" "$(tail -3 "$SOCKETLEY_DLOG")"
ready_tcp 127.0.0.1 "$P" || bad "it listens" "$(tail -5 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do
    [ "$("$BIN" stats sh 2>/dev/null | awk -F: '$1=="shard_peers_known"{s+=$2} END{print s+0}')" -ge 6 ] && break
    sleep 0.2
done

run() {
    PYTHONPATH="$HERE" python3 - "$1" "$P" "$BIN" 2>&1 <<'PY'
import json, subprocess, sys, time
from lib_mqtt import *
phase, port, binary = sys.argv[1], int(sys.argv[2]), sys.argv[3]

def check(name, got, want):
    print(("ok " if got == want else "bad ") + name + ("" if got == want else ": got %r, want %r" % (got, want)))

def truth(name, cond, detail=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + str(detail)))

def guarded(name, fn):
    try:
        fn()
    except Exception as e:
        print("bad %s: %s %s" % (name, type(e).__name__, e))

def sessions():
    out = subprocess.run([binary, "mqtt-sessions", "sh"], capture_output=True, timeout=10).stdout.decode()
    return json.loads(out)

def shard_of(cid):
    for s in sessions():
        if s["client"] == cid and s["connected"]:
            return s["shard"]
    return None

if phase == "main":
    def spread():
        subs = [connected(port, "s-%d" % i) for i in range(12)]
        for c in subs:
            c.subscribe(("x/#", 1))
        shards = {s["shard"] for s in sessions() if s["client"].startswith("s-")}
        truth("the kernel spreads the connections over the shards", len(shards) >= 2, shards)
        check("mqtt-sessions lists the sessions of every shard", len([s for s in sessions() if s["client"].startswith("s-")]), 12)
        time.sleep(0.5)
        pub = connected(port, "x-pub")
        for i in range(10):
            pub.publish("x/t", str(i), qos=1)
        got = [[m.payload for m in c.messages(10, 3)] for c in subs]
        check("every subscriber on every shard gets every message once, in order",
              got, [[str(i).encode() for i in range(10)]] * 12)
        truth("and nothing more", all(c.quiet(0.3) for c in subs[:3]))

        pub.publish("kept/one", "everywhere", qos=1, retain=True)
        time.sleep(0.5)
        late = [connected(port, "late-%d" % i) for i in range(8)]
        for c in late:
            c.subscribe(("kept/#", 1))
        got = [(m.payload if m else None) for m in (c.message(2) for c in late)]
        check("a retained message is given on every shard", got, [b"everywhere"] * 8)
        pub.publish("kept/one", "", qos=1, retain=True)
        time.sleep(0.5)
        later = [connected(port, "later-%d" % i) for i in range(6)]
        for c in later:
            c.subscribe(("kept/#", 1))
        truth("and cleared on every shard", all(c.quiet(0.4) for c in later))

        # The same group over the shards: each message once to one member.
        members = [connected(port, "m-%d" % i) for i in range(6)]
        for c in members:
            c.subscribe(("$share/g/work", 1))
        time.sleep(0.6)
        for i in range(60):
            pub.publish("work", "job-%d" % i, qos=1)
        got = [m.payload for c in members for m in c.messages(60, 1.5)]
        check("a shared subscription over the shards delivers each message to one member",
              sorted(got), sorted(b"job-%d" % i for i in range(60)))
        for c in subs + late + later + members:
            c.disconnect()
        pub.disconnect()
    guarded("spread", spread)

    def roaming():
        c = connected(port, "roamer", props={SESSION_EXPIRY: 600})
        c.subscribe(("roam/#", 1))
        first = shard_of("roamer")
        c.disconnect()
        pub = connected(port, "roam-pub")
        moved = False
        for attempt in range(12):
            pub.publish("roam/t", "m%d" % attempt, qos=1)
            c = Client(port)
            present, code, _ = c.connect("roamer", clean=False, props={SESSION_EXPIRY: 600})
            m = c.message(3)
            now = shard_of("roamer")
            if present is not True or m is None or m.payload != b"m%d" % attempt:
                truth("a session follows its client to whichever shard it lands on", False,
                      (attempt, present, m, first, now))
                break
            if now != first:
                moved = True
            c.disconnect()
        truth("the client landed on another shard and found its session there", moved, (first,))
        owners = [s["shard"] for s in sessions() if s["client"] == "roamer"]
        check("and only one shard holds it", len(owners), 1)

        # Two connections of one id at once: the later takes the session, wherever each landed.
        conns = []
        for i in range(6):
            conns.append(connected(port, "twin", clean=False, props={SESSION_EXPIRY: 60}))
            time.sleep(0.2)
        alive = [x for x in conns[:-1] if not x.closed_within(0.5)]
        check("every earlier connection of a client id is taken over", len(alive), 0)
        truth("the last goes on", conns[-1].ping())
        conns[-1].disconnect()
        check("one session of the id remains", len([s for s in sessions() if s["client"] == "twin"]), 1)
        pub.disconnect()
    guarded("roaming", roaming)

    def commands():
        held = [connected(port, "k-%d" % i, props={SESSION_EXPIRY: 600}) for i in range(6)]
        for i, c in enumerate(held):
            r = subprocess.run([binary, "mqtt-kick", "sh", "k-%d" % i], capture_output=True, timeout=10)
            check("mqtt-kick reaches the session on its shard (k-%d)" % i, r.returncode, 0)
            truth("which is closed (k-%d)" % i, c.closed_within(2))
        proc = subprocess.Popen([binary, "mqtt-sub", "sh", "tap/#", "--count", "12"], stdout=subprocess.PIPE)
        time.sleep(0.8)
        pubs = [connected(port, "tp-%d" % i) for i in range(6)]
        for i, p in enumerate(pubs):
            p.publish("tap/%d" % i, "a")
            p.publish("tap/%d" % i, "b", qos=1)
        try:
            out, _ = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
        lines = [json.loads(l) for l in out.decode().splitlines() if l.startswith("{")]
        check("mqtt-sub hears what every shard accepts, once", sorted((l["topic"], l["payload"]) for l in lines),
              sorted([("tap/%d" % i, "a") for i in range(6)] + [("tap/%d" % i, "b") for i in range(6)]))
        for p in pubs:
            p.disconnect()
        rc = subprocess.run([binary, "mqtt-pub", "sh", "--retain", "cli/kept", "from the cli"], capture_output=True).returncode
        check("mqtt-pub publishes on a sharded broker", rc, 0)
        time.sleep(0.4)
        cs = [connected(port, "cli-%d" % i) for i in range(6)]
        for c in cs:
            c.subscribe(("cli/kept", 1))
        check("and what it retains is on every shard", [(m.payload if m else None) for m in (c.message(2) for c in cs)],
              [b"from the cli"] * 6)
        for c in cs:
            c.disconnect()
    guarded("commands", commands)

    def sys_topics():
        c = connected(port, "sys")
        c.subscribe(("$SYS/broker/shard/+/clients/connected", 0))
        got = {m.topic for m in c.messages(10, 2)}
        check("each shard publishes its own figures under its number",
              got, {"$SYS/broker/shard/%d/clients/connected" % i for i in range(3)})
        c.disconnect()
    guarded("sys", sys_topics)

    def keep():
        for i in range(9):
            c = connected(port, "keep-%d" % i, props={SESSION_EXPIRY: 3600})
            c.subscribe(("keep/%d" % i, 1))
            c.disconnect()
        p = connected(port, "keep-pub")
        for i in range(9):
            p.publish("keep/%d" % i, "for %d" % i, qos=1)
        p.disconnect()
        time.sleep(1.6)
    guarded("keep", keep)

if phase == "after":
    def after():
        got = []
        for i in range(9):
            c = Client(port)
            present, _, _ = c.connect("keep-%d" % i, clean=False, props={SESSION_EXPIRY: 3600})
            m = c.message(3)
            got.append((present, m.payload if m else None))
            c.disconnect()
        check("every shard's sessions and their queued messages come back after a restart", got,
              [(True, b"for %d" % i) for i in range(9)])
    guarded("after", after)
PY
}

tally < <(run main)
st=$("$BIN" stats sh 2>&1)
fw=$(echo "$st" | awk -F: '$1=="shard_forwarded"{s+=$2} END{print s+0}')
mv=$(echo "$st" | awk -F: '$1=="sessions_moved"{s+=$2} END{print s+0}')
[ "$fw" -gt 0 ] && [ "$mv" -gt 0 ] && ok || bad "stats count the messages forwarded and the sessions moved between shards" "forwarded $fw moved $mv"
snaps=$(find "$HOME" -name 'sh.snapshot.*' | wc -l)
[ "$snaps" -eq 3 ] && ok || bad "each shard keeps a snapshot of its own" "$(find "$HOME" -name 'sh.snapshot*')"

"$BIN" stop sh >/dev/null 2>&1 && "$BIN" start sh >/dev/null 2>&1
ready_tcp 127.0.0.1 "$P" || bad "the broker listens after a start" "$(tail -5 "$SOCKETLEY_DLOG")"
sleep 1
tally < <(run after)

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
