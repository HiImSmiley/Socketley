#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# An mqtt runtime of several shards when one shard hears late of what another did.
#
# What each part would catch:
#   * a SUBACK sent before the other shards know of its new filter, so a QoS 1 message published on another shard
#     right after it never reaches the subscriber, with the mesh and with the daemon carrying the shards' words
#   * a session lost because the shard holding it answered its claim after the claim's patience: its queued
#     messages and its subscription missing on the connection that was let in without it; or past what the asker
#     waits for an answer at all, the session ended when its shard hears of the connection let in
#   * a session too large for one frame through the daemon ended, rather than carried in pieces, when its shard
#     answers late
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

echo "=== Integration: an mqtt runtime of several shards when one hears late ==="
P=$((SL_PORT_BASE + 1960))

run() {
    PYTHONPATH="$HERE" python3 - "$1" "$P" "$BIN" 2>&1 <<'PY'
import os, re, signal, subprocess, sys, time
from lib_mqtt import *
phase, port, binary = sys.argv[1], int(sys.argv[2]), sys.argv[3]

def owner(c):
    lport = c.sock.getsockname()[1]
    out = subprocess.run(["ss", "-tnpH", "sport = :%d and dport = :%d" % (port, lport)],
                         capture_output=True, timeout=10).stdout.decode()
    m = re.search(r"pid=(\d+)", out)
    return int(m.group(1)) if m else None

def stat(name, least=1):
    # A shard's figures reach the daemon a moment after they change.
    for _ in range(50):
        out = subprocess.run([binary, "stats", "sh"], capture_output=True, timeout=30).stdout.decode()
        n = sum(int(v) for k, _, v in (l.partition(":") for l in out.splitlines()) if k == name)
        if n >= least:
            break
        time.sleep(0.2)
    return n

def elsewhere(name, home):
    for i in range(60):
        c = connected(port, "%s-%d" % (name, i))
        if owner(c) not in (home, None):
            return c
        c.disconnect()
    return None

if phase in ("suback", "suback_relayed"):
    def suback():
        pub = connected(port, "pub")
        sub = elsewhere("sub", owner(pub))
        truth("a subscriber lands on another shard than its publisher", sub is not None)
        if sub is None:
            return
        # Each filter new to every shard, published to at once from the other one.
        got = 0
        for i in range(40):
            sub.subscribe(("fresh/%d" % i, 1))
            pub.publish("fresh/%d" % i, b"m%d" % i, qos=1)
            m = sub.message(3)
            got += m is not None and m.payload == b"m%d" % i
        check("every QoS 1 message published on another shard right after the SUBACK arrives (%s)" % phase, got, 40)
        held = stat("subacks_held")
        truth("stats count the SUBACKs that waited", held >= 1, held)
        # One the other shards know already is answered at once.
        again = connected(port, "again")
        t = time.time()
        again.subscribe(("fresh/0", 1))
        truth("a SUBACK for a filter every shard knows is not held", time.time() - t < 0.5, time.time() - t)
        pub.disconnect(); sub.disconnect(); again.disconnect()
    guarded("suback", suback)

if phase in ("late", "stale"):
    def late(stopped, name, counted):
        c = connected(port, name, clean=False, props={SESSION_EXPIRY: 600})
        c.subscribe((name + "/#", 1))
        old = owner(c)
        c.disconnect()
        pub = elsewhere(name + "-pub", old)
        truth("a publisher lands on another shard than the session", pub is not None)
        if pub is None:
            return
        for i in range(3):
            pub.publish(name + "/t", b"q%d" % i, qos=1)
        for _ in range(50):
            out = subprocess.run([binary, "mqtt-sessions", "sh"], capture_output=True, timeout=10).stdout.decode()
            if '"queued":3' in out.replace(" ", ""):
                break
            time.sleep(0.1)
        home = owner(pub)
        # The session's shard stopped past the claim's patience, so the connection is let in without it.
        os.kill(old, signal.SIGSTOP)
        try:
            x = None
            for _ in range(60):
                x = Client(port, timeout=15)
                if owner(x) == home:
                    break
                x.close()
                x = None
            t = time.time()
            present, code, _ = x.connect(name, clean=False, props={SESSION_EXPIRY: 600})
            waited = time.time() - t
            time.sleep(max(0.0, stopped - (time.time() - t)))
        finally:
            os.kill(old, signal.SIGCONT)
        check("the connection is let in without its session after the claim's patience", (present, code), (False, 0))
        truth("and only after it", waited >= 2.5, waited)
        got = sorted(m.payload for m in x.messages(3, 10))
        check("the session's queued messages reach it once the late answer comes", got, [b"q0", b"q1", b"q2"])
        pub.publish(name + "/t", b"after", qos=1)
        m = x.message(5)
        check("and its subscription goes on", m.payload if m else None, b"after")
        n = stat(counted)
        truth("stats count it in " + counted, n >= 1, n)
        x.disconnect(); pub.disconnect()
    if phase == "late":
        guarded("late", lambda: late(0, "roam", "sessions_late"))
    else:
        # Past what the asker's channel waits for an answer: the session goes over once its shard hears the
        # connection was let in.
        guarded("stale", lambda: late(17, "stale", "sessions_yielded"))
if phase == "large":
    def large():
        # Past the 8 MiB one frame through the daemon holds, so only pieces carry it.
        body = b"L" * 200000
        c = connected(port, "big", clean=False, props={SESSION_EXPIRY: 600})
        c.subscribe(("big/#", 1))
        old = owner(c)
        c.disconnect()
        pub = None
        for i in range(60):
            p = connected(port, "big-pub-%d" % i)
            if owner(p) == old:
                pub = p
                break
            p.disconnect()
        truth("a publisher lands on the session's shard", pub is not None)
        if pub is None:
            return
        for i in range(50):
            pub.publish("big/t", body + b"%02d" % i, qos=1)
        pub.disconnect()
        os.kill(old, signal.SIGSTOP)
        try:
            x = None
            for _ in range(60):
                x = Client(port, timeout=15)
                if owner(x) not in (old, None):
                    break
                x.close()
                x = None
            present, code, _ = x.connect("big", clean=False, props={SESSION_EXPIRY: 600})
        finally:
            os.kill(old, signal.SIGCONT)
        check("the connection is let in without its large session after the claim's patience", (present, code), (False, 0))
        got = x.messages(50, 30)
        check("every queued message of a session past 8 MiB reaches it once its shard answers", len(got), 50)
        check("whole and in order", [m.payload[-2:] for m in got], [b"%02d" % i for i in range(50)])
        n = stat("sessions_pieced")
        truth("stats count a session carried in pieces", n >= 1, n)
        x.disconnect()
    guarded("large", large)
PY
}

for mode in mesh relayed; do
    daemon_isolate "mqttlate$mode"
    trap 'daemon_stop' EXIT
    if [ "$mode" = relayed ]; then export SOCKETLEY_NO_SHARD_MESH=1; else unset SOCKETLEY_NO_SHARD_MESH; fi
    daemon_start "$BIN"
    "$BIN" create mqtt sh -p "$P" --anonymous --shards 3 -s >/dev/null 2>&1 \
        && ok || bad "a broker of three shards is made ($mode)" "$(tail -3 "$SOCKETLEY_DLOG")"
    ready_tcp 127.0.0.1 "$P" || bad "it listens ($mode)" "$(tail -5 "$SOCKETLEY_DLOG")"
    for _ in $(seq 1 50); do
        [ "$("$BIN" stats sh 2>/dev/null | awk -F: '$1=="shard_peers_known"{s+=$2} END{print s+0}')" -ge 6 ] && break
        sleep 0.2
    done
    if [ "$mode" = relayed ]; then tally < <(run suback_relayed); else tally < <(run suback); fi
    tally < <(run late)
    [ "$mode" = mesh ] && tally < <(run stale)
    [ "$mode" = relayed ] && tally < <(run large)
    daemon_stop
done
unset SOCKETLEY_NO_SHARD_MESH

echo "  Results: $PASS/$((PASS + FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
